/*
 * ApplyFileSharingACLs.swift
 * ApplyFileSharingACLs
 *
 * Created by François Lamboley.
 */

import Foundation
import OpenDirectory

import ArgumentParser



/* Useful: https://opensource.apple.com/source/Libc/Libc-583/include/sys/acl.h.auto.html */

struct ApplyFileSharingACLs : ParsableCommand {
	
	static var configuration = CommandConfiguration(
		commandName: "ApplyFileSharingACLs",
		abstract: "Apply ACLs in a hierarchy of files and folders given a list of rules.",
		discussion: """
		The config file format is as follow:
		   One PATH per line (if a path is present more than once, the latest entry will win)
		   Each line must have the following format: `([u|g]:[r|rw]:USER_OR_GROUP_NAME:)*:PATH`
		""")
	
	@Flag
	var dryRun: Bool = false
	
	@Flag
	var verbose: Bool = false
	
	@Argument
	var configFilePath: String
	
	func run() throws {
		/* Commented because the compiler knows KAUTH_GUID_SIZE == 16 at compile
		 * time and thus complains w/ a warning the else part of the guard will
		 * never be executed…
		 * Instead we do the opposite, and (hopefully) trigger a warning if
		 * KAUTH_GUID_SIZE is not 16! I don’t know if a static check from the
		 * compiler is possible, but it does not seem to be. (It is technically
		 * possible; KAUTH_GUID_SIZE is a #define, but I don’t think it’s
		 * implemented in the compiler.)
		 * This is indeed not the same thing! But I don’t want a warning in my
		 * code, and realistically KAUTH_GUID_SIZE will never be != 16. */
//		guard KAUTH_GUID_SIZE == 16 else {
//			throw SimpleError(message: "The auth GUID has not the expected size (thus is probably not a UUID), so we can’t run. At all. Bye.")
//		}
		if KAUTH_GUID_SIZE == 16 {
			_ = "not an empty if! The auth GUID has not the expected size (thus is probably not a UUID), so you’ll probably run into weird issues…"
		}
		
		let fm = FileManager.default
		
		let odSession = ODSession.default()
		let odNode = try ODNode(session: odSession, type: ODNodeType(kODNodeTypeAuthentication))
		let spotlightRecord = try odNode.record(withRecordType: kODRecordTypeUsers, name: "spotlight", attributes: [kODAttributeTypeGUID])
		guard let spotlightGUID = try (spotlightRecord.values(forAttribute: kODAttributeTypeGUID).onlyElement as? String).flatMap({ UUID(uuidString: $0) }) else {
			throw SimpleError(message: "Zero or more than one value, or invalid UUID string for attribute kODAttributeTypeGUID for the spotlight user; cannot continue.")
		}
		
		/* Parsing the config */
		let configs: [PreprocessedFileShareEntryConfig]
		do {
			guard let stream = InputStream(fileAtPath: configFilePath != "-" ? configFilePath : "/dev/stdin") else {
				throw SimpleError(message: "Cannot open file")
			}
			let baseURLForPaths: URL
			if configFilePath != "-" {baseURLForPaths = URL(fileURLWithPath: configFilePath).deletingLastPathComponent()}
			else                     {baseURLForPaths = URL(fileURLWithPath: fm.currentDirectoryPath, isDirectory: true)}
			stream.open(); defer {stream.close()}
			configs = try FileShareEntryConfig.parse(config: stream, baseURLForPaths: baseURLForPaths, verbose: verbose)
				.map{ try PreprocessedFileShareEntryConfig(config: $0, odNode: odNode) }
		}
		
		/* First step is to remove any custom ACL from all of the files in the
		 * paths given in the config (except for Spotlight’s).
		 *
		 * We want to treat longer paths at the end to optimize away all path that
		 * have a parent which include them.
		 * Because the paths are absolute (and dropped of all the .. components),
		 * treating longer paths at the end works (we’re guaranteed to have
		 * treated the parent if it is listed). */
		var treated = Set<String>()
		for config in configs.sorted(by: { $0.absolutePath.count < $1.absolutePath.count }) {
			let path = config.absolutePath
			guard !treated.contains(where: { path.hasPrefix($0) }) else {continue}
			
			if verbose {
				print((dryRun ? "** DRY RUN ** " : "") + "Removing all ACLs recursively in all files and folders in \(path)")
			}
			treated.insert(path)
			let url = URL(fileURLWithPath: path, isDirectory: true)
			
			/* Let’s create a directory enumerator to enumerate all the files and
			 * folder in the path being treated. */
			guard let enumerator = fm.enumerator(at: url, includingPropertiesForKeys: nil) else {
				throw SimpleError(message: "Cannot get directory enumerator for url \(url)")
			}
			
			/* Actually removing all the ACLs except Spotlight’s */
			try removeACLs(from: url, whitelist: [spotlightGUID], dryRun: dryRun) /* We must first call for the current path itself: the directory enumerator does not output the source. */
			while let subURL = enumerator.nextObject() as! URL? {
				try removeACLs(from: subURL, whitelist: [spotlightGUID], dryRun: dryRun)
			}
		}
		
		/* Then we add the ACLs required from the config.
		 * We also treat longer path at the end so the parents are treated first.
		 * Note: This algorithm is not efficient; we should resove the final ACLs
		 *       needed and apply them! However it’s simpler that way :-) */
		for config in configs.sorted(by: { $0.absolutePath.count < $1.absolutePath.count }) {
			let path = config.absolutePath
			
			if verbose {
				print((dryRun ? "** DRY RUN ** " : "") + "Adding ACLs recursively in all files and folders in \(path)")
			}
			let url = URL(fileURLWithPath: path, isDirectory: true)
			
			/* Let’s create a directory enumerator to enumerate all the files and
			 * folder in the path being treated. */
			guard let enumerator = fm.enumerator(at: url, includingPropertiesForKeys: [.fileResourceTypeKey]) else {
				throw SimpleError(message: "Cannot get directory enumerator for path \(path)")
			}
			
			/* Actually adding the ACLs */
			try addACLs(to: url, conf: config, fileManager: fm, isRoot: true, dryRun: dryRun)
			while let subURL = enumerator.nextObject() as! URL? {
				try addACLs(to: subURL, conf: config, fileManager: fm, isRoot: false, dryRun: dryRun)
			}
		}
	}
	
	private func addACLs(to url: URL, conf: PreprocessedFileShareEntryConfig, fileManager fm: FileManager, isRoot: Bool, dryRun: Bool) throws {
		let path = url.absoluteURL.path
		guard let fileResourceType = try url.resourceValues(forKeys: [.fileResourceTypeKey]).fileResourceType else {
			throw SimpleError(message: "Cannot get file type of URL \(url)")
		}
		guard fileResourceType == .directory || fileResourceType == .regular else {
			print("ignored non-regular and non-directory path \(path)")
			return
		}
		
		let acl: acl_t!
		if let currentACL = acl_get_link_np(path, ACL_TYPE_EXTENDED) {
			acl = currentACL
		} else {
			guard errno == ENOENT else {throw SimpleError(message: "Cannot read ACLs for path \(path); got error number \(errno)")}
			acl = acl_init(conf.permCount)
		}
		defer {acl_free(UnsafeMutableRawPointer(acl))}
		
		let modified: Bool
		let isDir = fileResourceType == .directory
		if !isDir {modified = try conf.addFileACLEntries(to: acl, isRoot: isRoot)}
		else      {modified = try conf.addFolderACLEntries(to: acl, isRoot: isRoot)}
		
		if modified {
			if verbose || dryRun {
				print((dryRun ? "** DRY RUN ** " : "") + "Adding ACLs to file \(path)")
			}
			if !dryRun {
				guard acl_set_link_np(path, ACL_TYPE_EXTENDED, acl) == 0 else {
					throw SimpleError(message: "cannot set ACL on file at path \(path)")
				}
			}
		}
	}
	
	private func removeACLs(from url: URL, whitelist: Set<UUID>, dryRun: Bool) throws {
		let path = url.absoluteURL.path
		guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else {
			if errno == ENOENT {return} /* No ACL for this file or folder */
			else               {throw SimpleError(message: "Cannot read ACLs for path \(path); got error number \(errno)")}
		}
		defer {acl_free(UnsafeMutableRawPointer(acl))}
		
		var modified = false
		var currentACLEntry: acl_entry_t?
		var currentACLEntryId = ACL_FIRST_ENTRY.rawValue
		/* The only error possible is invalid entry id (either completely invalid
		 * or next id after last entry has been reached).
		 * We know we’re giving a correct entry id, so if we get an error we have
		 * reached the latest entry! */
		while acl_get_entry(acl, currentACLEntryId, &currentACLEntry) == 0 {
			let currentACLEntry = currentACLEntry! /* No error from acl_get_entry: the entry must be filled in and non-nil */
			defer {currentACLEntryId = ACL_NEXT_ENTRY.rawValue}
			
			/* Getting ACL entry tag */
			var currentACLEntryTagType = ACL_UNDEFINED_TAG
			guard acl_get_tag_type(currentACLEntry, &currentACLEntryTagType) == 0 else {
				throw SimpleError(message: "Cannot get ACL Entry Tag Type")
			}
			guard currentACLEntryTagType == ACL_EXTENDED_ALLOW || currentACLEntryTagType == ACL_EXTENDED_DENY else {
				throw SimpleError(message: "Unknown ACL tag type \(currentACLEntryTagType) for path \(path); bailing out")
			}
			
			/* The man of acl_get_qualifier says if the tag type is
			 * ACL_EXTENDED_ALLOW or ACL_EXTENDED_DENY, the returned pointer will
			 * point to a guid_t */
			guard let userOrGroupGUIDPointer = acl_get_qualifier(currentACLEntry)?.assumingMemoryBound(to: guid_t.self) else {
				throw SimpleError(message: "Cannot fetch userOrGroupGUID GUID for path \(path)")
			}
			defer {acl_free(userOrGroupGUIDPointer)}
			guard let userOrGroupGUID = UUID(guid: userOrGroupGUIDPointer.pointee) else {
				throw SimpleError(message: "Cannot convert guid_t to UUID (weird though)")
			}
			guard !whitelist.contains(userOrGroupGUID) else {
				continue
			}
			
			/* We do not need to know what are the permission on this ACL, we will
			 * just drop it. */
//			var currentACLEntryPermset: acl_permset_t?
//			guard acl_get_permset(currentACLEntry, &currentACLEntryPermset) == 0 else {
//				throw SimpleError(message: "Cannot get ACL Entry Permset")
//			}
//			for perm in [ACL_READ_DATA, ACL_LIST_DIRECTORY, ...] {
//				let ret = acl_get_perm_np(currentACLEntryPermset, ACL_READ_DATA);
//				switch ret {
//					case 0: (/* Permission is not in the permset */)
//					case 1: (/* Permission is in the permset */)
//					default: (/* An error occurred */)
//				}
//			}
			
			/* Source code https://opensource.apple.com/source/Libc/Libc-825.26/posix1e/acl_entry.c.auto.html
			 * confirms it is valid to get next entry when we have deleted one. */
			acl_delete_entry(acl, currentACLEntry)
			modified = true
		}
		if modified {
			if verbose || dryRun {
				print((dryRun ? "** DRY RUN ** " : "") + "Removed ACLs from file \(path)")
			}
			if !dryRun {
				guard acl_set_link_np(path, ACL_TYPE_EXTENDED, acl) == 0 else {
					throw SimpleError(message: "cannot set ACL on file at path \(path)")
				}
			}
		}
	}
	
	
	/* Must be a class to have a deinit, because we keep refs to acl_t pointers
	 * and need to free them when we are dealloc’d. */
	private class PreprocessedFileShareEntryConfig {
		
		var absolutePath: String
		var permCount: Int32
		
		init(config: FileShareEntryConfig, odNode: ODNode) throws {
			absolutePath = config.absolutePath
			permCount = Int32(config.permissions.count)
			
			refACLForFile = acl_init(permCount /* This is a minimum; we could put 0 here. */)
			refACLForFolder = acl_init(permCount /* This is a minimum; we could put 0 here. */)
			
			for perm in config.permissions {
				var aclEntryForFile, aclEntryForFolder: acl_entry_t?
				guard acl_create_entry(&refACLForFile, &aclEntryForFile) == 0, acl_create_entry(&refACLForFolder, &aclEntryForFolder) == 0 else {
					throw SimpleError(message: "cannot create ACL entry while init’ing a PreprocessedFileShareEntryConfig")
				}
				
				guard acl_set_tag_type(aclEntryForFile, ACL_EXTENDED_ALLOW) == 0, acl_set_tag_type(aclEntryForFolder, ACL_EXTENDED_ALLOW) == 0 else {
					throw SimpleError(message: "cannot set tag type of ACL entry while init’ing a PreprocessedFileShareEntryConfig")
				}
				
				let destRecordType: String
				let destRecordName: String
				switch perm.destination {
					case .user(let username):   destRecordType = kODRecordTypeUsers;  destRecordName = username
					case .group(let groupname): destRecordType = kODRecordTypeGroups; destRecordName = groupname
				}
				let record = try odNode.record(withRecordType: destRecordType, name: destRecordName, attributes: [kODAttributeTypeGUID])
				guard var guid = try (record.values(forAttribute: kODAttributeTypeGUID).onlyElement as? String).flatMap({ UUID(uuidString: $0) })?.guid else {
					throw SimpleError(message: "zero or more than one value, or invalid UUID string for attribute kODAttributeTypeGUID for permission destination \(perm.destination); cannot continue.")
				}
				guard acl_set_qualifier(aclEntryForFile, &guid) == 0, acl_set_qualifier(aclEntryForFolder, &guid) == 0 else {
					throw SimpleError(message: "cannot set qualifier of ACL entry while init’ing a PreprocessedFileShareEntryConfig")
				}
				
				var aclPermsetForFile, aclPermsetForFolder: acl_permset_t!
				guard acl_get_permset(aclEntryForFile, &aclPermsetForFile) == 0, acl_get_permset(aclEntryForFolder, &aclPermsetForFolder) == 0 else {
					throw SimpleError(message: "cannot get ACL entry permset while init’ing a PreprocessedFileShareEntryConfig")
				}
				switch perm.rights {
					case .readwrite:
						try Self.addPerm(ACL_DELETE, to: aclPermsetForFile)
						try Self.addPerm(ACL_DELETE, to: aclPermsetForFolder)
						try Self.addPerm(ACL_WRITE_ATTRIBUTES, to: aclPermsetForFile)
						try Self.addPerm(ACL_WRITE_ATTRIBUTES, to: aclPermsetForFolder)
						try Self.addPerm(ACL_WRITE_EXTATTRIBUTES, to: aclPermsetForFile)
						try Self.addPerm(ACL_WRITE_EXTATTRIBUTES, to: aclPermsetForFolder)
						
						try Self.addPerm(ACL_WRITE_DATA, to: aclPermsetForFile)
						try Self.addPerm(ACL_APPEND_DATA, to: aclPermsetForFile)
						
						try Self.addPerm(ACL_ADD_FILE, to: aclPermsetForFolder)
						try Self.addPerm(ACL_ADD_SUBDIRECTORY, to: aclPermsetForFolder)
						try Self.addPerm(ACL_DELETE_CHILD, to: aclPermsetForFolder)
						
						fallthrough
						
					case .readonly:
						try Self.addPerm(ACL_READ_ATTRIBUTES, to: aclPermsetForFile)
						try Self.addPerm(ACL_READ_ATTRIBUTES, to: aclPermsetForFolder)
						try Self.addPerm(ACL_READ_EXTATTRIBUTES, to: aclPermsetForFile)
						try Self.addPerm(ACL_READ_EXTATTRIBUTES, to: aclPermsetForFolder)
						
						try Self.addPerm(ACL_READ_DATA, to: aclPermsetForFile)
						
						try Self.addPerm(ACL_LIST_DIRECTORY, to: aclPermsetForFolder)
						try Self.addPerm(ACL_SEARCH, to: aclPermsetForFolder)
				}
				guard acl_set_permset(aclEntryForFile, aclPermsetForFile) == 0, acl_set_permset(aclEntryForFolder, aclPermsetForFolder) == 0 else {
					throw SimpleError(message: "cannot set ACL entry permset while init’ing a PreprocessedFileShareEntryConfig")
				}
				
				/* We do not set any flag on the files… Note a flagset can be set on
				 * the ACL and the ACL entry. We only set it on the ACL entry, both
				 * because it’s what we really want and also because I’m not sure
				 * what setting on the ACL directly does. */
				var aclFlagsetForFolder: acl_flagset_t!
				guard acl_get_flagset_np(aclEntryForFolder.flatMap({ UnsafeMutableRawPointer($0) }), &aclFlagsetForFolder) == 0 else {
					throw SimpleError(message: "cannot get ACL entry flagset while init’ing a PreprocessedFileShareEntryConfig")
				}
				try Self.addFlag(ACL_ENTRY_FILE_INHERIT, to: aclFlagsetForFolder)
				try Self.addFlag(ACL_ENTRY_DIRECTORY_INHERIT, to: aclFlagsetForFolder)
				guard acl_set_flagset_np(aclEntryForFolder.flatMap({ UnsafeMutableRawPointer($0) }), aclFlagsetForFolder) == 0 else {
					throw SimpleError(message: "cannot set ACL entry flagset while init’ing a PreprocessedFileShareEntryConfig")
				}
			}
		}
		
		deinit {
			acl_free(UnsafeMutableRawPointer(refACLForFile))
			acl_free(UnsafeMutableRawPointer(refACLForFolder))
		}
		
		/** Returns `true` if the ACL has been modified. */
		func addFileACLEntries(to acl: acl_t, isRoot: Bool) throws -> Bool {
			return try addACLEntries(to: acl, isRoot: isRoot, ref: refACLForFile)
		}
		
		/** Returns `true` if the ACL has been modified. */
		func addFolderACLEntries(to acl: acl_t, isRoot: Bool) throws -> Bool {
			return try addACLEntries(to: acl, isRoot: isRoot, ref: refACLForFolder)
		}
		
		private static func addPerm(_ perm: acl_perm_t, to permset: acl_permset_t) throws {
			guard acl_add_perm(permset, perm) == 0 else {
				throw SimpleError(message: "cannot add perm to permset")
			}
		}
		
		private static func addFlag(_ flag: acl_flag_t, to flagset: acl_flagset_t) throws {
			guard acl_add_flag_np(flagset, flag) == 0 else {
				throw SimpleError(message: "cannot add flag to flagset")
			}
		}
		
		/* Must be implicitely unwrapped because of weird interoperability w/ C. */
		private var refACLForFile: acl_t!
		private var refACLForFolder: acl_t!
		
		private func addACLEntries(to acl: acl_t, isRoot: Bool, ref: acl_t) throws -> Bool {
			var modified = false
			var acl: acl_t! = acl
			var currentRefACLEntry: acl_entry_t?
			var currentRefACLEntryId = ACL_FIRST_ENTRY.rawValue
			while acl_get_entry(ref, currentRefACLEntryId, &currentRefACLEntry) == 0 {
				let currentRefACLEntry = currentRefACLEntry! /* No error from acl_get_entry: the entry must be filled in and non-nil */
				defer {currentRefACLEntryId = ACL_NEXT_ENTRY.rawValue}
				
				/* Creating a new ACL entry in the destination ACL */
				var currentACLEntry: acl_entry_t?
				guard acl_create_entry(&acl, &currentACLEntry) == 0 else {
					throw SimpleError(message: "cannot create ACL entry while copying ACL entries")
				}
				modified = true
				
				/* Copying ACL entry tag */
				var currentRefACLEntryTagType = ACL_UNDEFINED_TAG
				guard acl_get_tag_type(currentRefACLEntry, &currentRefACLEntryTagType) == 0, acl_set_tag_type(currentACLEntry, currentRefACLEntryTagType) == 0 else {
					throw SimpleError(message: "cannot copy ACL entry tag type while copying ACL entries")
				}
				
				/* Copying ACL qualifier */
				guard let qualifer = acl_get_qualifier(currentRefACLEntry) else {
					throw SimpleError(message: "cannot copy ACL entry qualifier while copying ACL entries")
				}
				defer {acl_free(qualifer)}
				guard acl_set_qualifier(currentACLEntry, qualifer) == 0 else {
					throw SimpleError(message: "cannot copy ACL entry qualifier while copying ACL entries")
				}
				
				/* Copying ACL permset */
				var currentRefACLEntryPermset: acl_permset_t?
				guard acl_get_permset(currentRefACLEntry, &currentRefACLEntryPermset) == 0, acl_set_permset(currentACLEntry, currentRefACLEntryPermset) == 0 else {
					throw SimpleError(message: "cannot copy ACL entry permset while copying ACL entries")
				}
				
				/* Copying (and modifying if needed) flagset */
				var currentRefACLEntryFlagset: acl_flagset_t?
				guard acl_get_flagset_np(UnsafeMutableRawPointer(currentRefACLEntry), &currentRefACLEntryFlagset) == 0 else {
					throw SimpleError(message: "cannot copy ACL entry flagset while copying ACL entries")
				}
				/* We mark the permission as being inherited if needed. Actually
				 * changes the flagset of the ref ACL, but we do not care because we
				 * will always set it to the correct value (and we run on 1 thread
				 * only). */
				if !isRoot {acl_add_flag_np(currentRefACLEntryFlagset, ACL_ENTRY_INHERITED)}
				else       {acl_delete_flag_np(currentRefACLEntryFlagset, ACL_ENTRY_INHERITED)}
				guard acl_set_flagset_np(currentACLEntry.flatMap({ UnsafeMutableRawPointer($0) }), currentRefACLEntryFlagset) == 0 else {
					throw SimpleError(message: "cannot copy ACL entry flagset while copying ACL entries")
				}
			}
			return modified
		}
		
	}
	
}
