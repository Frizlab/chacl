/*
 * ApplyFileSharingACLs.swift
 * ApplyFileSharingACLs
 *
 * Created by François Lamboley.
 */

import Foundation
import OpenDirectory

import ArgumentParser



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
		guard KAUTH_GUID_SIZE == 16 else {
			throw SimpleError(message: "The GUID of a user has not the expected size (thus is probably not a UUID), so we can’t run. At all. Bye.")
		}
		
		/* Parsing the config */
		let configs = try FileShareEntryConfig.parse(configFile: configFilePath)
		
		let fm = FileManager.default
		
		let odSession = ODSession.default()
		let odNode = try ODNode(session: odSession, type: ODNodeType(kODNodeTypeAuthentication))
		let spotlightRecord = try odNode.record(withRecordType: kODRecordTypeUsers, name: "spotlight", attributes: nil)
		guard let spotlightGUID = try (spotlightRecord.values(forAttribute: kODAttributeTypeGUID).onlyElement as? String).flatMap({ UUID(uuidString: $0) }) else {
			throw SimpleError(message: "Zero or more than one value, or invalid UUID string for attribute kODAttributeTypeGUID for the spotlight user; cannot continue.")
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
			
			print("Removing all ACLs recursively in all files and folders in \(path)")
			treated.insert(path)
			let url = URL(fileURLWithPath: path, isDirectory: true)
			
			/* Let’s create a directory enumerator to enumerate all the files and
			 * folder in the path being treated. */
			guard let enumerator = fm.enumerator(atPath: path) else {
				throw SimpleError(message: "Cannot get directory enumerator for path \(path)")
			}
			
			/* Actually removing all the ACLs except Spotlight’s */
			try removeACLs(from: url, whitelist: [spotlightGUID], dryRun: dryRun) /* We must first call for the current path itself: the directory enumerator does not output the source. */
			while let subPath = enumerator.nextObject() as! String? {
				try removeACLs(from: URL(fileURLWithPath: subPath, relativeTo: url), whitelist: [spotlightGUID], dryRun: dryRun)
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
			guard let userOrGroupGUIDLowPointer = acl_get_qualifier(currentACLEntry)?.assumingMemoryBound(to: guid_t.self) else {
				throw SimpleError(message: "Cannot fetch userOrGroupGUID GUID for path \(path)")
			}
			defer {acl_free(userOrGroupGUIDLowPointer)}
			let userOrGroupGUID = try guid_tToUUID(userOrGroupGUIDLowPointer.pointee)
			guard !whitelist.contains(userOrGroupGUID) else {
				continue
			}
			print(userOrGroupGUID)
		}
	}
	
	private func guid_tToUUID(_ guid: guid_t) throws -> UUID {
		guard let cfUUID = CFUUIDCreateWithBytes(nil, guid.g_guid.0, guid.g_guid.1, guid.g_guid.2, guid.g_guid.3, guid.g_guid.4, guid.g_guid.5, guid.g_guid.6, guid.g_guid.7, guid.g_guid.8, guid.g_guid.9, guid.g_guid.10, guid.g_guid.11, guid.g_guid.12, guid.g_guid.13, guid.g_guid.14, guid.g_guid.15) else {
			throw SimpleError(message: "Cannot convert guid_t to CFUUID (this is weird though)")
		}
		/* CFUUID is not toll-free bridged w/ UUID… So we use the string
		 * representation like the doc suggests! */
		guard let str = CFUUIDCreateString(nil, cfUUID) as String? else {
			throw SimpleError(message: "Cannot convert CFUUID to String (this is weird though)")
		}
		guard let uuid = UUID(uuidString: str) else {
			throw SimpleError(message: "Cannot convert String representation of CFUUID to UUID (this is weird though)")
		}
		return uuid
	}
	
}
