/* ApplyFileSharingACLs */

import Foundation

func usage<TargetStream: TextOutputStream>(program_name: String, stream: inout TargetStream) {
	print("ApplyFileSharingACLs config_file", to: &stream)
	print("", to: &stream)
	print("", to: &stream)
	print("", to: &stream)
	print("config_file format:", to: &stream)
	print("One path per line (if a path is present more than once, the latest entry will win):", to: &stream)
	print("[u|g]:[r|rw]:USER_OR_GROUP_NAME(:[u|g]:[r|rw]:USER_OR_GROUP_NAME)*::PATH", to: &stream)
}

let progName = CommandLine.arguments[0]
guard CommandLine.arguments.count == 2 else {
	usage(program_name: progName, stream: &mx_stderr)
	exit(1)
}

do {
	/* Parsing the config */
	let configs = try FileShareEntryConfig.parse(configFile: CommandLine.arguments[1])
	
	/* First step is to remove any custom ACL from all of the files in the paths
	 * given in the config (except for _spotlight’s). */
	for config in configs {
		#warning("TODO")
		let path = config.absolutePath
		guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else {continue /* No ACL for this file/folder */}
		
		var currentACLEntry: acl_entry_t?
		var currentACLEntryId = ACL_FIRST_ENTRY.rawValue
		/* The only error possible is invalid entry id (either completely invalid or next id after last entry has been reached).
		 * We know we’re giving a correct entry id, so if we get an error we have reached the latest entry! */
		while acl_get_entry(acl, currentACLEntryId, &currentACLEntry) == 0 {
			let currentACLEntry = currentACLEntry! /* No error from acl_get_entry: the entry must be filled in and non-nil */
			
			/* Getting ACL entry tag */
			var currentACLEntryTagType = ACL_UNDEFINED_TAG
			guard acl_get_tag_type(currentACLEntry, &currentACLEntryTagType) == 0 else {
				throw NSError(domain: "main", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cannot get ACL Entry Tag Type"])
			}
			
//			ACL_EXTENDED_ALLOW || ACL_EXTENDED_DENY
			
			currentACLEntryId = ACL_NEXT_ENTRY.rawValue
		}
	}
} catch {
	print("error: \(error)")
	exit(Int32((error as NSError).code))
}
