/* ApplyFileSharingACLs */

func usage<TargetStream: TextOutputStream>(program_name: String, stream: inout TargetStream) {
	print("ApplyFileSharingACLs config_file", to: &stream)
	print("", to: &stream)
	print("", to: &stream)
	print("", to: &stream)
	print("config_file format:", to: &stream)
	print("One path per line (if a path is present more than once, the latest entry will win):", to: &stream)
	print("[u|g]:[r|rw]:USER_OR_GROUP_NAME(:[u|g]:[r|rw]:USER_OR_GROUP_NAME)*::PATH", to: &stream)
}
