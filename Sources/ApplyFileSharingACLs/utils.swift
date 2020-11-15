/*
 * utils.swift
 * ApplyFileSharingACLs
 *
 * Created by François Lamboley on 11/15/17.
 */

import Foundation



extension UUID {
	
	init?(guid: guid_t) {
		guard let cfUUID = CFUUIDCreateWithBytes(nil, guid.g_guid.0, guid.g_guid.1, guid.g_guid.2, guid.g_guid.3, guid.g_guid.4, guid.g_guid.5, guid.g_guid.6, guid.g_guid.7, guid.g_guid.8, guid.g_guid.9, guid.g_guid.10, guid.g_guid.11, guid.g_guid.12, guid.g_guid.13, guid.g_guid.14, guid.g_guid.15) else {
			return nil
		}
		/* CFUUID is not toll-free bridged w/ UUID… So we use the string
		 * representation like the doc suggests! */
		guard let str = CFUUIDCreateString(nil, cfUUID) as String? else {
			return nil
		}
		self.init(uuidString: str)
	}
	
	var guid: guid_t {
		return guid_t(g_guid: uuid)
	}
	
}


extension Collection {
	
	public var onlyElement: Element? {
		guard let e = first, count == 1 else {
			return nil
		}
		return e
	}
	
}


class StandardErrorOutputStream: TextOutputStream {
	
	func write(_ string: String) {
		let stderr = FileHandle.standardError
		stderr.write(string.data(using: String.Encoding.utf8)!)
	}
	
}

class StandardOutputStream: TextOutputStream {
	
	func write(_ string: String) {
		let stderr = FileHandle.standardOutput
		stderr.write(string.data(using: String.Encoding.utf8)!)
	}
	
}

var mx_stdout = StandardOutputStream()
var mx_stderr = StandardErrorOutputStream()
