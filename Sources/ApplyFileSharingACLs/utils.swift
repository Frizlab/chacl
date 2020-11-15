/*
 * utils.swift
 * ApplyFileSharingACLs
 *
 * Created by François Lamboley on 11/15/17.
 */

import Foundation



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
