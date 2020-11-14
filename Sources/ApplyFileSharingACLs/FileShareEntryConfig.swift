/*
 * FileShareEntryConfig.swift
 * ApplyFileSharingACLs
 *
 * Created by François Lamboley on 11/15/17.
 */

import Foundation
import SimpleStream



struct FileShareEntryConfig {
	
	/** Parses the given config file. If file is "-", will read from stdin. */
	static func parse(configFile: String) throws -> [FileShareEntryConfig] {
		guard let stream = InputStream(fileAtPath: configFile != "-" ? configFile : "/dev/stdin") else {throw SimpleError(message: "Cannot open file")}
		stream.open(); defer {stream.close()}
		
		var entries = [FileShareEntryConfig]()
		let simpleStream = SimpleInputStream(stream: stream, bufferSize: 1*1024*1024 /* 1MiB */, bufferSizeIncrement: 1*1024 /* 1KiB */, streamReadSizeLimit: nil)
		repeat {
			let lineData: Data
			do {
				lineData = try simpleStream.readData(upTo: [Data(base64Encoded: "Cg==")!], matchingMode: .anyMatchWins, includeDelimiter: true).data
			} catch SimpleStreamError.delimitersNotFound {
				/* If we have a delimitersNotFound error, we still want to read the text remaining. */
				lineData = try simpleStream.readData(upTo: [], matchingMode: .anyMatchWins, includeDelimiter: false).data
			} catch {
				throw error
			}
			guard lineData.count > 0 else {break} /* We've reached the end of the file */
			
			guard let line = (String(data: lineData, encoding: .utf8)?.dropLast()).flatMap(String.init) else {
				throw SimpleError(message: "Cannot read one line in text")
			}
			guard line.first != "#" else {continue} /* Removing comments */
			guard line.count > 0 else {continue} /* Removing empty (whitespace-only) lines */
			
			var curString: NSString?
			let scanner = Scanner(string: line)
			scanner.charactersToBeSkipped = CharacterSet()
			
			/* Getting permission destination */
			var permissions = [Permission]()
			while !scanner.scanString(":", into: nil) {
				guard scanner.scanUpToCharacters(from: CharacterSet(charactersIn: ":"), into: &curString), scanner.scanString(":", into: nil) else {
					throw SimpleError(message: "Invalid input line (cannot read permission destination) ——— \(line)")
				}
				let permissionDestinationAsString = curString!.trimmingCharacters(in: .whitespacesAndNewlines)
				curString = nil
				
				/* Getting permission rights */
				guard scanner.scanUpToCharacters(from: CharacterSet(charactersIn: ":"), into: &curString), scanner.scanString(":", into: nil) else {
					throw SimpleError(message: "Invalid input line (cannot read permission rights) ——— \(line)")
				}
				let permissionRightsAsString = curString!.trimmingCharacters(in: .whitespacesAndNewlines)
				curString = nil
				
				/* Getting permission destination group or user name */
				guard scanner.scanUpToCharacters(from: CharacterSet(charactersIn: ":"), into: &curString), scanner.scanString(":", into: nil) else {
					throw SimpleError(message: "Invalid input line (cannot read group or user name) ——— \(line)")
				}
				let permissionDestinationGroupOrUserName = curString!.trimmingCharacters(in: .whitespacesAndNewlines)
				curString = nil
				
				guard let destination = Permission.Destination.fromString(permissionDestinationAsString, with: permissionDestinationGroupOrUserName) else {
					throw SimpleError(message: "Invalid input line (invalid permission destination) ——— \(line)")
				}
				guard let rights = Permission.Rights.fromString(permissionRightsAsString) else {
					throw SimpleError(message: "Invalid input line (invalid permission destination) ——— \(line)")
				}
				permissions.append(Permission(destination: destination, rights: rights))
			}
			
			guard scanner.scanUpToCharacters(from: CharacterSet(), into: &curString) else {
				throw SimpleError(message: "Invalid input line (cannot read path) ——— \(line)")
			}
			let path = curString! as String
			let absolutePath = URL(fileURLWithPath: path).absoluteURL.path
			if let idx = entries.firstIndex(where: { $0.absolutePath == absolutePath }) {
				print("*** warning: entry for path \(absolutePath) found more than once; latest one wins.")
				entries.remove(at: idx)
				assert(!entries.contains(where: { $0.absolutePath == absolutePath }))
			}
			entries.append(FileShareEntryConfig(absolutePath: absolutePath, permissions: permissions))
		} while true
		
		return entries
	}
	
	struct Permission {
		
		enum Destination {
			case user(String)
			case group(String)
			
			static func fromString(_ str: String, with userOrGroupName: String) -> Destination? {
				switch str {
				case "u": return .user(userOrGroupName)
				case "g": return .group(userOrGroupName)
				default: return nil
				}
			}
		}
		
		enum Rights {
			case readonly
			case readwrite
			
			static func fromString(_ str: String) -> Rights? {
				switch str {
				case "r":  return .readonly
				case "rw": return .readwrite
				default: return nil
				}
			}
		}
		
		let destination: Destination
		let rights: Rights
		
	}
	
	var absolutePath: String
	var permissions: [Permission]
	
}
