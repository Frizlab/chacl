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
		guard let stream = InputStream(fileAtPath: configFile != "-" ? configFile : "/dev/stdin") else {throw NSError(domain: "main", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cannot open file"])}
		stream.open(); defer {stream.close()}
		
		var entries = [FileShareEntryConfig]()
		let simpleStream = SimpleInputStream(stream: stream, bufferSize: 1*1024*1024 /* 1MiB */, streamReadSizeLimit: nil)
		repeat {
			let lineData: Data
			do {
				lineData = try simpleStream.readData(upToDelimiters: [Data(base64Encoded: "Cg==")!], matchingMode: .anyMatchWins, includeDelimiter: true, alwaysCopyBytes: false)
			} catch SimpleStreamError.delimitersNotFound {
				/* If we have a delimitersNotFound error, we still want to read the text remaining. */
				lineData = try simpleStream.readData(upToDelimiters: [], matchingMode: .anyMatchWins, includeDelimiter: false, alwaysCopyBytes: false)
			} catch {
				throw error
			}
			guard lineData.count > 0 else {break} /* We've reached the end of the file */
			
			guard let line = String(data: lineData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) else {
				throw NSError(domain: "main", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cannot read one line in text"])
			}
			guard line.first != "#" else {continue} /* Removing comments */
			guard line.count > 0 else {continue} /* Removing empty (whitespace-only) lines */
			
			var foundEnd = false
			var curString: NSString?
			let scanner = Scanner(string: line)
			scanner.charactersToBeSkipped = CharacterSet()
			
			var permissions = [Permission]()
			
			/* Getting permission destination */
			repeat {
				guard scanner.scanUpToCharacters(from: CharacterSet(charactersIn: ":"), into: &curString), scanner.scanString(":", into: nil) else {
					throw NSError(domain: "main", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid input line (cannot read permission destination) ——— \(line)"])
				}
				let permissionDestinationAsString = curString!.trimmingCharacters(in: .whitespacesAndNewlines)
				curString = nil
				
				/* Getting permission rights */
				guard scanner.scanUpToCharacters(from: CharacterSet(charactersIn: ":"), into: &curString), scanner.scanString(":", into: nil) else {
					throw NSError(domain: "main", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid input line (cannot read permission rights) ——— \(line)"])
				}
				let permissionRightsAsString = curString!.trimmingCharacters(in: .whitespacesAndNewlines)
				curString = nil
				
				/* Getting permission destination group or user name */
				guard scanner.scanUpToCharacters(from: CharacterSet(charactersIn: ":"), into: &curString), scanner.scanString(":", into: nil) else {
					throw NSError(domain: "main", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid input line (cannot read group or user name) ——— \(line)"])
				}
				let permissionDestinationGroupOrUserName = curString!.trimmingCharacters(in: .whitespacesAndNewlines)
				curString = nil
				
				guard let destination = Permission.Destination.fromString(permissionDestinationAsString, with: permissionDestinationGroupOrUserName) else {
					throw NSError(domain: "main", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid input line (invalid permission destination) ——— \(line)"])
				}
				guard let rights = Permission.Rights.fromString(permissionRightsAsString) else {
					throw NSError(domain: "main", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid input line (invalid permission destination) ——— \(line)"])
				}
				permissions.append(Permission(destination: destination, rights: rights))
				
				foundEnd = scanner.scanString(":", into: nil)
			} while !foundEnd
			
			guard scanner.scanUpToCharacters(from: CharacterSet(), into: &curString) else {
				throw NSError(domain: "main", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid input line (cannot read path) ——— \(line)"])
			}
			let path = curString! as String
			entries.append(FileShareEntryConfig(url: URL(fileURLWithPath: path), permissions: permissions))
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
	
	var url: URL
	var permissions: [Permission]
	
}
