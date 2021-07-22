/*
 * ChaclConfigEntry.swift
 * chacl
 *
 * Created by François Lamboley on 11/15/17.
 */

import Foundation

import Logging
import StreamReader



struct ChaclConfigEntry {
	
	/** Parses the given FileHandle. */
	static func parse(config fh: FileHandle, baseURLForPaths: URL, logger: Logger) throws -> [ChaclConfigEntry] {
		var entries = [ChaclConfigEntry]()
		let simpleStream = FileHandleReader(stream: fh, bufferSize: 1*1024*1024 /* 1MiB */, bufferSizeIncrement: 1*1024 /* 1KiB */, readSizeLimit: nil)
		while let (lineData, _) = try simpleStream.readLine() {
			guard let line = String(data: lineData, encoding: .utf8) else {
				throw SimpleError(message: "Cannot read one line in text")
			}
			guard line.first != "#" else {continue} /* Removing comments */
			guard line.count > 0 else {continue} /* Removing empty (whitespace-only) lines */
			
			let scanner = Scanner(string: line)
			scanner.charactersToBeSkipped = CharacterSet()
			
			/* Getting permission destination */
			var permissions = [Permission]()
			while (scanner.scanCharacters(from: .whitespaces) != nil || true) && scanner.scanString(":") == nil {
				guard
					let permissionDestinationAsString = scanner.scanUpToCharacters(from: CharacterSet(charactersIn: ":"))?.trimmingCharacters(in: .whitespacesAndNewlines),
					scanner.scanString(":") != nil
				else {
					throw SimpleError(message: "Invalid input line (cannot read permission destination) ——— \(line)")
				}
				
				/* Getting permission destination group or user name */
				guard
					let permissionDestinationGroupOrUserName = scanner.scanUpToCharacters(from: CharacterSet(charactersIn: ":"))?.trimmingCharacters(in: .whitespacesAndNewlines),
					scanner.scanString(":") != nil
				else {
					throw SimpleError(message: "Invalid input line (cannot read group or user name) ——— \(line)")
				}
				
				/* Getting permission rights */
				guard
					let permissionRightsAsString = scanner.scanUpToCharacters(from: CharacterSet(charactersIn: ":"))?.trimmingCharacters(in: .whitespacesAndNewlines),
					scanner.scanString(":") != nil
				else {
					throw SimpleError(message: "Invalid input line (cannot read permission rights) ——— \(line)")
				}
				
				guard let destination = Permission.Destination.fromString(permissionDestinationAsString, with: permissionDestinationGroupOrUserName) else {
					throw SimpleError(message: "Invalid input line (invalid permission destination) ——— \(line)")
				}
				guard let rights = Permission.Rights.fromString(permissionRightsAsString) else {
					throw SimpleError(message: "Invalid input line (invalid permission destination) ——— \(line)")
				}
				permissions.append(Permission(destination: destination, rights: rights))
			}
			
			guard let parsedPath = scanner.scanUpToCharacters(from: CharacterSet()) else {
				throw SimpleError(message: "Invalid input line (cannot read path) ——— \(line)")
			}
			let url = URL(fileURLWithPath: parsedPath, relativeTo: baseURLForPaths)
			
			let absolutePath: String
			switch URL(fileURLWithPath: parsedPath).pathComponents.count {
				case 0: throw SimpleError(message: "Internal logic error: Got a URL with 0 path components; that’s weird…")
				case 1: absolutePath = url.absoluteURL.path
				default:
					let realpathed = url.deletingLastPathComponent().path
					guard let realpathC = Darwin.realpath(realpathed, nil) else {
						throw SimpleError(message: "realpath cannot resolve path \(realpathed)")
					}
					defer {free(realpathC)}
					let realpath = String(cString: realpathC)
					absolutePath = URL(fileURLWithPath: realpath).appendingPathComponent(url.lastPathComponent).absoluteURL.path
			}
			guard FileManager.default.fileExists(atPath: absolutePath) else {
				throw SimpleError(message: "File does not exist (or do not have permission to read) at path \(absolutePath)")
			}
			if parsedPath != absolutePath {
				logger.notice("path cleanup: \(parsedPath) -> \(absolutePath)")
			}
			
			if let idx = entries.firstIndex(where: { $0.absolutePath == absolutePath }) {
				logger.warning("entry for path \(absolutePath) found more than once; latest one wins")
				entries.remove(at: idx)
				assert(!entries.contains(where: { $0.absolutePath == absolutePath }))
			}
			entries.append(ChaclConfigEntry(absolutePath: absolutePath, permissions: permissions))
		}
		
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
