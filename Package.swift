// swift-tools-version:5.4
import PackageDescription


let package = Package(
	name: "chacl",
	platforms: [
		.macOS(.v10_15)
	],
	products: [
		.executable(name: "chacl", targets: ["chacl"])
	],
	dependencies: [
//		.package(url: "https://github.com/apple/swift-argument-parser", from: "0.4.3"),
//		.package(url: "https://github.com/Frizlab/stream-reader.git", from: "3.2.1")
		.package(url: "https://github.com/apple/swift-argument-parser", from: "0.2.1"),
		.package(url: "https://github.com/Frizlab/stream-reader.git", from: "3.0.0")
	],
	targets: [
		.executableTarget(name: "chacl", dependencies: [
			.product(name: "ArgumentParser", package: "swift-argument-parser"),
			.product(name: "StreamReader",   package: "stream-reader")
		])
	]
)
