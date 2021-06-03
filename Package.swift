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
		.package(url: "https://github.com/apple/swift-argument-parser", from: "0.4.3"),
		.package(url: "https://github.com/apple/swift-log", from: "1.4.2"),
		.package(url: "https://github.com/Frizlab/stream-reader.git", from: "3.2.1"),
		.package(url: "https://github.com/xcode-actions/clt-logger.git", from: "0.3.4")
	],
	targets: [
		.executableTarget(name: "chacl", dependencies: [
			.product(name: "ArgumentParser", package: "swift-argument-parser"),
			.product(name: "CLTLogger",      package: "clt-logger"),
			.product(name: "Logging",        package: "swift-log"),
			.product(name: "StreamReader",   package: "stream-reader")
		])
	]
)
