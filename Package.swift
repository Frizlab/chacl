// swift-tools-version:5.1
import PackageDescription


let package = Package(
	name: "ApplyFileSharingACLs",
	platforms: [
		.macOS(.v10_15)
	],
	products: [
		.executable(name: "ApplyFileSharingACLs", targets: ["ApplyFileSharingACLs"])
	],
	dependencies: [
		.package(url: "https://github.com/apple/swift-argument-parser", from: "0.2.1"),
		.package(url: "https://github.com/Frizlab/stream-reader.git", from: "3.0.0")
	],
	targets: [
		.target(name: "ApplyFileSharingACLs", dependencies: [
			.product(name: "ArgumentParser", package: "swift-argument-parser"),
			.product(name: "StreamReader",   package: "stream-reader")
		])
	]
)
