// swift-tools-version:5.0
import PackageDescription


let package = Package(
	name: "ApplyFileSharingACLs",
	products: [
		.executable(name: "ApplyFileSharingACLs", targets: ["ApplyFileSharingACLs"])
	],
	dependencies: [
		.package(url: "https://github.com/apple/swift-argument-parser", from: "0.2.1"),
		.package(url: "https://github.com/Frizlab/SimpleStream.git", from: "2.1.0")
	],
	targets: [
		.target(name: "ApplyFileSharingACLs", dependencies: [
			.product(name: "ArgumentParser", package: "swift-argument-parser"),
			.product(name: "SimpleStream",   package: "SimpleStream")
		])
	]
)
