// swift-tools-version:4.0
import PackageDescription



let package = Package(
	name: "ApplyFileSharingACLs",
	dependencies: [
		.package(url: "https://github.com/Frizlab/SimpleStream", from: "1.0.0")
	],
	targets: [
		.target(
			name: "ApplyFileSharingACLs",
			dependencies: ["SimpleStream"]
		)
	]
)
