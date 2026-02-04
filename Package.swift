// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ReticulumSwift",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "ReticulumSwift",
            targets: ["ReticulumSwift"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0"),
    ],
    targets: [
        .target(
            name: "ReticulumSwift",
            dependencies: ["CryptoSwift"],
            path: "Sources/ReticulumSwift"
        ),
        .testTarget(
            name: "ReticulumSwiftTests",
            dependencies: ["ReticulumSwift"],
            path: "Tests/ReticulumSwiftTests"
        )
    ]
)
