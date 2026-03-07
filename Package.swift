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
        .systemLibrary(
            name: "CBZ2",
            path: "Sources/CBZ2"
        ),
        .target(
            name: "CEd25519",
            path: "Sources/CEd25519",
            publicHeadersPath: "include"
        ),
        .target(
            name: "ReticulumSwift",
            dependencies: ["CryptoSwift", "CBZ2", "CEd25519"],
            path: "Sources/ReticulumSwift"
        ),
        .executableTarget(
            name: "ConformanceBridge",
            dependencies: ["ReticulumSwift", "CryptoSwift"],
            path: "Sources/ConformanceBridge"
        ),
        .testTarget(
            name: "ReticulumSwiftTests",
            dependencies: ["ReticulumSwift"],
            path: "Tests/ReticulumSwiftTests"
        )
    ]
)
