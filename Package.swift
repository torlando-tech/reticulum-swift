// swift-tools-version: 5.9

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

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
        .executableTarget(
            name: "PipePeer",
            dependencies: ["ReticulumSwift"],
            path: "Sources/PipePeer"
        ),
        .testTarget(
            name: "ReticulumSwiftTests",
            dependencies: ["ReticulumSwift"],
            path: "Tests/ReticulumSwiftTests"
        )
    ]
)
