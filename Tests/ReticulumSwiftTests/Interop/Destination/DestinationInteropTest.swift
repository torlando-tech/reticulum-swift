//
//  DestinationInteropTest.swift
//  ReticulumSwiftTests
//
//  Destination interoperability tests with Python RNS.
//

import XCTest
@testable import ReticulumSwift

final class DestinationInteropTest: InteropTestBase {

    // MARK: - Hash Computation

    func testNameHashMatchesPython() throws {
        let testCases: [(String, [String])] = [
            ("lxmf", ["delivery"]),
            ("nomadnetwork", ["node"]),
            ("myapp", ["aspect1", "aspect2"]),
            ("single", []),
        ]

        for (appName, aspects) in testCases {
            let swiftNameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)
            let fullName = ([appName] + aspects).joined(separator: ".")

            let pyResult = try bridge.execute("name_hash", ("name", fullName))

            assertBytesEqual(pyResult.getBytes("hash"), swiftNameHash, "Name hash for '\(fullName)'")
        }
    }

    func testDestinationHashWithIdentityMatchesPython() throws {
        let privateKey = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 7) })
        let identity = try Identity(privateKeyBytes: privateKey)

        let testCases: [(String, [String])] = [
            ("lxmf", ["delivery"]),
            ("nomadnetwork", ["node"]),
            ("myapp", ["aspect1", "aspect2"]),
        ]

        for (appName, aspects) in testCases {
            // Compute Swift destination hash
            let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)
            let swiftDestHash = Hashing.truncatedHash(nameHash + identity.hash)

            // Compute Python destination hash
            let pyResult = try bridge.execute(
                "destination_hash",
                ("identity_hash", identity.hash),
                ("app_name", appName),
                ("aspects", aspects.joined(separator: ","))
            )

            assertBytesEqual(
                pyResult.getBytes("destination_hash"),
                swiftDestHash,
                "Destination hash for '\(appName)' with identity"
            )

            assertBytesEqual(
                pyResult.getBytes("name_hash"),
                nameHash,
                "Name hash for '\(appName)'"
            )
        }
    }

    func testDestinationHashIsDeterministic() throws {
        let privateKey = Data(0..<64)
        let identity = try Identity(privateKeyBytes: privateKey)

        let nameHash = Hashing.destinationNameHash(appName: "test", aspects: ["app"])
        let dest1 = Hashing.truncatedHash(nameHash + identity.hash)
        let dest2 = Hashing.truncatedHash(nameHash + identity.hash)

        assertBytesEqual(dest1, dest2, "Destination hashes should be deterministic")
    }

    // MARK: - Static Hash Computation

    func testStaticHashComputationMatchesPython() throws {
        let privateKey = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 11) })
        let identity = try Identity(privateKeyBytes: privateKey)

        let appName = "testapp"
        let aspects = ["v1", "endpoint"]

        let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)
        let staticHash = Hashing.truncatedHash(nameHash + identity.hash)

        let pyResult = try bridge.execute(
            "destination_hash",
            ("identity_hash", identity.hash),
            ("app_name", appName),
            ("aspects", aspects.joined(separator: ","))
        )

        assertBytesEqual(pyResult.getBytes("destination_hash"), staticHash, "Static hash matches Python")
    }
}
