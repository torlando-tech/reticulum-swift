// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  HashInteropTest.swift
//  ReticulumSwiftTests
//
//  Hash function interoperability tests with Python RNS.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class HashInteropTest: InteropTestBase {

    func testSha256MatchesPython() throws {
        let testCases: [Data] = [
            Data(),
            "Hello, Reticulum!".data(using: .utf8)!,
            Data(0..<32),
            Data((0..<1000).map { UInt8($0 % 256) }),
        ]

        for data in testCases {
            let swiftHash = Hashing.fullHash(data)
            let pyResult = try bridge.execute("sha256", ("data", data))

            assertBytesEqual(pyResult.getBytes("hash"), swiftHash, "SHA-256 for \(data.count) bytes")
        }
    }

    func testSha512MatchesPython() throws {
        let testCases: [Data] = [
            Data(),
            "Test message".data(using: .utf8)!,
            Data(0..<64),
        ]

        for data in testCases {
            let digest = SHA512.hash(data: data)
            let swiftHash = Data(digest)
            let pyResult = try bridge.execute("sha512", ("data", data))

            assertBytesEqual(pyResult.getBytes("hash"), swiftHash, "SHA-512 for \(data.count) bytes")
        }
    }

    func testHmacSha256MatchesPython() throws {
        let testCases: [(Data, Data)] = [
            (Data(0..<16), "message".data(using: .utf8)!),
            (Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 2) }), Data(0..<100)),
            (Data(0..<64), Data()),  // Empty message
            (Data(0..<128), "test".data(using: .utf8)!),  // Key > 64 bytes
        ]

        for (key, message) in testCases {
            let symmetricKey = SymmetricKey(data: key)
            let hmac = HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey)
            let swiftHmac = Data(hmac)

            let pyResult = try bridge.execute(
                "hmac_sha256",
                ("key", key),
                ("message", message)
            )

            assertBytesEqual(
                pyResult.getBytes("hmac"), swiftHmac,
                "HMAC-SHA256 with \(key.count)-byte key, \(message.count)-byte message"
            )
        }
    }

    func testTruncatedHashMatchesPython() throws {
        let testCases: [Data] = [
            Data(0..<32),
            "test destination".data(using: .utf8)!,
            Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 3) }),
        ]

        for data in testCases {
            let swiftTruncated = Hashing.truncatedHash(data)
            let pyResult = try bridge.execute("truncated_hash", ("data", data))

            XCTAssertEqual(swiftTruncated.count, 16)
            assertBytesEqual(pyResult.getBytes("hash"), swiftTruncated, "Truncated hash for \(data.count) bytes")
        }
    }

    func testNameHashMatchesPython() throws {
        let testNames = ["lxmf.delivery", "nomadnetwork.node", "example.test.aspect", "single"]

        for name in testNames {
            let swiftNameHash = Hashing.destinationNameHash(
                appName: String(name.split(separator: ".").first!),
                aspects: Array(name.split(separator: ".").dropFirst().map(String.init))
            )
            let pyResult = try bridge.execute("name_hash", ("name", name))

            XCTAssertEqual(swiftNameHash.count, 10)
            assertBytesEqual(pyResult.getBytes("hash"), swiftNameHash, "Name hash for '\(name)'")
        }
    }
}
