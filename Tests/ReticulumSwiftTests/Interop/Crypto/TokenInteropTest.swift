// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  TokenInteropTest.swift
//  ReticulumSwiftTests
//
//  Token (modified Fernet) interoperability tests with Python RNS.
//

import XCTest
@testable import ReticulumSwift

final class TokenInteropTest: InteropTestBase {

    func testTokenEncryptionAES256MatchesPython() throws {
        let key = Data(0..<64)
        let plaintext = "Hello, Reticulum!".data(using: .utf8)!
        let fixedIv = Data((100..<116).map { UInt8($0) })

        let token = try Token(derivedKey: key)
        let swiftToken = try token.encrypt(plaintext, iv: fixedIv)

        let pyResult = try bridge.execute(
            "token_encrypt",
            ("key", key),
            ("plaintext", plaintext),
            ("iv", fixedIv)
        )

        assertBytesEqual(pyResult.getBytes("token"), swiftToken, "Token encryption (AES-256)")
    }

    func testTokenEncryptionAES128MatchesPython() throws {
        // 32-byte key for AES-128 mode
        let key = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 2) })
        // Pad to 64 bytes as Token requires 64-byte key
        let fullKey = key + Data(repeating: 0, count: 32)
        let plaintext = "Test message".data(using: .utf8)!
        let fixedIv = Data((50..<66).map { UInt8($0) })

        let token = try Token(derivedKey: fullKey)
        let swiftToken = try token.encrypt(plaintext, iv: fixedIv)

        let pyResult = try bridge.execute(
            "token_encrypt",
            ("key", fullKey),
            ("plaintext", plaintext),
            ("iv", fixedIv)
        )

        assertBytesEqual(pyResult.getBytes("token"), swiftToken, "Token encryption (AES-128 key)")
    }

    func testSwiftCanDecryptPythonToken() throws {
        let key = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 3) })
        let plaintext = "Secret message from Python".data(using: .utf8)!

        let pyResult = try bridge.execute(
            "token_encrypt",
            ("key", key),
            ("plaintext", plaintext)
        )
        let pyToken = pyResult.getBytes("token")

        let token = try Token(derivedKey: key)
        let decrypted = try token.decrypt(pyToken)

        assertBytesEqual(plaintext, decrypted, "Swift decrypting Python token")
    }

    func testPythonCanDecryptSwiftToken() throws {
        let key = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 5) })
        let plaintext = "Secret message from Swift".data(using: .utf8)!

        let token = try Token(derivedKey: key)
        let swiftToken = try token.encrypt(plaintext)

        let pyResult = try bridge.execute(
            "token_decrypt",
            ("key", key),
            ("token", swiftToken)
        )

        assertBytesEqual(plaintext, pyResult.getBytes("plaintext"), "Python decrypting Swift token")
    }

    func testTokenOverheadIs48Bytes() throws {
        let key = Data(0..<64)
        let token = try Token(derivedKey: key)

        for size in [1, 15, 16, 17, 32, 100] {
            let plaintext = Data((0..<size).map { UInt8($0 % 256) })
            let encrypted = try token.encrypt(plaintext)

            let paddedSize = ((size / 16) + 1) * 16
            let expectedSize = 16 + paddedSize + 32
            XCTAssertEqual(encrypted.count, expectedSize,
                "Token for \(size) bytes should be \(expectedSize) bytes")
        }
    }

    func testRoundTripEncryptionDecryption() throws {
        let key = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 7) })
        let token = try Token(derivedKey: key)

        let testCases: [Data] = [
            Data(),
            Data([42]),
            "Hello, World!".data(using: .utf8)!,
            Data((0..<256).map { UInt8($0) }),
            Data((0..<1000).map { UInt8($0 % 256) }),
        ]

        for plaintext in testCases {
            // Swift round-trip
            let encrypted = try token.encrypt(plaintext)
            let decrypted = try token.decrypt(encrypted)
            assertBytesEqual(plaintext, decrypted, "Round-trip for \(plaintext.count) bytes")

            // Cross-impl round-trip
            let pyToken = try bridge.execute(
                "token_encrypt",
                ("key", key),
                ("plaintext", plaintext)
            ).getBytes("token")

            let swiftDecrypted = try token.decrypt(pyToken)
            assertBytesEqual(plaintext, swiftDecrypted, "Cross-impl round-trip for \(plaintext.count) bytes")
        }
    }
}
