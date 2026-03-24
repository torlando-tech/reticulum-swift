// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  AnnounceInteropTest.swift
//  ReticulumSwiftTests
//
//  Announce interoperability tests with Python RNS.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class AnnounceInteropTest: InteropTestBase {

    // MARK: - Random Hash

    func testRandomHashFormatMatchesPython() throws {
        let randomBytes = Data([1, 2, 3, 4, 5])
        let timestamp: Int = 1702000000

        let pyResult = try bridge.execute(
            "random_hash",
            ("random_bytes", randomBytes),
            ("timestamp", "\(timestamp)")
        )

        let pyHash = pyResult.getBytes("random_hash")
        XCTAssertEqual(pyHash.count, 10)
        assertBytesEqual(randomBytes, Data(pyHash.prefix(5)), "Random bytes")

        // Verify timestamp encoding (big-endian 5 bytes)
        let ts = UInt64(timestamp)
        let timestampBytes = Data((0..<5).map { i in
            UInt8(truncatingIfNeeded: ts >> (8 * (4 - i)))
        })
        assertBytesEqual(timestampBytes, Data(pyHash.suffix(5)), "Timestamp bytes")
    }

    // MARK: - Announce Pack

    func testAnnouncePackWithoutRatchetMatchesPython() throws {
        let identity = Identity()
        let publicKey = identity.publicKeys
        let nameHash = Data((100..<110).map { UInt8($0) })
        let randomHash = Data((50..<60).map { UInt8($0) })
        let signature = Data((200..<264).map { UInt8(truncatingIfNeeded: $0) })

        let pyResult = try bridge.execute(
            "announce_pack",
            ("public_key", publicKey),
            ("name_hash", nameHash),
            ("random_hash", randomHash),
            ("signature", signature)
        )

        let pyAnnounce = pyResult.getBytes("announce_data")
        XCTAssertEqual(pyResult.getInt("size"), 148)

        let swiftAnnounce = publicKey + nameHash + randomHash + signature
        assertBytesEqual(pyAnnounce, swiftAnnounce, "Announce without ratchet")
    }

    func testAnnouncePackWithRatchetMatchesPython() throws {
        let identity = Identity()
        let publicKey = identity.publicKeys
        let nameHash = Data((100..<110).map { UInt8($0) })
        let randomHash = Data((50..<60).map { UInt8($0) })
        let ratchet = Data((150..<182).map { UInt8($0) })
        let signature = Data((200..<264).map { UInt8(truncatingIfNeeded: $0) })

        let pyResult = try bridge.execute(
            "announce_pack",
            ("public_key", publicKey),
            ("name_hash", nameHash),
            ("random_hash", randomHash),
            ("ratchet", ratchet),
            ("signature", signature)
        )

        let pyAnnounce = pyResult.getBytes("announce_data")
        XCTAssertEqual(pyResult.getInt("size"), 180)
        XCTAssertTrue(pyResult.getBool("has_ratchet"))

        let swiftAnnounce = publicKey + nameHash + randomHash + ratchet + signature
        assertBytesEqual(pyAnnounce, swiftAnnounce, "Announce with ratchet")
    }

    func testAnnouncePackWithAppDataMatchesPython() throws {
        let identity = Identity()
        let publicKey = identity.publicKeys
        let nameHash = Data((100..<110).map { UInt8($0) })
        let randomHash = Data((50..<60).map { UInt8($0) })
        let signature = Data((200..<264).map { UInt8(truncatingIfNeeded: $0) })
        let appData = "Hello, world!".data(using: .utf8)!

        let pyResult = try bridge.execute(
            "announce_pack",
            ("public_key", publicKey),
            ("name_hash", nameHash),
            ("random_hash", randomHash),
            ("signature", signature),
            ("app_data", appData)
        )

        let pyAnnounce = pyResult.getBytes("announce_data")
        XCTAssertEqual(pyResult.getInt("size"), 148 + appData.count)

        let swiftAnnounce = publicKey + nameHash + randomHash + signature + appData
        assertBytesEqual(pyAnnounce, swiftAnnounce, "Announce with app_data")
    }

    // MARK: - Announce Unpack

    func testAnnounceUnpackWithoutRatchetMatchesPython() throws {
        let publicKey = Data(1..<65)
        let nameHash = Data((100..<110).map { UInt8($0) })
        let randomHash = Data((50..<60).map { UInt8($0) })
        let signature = Data((200..<264).map { UInt8(truncatingIfNeeded: $0) })
        let appData = "test app data".data(using: .utf8)!

        let announce = publicKey + nameHash + randomHash + signature + appData

        let pyResult = try bridge.execute(
            "announce_unpack",
            ("announce_data", announce),
            ("has_ratchet", false)
        )

        assertBytesEqual(publicKey, pyResult.getBytes("public_key"), "Public key")
        assertBytesEqual(nameHash, pyResult.getBytes("name_hash"), "Name hash")
        assertBytesEqual(randomHash, pyResult.getBytes("random_hash"), "Random hash")
        assertBytesEqual(signature, pyResult.getBytes("signature"), "Signature")
        assertBytesEqual(appData, pyResult.getBytes("app_data"), "App data")
        XCTAssertFalse(pyResult.getBool("has_ratchet"))
    }

    // MARK: - Announce Signature

    func testAnnounceSignatureGenerationMatchesPython() throws {
        let identity = Identity()
        let publicKey = identity.publicKeys
        let privateKey = identity.encryptionPrivateKey!.rawRepresentation + identity.signingPrivateKey!.rawRepresentation

        let nameHash = Hashing.destinationNameHash(appName: "test", aspects: ["app"])
        let identityHash = Hashing.truncatedHash(publicKey)
        let destinationHash = Hashing.truncatedHash(nameHash + identityHash)
        let randomHash = Data((50..<60).map { UInt8($0) })
        let appData = "test data".data(using: .utf8)!

        let pyResult = try bridge.execute(
            "announce_sign",
            ("private_key", privateKey),
            ("destination_hash", destinationHash),
            ("public_key", publicKey),
            ("name_hash", nameHash),
            ("random_hash", randomHash),
            ("app_data", appData)
        )

        let pySignature = pyResult.getBytes("signature")
        XCTAssertEqual(pySignature.count, 64)

        let signedData = pyResult.getBytes("signed_data")
        let expectedSignedData = destinationHash + publicKey + nameHash + randomHash + appData
        assertBytesEqual(expectedSignedData, signedData, "Signed data format")
    }

    // MARK: - Announce Validation

    func testAnnounceValidationRequiresDestinationHash() throws {
        let identity = Identity()
        let publicKey = identity.publicKeys
        let privateKey = identity.encryptionPrivateKey!.rawRepresentation + identity.signingPrivateKey!.rawRepresentation

        let nameHash = Hashing.destinationNameHash(appName: "test", aspects: ["validate"])
        let identityHash = Hashing.truncatedHash(publicKey)
        let destinationHash = Hashing.truncatedHash(nameHash + identityHash)
        let randomHash = Data((50..<60).map { UInt8($0) })
        let appData = "validation test".data(using: .utf8)!

        // Sign with Python
        let signResult = try bridge.execute(
            "announce_sign",
            ("private_key", privateKey),
            ("destination_hash", destinationHash),
            ("public_key", publicKey),
            ("name_hash", nameHash),
            ("random_hash", randomHash),
            ("app_data", appData)
        )
        let signature = signResult.getBytes("signature")

        // Correct signed data WITH destination_hash
        let correctSignedData = destinationHash + publicKey + nameHash + randomHash + appData
        XCTAssertTrue(identity.verify(signature: signature, for: correctSignedData))

        // Signed data WITHOUT destination_hash should fail
        let incorrectSignedData = publicKey + nameHash + randomHash + appData
        XCTAssertFalse(identity.verify(signature: signature, for: incorrectSignedData))
    }
}
