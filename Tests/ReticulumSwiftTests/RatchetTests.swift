// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  RatchetTests.swift
//  ReticulumSwift
//
//  Tests for ratchet forward secrecy: key generation, rotation,
//  persistence, encrypt/decrypt, and announce integration.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class RatchetTests: XCTestCase {

    // MARK: - Key Generation

    func testRatchetGeneration() async throws {
        let privKey = RatchetManager.generateRatchet()
        XCTAssertEqual(privKey.count, 32, "Private key should be 32 bytes")

        let pubKey = try RatchetManager.publicBytes(from: privKey)
        XCTAssertEqual(pubKey.count, 32, "Public key should be 32 bytes")

        // Keys should be different
        XCTAssertNotEqual(privKey, pubKey)
    }

    // MARK: - Rotation

    func testRatchetRotation() async throws {
        let identity = Identity()
        let path = NSTemporaryDirectory() + "ratchet_rotation_test_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: path) }

        let manager = RatchetManager(storagePath: path, identity: identity)
        try await manager.loadOrCreate()

        let initialCount = await manager.count()
        XCTAssertEqual(initialCount, 1, "Should have 1 initial ratchet")

        let initialPub = await manager.currentRatchetPublicBytes()
        XCTAssertNotNil(initialPub)

        // Force rotation by setting time in the past
        await manager._setLatestRatchetTime(
            Date().timeIntervalSince1970 - RatchetManager.RATCHET_INTERVAL - 1
        )

        let rotated = await manager.rotateIfNeeded()
        XCTAssertTrue(rotated, "Should have rotated")

        let newCount = await manager.count()
        XCTAssertEqual(newCount, 2, "Should have 2 ratchets after rotation")

        let newPub = await manager.currentRatchetPublicBytes()
        XCTAssertNotNil(newPub)
        XCTAssertNotEqual(initialPub, newPub, "New ratchet should be different")
    }

    func testRotationInterval() async throws {
        let identity = Identity()
        let path = NSTemporaryDirectory() + "ratchet_interval_test_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: path) }

        let manager = RatchetManager(storagePath: path, identity: identity)
        try await manager.loadOrCreate()

        // Should NOT rotate immediately (interval hasn't elapsed)
        let rotated = await manager.rotateIfNeeded()
        XCTAssertFalse(rotated, "Should not rotate before interval")

        let count = await manager.count()
        XCTAssertEqual(count, 1)
    }

    func testRatchetCountLimit() async throws {
        let identity = Identity()
        let path = NSTemporaryDirectory() + "ratchet_limit_test_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: path) }

        let manager = RatchetManager(storagePath: path, identity: identity)
        try await manager.loadOrCreate()

        // Force-rotate 512 more times (exceeding RATCHET_COUNT)
        for _ in 0..<512 {
            await manager._setLatestRatchetTime(0)
            await manager.rotateIfNeeded()
        }

        let count = await manager.count()
        XCTAssertEqual(count, RatchetManager.RATCHET_COUNT,
                       "Should be capped at RATCHET_COUNT=512")
    }

    // MARK: - Encrypt/Decrypt with Ratchet

    func testEncryptWithRatchet() async throws {
        let identity = Identity()
        let identityHash = identity.hash

        // Generate a ratchet keypair
        let ratchetPriv = RatchetManager.generateRatchet()
        let ratchetPub = try RatchetManager.publicBytes(from: ratchetPriv)

        // Encrypt to ratchet public key
        let plaintext = "Hello, ratcheted world!".data(using: .utf8)!
        let ciphertext = try Identity.encrypt(
            plaintext,
            toRatchetKey: ratchetPub,
            identityHash: identityHash
        )

        XCTAssertTrue(ciphertext.count > plaintext.count)

        // Decrypt with ratchet private key (via identity.decrypt with ratchets)
        let decrypted = try identity.decrypt(
            ciphertext,
            identityHash: identityHash,
            ratchets: [ratchetPriv]
        )

        XCTAssertEqual(decrypted, plaintext)
    }

    func testDecryptFallbackToBase() async throws {
        let identity = Identity()
        let identityHash = identity.hash

        // Encrypt with base identity key (no ratchet)
        let plaintext = "Non-ratcheted message".data(using: .utf8)!
        let ciphertext = try identity.encryptTo(plaintext, identityHash: identityHash)

        // Decrypt with empty ratchets array — should fallback to base key
        let decrypted = try identity.decrypt(
            ciphertext,
            identityHash: identityHash,
            ratchets: []
        )

        XCTAssertEqual(decrypted, plaintext)
    }

    func testDecryptWithOldRatchet() async throws {
        let identity = Identity()
        let identityHash = identity.hash

        // Generate 3 ratchets
        let ratchet1 = RatchetManager.generateRatchet()
        let ratchet2 = RatchetManager.generateRatchet()
        let ratchet3 = RatchetManager.generateRatchet()

        let ratchet2Pub = try RatchetManager.publicBytes(from: ratchet2)

        // Encrypt with 2nd ratchet's public key
        let plaintext = "Encrypted to old ratchet".data(using: .utf8)!
        let ciphertext = try Identity.encrypt(
            plaintext,
            toRatchetKey: ratchet2Pub,
            identityHash: identityHash
        )

        // Decrypt trying all 3 ratchets — should succeed on 2nd
        let decrypted = try identity.decrypt(
            ciphertext,
            identityHash: identityHash,
            ratchets: [ratchet3, ratchet2, ratchet1]  // newest first
        )

        XCTAssertEqual(decrypted, plaintext)
    }

    func testEnforceDropsNonRatcheted() async throws {
        let identity = Identity()
        let identityHash = identity.hash

        // Encrypt with base key (no ratchet)
        let plaintext = "Should be rejected".data(using: .utf8)!
        let ciphertext = try identity.encryptTo(plaintext, identityHash: identityHash)

        // Generate a ratchet that doesn't match
        let ratchetPriv = RatchetManager.generateRatchet()

        // Decrypt with enforceRatchets=true — should fail
        XCTAssertThrowsError(try identity.decrypt(
            ciphertext,
            identityHash: identityHash,
            ratchets: [ratchetPriv],
            enforceRatchets: true
        )) { error in
            guard case IdentityError.decryptionFailed = error else {
                XCTFail("Expected decryptionFailed, got \(error)")
                return
            }
        }
    }

    // MARK: - Persistence

    func testRatchetPersistence() async throws {
        let identity = Identity()
        let path = NSTemporaryDirectory() + "ratchet_persist_test_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: path) }

        // Create and persist ratchets
        let manager1 = RatchetManager(storagePath: path, identity: identity)
        try await manager1.loadOrCreate()

        // Force a rotation to have 2 ratchets
        await manager1._setLatestRatchetTime(0)
        await manager1.rotateIfNeeded()

        let keys1 = await manager1.allRatchetPrivateKeys()
        XCTAssertEqual(keys1.count, 2)

        // Load from same path — should get same keys
        let manager2 = RatchetManager(storagePath: path, identity: identity)
        try await manager2.loadOrCreate()

        let keys2 = await manager2.allRatchetPrivateKeys()
        XCTAssertEqual(keys1, keys2, "Loaded keys should match persisted keys")
    }

    func testRatchetPersistenceSignature() async throws {
        let identity = Identity()
        let path = NSTemporaryDirectory() + "ratchet_tamper_test_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: path) }

        // Create and persist
        let manager1 = RatchetManager(storagePath: path, identity: identity)
        try await manager1.loadOrCreate()

        // Tamper with the file (flip a byte)
        var fileData = try Data(contentsOf: URL(fileURLWithPath: path))
        if fileData.count > 10 {
            fileData[10] ^= 0xFF
            try fileData.write(to: URL(fileURLWithPath: path))
        }

        // Load with tampered file — should fail and create fresh ratchet
        let manager2 = RatchetManager(storagePath: path, identity: identity)
        try await manager2.loadOrCreate()

        // It should have created a fresh ratchet (1 key)
        let keys = await manager2.allRatchetPrivateKeys()
        XCTAssertEqual(keys.count, 1, "Tampered file should cause fresh start")
    }

    // MARK: - Announce Integration

    func testAnnounceWithRatchet() throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["app"])

        let ratchetPub = Data(repeating: 0xAB, count: 32)
        let announce = Announce(destination: dest, ratchet: ratchetPub)

        let packet = try announce.buildPacket()

        // hasContext should be true when ratchet is present
        XCTAssertTrue(packet.header.hasContext, "Ratcheted announce should have context flag")

        // Verify ratchet is in payload at expected offset:
        // public_keys(64) + nameHash(10) + randomHash(10) = offset 84
        let payload = packet.data
        let nameHashLen = NAME_HASH_LENGTH  // 10 bytes
        let expectedOffset = PUBLIC_KEYS_LENGTH + nameHashLen + ANNOUNCE_RANDOM_HASH_LENGTH
        let ratchetFromPayload = Data(payload[expectedOffset..<expectedOffset + RATCHET_KEY_LENGTH])
        XCTAssertEqual(ratchetFromPayload, ratchetPub,
                       "Ratchet should be at offset \(expectedOffset)")
    }

    func testAnnounceRatchetSignature() throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "lxmf", aspects: ["delivery"])

        let ratchetPriv = RatchetManager.generateRatchet()
        let ratchetPub = try RatchetManager.publicBytes(from: ratchetPriv)

        let announce = Announce(destination: dest, ratchet: ratchetPub)
        let payload = try announce.build()

        // Parse the payload to verify signature
        let publicKeys = Data(payload.prefix(PUBLIC_KEYS_LENGTH))
        let nameHashLen = NAME_HASH_LENGTH  // 10 bytes
        let offset = PUBLIC_KEYS_LENGTH
        let nameHash = Data(payload[offset..<offset + nameHashLen])
        let randomHash = Data(payload[offset + nameHashLen..<offset + nameHashLen + ANNOUNCE_RANDOM_HASH_LENGTH])
        let ratchetFromPayload = Data(payload[offset + nameHashLen + ANNOUNCE_RANDOM_HASH_LENGTH..<offset + nameHashLen + ANNOUNCE_RANDOM_HASH_LENGTH + RATCHET_KEY_LENGTH])
        let sigOffset = offset + nameHashLen + ANNOUNCE_RANDOM_HASH_LENGTH + RATCHET_KEY_LENGTH
        let signature = Data(payload[sigOffset..<sigOffset + SIGNATURE_LENGTH])

        // Rebuild signed data
        var signedData = Data()
        signedData.append(dest.hash)
        signedData.append(publicKeys)
        signedData.append(nameHash)
        signedData.append(randomHash)
        signedData.append(ratchetFromPayload)

        let signingPub = Data(publicKeys[32..<64])
        let isValid = try Identity.verify(signature: signature, for: signedData, publicKey: signingPub)
        XCTAssertTrue(isValid, "Ratcheted announce signature should verify")
    }

    func testRoundTripRatchetAnnounce() throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "lxmf", aspects: ["delivery"])
        let appDataStr = "TestNode"
        let appDataBytes = appDataStr.data(using: .utf8)!

        let ratchetPriv = RatchetManager.generateRatchet()
        let ratchetPub = try RatchetManager.publicBytes(from: ratchetPriv)

        let announce = Announce(
            destination: dest,
            appData: appDataBytes,
            ratchet: ratchetPub
        )

        let payload = try announce.build()
        let packet = try announce.buildPacket()

        // Verify ratchet flag
        XCTAssertTrue(packet.header.hasContext)

        // Parse payload to extract app data (after signature)
        let nameHashLen = NAME_HASH_LENGTH
        let sigOffset = PUBLIC_KEYS_LENGTH + nameHashLen + ANNOUNCE_RANDOM_HASH_LENGTH + RATCHET_KEY_LENGTH
        let appDataOffset = sigOffset + SIGNATURE_LENGTH
        let extractedAppData = Data(payload[appDataOffset...])
        XCTAssertEqual(extractedAppData, appDataBytes, "App data should be preserved")

        // Extract and verify ratchet bytes
        let ratchetOffset = PUBLIC_KEYS_LENGTH + nameHashLen + ANNOUNCE_RANDOM_HASH_LENGTH
        let extractedRatchet = Data(payload[ratchetOffset..<ratchetOffset + RATCHET_KEY_LENGTH])
        XCTAssertEqual(extractedRatchet, ratchetPub, "Ratchet bytes should match")
    }

    // MARK: - Announce Without Ratchet (backward compat)

    func testAnnounceWithoutRatchet() throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["app"])

        let announce = Announce(destination: dest)
        let packet = try announce.buildPacket()

        // hasContext should be false when no ratchet
        XCTAssertFalse(packet.header.hasContext, "Non-ratcheted announce should not have context flag")
    }
}
