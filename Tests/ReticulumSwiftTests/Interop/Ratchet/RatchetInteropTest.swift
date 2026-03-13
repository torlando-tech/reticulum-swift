//
//  RatchetInteropTest.swift
//  ReticulumSwiftTests
//
//  Ratchet interoperability tests with Python RNS.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class RatchetInteropTest: InteropTestBase {

    // MARK: - Ratchet ID Computation

    func testRatchetIdComputationMatchesPython() throws {
        let ratchetPrivate = randomBytes(32)

        let pyPubResult = try bridge.execute(
            "ratchet_public_from_private",
            ("ratchet_private", ratchetPrivate)
        )
        let ratchetPublic = pyPubResult.getBytes("ratchet_public")

        let pyIdResult = try bridge.execute(
            "ratchet_id",
            ("ratchet_public", ratchetPublic)
        )
        let pyRatchetId = pyIdResult.getBytes("ratchet_id")

        // Compute in Swift: SHA256(ratchet_public)[:10]
        let swiftRatchetId = Data(Hashing.fullHash(ratchetPublic).prefix(10))

        assertBytesEqual(pyRatchetId, swiftRatchetId, "Ratchet ID")
        XCTAssertEqual(swiftRatchetId.count, 10)
    }

    func testRatchetIdFromKnownPublicKey() throws {
        let ratchetPublic = Data(hex: "deadbeef" + String(repeating: "a", count: 56))!

        let pyResult = try bridge.execute("ratchet_id", ("ratchet_public", ratchetPublic))
        let pyRatchetId = pyResult.getBytes("ratchet_id")

        let swiftRatchetId = Data(Hashing.fullHash(ratchetPublic).prefix(10))

        assertBytesEqual(pyRatchetId, swiftRatchetId, "Ratchet ID from known key")
    }

    // MARK: - Ratchet Key Derivation

    func testRatchetKeyDerivationMatchesPython() throws {
        let ephemeralPrivate = randomBytes(32)
        let ratchetPrivate = randomBytes(32)

        let pyPubResult = try bridge.execute(
            "ratchet_public_from_private",
            ("ratchet_private", ratchetPrivate)
        )
        let ratchetPublic = pyPubResult.getBytes("ratchet_public")

        let identityHash = randomBytes(16)

        let pyResult = try bridge.execute(
            "ratchet_derive_key",
            ("ephemeral_private", ephemeralPrivate),
            ("ratchet_public", ratchetPublic),
            ("identity_hash", identityHash)
        )

        // Derive in Swift
        let ephKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ephemeralPrivate)
        let ratchetPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ratchetPublic)
        let sharedSecret = try ephKey.sharedSecretFromKeyAgreement(with: ratchetPub)
        let sharedKey = sharedSecret.withUnsafeBytes { Data($0) }

        let derivedKey = KeyDerivation.deriveKey(
            length: 64, inputKeyMaterial: sharedKey, salt: identityHash, context: nil
        )

        assertBytesEqual(pyResult.getBytes("shared_key"), sharedKey, "Shared key")
        assertBytesEqual(pyResult.getBytes("derived_key"), derivedKey, "Derived key")
    }

    // MARK: - Ratchet in Announce

    func testRatchetExtractionFromAnnounceMatchesPython() throws {
        let privateKey = randomBytes(64)
        let identity = try Identity(privateKeyBytes: privateKey)
        let publicKey = identity.publicKeys

        let nameHash = randomBytes(10)
        let randomHash = randomBytes(10)
        let ratchet = randomBytes(32)
        let signature = randomBytes(64)
        let appData = "test".data(using: .utf8)!

        let announceData = publicKey + nameHash + randomHash + ratchet + signature + appData

        let pyResult = try bridge.execute(
            "ratchet_extract_from_announce",
            ("announce_data", announceData)
        )

        XCTAssertTrue(pyResult.getBool("has_ratchet"))
        assertBytesEqual(ratchet, pyResult.getBytes("ratchet"), "Extracted ratchet")

        let expectedRatchetId = Data(Hashing.fullHash(ratchet).prefix(10))
        assertBytesEqual(expectedRatchetId, pyResult.getBytes("ratchet_id"), "Ratchet ID")
    }

    func testAnnounceWithoutRatchetIsDetected() throws {
        let privateKey = randomBytes(64)
        let identity = try Identity(privateKeyBytes: privateKey)
        let publicKey = identity.publicKeys

        let nameHash = randomBytes(10)
        let randomHash = randomBytes(10)
        let signature = randomBytes(64)

        let announceData = publicKey + nameHash + randomHash + signature

        let pyResult = try bridge.execute(
            "ratchet_extract_from_announce",
            ("announce_data", announceData)
        )

        XCTAssertFalse(pyResult.getBool("has_ratchet"))
    }

    // MARK: - Ratchet Rotation

    func testDifferentRatchetsHaveDifferentIds() throws {
        let ratchet1 = randomBytes(32)
        let ratchet2 = randomBytes(32)

        let pyPub1 = try bridge.execute("ratchet_public_from_private", ("ratchet_private", ratchet1))
        let pyPub2 = try bridge.execute("ratchet_public_from_private", ("ratchet_private", ratchet2))

        let id1 = try bridge.execute("ratchet_id", ("ratchet_public", pyPub1.getBytes("ratchet_public")))
        let id2 = try bridge.execute("ratchet_id", ("ratchet_public", pyPub2.getBytes("ratchet_public")))

        XCTAssertNotEqual(id1.getBytes("ratchet_id"), id2.getBytes("ratchet_id"))
    }

    // MARK: - Helpers

    private func randomBytes(_ count: Int) -> Data {
        var bytes = Data(count: count)
        _ = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        return bytes
    }
}
