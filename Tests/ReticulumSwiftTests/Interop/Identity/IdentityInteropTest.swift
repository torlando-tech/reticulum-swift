// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  IdentityInteropTest.swift
//  ReticulumSwiftTests
//
//  Identity interoperability tests with Python RNS.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class IdentityInteropTest: InteropTestBase {

    // MARK: - Key Generation

    func testPublicKeyDerivationMatchesPython() throws {
        let privateKey = randomBytes(64)
        let identity = try Identity(privateKeyBytes: privateKey)

        let pyResult = try bridge.execute("identity_from_private_key", ("private_key", privateKey))

        assertBytesEqual(
            pyResult.getBytes("public_key"),
            identity.publicKeys,
            "Public key derivation"
        )
    }

    func testIdentityHashMatchesPython() throws {
        let privateKey = randomBytes(64)
        let identity = try Identity(privateKeyBytes: privateKey)

        let pyResult = try bridge.execute("identity_from_private_key", ("private_key", privateKey))

        assertBytesEqual(pyResult.getBytes("hash"), identity.hash, "Identity hash")
    }

    func testIdentityHexHashMatchesPython() throws {
        let privateKey = randomBytes(64)
        let identity = try Identity(privateKeyBytes: privateKey)

        let pyResult = try bridge.execute("identity_from_private_key", ("private_key", privateKey))

        XCTAssertEqual(identity.hexHash, pyResult.getString("hexhash"))
    }

    func testPublicOnlyIdentityHash() throws {
        let privateKey = randomBytes(64)
        let fullIdentity = try Identity(privateKeyBytes: privateKey)
        let publicIdentity = try Identity(publicKeyBytes: fullIdentity.publicKeys)

        XCTAssertEqual(fullIdentity.hash, publicIdentity.hash)
        XCTAssertFalse(publicIdentity.hasPrivateKeys)
    }

    // MARK: - Encryption / Decryption

    func testSwiftCanDecryptPythonEncryptedData() throws {
        let privateKey = randomBytes(64)
        let identity = try Identity(privateKeyBytes: privateKey)
        let plaintext = "Hello from Python!".data(using: .utf8)!

        let pyResult = try bridge.execute(
            "identity_encrypt",
            ("public_key", identity.publicKeys),
            ("plaintext", plaintext)
        )
        let ciphertext = pyResult.getBytes("ciphertext")

        let decrypted = try identity.decrypt(ciphertext, identityHash: identity.hash)
        assertBytesEqual(plaintext, decrypted, "Swift decrypting Python ciphertext")
    }

    func testPythonCanDecryptSwiftEncryptedData() throws {
        let privateKey = randomBytes(64)
        let identity = try Identity(privateKeyBytes: privateKey)
        let plaintext = "Hello from Swift!".data(using: .utf8)!

        let ciphertext = try identity.encryptTo(plaintext, identityHash: identity.hash)

        let pyResult = try bridge.execute(
            "identity_decrypt",
            ("private_key", privateKey),
            ("ciphertext", ciphertext)
        )
        let decrypted = Data(hex: pyResult.getString("plaintext"))!

        assertBytesEqual(plaintext, decrypted, "Python decrypting Swift ciphertext")
    }

    func testRoundTripEncryption() throws {
        let identity = Identity()
        let plaintext = "Secret message for round-trip test".data(using: .utf8)!

        let ciphertext = try identity.encryptTo(plaintext, identityHash: identity.hash)
        let decrypted = try identity.decrypt(ciphertext, identityHash: identity.hash)

        assertBytesEqual(plaintext, decrypted, "Round-trip encryption")
    }

    // MARK: - Signing / Verification

    func testSwiftSignatureValidatesInPython() throws {
        let privateKey = randomBytes(64)
        let identity = try Identity(privateKeyBytes: privateKey)
        let message = "Message to sign".data(using: .utf8)!

        let signature = try identity.sign(message)

        let pyResult = try bridge.execute(
            "identity_verify",
            ("public_key", identity.publicKeys),
            ("message", message),
            ("signature", signature)
        )

        XCTAssertTrue(pyResult.getBool("valid"))
    }

    func testPythonSignatureValidatesInSwift() throws {
        let privateKey = randomBytes(64)
        let identity = try Identity(privateKeyBytes: privateKey)
        let message = "Message to sign".data(using: .utf8)!

        let pyResult = try bridge.execute(
            "identity_sign",
            ("private_key", privateKey),
            ("message", message)
        )
        let pySignature = pyResult.getBytes("signature")

        XCTAssertTrue(identity.verify(signature: pySignature, for: message))
    }

    func testSignatureCrossVerification() throws {
        // Note: pure25519 and CryptoKit produce different (but both valid) Ed25519 signatures
        // from the same seed. Both verify against the same public key. We test cross-verification
        // instead of byte-exact matching.
        let privateKey = randomBytes(64)
        let identity = try Identity(privateKeyBytes: privateKey)
        let message = "Deterministic message".data(using: .utf8)!

        let swiftSignature = try identity.sign(message)

        // Verify Swift signature is valid (self-verify)
        XCTAssertTrue(identity.verify(signature: swiftSignature, for: message))

        // Verify Python signature is valid in Swift
        let pyResult = try bridge.execute(
            "identity_sign",
            ("private_key", privateKey),
            ("message", message)
        )
        let pySignature = pyResult.getBytes("signature")
        XCTAssertTrue(identity.verify(signature: pySignature, for: message),
            "Swift should verify Python's Ed25519 signature")
    }

    func testInvalidSignatureIsRejected() throws {
        let identity = Identity()
        let message = "Original message".data(using: .utf8)!
        let signature = try identity.sign(message)

        var badSig = signature
        badSig[0] ^= 0xFF

        XCTAssertFalse(identity.verify(signature: badSig, for: message))
    }

    // MARK: - Public-Only Identity

    func testCanVerifyWithPublicOnlyIdentity() throws {
        let identity = Identity()
        let publicIdentity = try Identity(publicKeyBytes: identity.publicKeys)
        let message = "Message to verify".data(using: .utf8)!

        let signature = try identity.sign(message)
        XCTAssertTrue(publicIdentity.verify(signature: signature, for: message))
    }

    // MARK: - Helpers

    private func randomBytes(_ count: Int) -> Data {
        var bytes = Data(count: count)
        _ = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        return bytes
    }
}
