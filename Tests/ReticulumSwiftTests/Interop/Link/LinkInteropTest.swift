//
//  LinkInteropTest.swift
//  ReticulumSwiftTests
//
//  Link interoperability tests with Python RNS.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class LinkInteropTest: InteropTestBase {

    // MARK: - Key Derivation

    func testLinkKeyDerivationMatchesPython() throws {
        let sharedKey = Data(0..<32)
        let linkId = Data((100..<116).map { UInt8($0) })

        let swiftDerived = KeyDerivation.deriveKey(
            length: 64, inputKeyMaterial: sharedKey, salt: linkId, context: nil
        )

        let pyResult = try bridge.execute(
            "link_derive_key",
            ("shared_key", sharedKey),
            ("link_id", linkId),
            ("mode", "AES_256_CBC")
        )

        assertBytesEqual(pyResult.getBytes("derived_key"), swiftDerived, "Link key derivation")

        let encKey = Data(swiftDerived.prefix(32))
        let sigKey = Data(swiftDerived.suffix(32))
        assertBytesEqual(pyResult.getBytes("encryption_key"), encKey, "Encryption key split")
        assertBytesEqual(pyResult.getBytes("signing_key"), sigKey, "Signing key split")
    }

    // MARK: - Link Encryption

    func testLinkEncryptionMatchesPython() throws {
        let derivedKey = Data(0..<64)
        let plaintext = "Hello over link!".data(using: .utf8)!
        let fixedIv = Data((50..<66).map { UInt8($0) })

        let token = try Token(derivedKey: derivedKey)
        let swiftCiphertext = try token.encrypt(plaintext, iv: fixedIv)

        let pyResult = try bridge.execute(
            "link_encrypt",
            ("derived_key", derivedKey),
            ("plaintext", plaintext),
            ("iv", fixedIv)
        )

        assertBytesEqual(pyResult.getBytes("ciphertext"), swiftCiphertext, "Link encryption")
    }

    func testSwiftCanDecryptPythonLinkCiphertext() throws {
        let derivedKey = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 2) })
        let plaintext = "Secret link message from Python".data(using: .utf8)!

        let pyResult = try bridge.execute(
            "link_encrypt",
            ("derived_key", derivedKey),
            ("plaintext", plaintext)
        )
        let pyCiphertext = pyResult.getBytes("ciphertext")

        let token = try Token(derivedKey: derivedKey)
        let decrypted = try token.decrypt(pyCiphertext)

        assertBytesEqual(plaintext, decrypted, "Swift decrypting Python link ciphertext")
    }

    func testPythonCanDecryptSwiftLinkCiphertext() throws {
        let derivedKey = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 3) })
        let plaintext = "Secret link message from Swift".data(using: .utf8)!

        let token = try Token(derivedKey: derivedKey)
        let swiftCiphertext = try token.encrypt(plaintext)

        let pyResult = try bridge.execute(
            "link_decrypt",
            ("derived_key", derivedKey),
            ("ciphertext", swiftCiphertext)
        )

        assertBytesEqual(plaintext, pyResult.getBytes("plaintext"), "Python decrypting Swift link ciphertext")
    }

    func testBidirectionalLinkEncryptionRoundTrip() throws {
        let derivedKey = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 5) })
        let token = try Token(derivedKey: derivedKey)

        let testMessages: [Data] = [
            Data(),
            "Short".data(using: .utf8)!,
            "A medium-length message for testing".data(using: .utf8)!,
            Data((0..<256).map { UInt8($0) }),
            Data((0..<500).map { UInt8($0 % 256) }),
        ]

        for plaintext in testMessages {
            // Swift -> Python
            let swiftEnc = try token.encrypt(plaintext)
            let pyDec = try bridge.execute(
                "link_decrypt",
                ("derived_key", derivedKey),
                ("ciphertext", swiftEnc)
            ).getBytes("plaintext")
            assertBytesEqual(plaintext, pyDec, "Swift->Python for \(plaintext.count) bytes")

            // Python -> Swift
            let pyEnc = try bridge.execute(
                "link_encrypt",
                ("derived_key", derivedKey),
                ("plaintext", plaintext)
            ).getBytes("ciphertext")
            let swiftDec = try token.decrypt(pyEnc)
            assertBytesEqual(plaintext, swiftDec, "Python->Swift for \(plaintext.count) bytes")
        }
    }

    // MARK: - Link Proof

    func testLinkProofSignatureCrossVerification() throws {
        // Note: pure25519 and CryptoKit produce different (but both valid) Ed25519 signatures.
        // We verify cross-verification instead of byte-exact matching.
        let seed = Data(0..<64)
        let x25519Seed = Data(seed.prefix(32))
        let ed25519Seed = Data(seed.suffix(32))

        let ed25519Key = try Curve25519.Signing.PrivateKey(rawRepresentation: ed25519Seed)

        let linkId = Data((10..<26).map { UInt8($0) })
        let receiverPub = Data((20..<52).map { UInt8($0) })
        let receiverSigPub = Data((30..<62).map { UInt8($0) })
        let signallingBytes = LinkConstants.DEFAULT_MTU_SIGNALING

        let signedData = linkId + receiverPub + receiverSigPub + signallingBytes

        // Get Python's signature
        let pyResult = try bridge.execute(
            "link_prove",
            ("identity_private", Data(x25519Seed + ed25519Seed)),
            ("link_id", linkId),
            ("receiver_pub", receiverPub),
            ("receiver_sig_pub", receiverSigPub),
            ("signalling_bytes", signallingBytes)
        )
        let pySignature = pyResult.getBytes("signature")

        // Both Swift and Python signatures should verify with the same public key
        let pubKey = ed25519Key.publicKey
        XCTAssertTrue(pubKey.isValidSignature(pySignature, for: signedData),
            "Swift should verify Python's link proof signature")

        let swiftSig = try ed25519Key.signature(for: signedData)
        XCTAssertTrue(pubKey.isValidSignature(swiftSig, for: signedData),
            "Swift's own link proof signature should also verify")

        // Signed data format should match
        assertBytesEqual(pyResult.getBytes("signed_data"), signedData, "Link proof signed data format")
    }

    // MARK: - Link ID

    func testLinkIdComputationMatchesPython() throws {
        let destHash = Data(0..<16)
        let peerPub = Data((100..<132).map { UInt8($0) })
        let peerSigPub = Data((200..<232).map { UInt8(truncatingIfNeeded: $0) })
        let signallingBytes = LinkConstants.DEFAULT_MTU_SIGNALING
        let requestData = peerPub + peerSigPub + signallingBytes

        let packet = Packet(
            header: PacketHeader(
                headerType: .header1, hasContext: false,
                transportType: .broadcast, destinationType: .single,
                packetType: .linkRequest, hopCount: 0
            ),
            destination: destHash,
            context: 0x00,
            data: requestData
        )

        let swiftLinkId = IncomingLinkRequest.calculateLinkId(from: packet)

        let pyResult = try bridge.execute(
            "link_id_from_packet",
            ("raw", packet.encode())
        )

        assertBytesEqual(pyResult.getBytes("link_id"), swiftLinkId, "Link ID from packet")
    }

    // MARK: - Complete Handshake

    func testEndToEndECDHProducesSameSharedSecret() throws {
        let initSeed = Data(0..<32)
        let recvSeed = Data((100..<132).map { UInt8($0) })

        let initKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: initSeed)
        let recvKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recvSeed)

        let initShared = try initKey.sharedSecretFromKeyAgreement(with: recvKey.publicKey)
        let recvShared = try recvKey.sharedSecretFromKeyAgreement(with: initKey.publicKey)

        let initData = initShared.withUnsafeBytes { Data($0) }
        let recvData = recvShared.withUnsafeBytes { Data($0) }

        assertBytesEqual(initData, recvData, "ECDH shared secrets match")

        let pyResult = try bridge.execute(
            "x25519_exchange",
            ("private_key", initKey.rawRepresentation),
            ("peer_public_key", recvKey.publicKey.rawRepresentation)
        )

        assertBytesEqual(pyResult.getBytes("shared_secret"), initData, "Swift ECDH matches Python")
    }
}
