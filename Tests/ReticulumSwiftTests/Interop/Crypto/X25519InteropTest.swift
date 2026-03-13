//
//  X25519InteropTest.swift
//  ReticulumSwiftTests
//
//  X25519 interoperability tests with Python RNS.
//  Verifies key generation and key exchange byte-compatibility.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class X25519InteropTest: InteropTestBase {

    func testPublicKeyGenerationMatchesPython() throws {
        let seed = Data(0..<32)
        let swiftKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: seed)
        let swiftPub = swiftKey.publicKey.rawRepresentation

        let pyResult = try bridge.execute("x25519_generate", ("seed", seed))
        let pyPub = pyResult.getBytes("public_key")

        assertBytesEqual(pyPub, swiftPub, "X25519 public key from seed")
    }

    func testPublicKeyDerivationWithVariousSeeds() throws {
        let seeds: [Data] = [
            Data(repeating: 0, count: 32),
            Data(repeating: 0xFF, count: 32),
            Data(0..<32),
            Data((0..<32).map { UInt8(255 - $0) }),
        ]

        for seed in seeds {
            let swiftKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: seed)
            let pyResult = try bridge.execute("x25519_generate", ("seed", seed))

            assertBytesEqual(
                pyResult.getBytes("public_key"),
                swiftKey.publicKey.rawRepresentation,
                "X25519 public key for seed \(seed.prefix(8).hexString)..."
            )
        }
    }

    func testKeyExchangeProducesIdenticalSharedSecret() throws {
        let aliceSeed = Data(0..<32)
        let bobSeed = Data((32..<64).map { UInt8($0) })

        let aliceKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: aliceSeed)

        // Generate Bob in Python
        let bobPy = try bridge.execute("x25519_generate", ("seed", bobSeed))
        let bobPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: bobPy.getBytes("public_key"))

        // Swift Alice × Python Bob
        let sharedSwift = try aliceKey.sharedSecretFromKeyAgreement(with: bobPub)
        let sharedSwiftData = sharedSwift.withUnsafeBytes { Data($0) }

        // Python Bob × Swift Alice
        let sharedPy = try bridge.execute(
            "x25519_exchange",
            ("private_key", bobSeed),
            ("peer_public_key", aliceKey.publicKey.rawRepresentation)
        )

        assertBytesEqual(sharedPy.getBytes("shared_secret"), sharedSwiftData, "X25519 shared secret")
    }

    func testBidirectionalExchangeProducesSameSecret() throws {
        let aliceSeed = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 3) })
        let bobSeed = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 11) })

        let aliceKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: aliceSeed)
        let bobKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bobSeed)

        let aliceShared = try aliceKey.sharedSecretFromKeyAgreement(with: bobKey.publicKey)
        let bobShared = try bobKey.sharedSecretFromKeyAgreement(with: aliceKey.publicKey)

        let aliceData = aliceShared.withUnsafeBytes { Data($0) }
        let bobData = bobShared.withUnsafeBytes { Data($0) }

        assertBytesEqual(aliceData, bobData, "Bidirectional shared secret")

        // Verify against Python
        let pyShared = try bridge.execute(
            "x25519_exchange",
            ("private_key", aliceSeed),
            ("peer_public_key", bobKey.publicKey.rawRepresentation)
        )

        assertBytesEqual(pyShared.getBytes("shared_secret"), aliceData, "Python verification")
    }

    func testCrossImplementationKeyExchange() throws {
        let swiftSeed = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 5) })
        let pythonSeed = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 13) })

        let swiftKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: swiftSeed)
        let pyKeyPair = try bridge.execute("x25519_generate", ("seed", pythonSeed))

        let pyPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pyKeyPair.getBytes("public_key"))
        let swiftShared = try swiftKey.sharedSecretFromKeyAgreement(with: pyPub)
        let swiftSharedData = swiftShared.withUnsafeBytes { Data($0) }

        let pyShared = try bridge.execute(
            "x25519_exchange",
            ("private_key", pythonSeed),
            ("peer_public_key", swiftKey.publicKey.rawRepresentation)
        )

        assertBytesEqual(pyShared.getBytes("shared_secret"), swiftSharedData, "Cross-impl ECDH")
    }
}
