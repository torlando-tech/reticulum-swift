// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ReticulumSwiftTests.swift
//  ReticulumSwift
//
//  Basic tests for the ReticulumSwift package.
//

import XCTest
@testable import ReticulumSwift

final class ReticulumSwiftTests: XCTestCase {

    // MARK: - Identity Tests

    func testIdentityGeneration() throws {
        let identity = Identity()

        XCTAssertTrue(identity.hasPrivateKeys)
        XCTAssertEqual(identity.hash.count, 16)
        XCTAssertEqual(identity.publicKeys.count, 64)
    }

    func testIdentitySigning() throws {
        let identity = Identity()
        let message = "Hello, Reticulum!".data(using: .utf8)!

        let signature = try identity.sign(message)
        XCTAssertEqual(signature.count, 64)

        let isValid = identity.verify(signature: signature, for: message)
        XCTAssertTrue(isValid)
    }

    func testIdentityPersistence() throws {
        let identity = Identity()

        // Export and reimport
        let exported = try identity.exportPrivateKeys()
        XCTAssertEqual(exported.count, 64)

        let restored = try Identity(privateKeyBytes: exported)
        XCTAssertEqual(restored.hash, identity.hash)
    }

    // MARK: - Destination Tests

    func testDestinationHash() throws {
        let identity = Identity()
        let dest = Destination(
            identity: identity,
            appName: "test",
            aspects: ["app"]
        )

        XCTAssertEqual(dest.hash.count, 16)
        XCTAssertEqual(dest.fullName, "test.app")
    }

    // MARK: - Hashing Tests

    func testTruncatedHash() {
        let data = "test data".data(using: .utf8)!
        let hash = Hashing.truncatedHash(data)

        XCTAssertEqual(hash.count, 16)
    }

    // MARK: - Packet Tests

    func testPacketEncodeDecode() throws {
        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .data,
            hopCount: 0
        )

        let destination = Data(repeating: 0xAB, count: 16)
        let payload = "Hello".data(using: .utf8)!

        let packet = Packet(
            header: header,
            destination: destination,
            context: 0x00,
            data: payload
        )

        let encoded = packet.encode()
        let decoded = try Packet(from: encoded)

        XCTAssertEqual(decoded.destination, destination)
        XCTAssertEqual(decoded.data, payload)
        XCTAssertEqual(decoded.header.packetType, .data)
    }

    // MARK: - HDLC Tests

    func testHDLCFraming() throws {
        let data = Data([0x01, 0x7E, 0x7D, 0x02])  // Contains FLAG and ESC bytes
        let framed = HDLC.frame(data)

        var buffer = framed
        let frames = HDLC.extractFrames(from: &buffer)

        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames[0], data)
    }

    // MARK: - Token Tests

    func testTokenEncryption() throws {
        let key = Data(repeating: 0x42, count: 64)
        let token = try Token(derivedKey: key)

        let plaintext = "Secret message".data(using: .utf8)!
        let ciphertext = try token.encrypt(plaintext)
        let decrypted = try token.decrypt(ciphertext)

        XCTAssertEqual(decrypted, plaintext)
    }
}
