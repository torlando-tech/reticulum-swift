// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  AnnounceBindingTests.swift
//  ReticulumSwiftTests
//
//  Verifies that announce validation binds the destination hash to the
//  announced identity, rejecting self-signed announces that claim a
//  destination hash they do not own (key-substitution / MITM).
//

import XCTest
@testable import ReticulumSwift

final class AnnounceBindingTests: XCTestCase {

    /// Reconstructs the signed material exactly as `AnnounceValidator.validate` does.
    private func signedData(destinationHash: Data, publicKeys: Data, nameHash: Data, randomHash: Data) -> Data {
        var data = Data()
        data.append(destinationHash)
        data.append(publicKeys)
        data.append(nameHash)
        data.append(randomHash)
        return data
    }

    func testAnnounceWithBoundDestinationHashIsAccepted() throws {
        let identity = Identity()
        let publicKeys = identity.publicKeys
        let nameHash = Hashing.destinationNameHash(appName: "lxmf", aspects: ["delivery"])
        let randomHash = Data((0..<10).map { UInt8($0) })

        // Correct binding: dest = truncatedHash(name_hash || truncatedHash(public_keys))
        var material = nameHash
        material.append(Hashing.truncatedHash(publicKeys))
        let destinationHash = Hashing.truncatedHash(material)

        let signature = try identity.sign(
            signedData(destinationHash: destinationHash, publicKeys: publicKeys, nameHash: nameHash, randomHash: randomHash)
        )

        let parsed = ParsedAnnounce(
            publicKeys: publicKeys,
            nameHash: nameHash,
            randomHash: randomHash,
            ratchet: nil,
            signature: signature,
            appData: nil,
            destinationHash: destinationHash
        )

        XCTAssertTrue(try AnnounceValidator.validate(parsed: parsed))
    }

    func testSpoofedDestinationHashIsRejectedDespiteValidSignature() throws {
        // The attacker signs with their OWN identity but sets the destination hash
        // to a victim's address. The signature is valid over this material, so a
        // signature-only check would accept it; the binding check must reject it.
        let attacker = Identity()
        let publicKeys = attacker.publicKeys
        let nameHash = Hashing.destinationNameHash(appName: "lxmf", aspects: ["delivery"])
        let randomHash = Data((0..<10).map { UInt8($0) })

        // A destination hash unrelated to the attacker's keys (stands in for a victim's).
        let victimDestinationHash = Hashing.truncatedHash(Data("victim.lxmf.delivery".utf8))

        let signature = try attacker.sign(
            signedData(destinationHash: victimDestinationHash, publicKeys: publicKeys, nameHash: nameHash, randomHash: randomHash)
        )

        let parsed = ParsedAnnounce(
            publicKeys: publicKeys,
            nameHash: nameHash,
            randomHash: randomHash,
            ratchet: nil,
            signature: signature,
            appData: nil,
            destinationHash: victimDestinationHash
        )

        XCTAssertThrowsError(try AnnounceValidator.validate(parsed: parsed)) { error in
            guard case AnnounceValidationError.hashMismatch = error else {
                return XCTFail("Expected hashMismatch, got \(error)")
            }
        }
    }
}
