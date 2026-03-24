// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  LinkProof.swift
//  ReticulumSwift
//
//  PROOF packet parsing and validation for link establishment.
//  Matches Python RNS Link.py wire format for interoperability.
//

import Foundation
import CryptoKit

// MARK: - Link Proof

/// PROOF packet parsing and validation for link establishment.
///
/// A PROOF packet is sent by the destination in response to a LINKREQUEST.
/// It contains a signature proving the destination's identity and ephemeral
/// key material for completing the ECDH key exchange.
///
/// Wire format (99+ bytes):
/// ```
/// [signature: 64 bytes][enc_pubkey: 32 bytes][signaling: 3 bytes]
/// ```
///
/// Note: In RNS, the responder uses the destination's identity keypair for signing,
/// not a separate ephemeral signing key. The signature proves the PROOF came from
/// the expected destination.
public struct LinkProof: Sendable {

    // MARK: - Properties

    /// 64-byte Ed25519 signature over the proof data
    public let signature: Data

    /// Peer's ephemeral X25519 public key for ECDH key agreement
    public let peerEncryptionPublicKey: Curve25519.KeyAgreement.PublicKey

    /// MTU signaling data echoed from the LINKREQUEST
    public let signaling: Data

    // MARK: - Initialization

    /// Parse PROOF packet data.
    ///
    /// Expected format: `[signature: 64][enc_pubkey: 32][signaling: 3]`
    ///
    /// - Parameter data: Raw PROOF payload (99+ bytes)
    /// - Throws: `LinkError.invalidProof` if data is malformed
    public init(from data: Data) throws {
        // Minimum size: 64 (signature) + 32 (enc_pubkey) + 3 (signaling) = 99 bytes
        guard data.count >= 99 else {
            throw LinkError.invalidProof(
                reason: "Packet too short: \(data.count) bytes, expected >= 99"
            )
        }

        // Extract signature (first 64 bytes)
        self.signature = Data(data.prefix(64))

        // Extract peer encryption public key (bytes 64-95)
        let encPubkeyBytes = Data(data[64..<96])
        do {
            self.peerEncryptionPublicKey = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: encPubkeyBytes
            )
        } catch {
            throw LinkError.invalidProof(
                reason: "Invalid peer encryption public key: \(error.localizedDescription)"
            )
        }

        // Signaling is at the end (last 3 bytes)
        self.signaling = Data(data.suffix(3))
    }

    /// Create a LinkProof with explicit values (for testing).
    ///
    /// - Parameters:
    ///   - signature: 64-byte Ed25519 signature
    ///   - peerEncryptionPublicKey: Peer's X25519 public key
    ///   - signaling: MTU signaling data (3 bytes)
    public init(
        signature: Data,
        peerEncryptionPublicKey: Curve25519.KeyAgreement.PublicKey,
        signaling: Data
    ) {
        self.signature = signature
        self.peerEncryptionPublicKey = peerEncryptionPublicKey
        self.signaling = signaling
    }

    // MARK: - Validation

    /// Validate PROOF signature against destination's identity.
    ///
    /// The signed data format matches Python RNS Link.py:
    /// `linkId || peerEncPubkey || peerSigPubkey || signaling`
    ///
    /// The destination signs with their identity key over:
    /// - link_id (16 bytes): The link identifier from LINKREQUEST
    /// - pub_bytes (32 bytes): Responder's ephemeral X25519 public key (from PROOF)
    /// - sig_pub_bytes (32 bytes): Responder's signing public key (from destination identity)
    /// - signalling_bytes (3 bytes): MTU signaling (from PROOF)
    ///
    /// - Parameters:
    ///   - linkId: Expected link ID from the original LINKREQUEST
    ///   - destinationIdentity: Identity that should have signed the PROOF
    /// - Throws: `LinkError.invalidProof` if signature verification fails
    public func validate(linkId: Data, destinationIdentity: Identity) throws {
        // Reconstruct the signed data
        // Format: linkId || peerEncPubkey || peerSigPubkey || signaling
        var signedData = Data()
        signedData.append(linkId)
        signedData.append(peerEncryptionPublicKey.rawRepresentation)
        signedData.append(destinationIdentity.signingPublicKey.rawRepresentation)
        signedData.append(signaling)

        // Verify signature using destination's signing public key
        let valid = destinationIdentity.verify(signature: signature, for: signedData)

        guard valid else {
            throw LinkError.invalidProof(reason: "Signature verification failed")
        }
    }

    /// Validate PROOF using only public key bytes (for remote destinations).
    ///
    /// Use this variant when you only have the destination's public keys
    /// from a received announce, not a full Identity object.
    ///
    /// The signed data format matches Python RNS Link.py:
    /// `linkId || peerEncPubkey || peerSigPubkey || signaling`
    ///
    /// - Parameters:
    ///   - linkId: Expected link ID from the original LINKREQUEST
    ///   - signingPublicKey: 32-byte Ed25519 public key of the destination
    /// - Throws: `LinkError.invalidProof` if signature verification fails
    public func validate(linkId: Data, signingPublicKey: Data) throws {
        // Reconstruct the signed data
        // Format: linkId || peerEncPubkey || peerSigPubkey || signaling
        var signedData = Data()
        signedData.append(linkId)
        signedData.append(peerEncryptionPublicKey.rawRepresentation)
        signedData.append(signingPublicKey)
        signedData.append(signaling)

        // Verify signature using the provided public key
        let valid: Bool
        do {
            valid = try Identity.verify(
                signature: signature,
                for: signedData,
                publicKey: signingPublicKey
            )
        } catch {
            throw LinkError.invalidProof(
                reason: "Failed to verify signature: \(error.localizedDescription)"
            )
        }

        guard valid else {
            throw LinkError.invalidProof(reason: "Signature verification failed")
        }
    }

    // MARK: - Serialization

    /// Serialize the PROOF to wire format.
    ///
    /// - Returns: PROOF data in wire format (99 bytes)
    public var data: Data {
        var result = Data()
        result.reserveCapacity(99)
        result.append(signature)
        result.append(peerEncryptionPublicKey.rawRepresentation)
        result.append(signaling)
        return result
    }

    // MARK: - PROOF Creation (for Link Responder)

    /// Create a PROOF packet for responding to a LINKREQUEST.
    ///
    /// The PROOF proves we control the destination identity and provides
    /// our ephemeral key for ECDH key exchange.
    ///
    /// Wire format (99 bytes):
    /// ```
    /// [signature: 64 bytes][enc_pubkey: 32 bytes][signaling: 3 bytes]
    /// ```
    ///
    /// The signed data is:
    /// ```
    /// linkId || peerEncPubkey || sigPubkey || signaling
    /// ```
    ///
    /// Where:
    /// - linkId: The link ID from the LINKREQUEST (16 bytes)
    /// - peerEncPubkey: Responder's ephemeral X25519 public key (32 bytes)
    /// - sigPubkey: Responder's signing public key from destination identity (32 bytes)
    /// - signaling: MTU signaling data (3 bytes)
    ///
    /// - Parameters:
    ///   - linkId: The link ID calculated from the LINKREQUEST
    ///   - ephemeralEncryptionPublicKey: Responder's ephemeral X25519 public key
    ///   - destinationIdentity: The destination's identity for signing
    ///   - signaling: MTU signaling data (defaults to standard signaling)
    /// - Returns: PROOF data in wire format (99 bytes)
    /// - Throws: `LinkError.invalidProof` if identity lacks private keys
    public static func create(
        linkId: Data,
        ephemeralEncryptionPublicKey: Curve25519.KeyAgreement.PublicKey,
        destinationIdentity: Identity,
        signaling: Data = LinkConstants.DEFAULT_MTU_SIGNALING
    ) throws -> Data {
        guard destinationIdentity.hasPrivateKeys else {
            throw LinkError.invalidProof(reason: "Identity has no private keys for signing")
        }

        // Build signed data: linkId || ephemeralEncPubkey || sigPubkey || signaling
        var signedData = Data()
        signedData.append(linkId)
        signedData.append(ephemeralEncryptionPublicKey.rawRepresentation)
        signedData.append(destinationIdentity.signingPublicKey.rawRepresentation)
        signedData.append(signaling)

        // Sign with destination's identity
        let signature = try destinationIdentity.sign(signedData)

        // Build PROOF: signature || ephemeralEncPubkey || signaling
        var proof = Data()
        proof.reserveCapacity(99)
        proof.append(signature)
        proof.append(ephemeralEncryptionPublicKey.rawRepresentation)
        proof.append(signaling)

        return proof
    }
}

// MARK: - CustomStringConvertible

extension LinkProof: CustomStringConvertible {
    public var description: String {
        let sigHex = signature.prefix(4).map { String(format: "%02x", $0) }.joined()
        let peerKeyHex = peerEncryptionPublicKey.rawRepresentation.prefix(4)
            .map { String(format: "%02x", $0) }.joined()
        return "LinkProof<sig:\(sigHex)..., peer:\(peerKeyHex)...>"
    }
}
