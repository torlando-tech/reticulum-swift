// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  LinkRequest.swift
//  ReticulumSwift
//
//  LINKREQUEST packet construction for link establishment.
//  Matches Python RNS Link.py wire format for interoperability.
//

import Foundation
import CryptoKit

// MARK: - Link Request

/// LINKREQUEST packet construction for initiating link establishment.
///
/// A LINKREQUEST contains ephemeral keypairs and MTU signaling data:
/// - 32-byte ephemeral encryption public key (X25519)
/// - 32-byte ephemeral signing public key (Ed25519)
/// - 3-byte MTU signaling
///
/// The link ID is calculated as the truncated hash of the ephemeral public keys,
/// which uniquely identifies this link attempt.
///
/// Wire format (67 bytes total):
/// ```
/// [enc_pubkey: 32 bytes][sig_pubkey: 32 bytes][signaling: 3 bytes]
/// ```
public struct LinkRequest: Sendable {

    // MARK: - Properties

    /// Target destination for the link
    public let destination: Destination

    /// Ephemeral X25519 private key for ECDH key agreement
    public let ephemeralEncryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey

    /// Ephemeral Ed25519 private key for link-specific signing operations
    public let ephemeralSigningPrivateKey: Curve25519.Signing.PrivateKey

    /// MTU signaling data (3 bytes)
    public let signaling: Data

    // MARK: - Computed Properties

    /// Ephemeral X25519 public key for ECDH key agreement
    public var ephemeralEncryptionPublicKey: Curve25519.KeyAgreement.PublicKey {
        ephemeralEncryptionPrivateKey.publicKey
    }

    /// Ephemeral Ed25519 public key
    public var ephemeralSigningPublicKey: Curve25519.Signing.PublicKey {
        ephemeralSigningPrivateKey.publicKey
    }

    /// Link ID calculated from the LINKREQUEST packet's hashable part.
    ///
    /// The link ID uniquely identifies this link attempt and is used as the HKDF salt
    /// during key derivation after ECDH.
    ///
    /// Python RNS formula (Link.link_id_from_lr_packet):
    /// ```
    /// hashable_part = packet.get_hashable_part()
    /// if len(packet.data) > ECPUBSIZE:  # 64 = 32 + 32
    ///     diff = len(packet.data) - ECPUBSIZE
    ///     hashable_part = hashable_part[:-diff]  # Trim signaling
    /// return truncated_hash(hashable_part)
    /// ```
    ///
    /// For HEADER_1, get_hashable_part returns:
    /// ```
    /// (raw[0] & 0x0F) + raw[2:]  # masked header byte + dest + context + data
    /// ```
    public var linkId: Data {
        // Build the packet to get its raw bytes
        let pkt = packet()
        let raw = pkt.encode()

        // Compute hashable part for HEADER_1:
        // - First byte masked to lower 4 bits
        // - Bytes from index 2 onward (dest + context + data)
        var hashable = Data()
        hashable.append(raw[0] & 0x0F)  // Lower 4 bits of first header byte
        hashable.append(contentsOf: raw[2...])  // Skip 2-byte header

        // Trim signaling bytes if data > 64 (ECPUBSIZE)
        // Our data is 67 bytes (32+32+3), so trim 3 bytes
        let ecPubSize = 64  // Two 32-byte public keys
        if requestData.count > ecPubSize {
            let trimCount = requestData.count - ecPubSize
            hashable = hashable.dropLast(trimCount)
        }

        let result = Hashing.truncatedHash(Data(hashable))
        return result
    }

    // MARK: - Initialization

    /// Create a link request with new ephemeral keypairs.
    ///
    /// Generates fresh X25519 and Ed25519 keypairs for this link attempt.
    ///
    /// - Parameters:
    ///   - destination: The destination to establish a link with
    ///   - signaling: MTU signaling data (default: 500 MTU encoded as 3-byte big-endian)
    public init(
        destination: Destination,
        signaling: Data = LinkConstants.DEFAULT_MTU_SIGNALING
    ) {
        self.destination = destination
        self.ephemeralEncryptionPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        self.ephemeralSigningPrivateKey = Curve25519.Signing.PrivateKey()
        self.signaling = signaling
    }

    /// Create a link request with known keys (for testing).
    ///
    /// - Parameters:
    ///   - destination: The destination to establish a link with
    ///   - ephemeralEncryptionPrivateKey: X25519 private key for ECDH
    ///   - ephemeralSigningPrivateKey: Ed25519 private key for signing
    ///   - signaling: MTU signaling data (default: 500 MTU)
    public init(
        destination: Destination,
        ephemeralEncryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        ephemeralSigningPrivateKey: Curve25519.Signing.PrivateKey,
        signaling: Data = LinkConstants.DEFAULT_MTU_SIGNALING
    ) {
        self.destination = destination
        self.ephemeralEncryptionPrivateKey = ephemeralEncryptionPrivateKey
        self.ephemeralSigningPrivateKey = ephemeralSigningPrivateKey
        self.signaling = signaling
    }

    // MARK: - Packet Construction

    /// Construct LINKREQUEST packet data (67 bytes).
    ///
    /// Format: `enc_pubkey(32) || sig_pubkey(32) || signaling(3)`
    public var requestData: Data {
        var data = Data()
        data.reserveCapacity(67)
        data.append(ephemeralEncryptionPublicKey.rawRepresentation)  // 32 bytes
        data.append(ephemeralSigningPublicKey.rawRepresentation)      // 32 bytes
        data.append(signaling)                                         // 3 bytes
        return data
    }

    /// Construct complete Packet for sending.
    ///
    /// Creates a LINKREQUEST packet with appropriate header fields:
    /// - Header type: HEADER_1 (single-hop direct)
    /// - Transport type: broadcast (sent directly to destination)
    /// - Destination type: single (specific destination)
    /// - Packet type: linkRequest
    ///
    /// Note: For multi-hop routing through transport nodes, the transport
    /// layer would need to wrap this in a HEADER_2 packet.
    ///
    /// - Returns: Packet ready for transmission
    public func packet() -> Packet {
        let header = PacketHeader(
            headerType: .header1,       // Single-hop direct (no transport address needed)
            hasContext: false,
            hasIFAC: false,
            transportType: .broadcast,  // Broadcast to interface
            destinationType: .single,   // Single destination
            packetType: .linkRequest,
            hopCount: 0
        )

        return Packet(
            header: header,
            destination: destination.hash,
            transportAddress: nil,
            context: 0x00,
            data: requestData
        )
    }
}

// MARK: - CustomStringConvertible

extension LinkRequest: CustomStringConvertible {
    public var description: String {
        let linkIdHex = linkId.prefix(4).map { String(format: "%02x", $0) }.joined()
        return "LinkRequest<\(linkIdHex)... -> \(destination)>"
    }
}
