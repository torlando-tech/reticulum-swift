//
//  IncomingLinkRequest.swift
//  ReticulumSwift
//
//  Parses incoming LINKREQUEST packets for link responder functionality.
//  Extracts peer's ephemeral public keys and MTU signaling.
//
//  Matches Python RNS Link.py validate_request() for interoperability.
//

import Foundation
import CryptoKit

// Note: Packet and Hashing are defined in other files in this module

// MARK: - IncomingLinkRequest Errors

/// Errors during LINKREQUEST parsing
public enum IncomingLinkRequestError: Error, Sendable {
    /// LINKREQUEST data has invalid length
    case invalidLength(expected: String, actual: Int)

    /// Failed to parse public key
    case invalidPublicKey(String)

    /// Failed to calculate link ID
    case linkIdCalculationFailed
}

// MARK: - IncomingLinkRequest

/// Parsed incoming LINKREQUEST packet.
///
/// LINKREQUEST wire format (64-67 bytes):
/// ```
/// [enc_pubkey: 32 bytes][sig_pubkey: 32 bytes][signaling: 3 bytes (optional)]
/// ```
///
/// The signaling bytes encode MTU and encryption mode:
/// - Bits 23-21: Encryption mode (3 bits)
/// - Bits 20-0: MTU value (21 bits)
///
/// Reference: Python RNS Link.py validate_request()
public struct IncomingLinkRequest: Sendable {

    // MARK: - Constants

    /// Size of ephemeral public keys (32 + 32 = 64 bytes)
    public static let ECPUBSIZE = 64

    /// Size of MTU signaling (3 bytes)
    public static let MTU_SIZE = 3

    /// Minimum valid LINKREQUEST size (keys only)
    public static let MIN_SIZE = ECPUBSIZE

    /// Maximum valid LINKREQUEST size (keys + signaling)
    public static let MAX_SIZE = ECPUBSIZE + MTU_SIZE

    // MARK: - Properties

    /// Peer's ephemeral X25519 encryption public key
    public let peerEncryptionPublicKey: Curve25519.KeyAgreement.PublicKey

    /// Peer's ephemeral Ed25519 signing public key
    public let peerSigningPublicKey: Curve25519.Signing.PublicKey

    /// Raw bytes of peer's encryption public key (for link ID calculation)
    public let peerEncryptionPublicKeyBytes: Data

    /// Raw bytes of peer's signing public key (for link ID calculation)
    public let peerSigningPublicKeyBytes: Data

    /// MTU signaling bytes (3 bytes, or nil if not provided)
    public let signalingBytes: Data?

    /// Parsed MTU value (default 500 if not provided)
    public let mtu: UInt32

    /// Parsed encryption mode (default 1 = AES-256-CBC)
    public let mode: UInt8

    /// The calculated link ID (16 bytes)
    public let linkId: Data

    // MARK: - Initialization

    /// Parse an incoming LINKREQUEST packet.
    ///
    /// - Parameters:
    ///   - data: LINKREQUEST payload (64-67 bytes)
    ///   - packet: Full packet for link ID calculation
    /// - Throws: `IncomingLinkRequestError` if parsing fails
    public init(data: Data, packet: Packet) throws {
        // Validate data length
        guard data.count == Self.MIN_SIZE || data.count == Self.MAX_SIZE else {
            throw IncomingLinkRequestError.invalidLength(
                expected: "\(Self.MIN_SIZE) or \(Self.MAX_SIZE)",
                actual: data.count
            )
        }

        // Extract peer's ephemeral public keys
        peerEncryptionPublicKeyBytes = Data(data.prefix(32))
        peerSigningPublicKeyBytes = Data(data[32..<64])

        do {
            peerEncryptionPublicKey = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: peerEncryptionPublicKeyBytes
            )
        } catch {
            throw IncomingLinkRequestError.invalidPublicKey("encryption: \(error.localizedDescription)")
        }

        do {
            peerSigningPublicKey = try Curve25519.Signing.PublicKey(
                rawRepresentation: peerSigningPublicKeyBytes
            )
        } catch {
            throw IncomingLinkRequestError.invalidPublicKey("signing: \(error.localizedDescription)")
        }

        // Parse signaling if present
        if data.count == Self.MAX_SIZE {
            signalingBytes = Data(data.suffix(3))
            let (parsedMtu, parsedMode) = Self.decodeSignaling(signalingBytes!)
            mtu = parsedMtu
            mode = parsedMode
        } else {
            signalingBytes = nil
            mtu = 500  // Default MTU
            mode = 1   // AES-256-CBC
        }

        // Calculate link ID from packet
        linkId = Self.calculateLinkId(from: packet)
    }

    // MARK: - Signaling Decoding

    /// Decode MTU and mode from signaling bytes.
    ///
    /// The 3-byte signaling field encodes both encryption mode and MTU:
    /// - Upper 3 bits of first byte: mode
    /// - Lower 21 bits: MTU value
    ///
    /// - Parameter signaling: 3-byte signaling data
    /// - Returns: Tuple of (mtu, mode)
    public static func decodeSignaling(_ signaling: Data) -> (mtu: UInt32, mode: UInt8) {
        guard signaling.count == 3 else { return (500, 1) }

        // Big-endian: [byte0][byte1][byte2]
        let value = UInt32(signaling[0]) << 16 | UInt32(signaling[1]) << 8 | UInt32(signaling[2])

        let mode = UInt8((signaling[0] & 0xE0) >> 5)  // Upper 3 bits of first byte
        let mtu = value & 0x1FFFFF  // Lower 21 bits

        return (mtu, mode)
    }

    /// Encode MTU and mode into signaling bytes.
    ///
    /// - Parameters:
    ///   - mtu: MTU value (max 21 bits)
    ///   - mode: Encryption mode (3 bits)
    /// - Returns: 3-byte signaling data
    public static func encodeSignaling(mtu: UInt32, mode: UInt8) -> Data {
        // value = (mtu & 0x1FFFFF) | ((mode & 0x07) << 21)
        let value = (mtu & 0x1FFFFF) | (UInt32(mode & 0x07) << 21)

        // Big-endian encoding
        return Data([
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF)
        ])
    }

    // MARK: - Link ID Calculation

    /// Calculate link ID from LINKREQUEST packet.
    ///
    /// The link ID is calculated as:
    /// ```
    /// truncated_hash(hashable_part)
    /// ```
    ///
    /// Where hashable_part for HEADER_1 packets is:
    /// ```
    /// (raw[0] & 0x0F) || raw[2:]  // masked flags + dest + data (minus signaling)
    /// ```
    ///
    /// The signaling bytes are trimmed from the end if data > ECPUBSIZE.
    ///
    /// Reference: Python RNS Link.link_id_from_lr_packet()
    ///
    /// - Parameter packet: The full LINKREQUEST packet
    /// - Returns: 16-byte link ID
    public static func calculateLinkId(from packet: Packet) -> Data {
        let raw = packet.encode()

        // Build hashable part for HEADER_1:
        // - First byte masked to lower 4 bits (removes header_type and context_flag)
        // - Bytes from index 2 onward (destination + data)
        var hashable = Data()
        hashable.append(raw[0] & 0x0F)
        hashable.append(contentsOf: raw[2...])

        // Trim signaling bytes if data > ECPUBSIZE (64 bytes)
        if packet.data.count > ECPUBSIZE {
            let trimCount = packet.data.count - ECPUBSIZE
            hashable = Data(hashable.dropLast(trimCount))
        }

        return Hashing.truncatedHash(hashable)
    }
}
