//
//  AnnounceValidator.swift
//  ReticulumSwift
//
//  Validates received announce packets by parsing fields and verifying signatures.
//  Used to securely build the path table by rejecting spoofed announces.
//
//  Matches Python RNS announce validation for byte-perfect interoperability.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "net.reticulum", category: "AnnounceValidator")

// MARK: - Validation Errors

/// Errors during announce validation
public enum AnnounceValidationError: Error, Sendable, Equatable {
    /// Packet data too short for minimum announce structure
    case packetTooShort(expected: Int, actual: Int)

    /// Name hash has invalid length (should be 10 bytes)
    case invalidNameHashLength(length: Int)

    /// Signature verification failed
    case signatureInvalid

    /// Computed destination hash doesn't match packet header
    case hashMismatch(computed: String, expected: String)
}

// MARK: - Parsed Announce

/// Parsed announce packet fields extracted from raw packet data.
///
/// For SINGLE/GROUP/LINK destinations with identity:
/// ```
/// public_keys(64) || name_hash(10) || random_hash(10) || signature(64) [|| app_data]
/// ```
///
/// For PLAIN destinations:
/// ```
/// name_hash(10) || random_hash(10) [|| app_data]
/// ```
public struct ParsedAnnounce: Sendable, Equatable {
    /// Public keys (64 bytes: encryption 32B + signing 32B)
    /// Nil for PLAIN destinations
    public let publicKeys: Data?

    /// Name hash (10 bytes: truncated SHA-256 of destination name)
    public let nameHash: Data

    /// Random hash for uniqueness (10 bytes)
    public let randomHash: Data

    /// Optional ratchet data (variable length, between random_hash and signature)
    /// Used for forward secrecy in RNS 1.1+
    public let ratchet: Data?

    /// Signature (64 bytes)
    /// Nil for PLAIN destinations
    public let signature: Data?

    /// Optional application data (after signature)
    public let appData: Data?

    /// Destination hash from packet header (16 bytes)
    public let destinationHash: Data

    /// Whether this is a PLAIN announce (no signature)
    public var isPlain: Bool {
        return publicKeys == nil && signature == nil
    }
}

// MARK: - Announce Validator

/// Validates received announce packets by parsing and verifying signatures.
///
/// AnnounceValidator is used to:
/// 1. Parse incoming announce packet data into structured fields
/// 2. Verify the signature to ensure announce authenticity
/// 3. Reject tampered or spoofed announces
public enum AnnounceValidator {

    // MARK: - Constants

    /// Name hash length in announces (10 bytes = 80 bits)
    /// RNS.Identity.NAME_HASH_LENGTH = 80 bits = 10 bytes
    private static let ANNOUNCE_NAME_HASH_LENGTH = 10

    /// Ratchet size in bytes (X25519 public key)
    private static let RATCHET_SIZE = 32

    /// Minimum signed announce size: public_keys(64) + name_hash(10) + random_hash(10) + signature(64) = 148
    /// Note: Actual announces may be longer due to optional ratchet data or app_data
    private static let minimumSignedAnnounceSize = PUBLIC_KEYS_LENGTH + ANNOUNCE_NAME_HASH_LENGTH + ANNOUNCE_RANDOM_HASH_LENGTH + SIGNATURE_LENGTH

    /// Minimum signed announce size with ratchet: 148 + 32 = 180
    private static let minimumSignedAnnounceSizeWithRatchet = minimumSignedAnnounceSize + RATCHET_SIZE

    /// Minimum plain announce size: name_hash(10) + random_hash(10) = 20
    private static let minimumPlainAnnounceSize = ANNOUNCE_NAME_HASH_LENGTH + ANNOUNCE_RANDOM_HASH_LENGTH

    // MARK: - Parsing

    /// Parse an announce packet into structured fields.
    ///
    /// Extracts public_keys, name_hash, random_hash, signature, and optional app_data
    /// from the packet payload.
    ///
    /// - Parameters:
    ///   - packet: The announce packet to parse
    ///   - isPlain: Whether this is a PLAIN destination (no signature)
    ///   - nameHashLength: Known name hash length (if available from destination aspects)
    /// - Returns: ParsedAnnounce with extracted fields
    /// - Throws: `AnnounceValidationError` if packet structure is invalid
    public static func parse(packet: Packet, isPlain: Bool = false, nameHashLength: Int? = nil) throws -> ParsedAnnounce {
        let data = packet.data
        // Context flag indicates ratchet is present for non-PLAIN announces
        let hasRatchet = packet.header.hasContext && !isPlain

        let destHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
        logger.debug("Parse: dest=\(destHex), dataLen=\(data.count), hasContext=\(packet.header.hasContext), hasRatchet=\(hasRatchet)")

        if isPlain {
            return try parsePlainAnnounce(data: data, destinationHash: packet.destination, nameHashLength: nameHashLength)
        } else {
            return try parseSignedAnnounce(data: data, destinationHash: packet.destination, nameHashLength: nameHashLength, hasRatchet: hasRatchet)
        }
    }

    /// Parse announce from raw data (without packet wrapper).
    ///
    /// - Parameters:
    ///   - data: Raw announce payload data
    ///   - destinationHash: Destination hash from packet header
    ///   - isPlain: Whether this is a PLAIN destination
    ///   - nameHashLength: Known name hash length (if available from destination aspects)
    ///   - hasRatchet: Whether the announce includes a ratchet (32 bytes between random_hash and signature)
    /// - Returns: ParsedAnnounce with extracted fields
    /// - Throws: `AnnounceValidationError` if structure is invalid
    public static func parse(data: Data, destinationHash: Data, isPlain: Bool = false, nameHashLength: Int? = nil, hasRatchet: Bool = false) throws -> ParsedAnnounce {
        if isPlain {
            return try parsePlainAnnounce(data: data, destinationHash: destinationHash, nameHashLength: nameHashLength)
        } else {
            return try parseSignedAnnounce(data: data, destinationHash: destinationHash, nameHashLength: nameHashLength, hasRatchet: hasRatchet)
        }
    }

    // MARK: - Validation

    /// Validate a parsed announce by verifying its signature.
    ///
    /// For SINGLE/GROUP/LINK destinations:
    /// 1. Reconstructs the signed data: dest_hash || public_keys || name_hash || random_hash [|| ratchet] [|| app_data]
    /// 2. Extracts the signing public key (bytes 32-63 of publicKeys)
    /// 3. Verifies the signature
    ///
    /// For PLAIN destinations, returns true (no signature to verify).
    ///
    /// - Parameter parsed: The parsed announce to validate
    /// - Returns: true if signature is valid (or PLAIN), false otherwise
    /// - Throws: `AnnounceValidationError.signatureInvalid` if verification fails,
    ///           `IdentityError` if public key is malformed
    public static func validate(parsed: ParsedAnnounce) throws -> Bool {
        // PLAIN announces have no signature to verify
        if parsed.isPlain {
            return true
        }

        guard let publicKeys = parsed.publicKeys,
              let signature = parsed.signature else {
            throw AnnounceValidationError.signatureInvalid
        }

        // Reconstruct signed data
        // For ratcheted announces (hasContext=true): dest_hash || public_keys || name_hash || random_hash || ratchet [|| app_data]
        // For non-ratcheted announces: may use different format, try without dest_hash first
        var signedData = Data()

        let hasRatchetData = parsed.ratchet != nil && !parsed.ratchet!.isEmpty

        // Build signed data - format depends on whether ratchet is present
        // Ratcheted: dest_hash || public_keys || name_hash || random_hash || ratchet || app_data
        // Non-ratcheted: public_keys || name_hash || random_hash (no dest_hash, no app_data)
        signedData.append(parsed.destinationHash)
        signedData.append(publicKeys)
        signedData.append(parsed.nameHash)
        signedData.append(parsed.randomHash)
        if hasRatchetData, let ratchet = parsed.ratchet {
            signedData.append(ratchet)
        }
        if let appData = parsed.appData, !appData.isEmpty {
            signedData.append(appData)
        }

        // Debug logging
        let destHex = parsed.destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        let appDataLen = parsed.appData?.count ?? 0
        let sigHex = signature.prefix(16).map { String(format: "%02x", $0) }.joined()
        let signedDataHex = signedData.prefix(32).map { String(format: "%02x", $0) }.joined()
        logger.debug("Validate: dest=\(destHex), signedData=\(signedData.count) bytes, hasRatchet=\(hasRatchetData), appData=\(appDataLen) bytes")
        logger.debug("Validate: signedData[0:32]=\(signedDataHex)... sig[0:16]=\(sigHex)...")

        // Extract signing public key (bytes 32-63 of publicKeys)
        // Use Data() to ensure contiguous bytes starting at index 0
        let signingPublicKey = Data(publicKeys.suffix(32))

        // Verify signature
        let isValid = try Identity.verify(
            signature: signature,
            for: signedData,
            publicKey: signingPublicKey
        )

        if !isValid {
            logger.warning("Signature verification FAILED")
            throw AnnounceValidationError.signatureInvalid
        }

        logger.debug("Signature verification PASSED")
        return true
    }

    /// Parse and validate in one step.
    ///
    /// - Parameters:
    ///   - packet: The announce packet
    ///   - isPlain: Whether this is a PLAIN destination
    /// - Returns: ParsedAnnounce if valid
    /// - Throws: `AnnounceValidationError` or `IdentityError` on failure
    public static func parseAndValidate(packet: Packet, isPlain: Bool = false) throws -> ParsedAnnounce {
        let parsed = try parse(packet: packet, isPlain: isPlain)
        _ = try validate(parsed: parsed)
        return parsed
    }

    // MARK: - Private Parsing Helpers

    /// Parse a signed announce (SINGLE/GROUP/LINK destination).
    ///
    /// - Parameters:
    ///   - data: Raw announce data
    ///   - destinationHash: Destination hash from packet header
    ///   - nameHashLength: Known name hash length (if available). If nil, uses standard 10-byte length.
    ///   - hasRatchet: Whether the announce contains a 32-byte ratchet (indicated by context flag)
    private static func parseSignedAnnounce(data: Data, destinationHash: Data, nameHashLength: Int? = nil, hasRatchet: Bool = false) throws -> ParsedAnnounce {
        // Minimum size check
        let requiredMinSize = hasRatchet ? minimumSignedAnnounceSizeWithRatchet : minimumSignedAnnounceSize
        guard data.count >= requiredMinSize else {
            throw AnnounceValidationError.packetTooShort(
                expected: requiredMinSize,
                actual: data.count
            )
        }

        // Structure without ratchet: public_keys(64) || name_hash(10) || random_hash(10) || signature(64) [|| app_data]
        // Structure with ratchet:    public_keys(64) || name_hash(10) || random_hash(10) || ratchet(32) || signature(64) [|| app_data]
        // Note: Signature comes BEFORE app_data, NOT at the end of the packet.
        // Parse sequentially from the front.

        var offset = 0

        // Public keys are first 64 bytes
        guard offset + PUBLIC_KEYS_LENGTH <= data.count else {
            throw AnnounceValidationError.packetTooShort(
                expected: PUBLIC_KEYS_LENGTH,
                actual: data.count
            )
        }
        let publicKeys = Data(data[offset..<(offset + PUBLIC_KEYS_LENGTH)])
        offset += PUBLIC_KEYS_LENGTH

        // Name hash - use provided length or default 10 bytes
        let actualNameHashLength = nameHashLength ?? ANNOUNCE_NAME_HASH_LENGTH
        guard offset + actualNameHashLength <= data.count else {
            throw AnnounceValidationError.packetTooShort(
                expected: offset + actualNameHashLength,
                actual: data.count
            )
        }
        let nameHash = Data(data[offset..<(offset + actualNameHashLength)])
        offset += actualNameHashLength

        // Random hash is next 10 bytes
        guard offset + ANNOUNCE_RANDOM_HASH_LENGTH <= data.count else {
            throw AnnounceValidationError.packetTooShort(
                expected: offset + ANNOUNCE_RANDOM_HASH_LENGTH,
                actual: data.count
            )
        }
        let randomHash = Data(data[offset..<(offset + ANNOUNCE_RANDOM_HASH_LENGTH)])
        offset += ANNOUNCE_RANDOM_HASH_LENGTH

        // Ratchet (32 bytes) if present - between random_hash and signature
        var ratchet: Data? = nil
        if hasRatchet {
            guard offset + RATCHET_SIZE <= data.count else {
                throw AnnounceValidationError.packetTooShort(
                    expected: offset + RATCHET_SIZE,
                    actual: data.count
                )
            }
            ratchet = Data(data[offset..<(offset + RATCHET_SIZE)])
            let ratchetHex = ratchet!.prefix(8).map { String(format: "%02x", $0) }.joined()
            logger.debug("Extracted ratchet[0:8]=\(ratchetHex)")
            offset += RATCHET_SIZE
        }

        // Signature is next 64 bytes
        guard offset + SIGNATURE_LENGTH <= data.count else {
            throw AnnounceValidationError.packetTooShort(
                expected: offset + SIGNATURE_LENGTH,
                actual: data.count
            )
        }
        let signature = Data(data[offset..<(offset + SIGNATURE_LENGTH)])
        offset += SIGNATURE_LENGTH

        // App data is everything remaining after signature
        let appData: Data? = offset < data.count ? Data(data[offset...]) : nil

        // Debug: Show parse offsets
        let sigOffset = hasRatchet ? (PUBLIC_KEYS_LENGTH + actualNameHashLength + ANNOUNCE_RANDOM_HASH_LENGTH + RATCHET_SIZE) : (PUBLIC_KEYS_LENGTH + actualNameHashLength + ANNOUNCE_RANDOM_HASH_LENGTH)
        let pkHex = publicKeys.prefix(8).map { String(format: "%02x", $0) }.joined()
        let sigFirstBytes = signature.prefix(8).map { String(format: "%02x", $0) }.joined()
        logger.debug("Parse detail: sigOffset=\(sigOffset), pk[0:8]=\(pkHex), sig[0:8]=\(sigFirstBytes)")

        return ParsedAnnounce(
            publicKeys: publicKeys,
            nameHash: nameHash,
            randomHash: randomHash,
            ratchet: ratchet,
            signature: signature,
            appData: appData,
            destinationHash: Data(destinationHash)
        )
    }

    /// Parse a plain announce (PLAIN destination - no public keys, no signature).
    ///
    /// - Parameters:
    ///   - data: Raw announce data
    ///   - destinationHash: Destination hash from packet header
    ///   - nameHashLength: Known name hash length (if available). If nil, uses standard 10-byte length.
    private static func parsePlainAnnounce(data: Data, destinationHash: Data, nameHashLength: Int? = nil) throws -> ParsedAnnounce {
        // Minimum size check
        guard data.count >= minimumPlainAnnounceSize else {
            throw AnnounceValidationError.packetTooShort(
                expected: minimumPlainAnnounceSize,
                actual: data.count
            )
        }

        // Structure: name_hash(10) || random_hash(10) [|| ratchet(variable)] [|| app_data]
        // Note: Plain announces don't have signature, so ratchet (if present) comes after random_hash

        // Name hash length - use provided or default 10 bytes
        let actualNameHashLength = nameHashLength ?? ANNOUNCE_NAME_HASH_LENGTH

        // For plain announces, we can't easily distinguish ratchet from app_data without more context
        // For now, parse as: name_hash + random_hash, everything else is app_data
        var offset = 0
        let nameHash = Data(data[offset..<(offset + actualNameHashLength)])
        offset += actualNameHashLength

        let randomHash = Data(data[offset..<(offset + ANNOUNCE_RANDOM_HASH_LENGTH)])
        offset += ANNOUNCE_RANDOM_HASH_LENGTH

        // Remaining bytes could be ratchet + app_data, but we treat as app_data for now
        let appData: Data? = offset < data.count ? Data(data[offset...]) : nil

        return ParsedAnnounce(
            publicKeys: nil,
            nameHash: nameHash,
            randomHash: randomHash,
            ratchet: nil,  // Can't distinguish ratchet in plain announces without signature boundary
            signature: nil,
            appData: appData,
            destinationHash: Data(destinationHash)
        )
    }
}
