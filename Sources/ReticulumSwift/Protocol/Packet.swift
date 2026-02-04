//
//  Packet.swift
//  ReticulumSwift
//
//  Reticulum packet structure.
//  Based on Python RNS Packet.py implementation.
//

import Foundation

/// Reticulum packet containing header, addresses, and payload.
///
/// Packet structure varies based on header type:
/// - HEADER_1: 2-byte header + 16-byte destination + 1-byte context + data
/// - HEADER_2: 2-byte header + 16-byte transport + 16-byte destination + 1-byte context + data
///
/// The context byte is always present in the wire format. The hasContext header flag
/// indicates semantic meaning (e.g., ratchet presence for announces), not byte presence.
public struct Packet: Sendable, Equatable {

    /// Packet header containing type and routing information
    public let header: PacketHeader

    /// Destination address (truncated hash, 16 bytes)
    public let destination: Data

    /// Transport address for routed packets (truncated hash, 16 bytes)
    /// Only present when header.headerType == .header2
    public let transportAddress: Data?

    /// Context byte (always present in wire format)
    /// The hasContext header flag indicates semantic meaning, not presence
    public let context: UInt8

    /// Packet payload data
    public let data: Data

    // MARK: - Initialization

    /// Parse packet from raw bytes.
    ///
    /// - Parameter rawData: Complete packet bytes
    /// - Throws: `PacketError` if packet structure is invalid
    public init(from rawData: Data) throws {
        // Parse header first
        self.header = try PacketHeader(from: rawData)

        var offset = PacketHeader.size  // Start after header

        // HEADER_2 wire format: [transport_id 16B][destination_hash 16B]
        // HEADER_1 wire format: [destination_hash 16B]
        // Parse transport address FIRST if HEADER_2
        if header.headerType == .header2 {
            let transportEnd = offset + TRUNCATED_HASH_LENGTH
            guard rawData.count >= transportEnd else {
                throw PacketError.payloadTooShort
            }
            self.transportAddress = Data(rawData[offset..<transportEnd])
            offset = transportEnd
        } else {
            self.transportAddress = nil
        }

        // Parse destination address (always present, 16 bytes)
        // Use Data() constructor to rebase indices to 0
        let destEnd = offset + TRUNCATED_HASH_LENGTH
        guard rawData.count >= destEnd else {
            throw PacketError.payloadTooShort
        }
        self.destination = Data(rawData[offset..<destEnd])
        offset = destEnd

        // Parse context byte (always present in wire format)
        // The hasContext flag indicates semantic meaning, not presence of the byte
        guard rawData.count > offset else {
            throw PacketError.payloadTooShort
        }
        self.context = rawData[offset]
        offset += 1

        // Remaining bytes are payload data
        // Use Data() constructor to rebase indices to 0
        if offset < rawData.count {
            self.data = Data(rawData[offset...])
        } else {
            self.data = Data()
        }
    }

    /// Create packet with explicit values.
    public init(
        header: PacketHeader,
        destination: Data,
        transportAddress: Data? = nil,
        context: UInt8 = 0x00,
        data: Data
    ) {
        self.header = header
        self.destination = destination
        self.transportAddress = transportAddress
        self.context = context
        self.data = data
    }

    // MARK: - Encoding

    /// Encode packet to raw bytes.
    ///
    /// - Returns: Complete packet data
    public func encode() -> Data {
        var result = Data()
        result.reserveCapacity(MTU)

        // Header
        result.append(header.encode())

        // HEADER_2 wire format: [transport_id 16B][destination_hash 16B]
        // HEADER_1 wire format: [destination_hash 16B]
        // Transport address FIRST if HEADER_2
        if header.headerType == .header2, let transport = transportAddress {
            result.append(transport.prefix(TRUNCATED_HASH_LENGTH))
            if transport.count < TRUNCATED_HASH_LENGTH {
                result.append(Data(repeating: 0, count: TRUNCATED_HASH_LENGTH - transport.count))
            }
        }

        // Destination (ensure exactly 16 bytes)
        result.append(destination.prefix(TRUNCATED_HASH_LENGTH))
        if destination.count < TRUNCATED_HASH_LENGTH {
            result.append(Data(repeating: 0, count: TRUNCATED_HASH_LENGTH - destination.count))
        }

        // Context byte (always present in wire format)
        result.append(context)

        // Payload data
        result.append(data)

        return result
    }

    // MARK: - Packet Hash

    /// Get the hashable part of the packet for hash computation.
    ///
    /// For HEADER_1: (raw[0] & 0x0F) + raw[2:]
    /// For HEADER_2: (raw[0] & 0x0F) + raw[2:]
    ///
    /// The first byte is masked to lower 4 bits, and the hop count byte is skipped.
    /// This matches Python RNS Packet.get_hashable_part().
    ///
    /// - Returns: Hashable part of the packet
    public func getHashablePart() -> Data {
        let raw = encode()
        guard raw.count >= 2 else { return Data() }

        var hashable = Data()
        hashable.append(raw[0] & 0x0F)  // Lower 4 bits of first header byte
        if raw.count > 2 {
            hashable.append(contentsOf: raw[2...])  // Skip hop count byte
        }
        return hashable
    }

    /// Compute the packet hash (full 32-byte SHA256).
    ///
    /// The packet hash uniquely identifies this packet and is used for:
    /// - Proof destination calculation
    /// - Signature verification
    /// - Deduplication
    ///
    /// - Returns: 32-byte SHA256 hash of hashable part
    public func getFullHash() -> Data {
        let hashable = getHashablePart()
        return Hashing.fullHash(hashable)
    }

    /// Compute the truncated packet hash (16 bytes).
    ///
    /// Used as the proof destination for routing proofs back to sender.
    ///
    /// - Returns: 16-byte truncated hash
    public func getTruncatedHash() -> Data {
        return getFullHash().prefix(TRUNCATED_HASH_LENGTH)
    }

    // MARK: - Computed Properties

    /// Total packet size in bytes
    public var size: Int {
        return encode().count
    }

    /// Whether this is a routed packet (via transport node)
    public var isRouted: Bool {
        return header.transportType == .transport
    }

    /// Whether packet payload is encrypted (determined by destination type)
    public var isEncrypted: Bool {
        switch header.destinationType {
        case .single, .group, .link:
            return true
        case .plain:
            return false
        }
    }
}

// MARK: - CustomStringConvertible

extension Packet: CustomStringConvertible {
    public var description: String {
        let destHex = destination.prefix(4).map { String(format: "%02x", $0) }.joined()
        return "Packet(\(header.packetType), dest:\(destHex)..., \(data.count) bytes)"
    }
}
