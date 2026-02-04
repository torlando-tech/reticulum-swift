//
//  PacketHeader.swift
//  ReticulumSwift
//
//  Reticulum packet header parsing.
//  Based on Python RNS Packet.py implementation.
//

import Foundation

/// Reticulum packet header (2 bytes).
///
/// Header byte 1 bit fields:
/// ```
/// Bit 7: IFAC flag
/// Bit 6: Header type
/// Bit 5: Context flag
/// Bit 4: Transport type
/// Bits 3-2: Destination type
/// Bits 1-0: Packet type
/// ```
///
/// Header byte 2: Hop count
public struct PacketHeader: Sendable, Equatable {

    /// Header format type (single or dual address)
    public let headerType: HeaderType

    /// Whether packet has context byte
    public let hasContext: Bool

    /// Whether packet has IFAC field
    public let hasIFAC: Bool

    /// Transport propagation type
    public let transportType: TransportType

    /// Destination addressing type
    public let destinationType: DestinationType

    /// Packet content type
    public let packetType: PacketType

    /// Number of hops this packet has traversed
    public let hopCount: UInt8

    /// Header size in bytes (always 2)
    public static let size: Int = 2

    // MARK: - Initialization

    /// Create header from raw bytes.
    ///
    /// - Parameter data: Raw packet data (at least 2 bytes)
    /// - Throws: `PacketError` if data is invalid
    public init(from data: Data) throws {
        guard data.count >= 2 else {
            throw PacketError.headerTooShort
        }

        let flags = data[data.startIndex]
        let hops = data[data.index(after: data.startIndex)]

        // Bit 7: IFAC flag
        self.hasIFAC = (flags & 0b1000_0000) != 0

        // For Phase 1.2, IFAC packets are not supported (requires crypto)
        if hasIFAC {
            throw PacketError.ifacNotYetImplemented
        }

        // Bit 6: Header type
        let headerTypeRaw = (flags & 0b0100_0000) >> 6
        guard let ht = HeaderType(rawValue: headerTypeRaw) else {
            throw PacketError.invalidHeaderType
        }
        self.headerType = ht

        // Bit 5: Context flag
        self.hasContext = (flags & 0b0010_0000) != 0

        // Bit 4: Transport type
        let transportTypeRaw = (flags & 0b0001_0000) >> 4
        guard let tt = TransportType(rawValue: transportTypeRaw) else {
            throw PacketError.invalidTransportType
        }
        self.transportType = tt

        // Bits 3-2: Destination type
        let destTypeRaw = (flags & 0b0000_1100) >> 2
        guard let dt = DestinationType(rawValue: destTypeRaw) else {
            throw PacketError.invalidDestinationType
        }
        self.destinationType = dt

        // Bits 1-0: Packet type
        let packetTypeRaw = flags & 0b0000_0011
        guard let pt = PacketType(rawValue: packetTypeRaw) else {
            throw PacketError.invalidPacketType
        }
        self.packetType = pt

        // Byte 2: Hop count
        self.hopCount = hops
    }

    /// Create header with explicit values.
    public init(
        headerType: HeaderType,
        hasContext: Bool,
        hasIFAC: Bool = false,
        transportType: TransportType,
        destinationType: DestinationType,
        packetType: PacketType,
        hopCount: UInt8
    ) {
        self.headerType = headerType
        self.hasContext = hasContext
        self.hasIFAC = hasIFAC
        self.transportType = transportType
        self.destinationType = destinationType
        self.packetType = packetType
        self.hopCount = hopCount
    }

    // MARK: - Encoding

    /// Encode header to raw bytes.
    ///
    /// - Returns: 2-byte header data
    public func encode() -> Data {
        var flags: UInt8 = 0

        if hasIFAC { flags |= 0b1000_0000 }
        flags |= (headerType.rawValue << 6)
        if hasContext { flags |= 0b0010_0000 }
        flags |= (transportType.rawValue << 4)
        flags |= (destinationType.rawValue << 2)
        flags |= packetType.rawValue

        return Data([flags, hopCount])
    }

    // MARK: - Computed Properties

    /// Number of address fields based on header type.
    /// HEADER_1 has 1 address (destination), HEADER_2 has 2 (destination + transport).
    public var addressCount: Int {
        switch headerType {
        case .header1: return 1
        case .header2: return 2
        }
    }

    /// Size of addresses section in bytes.
    /// Each address is TRUNCATED_HASH_LENGTH (16) bytes.
    public var addressesSize: Int {
        return addressCount * TRUNCATED_HASH_LENGTH
    }
}

// MARK: - CustomStringConvertible

extension PacketHeader: CustomStringConvertible {
    public var description: String {
        return "Header(\(packetType), \(destinationType), hops:\(hopCount))"
    }
}
