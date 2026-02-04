//
//  Constants.swift
//  ReticulumSwift
//
//  Reticulum protocol constants matching Python RNS.
//

import Foundation

// MARK: - Size Constants

/// Maximum Transmission Unit - maximum packet size
public let MTU: Int = 500

/// Maximum Data Unit - max payload after headers (MTU - header overhead)
public let MDU: Int = 464

/// Encrypted MDU after encryption overhead
public let ENCRYPTED_MDU: Int = 383

/// Truncated hash length (128 bits)
public let TRUNCATED_HASH_LENGTH: Int = 16

// MARK: - Packet Types

/// Reticulum packet types (bits 1-0 of header byte 1)
public enum PacketType: UInt8, CaseIterable, Sendable {
    case data = 0x00        // Application payload
    case announce = 0x01    // Identity broadcast
    case linkRequest = 0x02 // Link establishment
    case proof = 0x03       // Delivery confirmation
}

// MARK: - Destination Types

/// Destination addressing types (bits 3-2 of header byte 1)
public enum DestinationType: UInt8, CaseIterable, Sendable {
    case single = 0x00  // One-to-one encrypted
    case group = 0x01   // Shared key group
    case plain = 0x02   // Unencrypted broadcast
    case link = 0x03    // Over established link
}

// MARK: - Header Types

/// Header format types (bit 6 of header byte 1)
public enum HeaderType: UInt8, CaseIterable, Sendable {
    case header1 = 0x00 // Single address (destination only)
    case header2 = 0x01 // Two addresses (destination + transport)
}

// MARK: - Transport Types

/// Transport propagation types (bit 4 of header byte 1)
public enum TransportType: UInt8, CaseIterable, Sendable {
    case broadcast = 0x00   // Local broadcast
    case transport = 0x01   // Via transport node
}

// MARK: - HDLC Constants

/// HDLC-like framing constants for TCP transport
public enum HDLCConstants {
    /// Frame delimiter flag
    public static let FLAG: UInt8 = 0x7E

    /// Escape byte
    public static let ESC: UInt8 = 0x7D

    /// XOR mask for escaped bytes
    public static let ESC_MASK: UInt8 = 0x20
}

// MARK: - Errors

/// Errors during HDLC frame processing
public enum HDLCError: Error, Sendable {
    /// Frame data ended with incomplete escape sequence
    case truncatedEscape

    /// No frame delimiters found
    case noFrameFound

    /// Frame structure invalid
    case malformedFrame
}

/// Errors during packet parsing
public enum PacketError: Error, Sendable {
    /// Packet data too short for header
    case headerTooShort

    /// Invalid header type value
    case invalidHeaderType

    /// Invalid transport type value
    case invalidTransportType

    /// Invalid destination type value
    case invalidDestinationType

    /// Invalid packet type value
    case invalidPacketType

    /// Packet has IFAC flag set (not yet supported)
    case ifacNotYetImplemented

    /// Packet data shorter than header indicates
    case payloadTooShort
}
