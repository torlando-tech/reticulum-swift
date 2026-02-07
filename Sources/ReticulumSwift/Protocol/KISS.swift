//
//  KISS.swift
//  ReticulumSwift
//
//  KISS protocol framing for RNode BLE transport.
//  Based on Python RNS RNodeInterface.py implementation.
//

import Foundation

// MARK: - KISS Constants

/// KISS protocol framing constants for RNode communication
public enum KISSConstants {
    /// Frame End - marks start and end of frame
    public static let FEND: UInt8 = 0xC0

    /// Frame Escape - escapes special bytes in payload
    public static let FESC: UInt8 = 0xDB

    /// Transposed Frame End - escaped FEND becomes FESC + TFEND
    public static let TFEND: UInt8 = 0xDC

    /// Transposed Frame Escape - escaped FESC becomes FESC + TFESC
    public static let TFESC: UInt8 = 0xDD

    /// Command byte for data frames
    public static let CMD_DATA: UInt8 = 0x00
}

// MARK: - Errors

/// Errors during KISS frame processing
public enum KISSError: Error, Sendable {
    /// Frame data ended with incomplete escape sequence
    case truncatedEscape
}

// MARK: - KISS Protocol

/// KISS protocol framing for RNode BLE transport.
///
/// Uses FEND bytes (0xC0) to delimit frames and escape sequences for
/// special bytes in the payload. Unlike HDLC, KISS uses transposed values
/// (TFEND/TFESC) instead of XOR masking.
public enum KISS {

    /// Frame End delimiter byte
    public static let FEND = KISSConstants.FEND

    /// Frame Escape byte
    public static let FESC = KISSConstants.FESC

    /// Transposed Frame End value
    public static let TFEND = KISSConstants.TFEND

    /// Transposed Frame Escape value
    public static let TFESC = KISSConstants.TFESC

    /// Default command byte (data)
    public static let CMD_DATA = KISSConstants.CMD_DATA

    // MARK: - Encoding (STUB - RED phase)

    /// Escape special bytes in data for KISS framing.
    ///
    /// - Parameter data: Raw data to escape
    /// - Returns: Data with special bytes escaped
    public static func escape(_ data: Data) -> Data {
        // STUB: Return empty to make tests fail
        return Data()
    }

    /// Wrap data in KISS frame with FEND delimiters and command byte.
    ///
    /// - Parameters:
    ///   - data: Raw data to frame
    ///   - command: Command byte (defaults to CMD_DATA)
    /// - Returns: Complete KISS frame
    public static func frame(_ data: Data, command: UInt8 = CMD_DATA) -> Data {
        // STUB: Return empty to make tests fail
        return Data()
    }

    // MARK: - Decoding (STUB - RED phase)

    /// Unescape KISS frame content.
    ///
    /// - Parameter data: Escaped frame content
    /// - Returns: Unescaped original data
    /// - Throws: `KISSError.truncatedEscape` if data ends mid-escape
    public static func unescape(_ data: Data) throws -> Data {
        // STUB: Throw to make tests fail
        throw KISSError.truncatedEscape
    }

    /// Extract frames from a buffer of received data.
    ///
    /// - Parameter buffer: Mutable buffer of received data
    /// - Returns: Array of unescaped frame contents (may be empty)
    public static func extractFrames(from buffer: inout Data) -> [Data] {
        // STUB: Return empty to make tests fail
        return []
    }
}
