// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

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

    // MARK: - Encoding

    /// Escape special bytes in data for KISS framing.
    ///
    /// CRITICAL: Escape order matters!
    /// 1. Escape FESC bytes (0xDB) FIRST -> becomes [0xDB, 0xDD]
    /// 2. Then escape FEND bytes (0xC0) -> becomes [0xDB, 0xDC]
    ///
    /// This matches Python RNodeInterface.py lines 102-105 where 0xDB is
    /// replaced first, then 0xC0. Reversing this order would create incorrect
    /// frames because escaping FEND first would create new FESC bytes that
    /// wouldn't be handled.
    ///
    /// Unlike HDLC which uses XOR masking, KISS uses transposed values:
    /// - FEND (0xC0) -> FESC + TFEND (0xDB, 0xDC)
    /// - FESC (0xDB) -> FESC + TFESC (0xDB, 0xDD)
    ///
    /// - Parameter data: Raw data to escape
    /// - Returns: Data with special bytes escaped
    public static func escape(_ data: Data) -> Data {
        var result = Data()
        result.reserveCapacity(data.count * 2) // Worst case: all special bytes

        for byte in data {
            if byte == FESC {
                // FESC (0xDB) -> FESC + TFESC = 0xDB 0xDD
                result.append(FESC)
                result.append(TFESC)
            } else if byte == FEND {
                // FEND (0xC0) -> FESC + TFEND = 0xDB 0xDC
                result.append(FESC)
                result.append(TFEND)
            } else {
                result.append(byte)
            }
        }

        return result
    }

    /// Wrap data in KISS frame with FEND delimiters and command byte.
    ///
    /// Frame format: [FEND] [CMD] [escaped_data] [FEND]
    ///
    /// This differs from HDLC which uses 0x7E as delimiter. KISS uses 0xC0 (FEND).
    ///
    /// - Parameters:
    ///   - data: Raw data to frame
    ///   - command: Command byte (defaults to CMD_DATA = 0x00)
    /// - Returns: Complete KISS frame
    public static func frame(_ data: Data, command: UInt8 = CMD_DATA) -> Data {
        var result = Data()
        result.reserveCapacity(data.count * 2 + 3) // Worst case + delimiters + command

        result.append(FEND)          // Start delimiter (0xC0)
        result.append(command)       // Command byte (0x00 for data)
        result.append(escape(data))  // Escaped payload
        result.append(FEND)          // End delimiter (0xC0)

        return result
    }

    // MARK: - Decoding

    /// Unescape KISS frame content (data between FEND delimiters).
    ///
    /// Reverses the escape transformation using transposed values:
    /// - [0xDB, 0xDC] -> 0xC0 (FEND)
    /// - [0xDB, 0xDD] -> 0xDB (FESC)
    ///
    /// Unlike HDLC which uses XOR masking, KISS uses explicit transposed values.
    ///
    /// - Parameter data: Escaped frame content (without FEND bytes)
    /// - Returns: Unescaped original data
    /// - Throws: `KISSError.truncatedEscape` if data ends mid-escape
    public static func unescape(_ data: Data) throws -> Data {
        var result = Data()
        result.reserveCapacity(data.count)

        var escapeNext = false

        for byte in data {
            if escapeNext {
                // Unescape using transposed values
                if byte == TFEND {
                    // FESC + TFEND (0xDB, 0xDC) -> FEND (0xC0)
                    result.append(FEND)
                } else if byte == TFESC {
                    // FESC + TFESC (0xDB, 0xDD) -> FESC (0xDB)
                    result.append(FESC)
                } else {
                    // Unknown escape sequence, pass through
                    result.append(byte)
                }
                escapeNext = false
            } else if byte == FESC {
                // Next byte is escaped
                escapeNext = true
            } else {
                result.append(byte)
            }
        }

        // If we ended expecting an escaped byte, frame is truncated
        if escapeNext {
            throw KISSError.truncatedEscape
        }

        return result
    }

    /// Extract frames from a buffer of received data.
    ///
    /// Searches for FEND-delimited frames and extracts them.
    /// Modifies the buffer in-place, removing extracted frames.
    ///
    /// Frame format: [FEND] [CMD] [escaped_payload] [FEND]
    ///
    /// The command byte is stripped and only the unescaped payload is returned.
    ///
    /// - Parameter buffer: Mutable buffer of received data
    /// - Returns: Array of unescaped frame payloads (may be empty)
    public static func extractFrames(from buffer: inout Data) -> [Data] {
        var frames: [Data] = []

        while true {
            // Find start FEND
            guard let startIdx = buffer.firstIndex(of: FEND) else {
                break
            }

            // Find end FEND (must be after start)
            let searchStart = buffer.index(after: startIdx)
            guard searchStart < buffer.endIndex,
                  let endIdx = buffer[searchStart...].firstIndex(of: FEND) else {
                break
            }

            // Extract frame content (between FENDs)
            let frameContent = buffer[(buffer.index(after: startIdx))..<endIdx]

            // Remove processed data including end FEND
            buffer.removeSubrange(buffer.startIndex...endIdx)

            // Skip empty frames (consecutive FENDs)
            if frameContent.isEmpty {
                continue
            }

            // First byte is command, remaining bytes are escaped payload
            let commandAndPayload = Data(frameContent)
            guard commandAndPayload.count > 1 else {
                // Frame with only command byte, no payload
                continue
            }

            // Extract payload (skip command byte at index 0)
            let escapedPayload = commandAndPayload.dropFirst()

            // Unescape and add to results
            // Silently skip malformed frames (truncated escape)
            if let unescaped = try? unescape(Data(escapedPayload)) {
                frames.append(unescaped)
            }
        }

        return frames
    }
}
