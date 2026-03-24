// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  HDLC.swift
//  ReticulumSwift
//
//  HDLC-like framing for TCP transport.
//  Based on Python RNS TCPInterface.py implementation.
//

import Foundation

/// HDLC-like framing for Reticulum TCP transport.
///
/// Uses flag bytes (0x7E) to delimit frames and escape sequences for
/// special bytes in the payload. Unlike standard HDLC, does NOT use CRC
/// for TCP transport (TCP provides reliability).
public enum HDLC {

    /// Frame delimiter flag byte
    public static let FLAG = HDLCConstants.FLAG

    /// Escape byte
    public static let ESC = HDLCConstants.ESC

    /// XOR mask for escaped bytes
    public static let ESC_MASK = HDLCConstants.ESC_MASK

    // MARK: - Encoding

    /// Escape special bytes in data for HDLC framing.
    ///
    /// CRITICAL: Escape order matters!
    /// 1. Escape ESC bytes (0x7D) FIRST -> becomes [0x7D, 0x5D]
    /// 2. Then escape FLAG bytes (0x7E) -> becomes [0x7D, 0x5E]
    ///
    /// Reversing this order creates incorrect frames because escaping
    /// FLAG first would create new ESC bytes that wouldn't be handled.
    ///
    /// - Parameter data: Raw data to escape
    /// - Returns: Data with special bytes escaped
    public static func escape(_ data: Data) -> Data {
        var result = Data()
        result.reserveCapacity(data.count * 2) // Worst case: all special bytes

        for byte in data {
            if byte == ESC {
                // ESC (0x7D) -> ESC + (ESC XOR MASK) = 0x7D 0x5D
                result.append(ESC)
                result.append(ESC ^ ESC_MASK)
            } else if byte == FLAG {
                // FLAG (0x7E) -> ESC + (FLAG XOR MASK) = 0x7D 0x5E
                result.append(ESC)
                result.append(FLAG ^ ESC_MASK)
            } else {
                result.append(byte)
            }
        }

        return result
    }

    /// Wrap data in HDLC frame with flag delimiters.
    ///
    /// Frame format: [FLAG] [escaped_data] [FLAG]
    ///
    /// - Parameter data: Raw data to frame
    /// - Returns: Complete HDLC frame
    public static func frame(_ data: Data) -> Data {
        var result = Data()
        result.reserveCapacity(data.count * 2 + 2)

        result.append(FLAG)
        result.append(escape(data))
        result.append(FLAG)

        return result
    }

    // MARK: - Decoding

    /// Unescape HDLC frame content (data between flag delimiters).
    ///
    /// Reverses the escape transformation:
    /// - [0x7D, 0x5D] -> 0x7D (ESC)
    /// - [0x7D, 0x5E] -> 0x7E (FLAG)
    ///
    /// - Parameter data: Escaped frame content (without flag bytes)
    /// - Returns: Unescaped original data
    /// - Throws: `HDLCError.truncatedEscape` if data ends mid-escape
    public static func unescape(_ data: Data) throws -> Data {
        var result = Data()
        result.reserveCapacity(data.count)

        var escapeNext = false

        for byte in data {
            if escapeNext {
                // XOR with mask to recover original byte
                result.append(byte ^ ESC_MASK)
                escapeNext = false
            } else if byte == ESC {
                // Next byte is escaped
                escapeNext = true
            } else {
                result.append(byte)
            }
        }

        // If we ended expecting an escaped byte, frame is truncated
        if escapeNext {
            throw HDLCError.truncatedEscape
        }

        return result
    }

    /// Extract frames from a buffer of received data.
    ///
    /// Searches for FLAG-delimited frames and extracts them.
    /// Modifies the buffer in-place, removing extracted frames.
    ///
    /// - Parameter buffer: Mutable buffer of received data
    /// - Returns: Array of unescaped frame contents (may be empty)
    public static func extractFrames(from buffer: inout Data) -> [Data] {
        var frames: [Data] = []

        while true {
            // Find start flag
            guard let startIdx = buffer.firstIndex(of: FLAG) else {
                break
            }

            // Find end flag (must be after start)
            let searchStart = buffer.index(after: startIdx)
            guard searchStart < buffer.endIndex,
                  let endIdx = buffer[searchStart...].firstIndex(of: FLAG) else {
                break
            }

            // Extract frame content (between flags)
            let frameContent = buffer[(buffer.index(after: startIdx))..<endIdx]

            // Remove processed data including end flag
            buffer.removeSubrange(buffer.startIndex...endIdx)

            // Skip empty frames (consecutive flags)
            if frameContent.isEmpty {
                continue
            }

            // Unescape and add to results
            if let unescaped = try? unescape(Data(frameContent)) {
                frames.append(unescaped)
            }
            // Note: Silently skip malformed frames (truncated escape)
        }

        return frames
    }
}
