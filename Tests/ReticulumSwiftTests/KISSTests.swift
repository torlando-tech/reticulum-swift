// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  KISSTests.swift
//  ReticulumSwiftTests
//
//  Unit tests for KISS protocol framing.
//

import XCTest
@testable import ReticulumSwift

final class KISSTests: XCTestCase {

    // MARK: - Escape Tests

    func testEscapeFEND() throws {
        // Input containing FEND (0xC0) should be escaped to [FESC, TFEND] (0xDB, 0xDC)
        let input = Data([0x01, 0xC0, 0x02])
        let result = KISS.escape(input)
        let expected = Data([0x01, 0xDB, 0xDC, 0x02])
        XCTAssertEqual(result, expected, "FEND (0xC0) must be escaped to [0xDB, 0xDC]")
    }

    func testEscapeFESC() throws {
        // Input containing FESC (0xDB) should be escaped to [FESC, TFESC] (0xDB, 0xDD)
        let input = Data([0x01, 0xDB, 0x02])
        let result = KISS.escape(input)
        let expected = Data([0x01, 0xDB, 0xDD, 0x02])
        XCTAssertEqual(result, expected, "FESC (0xDB) must be escaped to [0xDB, 0xDD]")
    }

    func testEscapeOrder() throws {
        // CRITICAL: Verify FESC is escaped BEFORE FEND
        // Input: [0xDB, 0xC0]
        // Expected: [0xDB, 0xDD, 0xDB, 0xDC]
        // If FEND were escaped first, you'd get wrong result
        let input = Data([0xDB, 0xC0])
        let result = KISS.escape(input)
        let expected = Data([0xDB, 0xDD, 0xDB, 0xDC])
        XCTAssertEqual(result, expected, "FESC must be escaped before FEND to avoid double-escaping")
    }

    func testEscapeNoSpecialBytes() throws {
        // Input with no special bytes should return unchanged
        let input = Data([0x01, 0x02, 0x03, 0x04])
        let result = KISS.escape(input)
        XCTAssertEqual(result, input, "Data without special bytes should be unchanged")
    }

    func testEscapeEmpty() throws {
        // Empty input should return empty output
        let input = Data()
        let result = KISS.escape(input)
        XCTAssertEqual(result, Data(), "Empty input should return empty output")
    }

    // MARK: - Frame Tests

    func testFrame() throws {
        // Frame format: [FEND] [CMD] [escaped_data] [FEND]
        // For input [0x01, 0x02], expect [0xC0, 0x00, 0x01, 0x02, 0xC0]
        let input = Data([0x01, 0x02])
        let result = KISS.frame(input)
        let expected = Data([0xC0, 0x00, 0x01, 0x02, 0xC0])
        XCTAssertEqual(result, expected, "Frame must be [FEND, CMD_DATA, data, FEND]")

        // Verify frame starts with 0xC0 NOT 0x7E (Pitfall #12)
        XCTAssertEqual(result.first, 0xC0, "KISS frames must start with 0xC0 (not 0x7E)")
    }

    func testFrameWithSpecialBytes() throws {
        // Frame containing FEND (0xC0) in payload should escape it
        let input = Data([0x01, 0xC0, 0x02])
        let result = KISS.frame(input)
        // Expected: [0xC0, 0x00, 0x01, 0xDB, 0xDC, 0x02, 0xC0]
        let expected = Data([0xC0, 0x00, 0x01, 0xDB, 0xDC, 0x02, 0xC0])
        XCTAssertEqual(result, expected, "Special bytes in payload must be escaped")
    }

    // MARK: - Unescape Tests

    func testUnescape() throws {
        // [0xDB, 0xDC] should unescape to [0xC0]
        let input1 = Data([0xDB, 0xDC])
        let result1 = try KISS.unescape(input1)
        XCTAssertEqual(result1, Data([0xC0]), "FESC + TFEND must unescape to FEND")

        // [0xDB, 0xDD] should unescape to [0xDB]
        let input2 = Data([0xDB, 0xDD])
        let result2 = try KISS.unescape(input2)
        XCTAssertEqual(result2, Data([0xDB]), "FESC + TFESC must unescape to FESC")
    }

    func testUnescapeNoEscapes() throws {
        // Input without escape sequences should return unchanged
        let input = Data([0x01, 0x02, 0x03])
        let result = try KISS.unescape(input)
        XCTAssertEqual(result, input, "Data without escapes should be unchanged")
    }

    func testUnescapeTruncated() throws {
        // Trailing FESC (0xDB) without following byte should throw
        let input = Data([0x01, 0x02, 0xDB])
        XCTAssertThrowsError(try KISS.unescape(input)) { error in
            XCTAssertTrue(error is KISSError, "Should throw KISSError")
            if let kissError = error as? KISSError {
                XCTAssertEqual(kissError, KISSError.truncatedEscape, "Should throw truncatedEscape")
            }
        }
    }

    // MARK: - Extract Frames Tests

    func testExtractSingleFrame() throws {
        // Buffer: [0xC0, 0x00, 0x01, 0x02, 0xC0]
        // Should extract one frame with payload [0x01, 0x02] (command byte stripped)
        var buffer = Data([0xC0, 0x00, 0x01, 0x02, 0xC0])
        let frames = KISS.extractFrames(from: &buffer)

        XCTAssertEqual(frames.count, 1, "Should extract one frame")
        XCTAssertEqual(frames[0], Data([0x01, 0x02]), "Payload should be [0x01, 0x02]")
        XCTAssertTrue(buffer.isEmpty, "Buffer should be empty after extraction")
    }

    func testExtractMultipleFrames() throws {
        // Buffer with two back-to-back frames
        var buffer = Data([
            0xC0, 0x00, 0x01, 0x02, 0xC0,  // Frame 1
            0xC0, 0x00, 0x03, 0x04, 0xC0   // Frame 2
        ])
        let frames = KISS.extractFrames(from: &buffer)

        XCTAssertEqual(frames.count, 2, "Should extract two frames")
        XCTAssertEqual(frames[0], Data([0x01, 0x02]), "First frame payload")
        XCTAssertEqual(frames[1], Data([0x03, 0x04]), "Second frame payload")
        XCTAssertTrue(buffer.isEmpty, "Buffer should be empty after extraction")
    }

    func testExtractPartialFrame() throws {
        // Buffer with only start FEND, no end FEND
        var buffer = Data([0xC0, 0x00, 0x01, 0x02])
        let frames = KISS.extractFrames(from: &buffer)

        XCTAssertEqual(frames.count, 0, "Should extract no frames from partial data")
        XCTAssertEqual(buffer, Data([0xC0, 0x00, 0x01, 0x02]), "Buffer should be preserved")
    }

    func testExtractEmptyFrame() throws {
        // Consecutive FENDs [0xC0, 0xC0] should produce no frames
        var buffer = Data([0xC0, 0xC0])
        let frames = KISS.extractFrames(from: &buffer)

        XCTAssertEqual(frames.count, 0, "Empty frames should be skipped")
        XCTAssertTrue(buffer.isEmpty, "Buffer should be empty after processing")
    }

    func testExtractFrameWithEscapedData() throws {
        // Frame with escaped FEND in payload
        // [0xC0, 0x00, 0x01, 0xDB, 0xDC, 0x02, 0xC0]
        // Should extract and unescape to [0x01, 0xC0, 0x02]
        var buffer = Data([0xC0, 0x00, 0x01, 0xDB, 0xDC, 0x02, 0xC0])
        let frames = KISS.extractFrames(from: &buffer)

        XCTAssertEqual(frames.count, 1, "Should extract one frame")
        XCTAssertEqual(frames[0], Data([0x01, 0xC0, 0x02]), "Should unescape to [0x01, 0xC0, 0x02]")
    }

    // MARK: - Round-Trip Tests

    func testRoundTrip() throws {
        // Verify escape/unescape round-trip for various payloads
        let testPayloads: [Data] = [
            Data([0xC0, 0xDB, 0x00, 0xFF]),  // All special bytes
            Data([0x01, 0x02, 0x03]),        // No special bytes
            Data([0xC0, 0xC0, 0xC0]),        // Multiple FENDs
            Data([0xDB, 0xDB, 0xDB]),        // Multiple FESCs
            Data([0xDB, 0xC0]),              // FESC then FEND (order test)
            Data(),                          // Empty
        ]

        for payload in testPayloads {
            let escaped = KISS.escape(payload)
            let unescaped = try KISS.unescape(escaped)
            XCTAssertEqual(unescaped, payload, "Round-trip failed for payload: \(payload.map { String(format: "%02X", $0) }.joined())")
        }
    }
}
