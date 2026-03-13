//
//  FramingInteropTest.swift
//  ReticulumSwiftTests
//
//  Framing interoperability tests with Python RNS (HDLC and KISS).
//

import XCTest
@testable import ReticulumSwift

final class FramingInteropTest: InteropTestBase {

    // MARK: - HDLC Framing

    func testHdlcEscapeMatchesPython() throws {
        let testCases: [Data] = [
            Data(0..<10),
            Data([0x01, 0x7E, 0x02]),
            Data([0x01, 0x7D, 0x02]),
            Data([0x7E, 0x7D, 0x7E, 0x7D]),
            Data([0x7E, 0x7E, 0x7D, 0x7D]),
            Data(),
            Data([0x7E]),
            Data([0x7D]),
        ]

        for data in testCases {
            let swiftEscaped = HDLC.escape(data)
            let pyResult = try bridge.execute("hdlc_escape", ("data", data))

            assertBytesEqual(pyResult.getBytes("escaped"), swiftEscaped,
                "HDLC escape for \(data.hexString)")
        }
    }

    func testHdlcFrameMatchesPython() throws {
        let testCases: [Data] = [
            "Hello, World!".data(using: .utf8)!,
            Data(0..<100),
            Data([0x7E, 0x7D, 0x00, 0xFF]),
            Data(),
        ]

        for data in testCases {
            let swiftFramed = HDLC.frame(data)
            let pyResult = try bridge.execute("hdlc_frame", ("data", data))

            assertBytesEqual(pyResult.getBytes("framed"), swiftFramed,
                "HDLC frame for \(data.count) bytes")

            XCTAssertEqual(swiftFramed.first, HDLC.FLAG)
            XCTAssertEqual(swiftFramed.last, HDLC.FLAG)
        }
    }

    func testHdlcEscapeUnescapeRoundTrip() throws {
        let testCases: [Data] = [
            Data((0..<256).map { UInt8($0) }),
            Data([0x7E, 0x7D, 0x7E, 0x7D]),
            Data((0..<1000).map { UInt8($0 % 256) }),
        ]

        for original in testCases {
            let escaped = HDLC.escape(original)
            let unescaped = try HDLC.unescape(escaped)

            assertBytesEqual(original, unescaped, "Round-trip for \(original.count) bytes")
        }
    }

    // MARK: - KISS Framing

    func testKissEscapeMatchesPython() throws {
        let testCases: [Data] = [
            Data(0..<10),
            Data([0x01, 0xC0, 0x02]),
            Data([0x01, 0xDB, 0x02]),
            Data([0xC0, 0xDB, 0xC0, 0xDB]),
            Data(),
            Data([0xC0]),
            Data([0xDB]),
        ]

        for data in testCases {
            let swiftEscaped = KISS.escape(data)
            let pyResult = try bridge.execute("kiss_escape", ("data", data))

            assertBytesEqual(pyResult.getBytes("escaped"), swiftEscaped,
                "KISS escape for \(data.hexString)")
        }
    }

    func testKissFrameMatchesPython() throws {
        let testCases: [Data] = [
            "Hello, World!".data(using: .utf8)!,
            Data(0..<100),
            Data([0xC0, 0xDB, 0x00, 0xFF]),
            Data(),
        ]

        for data in testCases {
            let swiftFramed = KISS.frame(data)
            let pyResult = try bridge.execute("kiss_frame", ("data", data))

            assertBytesEqual(pyResult.getBytes("framed"), swiftFramed,
                "KISS frame for \(data.count) bytes")

            XCTAssertEqual(swiftFramed.first, KISSConstants.FEND)
            XCTAssertEqual(swiftFramed[1], KISSConstants.CMD_DATA)
            XCTAssertEqual(swiftFramed.last, KISSConstants.FEND)
        }
    }

    func testKissEscapeUnescapeRoundTrip() throws {
        let testCases: [Data] = [
            Data((0..<256).map { UInt8($0) }),
            Data([0xC0, 0xDB, 0xC0, 0xDB]),
            Data((0..<1000).map { UInt8($0 % 256) }),
        ]

        for original in testCases {
            let escaped = KISS.escape(original)
            let unescaped = try KISS.unescape(escaped)

            assertBytesEqual(original, unescaped, "Round-trip for \(original.count) bytes")
        }
    }
}
