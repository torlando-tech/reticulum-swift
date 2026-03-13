//
//  PacketInteropTest.swift
//  ReticulumSwiftTests
//
//  Packet interoperability tests with Python RNS.
//

import XCTest
@testable import ReticulumSwift

final class PacketInteropTest: InteropTestBase {

    // MARK: - Flags Encoding

    func testFlagsByteEncodingMatchesPython() throws {
        let testCases: [(HeaderType, Bool, TransportType, DestinationType, PacketType)] = [
            (.header1, false, .broadcast, .single, .data),
            (.header1, false, .broadcast, .single, .announce),
            (.header1, true,  .broadcast, .single, .data),
            (.header2, false, .transport, .single, .data),
            (.header1, false, .broadcast, .group, .data),
            (.header1, false, .broadcast, .plain, .data),
            (.header1, false, .broadcast, .link, .data),
            (.header1, false, .broadcast, .single, .linkRequest),
            (.header1, false, .broadcast, .single, .proof),
        ]

        for (ht, ctx, tt, dt, pt) in testCases {
            let header = PacketHeader(
                headerType: ht, hasContext: ctx, transportType: tt,
                destinationType: dt, packetType: pt, hopCount: 0
            )
            let swiftFlags = Int(header.encode()[0])

            let pyResult = try bridge.execute(
                "packet_flags",
                ("header_type", "\(ht.rawValue)"),
                ("context_flag", ctx ? "1" : "0"),
                ("transport_type", "\(tt.rawValue)"),
                ("destination_type", "\(dt.rawValue)"),
                ("packet_type", "\(pt.rawValue)")
            )
            let pyFlags = pyResult.getInt("flags")

            XCTAssertEqual(swiftFlags, pyFlags,
                "Flags mismatch: Swift=\(String(swiftFlags, radix: 2)), Python=\(String(pyFlags, radix: 2))")
        }
    }

    func testFlagsByteParsingMatchesPython() throws {
        let testFlags: [UInt8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x08, 0x10, 0x20, 0x40, 0x41, 0x50]

        for flagsByte in testFlags {
            // Skip IFAC-flagged packets as Swift throws for those
            if flagsByte & 0x80 != 0 { continue }
            // HEADER_2 (bit 6) needs 16 extra bytes for transport address
            let isHeader2 = (flagsByte & 0x40) != 0
            let minPayload = isHeader2 ? 33 + 4 : 17 + 4
            let raw = Data([flagsByte, 0x00]) + Data(repeating: 0, count: minPayload)

            let packet = try Packet(from: raw)
            let pyResult = try bridge.execute("packet_parse_flags", ("flags", "\(flagsByte)"))

            XCTAssertEqual(Int(packet.header.headerType.rawValue), pyResult.getInt("header_type"),
                "Header type for 0x\(String(format: "%02x", flagsByte))")
            XCTAssertEqual(Int(packet.header.transportType.rawValue), pyResult.getInt("transport_type"),
                "Transport type for 0x\(String(format: "%02x", flagsByte))")
            XCTAssertEqual(Int(packet.header.destinationType.rawValue), pyResult.getInt("destination_type"),
                "Dest type for 0x\(String(format: "%02x", flagsByte))")
            XCTAssertEqual(Int(packet.header.packetType.rawValue), pyResult.getInt("packet_type"),
                "Packet type for 0x\(String(format: "%02x", flagsByte))")
        }
    }

    // MARK: - Pack Operations

    func testHeader1PackMatchesPython() throws {
        let destHash = Data((0..<16).map { UInt8(truncatingIfNeeded: $0 &* 5) })
        let payload = "Hello, Reticulum!".data(using: .utf8)!

        let packet = Packet(
            header: PacketHeader(
                headerType: .header1, hasContext: false,
                transportType: .broadcast, destinationType: .single,
                packetType: .data, hopCount: 0
            ),
            destination: destHash,
            context: 0x00,
            data: payload
        )

        let swiftRaw = packet.encode()

        let pyResult = try bridge.execute(
            "packet_pack",
            ("header_type", "0"), ("context_flag", "0"), ("transport_type", "0"),
            ("destination_type", "0"), ("packet_type", "0"), ("hops", "0"),
            ("destination_hash", destHash), ("context", "0"), ("data", payload)
        )

        assertBytesEqual(pyResult.getBytes("raw"), swiftRaw, "HEADER_1 packet pack")
    }

    func testHeader2PackMatchesPython() throws {
        let destHash = Data((0..<16).map { UInt8(truncatingIfNeeded: $0 &* 3) })
        let transportId = Data((128..<144).map { UInt8($0) })
        let payload = "Transport packet data".data(using: .utf8)!

        let packet = Packet(
            header: PacketHeader(
                headerType: .header2, hasContext: false,
                transportType: .transport, destinationType: .single,
                packetType: .data, hopCount: 0
            ),
            destination: destHash,
            transportAddress: transportId,
            context: 0x00,
            data: payload
        )

        let swiftRaw = packet.encode()

        let pyResult = try bridge.execute(
            "packet_pack",
            ("header_type", "1"), ("context_flag", "0"), ("transport_type", "1"),
            ("destination_type", "0"), ("packet_type", "0"), ("hops", "0"),
            ("destination_hash", destHash), ("transport_id", transportId),
            ("context", "0"), ("data", payload)
        )

        assertBytesEqual(pyResult.getBytes("raw"), swiftRaw, "HEADER_2 packet pack")
    }

    // MARK: - Unpack Operations

    func testHeader1UnpackMatchesPython() throws {
        let destHash = Data((0..<16).map { UInt8(truncatingIfNeeded: $0 &* 2) })
        let payload = "Test data".data(using: .utf8)!
        let rawPacket = Data([0x00, 0x05]) + destHash + Data([0x00]) + payload

        let packet = try Packet(from: rawPacket)
        let pyResult = try bridge.execute("packet_unpack", ("raw", rawPacket))

        XCTAssertEqual(Int(packet.header.headerType.rawValue), pyResult.getInt("header_type"))
        XCTAssertEqual(Int(packet.header.packetType.rawValue), pyResult.getInt("packet_type"))
        XCTAssertEqual(Int(packet.header.hopCount), pyResult.getInt("hops"))
        assertBytesEqual(pyResult.getBytes("destination_hash"), packet.destination, "Destination hash")
        assertBytesEqual(pyResult.getBytes("data"), packet.data, "Packet data")
    }

    func testRoundTripPackUnpackPreservesData() throws {
        let destHash = Data((0..<16).map { UInt8(truncatingIfNeeded: $0 &* 11) })
        let payload = "Round-trip test message".data(using: .utf8)!

        let original = Packet(
            header: PacketHeader(
                headerType: .header1, hasContext: false,
                transportType: .broadcast, destinationType: .single,
                packetType: .data, hopCount: 0
            ),
            destination: destHash,
            context: 0x06, // REQUEST context
            data: payload
        )

        let raw = original.encode()
        let unpacked = try Packet(from: raw)

        XCTAssertEqual(original.header.packetType, unpacked.header.packetType)
        XCTAssertEqual(original.header.headerType, unpacked.header.headerType)
        XCTAssertEqual(original.context, unpacked.context)
        assertBytesEqual(original.destination, unpacked.destination, "Destination hash")
        assertBytesEqual(original.data, unpacked.data, "Packet data")
    }

    // MARK: - Packet Hash

    func testHeader1PacketHashMatchesPython() throws {
        let destHash = Data((0..<16).map { UInt8(truncatingIfNeeded: $0 &* 13) })
        let payload = "Hash test data".data(using: .utf8)!

        let packet = Packet(
            header: PacketHeader(
                headerType: .header1, hasContext: false,
                transportType: .broadcast, destinationType: .single,
                packetType: .data, hopCount: 0
            ),
            destination: destHash,
            context: 0x00,
            data: payload
        )

        let raw = packet.encode()
        let swiftHash = packet.getFullHash()

        let pyResult = try bridge.execute("packet_hash", ("raw", raw))

        assertBytesEqual(pyResult.getBytes("hash"), swiftHash, "HEADER_1 packet hash")
    }

    func testHeader2PacketHashExcludesTransportId() throws {
        let destHash = Data((0..<16).map { UInt8(truncatingIfNeeded: $0 &* 17) })
        let transportId = Data((64..<80).map { UInt8($0) })
        let payload = "Transport hash test".data(using: .utf8)!

        let packet = Packet(
            header: PacketHeader(
                headerType: .header2, hasContext: false,
                transportType: .transport, destinationType: .single,
                packetType: .data, hopCount: 0
            ),
            destination: destHash,
            transportAddress: transportId,
            context: 0x00,
            data: payload
        )

        let raw = packet.encode()
        let swiftHash = packet.getFullHash()
        let swiftHashable = packet.getHashablePart()

        let pyResult = try bridge.execute("packet_hash", ("raw", raw))

        assertBytesEqual(pyResult.getBytes("hash"), swiftHash, "HEADER_2 packet hash")
        assertBytesEqual(pyResult.getBytes("hashable_part"), swiftHashable, "Hashable part")
    }

    func testTruncatedPacketHashMatchesPython() throws {
        let destHash = Data((0..<16).map { UInt8(truncatingIfNeeded: $0 &* 19) })
        let payload = "Truncated hash test".data(using: .utf8)!

        let packet = Packet(
            header: PacketHeader(
                headerType: .header1, hasContext: false,
                transportType: .broadcast, destinationType: .single,
                packetType: .announce, hopCount: 0
            ),
            destination: destHash,
            context: 0x00,
            data: payload
        )

        let raw = packet.encode()
        let swiftTruncated = packet.getTruncatedHash()

        let pyResult = try bridge.execute("packet_hash", ("raw", raw))

        assertBytesEqual(pyResult.getBytes("truncated_hash"), swiftTruncated, "Truncated packet hash")
        XCTAssertEqual(swiftTruncated.count, TRUNCATED_HASH_LENGTH)
    }
}
