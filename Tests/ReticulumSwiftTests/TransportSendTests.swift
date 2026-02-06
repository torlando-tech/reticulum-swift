//
//  TransportSendTests.swift
//  ReticulumSwift
//
//  Tests for ReticuLumTransport.send(packet:) verifying that ANNOUNCE packets
//  are never converted to HEADER_2, matching Python RNS Transport.py behavior.
//
//  Python reference: RNS/Transport.py outbound() (line 939)
//  Line 972: `if packet.packet_type != RNS.Packet.ANNOUNCE and ... and
//             packet.destination_hash in Transport.path_table:`
//  This guard explicitly excludes ANNOUNCE packets from HEADER_2 conversion.
//  Announces always fall through to the broadcast branch (line 1025) and are
//  transmitted as HEADER_1 on all outgoing interfaces.
//

import XCTest
@testable import ReticulumSwift

// MARK: - Mock Interface

/// A mock NetworkInterface that records sent bytes for verification.
/// Starts in .connected state so sendToAllInterfaces won't skip it.
actor MockInterface: NetworkInterface {
    let id: String
    let config: InterfaceConfig
    nonisolated var state: InterfaceState { .connected }

    /// All raw packets sent through this interface, in order.
    private(set) var sentPackets: [Data] = []

    init(id: String = "mock-interface") {
        self.id = id
        self.config = InterfaceConfig(
            id: id,
            name: "Mock Interface",
            type: .tcp,
            enabled: true,
            mode: .full,
            host: "127.0.0.1",
            port: 0
        )
    }

    func connect() async throws {
        // Already connected
    }

    func disconnect() async {
        // No-op for tests
    }

    func send(_ data: Data) async throws {
        sentPackets.append(data)
    }

    func setDelegate(_ delegate: InterfaceDelegate) async {
        // No-op for tests
    }

    /// Retrieve and clear sent packets.
    func drainSentPackets() -> [Data] {
        let packets = sentPackets
        sentPackets = []
        return packets
    }
}

// MARK: - Tests

final class TransportSendTests: XCTestCase {

    /// Build test fixtures used across multiple tests.
    ///
    /// Sets up a ReticuLumTransport with:
    /// - A mock interface (connected)
    /// - A path table entry for `destHash` with hopCount=3 and a nextHop,
    ///   simulating what happens when our own announce is echoed back through
    ///   a relay (the scenario that triggered the bug).
    private func makeTransportWithPath() async throws -> (ReticuLumTransport, MockInterface, Data, Data) {
        let destHash = Data(repeating: 0x07, count: 16)      // Target destination
        let nextHop  = Data(repeating: 0xD7, count: 16)      // Transport node address

        let pathTable = PathTable()
        let entry = PathEntry(
            destinationHash: destHash,
            publicKeys: Data(repeating: 0xAA, count: 64),
            interfaceId: "mock-interface",
            hopCount: 3,
            randomBlob: Data(repeating: 0xBB, count: 10),
            nextHop: nextHop
        )
        await pathTable.record(entry: entry)

        let transport = ReticuLumTransport(pathTable: pathTable)
        let mockInterface = MockInterface()
        try await transport.addInterface(mockInterface)

        return (transport, mockInterface, destHash, nextHop)
    }

    // MARK: - Announce must stay HEADER_1

    /// Verify that ANNOUNCE packets are always sent as HEADER_1/BROADCAST,
    /// even when the path table has an entry for the destination.
    ///
    /// Python reference: RNS/Transport.py line 972
    ///   `if packet.packet_type != RNS.Packet.ANNOUNCE ...`
    /// This guard ensures announces bypass the HEADER_2 conversion block
    /// (lines 980-1018) and are broadcast as-is on all interfaces (line 1172).
    ///
    /// Bug context: Without this guard, our own announce gets converted to
    /// HEADER_2/TRANSPORT (flags=0x51, 206 bytes) when a path entry exists
    /// for our destination hash (from the relay echoing back our announce).
    /// The relay then mishandles it as a forwarded re-broadcast instead of
    /// an original announce, preventing propagation to other clients.
    func testAnnounceSentAsHeader1EvenWithPathEntry() async throws {
        let (transport, mockInterface, destHash, _) = try await makeTransportWithPath()

        // Build an ANNOUNCE packet as HEADER_1/BROADCAST — exactly how
        // Announce.buildPacket() creates it.
        let announceHeader = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .announce,
            hopCount: 0
        )
        let announcePayload = Data(repeating: 0xCC, count: 171)  // Simulate announce body
        let announcePacket = Packet(
            header: announceHeader,
            destination: destHash,
            context: 0x00,
            data: announcePayload
        )

        // Send through transport — this is where the bug was
        try await transport.send(packet: announcePacket)

        // Verify the bytes that arrived at the interface
        let sent = await mockInterface.drainSentPackets()
        XCTAssertEqual(sent.count, 1, "Exactly one packet should be sent")

        let raw = sent[0]

        // Parse the flags byte
        let flags = raw[0]
        let headerType    = (flags >> 6) & 0x01  // bit 6: 0=HEADER_1, 1=HEADER_2
        let transportType = (flags >> 4) & 0x01  // bit 4: 0=BROADCAST, 1=TRANSPORT
        let packetType    = flags & 0x03          // bits 0-1: 1=ANNOUNCE

        XCTAssertEqual(packetType, 1, "Packet type must be ANNOUNCE (1)")
        XCTAssertEqual(headerType, 0,
            "ANNOUNCE must be HEADER_1 (0), not HEADER_2 (1). " +
            "Python Transport.py line 972 excludes announces from HEADER_2 conversion.")
        XCTAssertEqual(transportType, 0,
            "ANNOUNCE must be BROADCAST (0), not TRANSPORT (1)")

        // HEADER_1 announce wire format:
        // [flags:1][hops:1][dest:16][context:1][payload:171] = 190 bytes
        let expectedSize = 2 + 16 + 1 + announcePayload.count  // 190
        XCTAssertEqual(raw.count, expectedSize,
            "HEADER_1 announce should be \(expectedSize) bytes, got \(raw.count). " +
            "HEADER_2 would be \(expectedSize + 16) bytes (extra 16B transport address).")

        // Verify no transport address is present (HEADER_1 has no transport field)
        // Destination should start at offset 2
        let destFromWire = Data(raw[2..<18])
        XCTAssertEqual(destFromWire, destHash,
            "Destination hash at offset 2 should match (HEADER_1 layout)")
    }

    // MARK: - DATA packet should still get HEADER_2

    /// Verify that DATA packets ARE converted to HEADER_2 when a multi-hop
    /// path exists — confirming the fix only exempts announces, not all packets.
    ///
    /// Python reference: RNS/Transport.py lines 980-991
    ///   When `hops > 1` and `header_type == HEADER_1`, the packet is inserted
    ///   into transport by prepending the next hop address and setting HEADER_2 flags.
    func testDataPacketConvertedToHeader2WithPathEntry() async throws {
        let (transport, mockInterface, destHash, nextHop) = try await makeTransportWithPath()

        // Build a DATA packet as HEADER_1/BROADCAST
        let dataHeader = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .data,
            hopCount: 0
        )
        let payload = Data(repeating: 0xDD, count: 50)
        let dataPacket = Packet(
            header: dataHeader,
            destination: destHash,
            context: 0x00,
            data: payload
        )

        try await transport.send(packet: dataPacket)

        let sent = await mockInterface.drainSentPackets()
        XCTAssertEqual(sent.count, 1, "Exactly one packet should be sent")

        let raw = sent[0]

        let flags = raw[0]
        let headerType    = (flags >> 6) & 0x01
        let transportType = (flags >> 4) & 0x01
        let packetType    = flags & 0x03

        XCTAssertEqual(packetType, 0, "Packet type must be DATA (0)")
        XCTAssertEqual(headerType, 1,
            "DATA with multi-hop path should be HEADER_2 (1). " +
            "Python Transport.py lines 980-991 convert HEADER_1 DATA to HEADER_2.")
        XCTAssertEqual(transportType, 1,
            "DATA with multi-hop path should be TRANSPORT (1)")

        // HEADER_2 wire format:
        // [flags:1][hops:1][transport:16][dest:16][context:1][payload] = 2+16+16+1+50 = 85
        let expectedSize = 2 + 16 + 16 + 1 + payload.count  // 85
        XCTAssertEqual(raw.count, expectedSize,
            "HEADER_2 DATA should be \(expectedSize) bytes, got \(raw.count)")

        // Verify transport address (next hop) is at offset 2
        let transportFromWire = Data(raw[2..<18])
        XCTAssertEqual(transportFromWire, nextHop,
            "Transport address at offset 2 should be the next hop from path table")

        // Verify destination is at offset 18 (after transport address)
        let destFromWire = Data(raw[18..<34])
        XCTAssertEqual(destFromWire, destHash,
            "Destination hash at offset 18 should match (HEADER_2 layout)")
    }

    // MARK: - Announce without path entry

    /// Verify announces work correctly when NO path entry exists
    /// (the normal first-announce case).
    func testAnnounceSentAsHeader1WithoutPathEntry() async throws {
        let pathTable = PathTable()
        let transport = ReticuLumTransport(pathTable: pathTable)
        let mockInterface = MockInterface()
        try await transport.addInterface(mockInterface)

        let destHash = Data(repeating: 0x42, count: 16)
        let announceHeader = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .announce,
            hopCount: 0
        )
        let announcePacket = Packet(
            header: announceHeader,
            destination: destHash,
            context: 0x00,
            data: Data(repeating: 0xEE, count: 100)
        )

        try await transport.send(packet: announcePacket)

        let sent = await mockInterface.drainSentPackets()
        XCTAssertEqual(sent.count, 1)

        let flags = sent[0][0]
        XCTAssertEqual(flags & 0x03, 1, "Must be ANNOUNCE")
        XCTAssertEqual((flags >> 6) & 1, 0, "Must be HEADER_1")
        XCTAssertEqual((flags >> 4) & 1, 0, "Must be BROADCAST")
    }

    // MARK: - Flags byte encoding matches Python

    /// Verify our flags byte encoding matches Python's Packet.get_packed_flags().
    ///
    /// Python reference: RNS/Packet.py get_packed_flags()
    ///   `packed_flags = (self.header_type << 6) | (self.transport_type << 4) |
    ///                   (self.destination_type << 2) | self.packet_type`
    ///   With context flag: `packed_flags |= (1 << 5)`
    func testFlagsByteEncodingMatchesPython() {
        // HEADER_1 + BROADCAST + SINGLE + ANNOUNCE = 0x01
        let h1 = PacketHeader(
            headerType: .header1, hasContext: false,
            transportType: .broadcast, destinationType: .single,
            packetType: .announce, hopCount: 0
        )
        XCTAssertEqual(h1.encode()[0], 0x01,
            "HEADER_1/BROADCAST/SINGLE/ANNOUNCE should encode to 0x01")

        // HEADER_2 + TRANSPORT + SINGLE + ANNOUNCE = 0x51
        let h2 = PacketHeader(
            headerType: .header2, hasContext: false,
            transportType: .transport, destinationType: .single,
            packetType: .announce, hopCount: 0
        )
        XCTAssertEqual(h2.encode()[0], 0x51,
            "HEADER_2/TRANSPORT/SINGLE/ANNOUNCE should encode to 0x51")

        // HEADER_1 + BROADCAST + SINGLE + ANNOUNCE + CONTEXT = 0x21
        let h1ctx = PacketHeader(
            headerType: .header1, hasContext: true,
            transportType: .broadcast, destinationType: .single,
            packetType: .announce, hopCount: 0
        )
        XCTAssertEqual(h1ctx.encode()[0], 0x21,
            "HEADER_1/BROADCAST/SINGLE/ANNOUNCE with context should encode to 0x21")

        // HEADER_2 + TRANSPORT + SINGLE + ANNOUNCE + CONTEXT = 0x71
        let h2ctx = PacketHeader(
            headerType: .header2, hasContext: true,
            transportType: .transport, destinationType: .single,
            packetType: .announce, hopCount: 0
        )
        XCTAssertEqual(h2ctx.encode()[0], 0x71,
            "HEADER_2/TRANSPORT/SINGLE/ANNOUNCE with context should encode to 0x71")
    }
}
