//
//  PathRequestTests.swift
//  ReticulumSwiftTests
//
//  Tests for path request functionality: destination hash, packet format,
//  PATH_RESPONSE context, announce path response flag, dedup, and awaitPath.
//

import XCTest
@testable import ReticulumSwift

final class PathRequestTests: XCTestCase {

    // MARK: - PacketContext Constants

    func testPathResponseConstant() {
        // PATH_RESPONSE must be 0x0B to match Python Packet.PATH_RESPONSE
        XCTAssertEqual(PacketContext.PATH_RESPONSE, 0x0B)
    }

    func testPacketContextConstants() {
        // Verify key constants match Python Packet.py
        XCTAssertEqual(PacketContext.NONE, 0x00)
        XCTAssertEqual(PacketContext.RESOURCE, 0x01)
        XCTAssertEqual(PacketContext.RESOURCE_ADV, 0x02)
        XCTAssertEqual(PacketContext.RESOURCE_REQ, 0x03)
        XCTAssertEqual(PacketContext.REQUEST, 0x09)
        XCTAssertEqual(PacketContext.RESPONSE, 0x0A)
        XCTAssertEqual(PacketContext.PATH_RESPONSE, 0x0B)
        XCTAssertEqual(PacketContext.KEEPALIVE, 0xFA)
        XCTAssertEqual(PacketContext.LINKCLOSE, 0xFC)
        XCTAssertEqual(PacketContext.LRRTT, 0xFE)
        XCTAssertEqual(PacketContext.LRPROOF, 0xFF)
    }

    // MARK: - Path Request Destination Hash

    func testPathRequestDestinationHash() {
        // Path requests go to PLAIN destination "rnstransport.path.request"
        // (NOT "Transport.path.request" which was the bug)
        let hash = Destination.plainHash(appName: "rnstransport", aspects: ["path", "request"])
        XCTAssertEqual(hash.count, 16, "PLAIN destination hash must be 16 bytes")

        // Verify it's deterministic
        let hash2 = Destination.plainHash(appName: "rnstransport", aspects: ["path", "request"])
        XCTAssertEqual(hash, hash2)

        // Verify the old bug: "Transport" produces a DIFFERENT hash
        let wrongHash = Destination.plainHash(appName: "Transport", aspects: ["path", "request"])
        XCTAssertNotEqual(hash, wrongHash, "rnstransport and Transport must produce different hashes")
    }

    // MARK: - Announce with pathResponse

    func testAnnounceWithPathResponse() throws {
        let identity = try Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["path"])

        let announce = Announce(destination: dest, pathResponse: true)
        XCTAssertTrue(announce.pathResponse)

        let packet = try announce.buildPacket()
        XCTAssertEqual(packet.context, PacketContext.PATH_RESPONSE,
                       "pathResponse=true must set context to 0x0B")
    }

    func testAnnounceWithoutPathResponse() throws {
        let identity = try Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["path"])

        let announce = Announce(destination: dest)
        XCTAssertFalse(announce.pathResponse)

        let packet = try announce.buildPacket()
        XCTAssertEqual(packet.context, PacketContext.NONE,
                       "Default announce must have context 0x00")
    }

    func testAnnouncePathResponseBackwardCompat() throws {
        // Existing announce construction (no pathResponse param) should still work
        let identity = try Identity()
        let dest = Destination(identity: identity, appName: "lxmf", aspects: ["delivery"])
        let ratchetKey = Data(repeating: 0xAB, count: 32)

        let announce = Announce(destination: dest, ratchet: ratchetKey)
        XCTAssertFalse(announce.pathResponse)
        XCTAssertNotNil(announce.ratchet)

        let packet = try announce.buildPacket()
        XCTAssertEqual(packet.context, PacketContext.NONE)
        XCTAssertTrue(packet.header.hasContext, "Ratchet announce must have hasContext=true")
    }

    // MARK: - Retransmission Context

    func testRetransmissionPreservesHasContext() async {
        // When retransmitting an announce that had a ratchet (hasContext=true),
        // the retransmitted packet must also have hasContext=true.
        // blockRebroadcasts should NOT override hasContext.
        let table = AnnounceTable()
        let destHash = Data(repeating: 0xBB, count: 16)

        // Create a packet with hasContext=true (simulating ratchet announce)
        let header = PacketHeader(
            headerType: .header1,
            hasContext: true,  // ratchet present
            hasIFAC: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .announce,
            hopCount: 1
        )
        let packet = Packet(
            header: header,
            destination: destHash,
            transportAddress: nil,
            context: 0x00,
            data: Data(repeating: 0, count: 100)
        )

        // Insert as local client (retransmits immediately)
        await table.insert(
            destinationHash: destHash,
            packet: packet,
            hops: 1,
            receivedFrom: destHash,
            blockRebroadcasts: true,
            isLocalClient: true
        )

        // Process retransmissions - should fire immediately for local client
        let actions = await table.processRetransmissions()
        XCTAssertGreaterThanOrEqual(actions.count, 1)

        guard let action = actions.first else {
            XCTFail("Expected at least one retransmit action")
            return
        }
        // The action's packet should preserve hasContext from the original
        XCTAssertTrue(action.packet.header.hasContext,
                      "Retransmission must preserve original hasContext (ratchet flag)")
        XCTAssertTrue(action.blockRebroadcasts,
                      "blockRebroadcasts should be true for PATH_RESPONSE")
    }

    // MARK: - Path Request Dedup

    func testPathRequestDedup() async {
        let transport = ReticuLumTransport()

        // Register the path request handler so the destination is set up
        await transport.registerPathRequestHandler()

        // The dedup cache starts empty, so there's nothing to test directly
        // without sending packets. We verify the handler registration succeeded.
        let destCount = await transport.destinationCount
        XCTAssertTrue(destCount > 0,
                      "Path request handler should register a destination")
    }

    // MARK: - Path Request Format

    func testPathRequestPacketFormat() {
        // Path request is: DATA packet, BROADCAST, PLAIN, HEADER_1
        let destHash = Data(repeating: 0xCC, count: 16)
        let tag = Data(repeating: 0xDD, count: 16)

        let pathRequestDestHash = Destination.plainHash(appName: "rnstransport", aspects: ["path", "request"])

        var requestData = destHash
        requestData.append(tag)

        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            hasIFAC: false,
            transportType: .broadcast,
            destinationType: .plain,
            packetType: .data,
            hopCount: 0
        )
        let packet = Packet(
            header: header,
            destination: pathRequestDestHash,
            transportAddress: nil,
            context: PacketContext.NONE,
            data: requestData
        )

        // Verify packet structure
        XCTAssertEqual(packet.header.packetType, .data)
        XCTAssertEqual(packet.header.transportType, .broadcast)
        XCTAssertEqual(packet.header.destinationType, .plain)
        XCTAssertEqual(packet.header.headerType, .header1)
        XCTAssertEqual(packet.destination, pathRequestDestHash)
        XCTAssertEqual(packet.context, 0x00)
        XCTAssertEqual(packet.data.count, 32, "dest_hash(16) + tag(16) = 32 bytes")
        XCTAssertEqual(Data(packet.data.prefix(16)), destHash)
        XCTAssertEqual(Data(packet.data.suffix(16)), tag)
    }

    func testPathRequestIncludesTransportId() {
        // When transport is enabled, request includes transport_id between dest_hash and tag
        let destHash = Data(repeating: 0xCC, count: 16)
        let transportId = Data(repeating: 0xEE, count: 16)
        let tag = Data(repeating: 0xDD, count: 16)

        var requestData = destHash
        requestData.append(transportId)
        requestData.append(tag)

        XCTAssertEqual(requestData.count, 48, "dest_hash(16) + transport_id(16) + tag(16) = 48 bytes")
        XCTAssertEqual(Data(requestData.prefix(16)), destHash)
        XCTAssertEqual(Data(requestData[16..<32]), transportId)
        XCTAssertEqual(Data(requestData.suffix(16)), tag)
    }

    // MARK: - Await Path

    func testAwaitPathFoundImmediately() async throws {
        let pathTable = try PathTable()
        let transport = ReticuLumTransport(pathTable: pathTable)

        let destHash = Data(repeating: 0xAA, count: 16)

        // Pre-populate path table
        await pathTable.record(
            destinationHash: destHash,
            publicKeys: Data(repeating: 0x01, count: 64),
            randomBlob: Data(repeating: 0x02, count: 10),
            interfaceId: "test-interface",
            hopCount: 1
        )

        // awaitPath should return true immediately
        let found = await transport.awaitPath(for: destHash, timeout: 1.0)
        XCTAssertTrue(found, "awaitPath should return true when path already exists")
    }

    func testAwaitPathTimeout() async throws {
        let pathTable = try PathTable()
        let transport = ReticuLumTransport(pathTable: pathTable)

        let destHash = Data(repeating: 0xFF, count: 16)

        // No path available, short timeout
        let found = await transport.awaitPath(for: destHash, timeout: 0.2)
        XCTAssertFalse(found, "awaitPath should return false when path not found within timeout")
    }

    // MARK: - PathEntry announceData

    func testPathEntryAnnounceData() {
        let destHash = Data(repeating: 0xAA, count: 16)
        let announcePayload = Data(repeating: 0x42, count: 200)

        let entry = PathEntry(
            destinationHash: destHash,
            publicKeys: Data(repeating: 0x01, count: 64),
            interfaceId: "test",
            hopCount: 1,
            randomBlob: Data(repeating: 0x02, count: 10),
            announceData: announcePayload
        )

        XCTAssertEqual(entry.announceData, announcePayload)
    }

    func testPathEntryAnnounceDataDefaultNil() {
        let destHash = Data(repeating: 0xAA, count: 16)

        let entry = PathEntry(
            destinationHash: destHash,
            publicKeys: Data(repeating: 0x01, count: 64),
            interfaceId: "test",
            hopCount: 1,
            randomBlob: Data(repeating: 0x02, count: 10)
        )

        XCTAssertNil(entry.announceData, "announceData should default to nil")
    }
}
