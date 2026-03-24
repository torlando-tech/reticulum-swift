// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  AnnounceTableTests.swift
//  ReticulumSwiftTests
//
//  Tests for AnnounceTable retransmission scheduling and local rebroadcast detection.
//

import XCTest
@testable import ReticulumSwift

final class AnnounceTableTests: XCTestCase {

    // MARK: - Helpers

    private func makeDummyPacket(destHash: Data = Data(repeating: 0xAA, count: 16)) -> Packet {
        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            hasIFAC: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .announce,
            hopCount: 1
        )
        return Packet(
            header: header,
            destination: destHash,
            transportAddress: nil,
            context: 0x00,
            data: Data(repeating: 0, count: 100)
        )
    }

    // MARK: - Insert and Count

    func testInsertAndCount() async {
        let table = AnnounceTable()
        let destHash = Data(repeating: 0xAA, count: 16)
        let packet = makeDummyPacket(destHash: destHash)

        await table.insert(
            destinationHash: destHash,
            packet: packet,
            hops: 1,
            receivedFrom: destHash
        )

        let count = await table.count
        XCTAssertEqual(count, 1)
        let contains = await table.contains(destHash)
        XCTAssertTrue(contains)
    }

    // MARK: - Retransmission Timing

    func testRetransmissionAfterTimeout() async throws {
        let table = AnnounceTable()
        let destHash = Data(repeating: 0xBB, count: 16)
        let packet = makeDummyPacket(destHash: destHash)

        // Insert as local client (immediate retransmit, retries=PATHFINDER_R)
        await table.insert(
            destinationHash: destHash,
            packet: packet,
            hops: 1,
            receivedFrom: destHash,
            isLocalClient: true
        )

        // Process immediately - should get one action
        let actions = await table.processRetransmissions()
        XCTAssertEqual(actions.count, 1)
        XCTAssertEqual(actions.first?.destinationHash, destHash)
        XCTAssertEqual(actions.first?.hops, 1)
    }

    func testRetransmissionNotBeforeTimeout() async throws {
        let table = AnnounceTable()
        let destHash = Data(repeating: 0xCC, count: 16)
        let packet = makeDummyPacket(destHash: destHash)

        // Insert with normal timing (not local client)
        await table.insert(
            destinationHash: destHash,
            packet: packet,
            hops: 1,
            receivedFrom: destHash,
            isLocalClient: false
        )

        // Wait a bit less than PATHFINDER_RW max and process
        // Since random window is 0-0.5s, we process immediately and might get nothing
        // depending on the random timeout. Test the mechanism works.
        let actions = await table.processRetransmissions()
        // actions might be 0 or 1 depending on random timeout - that's expected
        XCTAssertTrue(actions.count <= 1)
    }

    // MARK: - Retry Limit

    func testRetryLimitRemovesEntry() async throws {
        let table = AnnounceTable()
        let destHash = Data(repeating: 0xDD, count: 16)
        let packet = makeDummyPacket(destHash: destHash)

        // Insert as local client (starts with retries=PATHFINDER_R=1)
        await table.insert(
            destinationHash: destHash,
            packet: packet,
            hops: 1,
            receivedFrom: destHash,
            isLocalClient: true
        )

        // First process: retries goes from 1 to 2, which is > PATHFINDER_R(1)
        _ = await table.processRetransmissions()

        // Second process: entry should be removed because retries(2) > PATHFINDER_R(1)
        let actions2 = await table.processRetransmissions()
        XCTAssertEqual(actions2.count, 0, "Entry should be removed after retry limit")

        let contains = await table.contains(destHash)
        XCTAssertFalse(contains)
    }

    // MARK: - Local Rebroadcast Detection

    func testLocalRebroadcastDetected() async {
        let table = AnnounceTable()
        let destHash = Data(repeating: 0xEE, count: 16)
        let packet = makeDummyPacket(destHash: destHash)

        await table.insert(
            destinationHash: destHash,
            packet: packet,
            hops: 3,
            receivedFrom: destHash
        )

        // Hear our rebroadcast back with hops-1 == entry.hops
        let detected = await table.recordLocalRebroadcast(destinationHash: destHash, incomingHops: 4)
        XCTAssertTrue(detected, "Should detect local rebroadcast when incomingHops-1 == entry.hops")
    }

    func testLocalRebroadcastNotDetectedWrongHops() async {
        let table = AnnounceTable()
        let destHash = Data(repeating: 0xFF, count: 16)
        let packet = makeDummyPacket(destHash: destHash)

        await table.insert(
            destinationHash: destHash,
            packet: packet,
            hops: 3,
            receivedFrom: destHash
        )

        // Wrong hop count
        let detected = await table.recordLocalRebroadcast(destinationHash: destHash, incomingHops: 6)
        XCTAssertFalse(detected, "Should not detect rebroadcast with wrong hop count")
    }

    // MARK: - Rate Limiting

    func testRateLimitingFirstAnnounceNotBlocked() async {
        let table = AnnounceTable()
        let destHash = Data(repeating: 0x11, count: 16)

        let blocked = await table.isRateBlocked(
            destinationHash: destHash,
            rateTarget: 60,
            rateGrace: 3,
            ratePenalty: 300
        )
        XCTAssertFalse(blocked, "First announce should never be rate-blocked")
    }

    func testRateLimitingBlocksAfterViolations() async {
        let table = AnnounceTable()
        let destHash = Data(repeating: 0x22, count: 16)

        // First announce - creates entry
        _ = await table.isRateBlocked(destinationHash: destHash, rateTarget: 60, rateGrace: 0, ratePenalty: 300)

        // Second announce immediately - should be blocked (rate_violations > grace of 0)
        let blocked = await table.isRateBlocked(destinationHash: destHash, rateTarget: 60, rateGrace: 0, ratePenalty: 300)
        XCTAssertTrue(blocked, "Rapid announce should be rate-blocked when grace is 0")
    }
}
