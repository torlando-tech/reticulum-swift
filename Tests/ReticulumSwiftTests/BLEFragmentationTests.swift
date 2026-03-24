// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  BLEFragmentationTests.swift
//  ReticulumSwiftTests
//
//  Tests for BLE mesh fragmentation and reassembly.
//  Port from BLEFragmentationTest.kt — verifies wire-format compatibility.
//

import XCTest
@testable import ReticulumSwift

final class BLEFragmentationTests: XCTestCase {

    // MARK: - Fragmenter Tests

    func testSingleFragmentSmallPacket() {
        let fragmenter = BLEFragmenter(mtu: 185)
        let packet = Data(repeating: 0xAB, count: 10)
        let fragments = fragmenter.fragment(packet)

        XCTAssertEqual(fragments.count, 1)
        XCTAssertEqual(fragments[0].count, 5 + 10)

        // Header: START=0x01, seq=0x0000, total=0x0001
        XCTAssertEqual(fragments[0][0], 0x01) // START
        XCTAssertEqual(fragments[0][1], 0x00) // seq high
        XCTAssertEqual(fragments[0][2], 0x00) // seq low
        XCTAssertEqual(fragments[0][3], 0x00) // total high
        XCTAssertEqual(fragments[0][4], 0x01) // total low
    }

    func testMultipleFragments() {
        let fragmenter = BLEFragmenter(mtu: 15) // 5 header + 10 payload
        let packet = Data(repeating: 0xCC, count: 25) // 3 fragments of 10, 10, 5
        let fragments = fragmenter.fragment(packet)

        XCTAssertEqual(fragments.count, 3)

        // Fragment 0: START, seq=0, total=3
        XCTAssertEqual(fragments[0][0], 0x01) // START
        XCTAssertEqual(fragments[0][1], 0x00)
        XCTAssertEqual(fragments[0][2], 0x00) // seq=0
        XCTAssertEqual(fragments[0][3], 0x00)
        XCTAssertEqual(fragments[0][4], 0x03) // total=3
        XCTAssertEqual(fragments[0].count, 15) // full fragment

        // Fragment 1: CONTINUE, seq=1, total=3
        XCTAssertEqual(fragments[1][0], 0x02) // CONTINUE
        XCTAssertEqual(fragments[1][1], 0x00)
        XCTAssertEqual(fragments[1][2], 0x01) // seq=1
        XCTAssertEqual(fragments[1][3], 0x00)
        XCTAssertEqual(fragments[1][4], 0x03) // total=3
        XCTAssertEqual(fragments[1].count, 15)

        // Fragment 2: END, seq=2, total=3
        XCTAssertEqual(fragments[2][0], 0x03) // END
        XCTAssertEqual(fragments[2][1], 0x00)
        XCTAssertEqual(fragments[2][2], 0x02) // seq=2
        XCTAssertEqual(fragments[2][3], 0x00)
        XCTAssertEqual(fragments[2][4], 0x03) // total=3
        XCTAssertEqual(fragments[2].count, 10) // 5 header + 5 payload
    }

    func testWireFormatBigEndian() {
        // Verify header: [0x01, 0x00, 0x00, 0x00, 0x03] == START, seq=0, total=3
        // This matches Python struct.pack("!BHH", 0x01, 0, 3)
        let fragmenter = BLEFragmenter(mtu: 15)
        let packet = Data(repeating: 0xDD, count: 25)
        let fragments = fragmenter.fragment(packet)

        XCTAssertEqual(fragments.count, 3)

        // First fragment header should be exactly [01 00 00 00 03]
        let header = Data(fragments[0].prefix(5))
        let expected = Data([0x01, 0x00, 0x00, 0x00, 0x03])
        XCTAssertEqual(header, expected, "Wire format mismatch: got \(header.map { String(format: "%02x", $0) }.joined())")
    }

    func testMTUBoundary() {
        // Packet exactly fills one fragment
        let fragmenter = BLEFragmenter(mtu: 185)
        let packet = Data(repeating: 0xEE, count: 180) // maxPayload = 180
        let fragments = fragmenter.fragment(packet)

        XCTAssertEqual(fragments.count, 1)
        XCTAssertEqual(fragments[0].count, 185) // Exactly MTU
    }

    func testMTUBoundaryPlusOne() {
        // Packet is one byte over one fragment
        let fragmenter = BLEFragmenter(mtu: 185)
        let packet = Data(repeating: 0xFF, count: 181) // 180 + 1 = needs 2 fragments
        let fragments = fragmenter.fragment(packet)

        XCTAssertEqual(fragments.count, 2)
        XCTAssertEqual(fragments[0].count, 185) // Full first fragment
        XCTAssertEqual(fragments[1].count, 6)   // 5 header + 1 payload byte
    }

    func testEmptyPacket() {
        let fragmenter = BLEFragmenter(mtu: 185)
        let fragments = fragmenter.fragment(Data())
        XCTAssertEqual(fragments.count, 0)
    }

    func testMinMTU() {
        // MTU=6: 5 header + 1 payload per fragment
        let fragmenter = BLEFragmenter(mtu: 6)
        let packet = Data([0x01, 0x02, 0x03])
        let fragments = fragmenter.fragment(packet)

        XCTAssertEqual(fragments.count, 3)
        for frag in fragments {
            XCTAssertEqual(frag.count, 6) // Each fragment has 1 payload byte
        }
    }

    // MARK: - Reassembler Tests

    func testReassembleInOrder() {
        let fragmenter = BLEFragmenter(mtu: 15)
        let reassembler = BLEReassembler()

        let original = Data(repeating: 0xAA, count: 25)
        let fragments = fragmenter.fragment(original)

        XCTAssertEqual(fragments.count, 3)

        // Feed fragments in order
        let result1 = try! reassembler.receiveFragment(fragments[0], senderId: "peer1")
        XCTAssertNil(result1)

        let result2 = try! reassembler.receiveFragment(fragments[1], senderId: "peer1")
        XCTAssertNil(result2)

        let result3 = try! reassembler.receiveFragment(fragments[2], senderId: "peer1")
        XCTAssertNotNil(result3)
        XCTAssertEqual(result3, original)
    }

    func testReassembleOutOfOrder() {
        let fragmenter = BLEFragmenter(mtu: 15)
        let reassembler = BLEReassembler()

        let original = Data(repeating: 0xBB, count: 25)
        let fragments = fragmenter.fragment(original)

        // Feed fragments out of order: 2, 0, 1
        let result1 = try! reassembler.receiveFragment(fragments[2], senderId: "peer1")
        XCTAssertNil(result1)

        let result2 = try! reassembler.receiveFragment(fragments[0], senderId: "peer1")
        XCTAssertNil(result2)

        let result3 = try! reassembler.receiveFragment(fragments[1], senderId: "peer1")
        XCTAssertNotNil(result3)
        XCTAssertEqual(result3, original)
    }

    func testSingleFragmentReassembly() {
        let fragmenter = BLEFragmenter(mtu: 185)
        let reassembler = BLEReassembler()

        let original = Data([0x01, 0x02, 0x03])
        let fragments = fragmenter.fragment(original)
        XCTAssertEqual(fragments.count, 1)

        let result = try! reassembler.receiveFragment(fragments[0], senderId: "peer1")
        XCTAssertNotNil(result)
        XCTAssertEqual(result, original)
    }

    func testBenignDuplicateIgnored() {
        let fragmenter = BLEFragmenter(mtu: 15)
        let reassembler = BLEReassembler()

        let original = Data(repeating: 0xCC, count: 25)
        let fragments = fragmenter.fragment(original)

        // Send fragment 0 twice
        _ = try! reassembler.receiveFragment(fragments[0], senderId: "peer1")
        let result = try! reassembler.receiveFragment(fragments[0], senderId: "peer1") // duplicate
        XCTAssertNil(result) // Should be ignored

        XCTAssertEqual(reassembler.statistics.duplicatesIgnored, 1)
    }

    func testDuplicateMismatchThrows() {
        let reassembler = BLEReassembler()

        // Create two fragments with same seq/total but different payload
        let frag1 = Data([0x01, 0x00, 0x00, 0x00, 0x02, 0xAA]) // START, seq=0, total=2, payload=0xAA
        let frag2 = Data([0x01, 0x00, 0x00, 0x00, 0x02, 0xBB]) // START, seq=0, total=2, payload=0xBB

        _ = try! reassembler.receiveFragment(frag1, senderId: "peer1")
        XCTAssertThrowsError(try reassembler.receiveFragment(frag2, senderId: "peer1")) { error in
            if case BLEReassemblyError.duplicateMismatch = error {
                // Expected
            } else {
                XCTFail("Expected duplicateMismatch, got \(error)")
            }
        }
    }

    func testTotalMismatchThrows() {
        let reassembler = BLEReassembler()

        // Fragment with total=2
        let frag1 = Data([0x01, 0x00, 0x00, 0x00, 0x02, 0xAA])
        // Fragment with total=3 from same sender
        let frag2 = Data([0x02, 0x00, 0x01, 0x00, 0x03, 0xBB])

        _ = try! reassembler.receiveFragment(frag1, senderId: "peer1")
        XCTAssertThrowsError(try reassembler.receiveFragment(frag2, senderId: "peer1")) { error in
            if case BLEReassemblyError.totalMismatch = error {
                // Expected
            } else {
                XCTFail("Expected totalMismatch, got \(error)")
            }
        }
    }

    func testConcurrentSenders() {
        let fragmenter = BLEFragmenter(mtu: 15)
        let reassembler = BLEReassembler()

        let packet1 = Data(repeating: 0x11, count: 25)
        let packet2 = Data(repeating: 0x22, count: 25)

        let frags1 = fragmenter.fragment(packet1)
        let frags2 = fragmenter.fragment(packet2)

        // Interleave fragments from different senders
        _ = try! reassembler.receiveFragment(frags1[0], senderId: "peer1")
        _ = try! reassembler.receiveFragment(frags2[0], senderId: "peer2")
        _ = try! reassembler.receiveFragment(frags1[1], senderId: "peer1")
        _ = try! reassembler.receiveFragment(frags2[1], senderId: "peer2")

        let result1 = try! reassembler.receiveFragment(frags1[2], senderId: "peer1")
        XCTAssertEqual(result1, packet1)

        let result2 = try! reassembler.receiveFragment(frags2[2], senderId: "peer2")
        XCTAssertEqual(result2, packet2)
    }

    func testStaleCleanup() {
        let reassembler = BLEReassembler(timeout: 0.1) // 100ms timeout

        // Start a reassembly
        let frag = Data([0x01, 0x00, 0x00, 0x00, 0x02, 0xAA])
        _ = try! reassembler.receiveFragment(frag, senderId: "peer1")

        // Wait for timeout
        Thread.sleep(forTimeInterval: 0.2)

        let removed = reassembler.cleanupStale()
        XCTAssertEqual(removed, 1)
        XCTAssertEqual(reassembler.statistics.timeoutsExpired, 1)
    }

    func testStatistics() {
        let fragmenter = BLEFragmenter(mtu: 15)
        let reassembler = BLEReassembler()

        let original = Data(repeating: 0xDD, count: 25)
        let fragments = fragmenter.fragment(original)

        for frag in fragments {
            _ = try? reassembler.receiveFragment(frag, senderId: "peer1")
        }

        XCTAssertEqual(reassembler.statistics.fragmentsReceived, 3)
        XCTAssertEqual(reassembler.statistics.packetsCompleted, 1)
        XCTAssertEqual(reassembler.statistics.duplicatesIgnored, 0)
        XCTAssertEqual(reassembler.statistics.errorsEncountered, 0)
    }

    func testInvalidHeaderTooShort() {
        let reassembler = BLEReassembler()

        XCTAssertThrowsError(try reassembler.receiveFragment(Data([0x01, 0x00]), senderId: "peer1")) { error in
            if case BLEReassemblyError.invalidHeader = error {
                // Expected
            } else {
                XCTFail("Expected invalidHeader, got \(error)")
            }
        }
    }

    func testInvalidHeaderBadType() {
        let reassembler = BLEReassembler()
        let frag = Data([0xFF, 0x00, 0x00, 0x00, 0x01, 0xAA])

        XCTAssertThrowsError(try reassembler.receiveFragment(frag, senderId: "peer1")) { error in
            if case BLEReassemblyError.invalidHeader = error {
                // Expected
            } else {
                XCTFail("Expected invalidHeader, got \(error)")
            }
        }
    }

    func testInvalidHeaderZeroTotal() {
        let reassembler = BLEReassembler()
        let frag = Data([0x01, 0x00, 0x00, 0x00, 0x00, 0xAA]) // total=0

        XCTAssertThrowsError(try reassembler.receiveFragment(frag, senderId: "peer1")) { error in
            if case BLEReassemblyError.invalidHeader = error {
                // Expected
            } else {
                XCTFail("Expected invalidHeader, got \(error)")
            }
        }
    }

    func testInvalidHeaderSeqExceedsTotal() {
        let reassembler = BLEReassembler()
        let frag = Data([0x01, 0x00, 0x05, 0x00, 0x03, 0xAA]) // seq=5, total=3

        XCTAssertThrowsError(try reassembler.receiveFragment(frag, senderId: "peer1")) { error in
            if case BLEReassemblyError.invalidHeader = error {
                // Expected
            } else {
                XCTFail("Expected invalidHeader, got \(error)")
            }
        }
    }

    // MARK: - Round-Trip Tests

    func testRoundTripDefaultMTU() {
        roundTripTest(mtu: 185, packetSize: 500)
    }

    func testRoundTripMinMTU() {
        roundTripTest(mtu: 6, packetSize: 100)
    }

    func testRoundTripMaxMTU() {
        roundTripTest(mtu: 517, packetSize: 1000)
    }

    func testRoundTripLargePacket() {
        roundTripTest(mtu: 185, packetSize: 10000)
    }

    func testRoundTripExactMultiple() {
        // Packet size is exact multiple of payload size
        let mtu = 25
        let payloadSize = mtu - 5 // 20
        roundTripTest(mtu: mtu, packetSize: payloadSize * 5) // 100 bytes = exactly 5 fragments
    }

    private func roundTripTest(mtu: Int, packetSize: Int) {
        let fragmenter = BLEFragmenter(mtu: mtu)
        let reassembler = BLEReassembler()

        // Generate random packet
        var original = Data(count: packetSize)
        for i in 0..<packetSize {
            original[i] = UInt8(i % 256)
        }

        let fragments = fragmenter.fragment(original)

        // All fragments should be <= MTU
        for frag in fragments {
            XCTAssertLessThanOrEqual(frag.count, mtu)
        }

        // Reassemble
        var result: Data?
        for frag in fragments {
            result = try! reassembler.receiveFragment(frag, senderId: "test")
        }

        XCTAssertNotNil(result)
        XCTAssertEqual(result, original)
    }

    // MARK: - Max Fragment Count

    func testMaxFragmentCount() {
        // With MTU=6 (1 byte payload), a 100-byte packet needs 100 fragments
        let fragmenter = BLEFragmenter(mtu: 6)
        let packet = Data(repeating: 0xAA, count: 100)
        let fragments = fragmenter.fragment(packet)

        XCTAssertEqual(fragments.count, 100)

        // Verify all have correct total
        for frag in fragments {
            // Total is at bytes 3-4 (big-endian)
            let total = UInt16(frag[3]) << 8 | UInt16(frag[4])
            XCTAssertEqual(total, 100)
        }
    }
}
