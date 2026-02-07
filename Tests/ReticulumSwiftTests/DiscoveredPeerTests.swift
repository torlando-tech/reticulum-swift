//
//  DiscoveredPeerTests.swift
//  ReticulumSwiftTests
//
//  Tests for DiscoveredPeer connection scoring.
//

import XCTest
@testable import ReticulumSwift

final class DiscoveredPeerTests: XCTestCase {

    func testScoreInRange() {
        let peer = DiscoveredPeer(address: "A", rssi: -60, lastSeen: Date(), attempts: 5, successes: 3)
        let score = peer.connectionScore()
        XCTAssertGreaterThanOrEqual(score, 0.0)
        XCTAssertLessThanOrEqual(score, 1.0)
    }

    func testStrongRSSIBetterThanWeak() {
        let strong = DiscoveredPeer(address: "A", rssi: -40, lastSeen: Date(), attempts: 1, successes: 1)
        let weak = DiscoveredPeer(address: "B", rssi: -90, lastSeen: Date(), attempts: 1, successes: 1)

        XCTAssertGreaterThan(strong.connectionScore(), weak.connectionScore())
    }

    func testHighSuccessRateBetter() {
        let good = DiscoveredPeer(address: "A", rssi: -60, lastSeen: Date(), attempts: 10, successes: 9)
        let bad = DiscoveredPeer(address: "B", rssi: -60, lastSeen: Date(), attempts: 10, successes: 1)

        XCTAssertGreaterThan(good.connectionScore(), bad.connectionScore())
    }

    func testRecentBetterThanOld() {
        let recent = DiscoveredPeer(address: "A", rssi: -60, lastSeen: Date(), attempts: 1, successes: 1)
        let old = DiscoveredPeer(address: "B", rssi: -60, lastSeen: Date().addingTimeInterval(-120), attempts: 1, successes: 1)

        XCTAssertGreaterThan(recent.connectionScore(), old.connectionScore())
    }

    func testNoAttemptsPeer() {
        // A peer with no attempts should get a neutral success rate (0.5)
        let peer = DiscoveredPeer(address: "A", rssi: -60, lastSeen: Date(), attempts: 0, successes: 0)
        let score = peer.connectionScore()
        XCTAssertGreaterThan(score, 0.0, "Score should be > 0 even with no history")
    }

    func testVeryWeakRSSI() {
        // RSSI at -100 should contribute 0 to RSSI component
        let peer = DiscoveredPeer(address: "A", rssi: -100, lastSeen: Date().addingTimeInterval(-120), attempts: 10, successes: 0)
        let score = peer.connectionScore()
        XCTAssertGreaterThanOrEqual(score, 0.0)
        XCTAssertLessThan(score, 0.1, "Very weak peer should score very low")
    }

    func testPerfectPeer() {
        // RSSI -40 (perfect), recent, 100% success
        let peer = DiscoveredPeer(address: "A", rssi: -40, lastSeen: Date(), attempts: 100, successes: 100)
        let score = peer.connectionScore()
        XCTAssertGreaterThan(score, 0.9, "Perfect peer should score > 0.9")
    }
}
