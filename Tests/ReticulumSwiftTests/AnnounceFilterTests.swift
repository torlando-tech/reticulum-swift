// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  AnnounceFilterTests.swift
//  ReticulumSwiftTests
//
//  Tests for AnnounceFilter matching Python Transport.py:1040-1084 decision table.
//

import XCTest
@testable import ReticulumSwift

final class AnnounceFilterTests: XCTestCase {

    // MARK: - ACCESS_POINT outgoing: always block

    func testAccessPointBlocksAll() {
        // AP mode blocks all announces regardless of source
        XCTAssertFalse(AnnounceFilter.shouldForward(outgoingMode: .accessPoint, sourceMode: nil, isLocalDestination: false))
        XCTAssertFalse(AnnounceFilter.shouldForward(outgoingMode: .accessPoint, sourceMode: .full, isLocalDestination: false))
        XCTAssertFalse(AnnounceFilter.shouldForward(outgoingMode: .accessPoint, sourceMode: .roaming, isLocalDestination: false))
        XCTAssertFalse(AnnounceFilter.shouldForward(outgoingMode: .accessPoint, sourceMode: .boundary, isLocalDestination: false))
        // Even local destinations are blocked on AP
        XCTAssertFalse(AnnounceFilter.shouldForward(outgoingMode: .accessPoint, sourceMode: nil, isLocalDestination: true))
    }

    // MARK: - ROAMING outgoing

    func testRoamingAllowsLocalDestination() {
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .roaming, sourceMode: nil, isLocalDestination: true))
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .roaming, sourceMode: .roaming, isLocalDestination: true))
    }

    func testRoamingBlocksUnknownSource() {
        XCTAssertFalse(AnnounceFilter.shouldForward(outgoingMode: .roaming, sourceMode: nil, isLocalDestination: false))
    }

    func testRoamingBlocksRoamingSource() {
        XCTAssertFalse(AnnounceFilter.shouldForward(outgoingMode: .roaming, sourceMode: .roaming, isLocalDestination: false))
    }

    func testRoamingBlocksBoundarySource() {
        XCTAssertFalse(AnnounceFilter.shouldForward(outgoingMode: .roaming, sourceMode: .boundary, isLocalDestination: false))
    }

    func testRoamingAllowsFullSource() {
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .roaming, sourceMode: .full, isLocalDestination: false))
    }

    func testRoamingAllowsGatewaySource() {
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .roaming, sourceMode: .gateway, isLocalDestination: false))
    }

    func testRoamingAllowsP2PSource() {
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .roaming, sourceMode: .pointToPoint, isLocalDestination: false))
    }

    // MARK: - BOUNDARY outgoing

    func testBoundaryAllowsLocalDestination() {
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .boundary, sourceMode: nil, isLocalDestination: true))
    }

    func testBoundaryBlocksUnknownSource() {
        XCTAssertFalse(AnnounceFilter.shouldForward(outgoingMode: .boundary, sourceMode: nil, isLocalDestination: false))
    }

    func testBoundaryBlocksRoamingSource() {
        XCTAssertFalse(AnnounceFilter.shouldForward(outgoingMode: .boundary, sourceMode: .roaming, isLocalDestination: false))
    }

    func testBoundaryAllowsBoundarySource() {
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .boundary, sourceMode: .boundary, isLocalDestination: false))
    }

    func testBoundaryAllowsFullSource() {
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .boundary, sourceMode: .full, isLocalDestination: false))
    }

    // MARK: - FULL/GATEWAY/P2P outgoing: always allow

    func testFullAllowsAll() {
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .full, sourceMode: nil, isLocalDestination: false))
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .full, sourceMode: .roaming, isLocalDestination: false))
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .full, sourceMode: .boundary, isLocalDestination: false))
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .full, sourceMode: .full, isLocalDestination: false))
    }

    func testGatewayAllowsAll() {
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .gateway, sourceMode: nil, isLocalDestination: false))
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .gateway, sourceMode: .roaming, isLocalDestination: false))
    }

    func testPointToPointAllowsAll() {
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .pointToPoint, sourceMode: nil, isLocalDestination: false))
        XCTAssertTrue(AnnounceFilter.shouldForward(outgoingMode: .pointToPoint, sourceMode: .roaming, isLocalDestination: false))
    }
}
