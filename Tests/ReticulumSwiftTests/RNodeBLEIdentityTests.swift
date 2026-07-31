// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  RNodeBLEIdentityTests.swift
//  ReticulumSwiftTests
//
//  Unit tests for RNode-by-CoreBluetooth-identifier matching (BLETransport pure
//  decision logic) and RNode failure-reason surfacing in interface snapshots.
//  These exercise REAL production code paths; the live CBCentralManager/CBPeripheral
//  orchestration is deliberately NOT tested (it can't run headless without faking the
//  very code under test).
//

#if canImport(CoreBluetooth)
import XCTest
import CoreBluetooth
@testable import ReticulumSwift

final class RNodeBLEIdentityTests: XCTestCase {

    // MARK: - B1: identifier-first / name-fallback match predicate

    func testMatchesByIdentifierIgnoringName() {
        let idA = UUID()
        let idB = UUID()
        // Identifier set → match only the same identifier, regardless of advertised name.
        XCTAssertTrue(BLETransport.peripheralMatchesTarget(
            peripheralId: idA, peripheralName: "RNode 9f", targetId: idA, targetName: nil))
        XCTAssertFalse(BLETransport.peripheralMatchesTarget(
            peripheralId: idB, peripheralName: "RNode 9f", targetId: idA, targetName: nil))
    }

    func testIdentifierWinsOverDuplicateName() {
        let idA = UUID()
        let idB = UUID()
        // Two RNodes sharing a name: the identifier disambiguates (the whole point of B13).
        XCTAssertTrue(BLETransport.peripheralMatchesTarget(
            peripheralId: idA, peripheralName: "RNode", targetId: idA, targetName: "RNode"))
        XCTAssertFalse(BLETransport.peripheralMatchesTarget(
            peripheralId: idB, peripheralName: "RNode", targetId: idA, targetName: "RNode"))
    }

    func testMatchesByNameWhenNoIdentifier() {
        let id = UUID()
        XCTAssertTrue(BLETransport.peripheralMatchesTarget(
            peripheralId: id, peripheralName: "RNode 9f", targetId: nil, targetName: "RNode 9f"))
        XCTAssertFalse(BLETransport.peripheralMatchesTarget(
            peripheralId: id, peripheralName: "RNode aa", targetId: nil, targetName: "RNode 9f"))
        // A nil advertised name never matches a name target.
        XCTAssertFalse(BLETransport.peripheralMatchesTarget(
            peripheralId: id, peripheralName: nil, targetId: nil, targetName: "RNode 9f"))
    }

    func testScanOnlyNeverAutoMatches() {
        // No target id and no target name = device-picker scan-only: never auto-connect.
        XCTAssertFalse(BLETransport.peripheralMatchesTarget(
            peripheralId: UUID(), peripheralName: "RNode", targetId: nil, targetName: nil))
    }

    // MARK: - B2: isScanOnly

    func testIsScanOnly() {
        let id = UUID()
        XCTAssertTrue(BLETransport(deviceName: nil, deviceIdentifier: nil).isScanOnly)
        XCTAssertFalse(BLETransport(deviceName: "RNode", deviceIdentifier: nil).isScanOnly)
        XCTAssertFalse(BLETransport(deviceName: nil, deviceIdentifier: id).isScanOnly)
        XCTAssertFalse(BLETransport(deviceName: "RNode", deviceIdentifier: id).isScanOnly)
    }

    func testRestorationIdentifierCanBeStablePerPhysicalSession() {
        let first = BLETransport(
            deviceName: "RNode A",
            restorationIdentifier: "com.columba.ble.rnode.AAAAAAAA"
        )
        let second = BLETransport(
            deviceName: "RNode B",
            restorationIdentifier: "com.columba.ble.rnode.BBBBBBBB"
        )

        XCTAssertEqual(first.restorationIdentifier, "com.columba.ble.rnode.AAAAAAAA")
        XCTAssertEqual(second.restorationIdentifier, "com.columba.ble.rnode.BBBBBBBB")
        XCTAssertNotEqual(first.restorationIdentifier, second.restorationIdentifier)
        XCTAssertEqual(
            BLETransport(deviceName: "legacy").restorationIdentifier,
            BLEConstants.RESTORE_IDENTIFIER_KEY
        )

        let options = BLETransport.centralManagerOptions(
            restorationIdentifier: first.restorationIdentifier
        )
        XCTAssertEqual(
            options[CBCentralManagerOptionRestoreIdentifierKey] as? String,
            "com.columba.ble.rnode.AAAAAAAA",
            "the custom namespace must reach CBCentralManager options"
        )
    }

    // MARK: - A3: RNode failure reason surfaces in getInterfaceSnapshots

    func testInterfaceSnapshotCarriesRNodeError() async throws {
        let fake = FakeRNodeTransport()
        let cfg = InterfaceConfig(
            id: "ne-rnode", name: "RNode", type: .rnode,
            enabled: true, mode: .full, host: "TestRNode", port: 0)
        let iface = try RNodeInterface(config: cfg, transportFactory: { _ in fake })
        let transport = ReticulumTransport(pathTable: PathTable())
        try await transport.addInterface(iface)

        // Drive a transport failure → the real handleTransportStateChange records the reason.
        fake.fail(FakeRadioError())

        // Await the actor hop that records lastErrorDescription.
        var reason: String?
        for _ in 0..<200 {
            reason = await iface.lastErrorDescription
            if reason != nil { break }
            try await Task.sleep(nanoseconds: 10_000_000)  // 10ms
        }
        XCTAssertEqual(reason, "firmware too old")

        // The snapshot must carry that reason (the +5 lines added to getInterfaceSnapshots).
        let snaps = await transport.getInterfaceSnapshots()
        let rnodeSnap = snaps.first { $0.id == "ne-rnode" }
        XCTAssertNotNil(rnodeSnap, "RNode interface should appear in the snapshot")
        XCTAssertEqual(rnodeSnap?.lastErrorDescription, "firmware too old")
    }
}

// MARK: - Test doubles

private struct FakeRadioError: LocalizedError {
    var errorDescription: String? { "firmware too old" }
}

/// A `Transport` that never auto-connects, so the test can drive a failure deterministically.
private final class FakeRNodeTransport: Transport, @unchecked Sendable {
    var state: TransportState = .disconnected
    var onStateChange: ((TransportState) -> Void)?
    var onDataReceived: ((Data) -> Void)?
    func connect() {}  // no auto-connect; the test drives state via fail()
    func send(_ data: Data, completion: ((Error?) -> Void)? = nil) { completion?(nil) }
    func disconnect() {}
    func fail(_ error: Error) {
        state = .failed(error)
        onStateChange?(.failed(error))
    }
}
#endif
