// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  BLEMeshConstants.swift
//  ReticulumSwift
//
//  Constants for BLE mesh peer-to-peer networking.
//  Wire-compatible with Python ble-reticulum and Kotlin reticulum-kt.
//
//  SEPARATE from BLEConstants.swift (RNode/NUS for LoRa radio control).
//

import Foundation
#if canImport(CoreBluetooth)
import CoreBluetooth
#endif

// MARK: - BLE Mesh Constants

public enum BLEMeshConstants {

    // MARK: - GATT Service & Characteristics

    public static let serviceUUIDString = "37145b00-442d-4a94-917f-8f42c5da28e3"
    public static let txCharUUIDString = "37145b00-442d-4a94-917f-8f42c5da28e4"
    public static let rxCharUUIDString = "37145b00-442d-4a94-917f-8f42c5da28e5"
    public static let identityCharUUIDString = "37145b00-442d-4a94-917f-8f42c5da28e6"

    #if canImport(CoreBluetooth)
    public static let serviceUUID = CBUUID(string: serviceUUIDString)
    public static let txCharUUID = CBUUID(string: txCharUUIDString)
    public static let rxCharUUID = CBUUID(string: rxCharUUIDString)
    public static let identityCharUUID = CBUUID(string: identityCharUUIDString)
    #endif

    // MARK: - Fragment Header

    public static let headerSize = 5
    public static let fragmentStart: UInt8 = 0x01
    public static let fragmentContinue: UInt8 = 0x02
    public static let fragmentEnd: UInt8 = 0x03

    // MARK: - MTU

    public static let defaultMTU = 185
    public static let minMTU = 20
    public static let maxMTU = 517

    // MARK: - Keepalive

    public static let keepaliveByte: UInt8 = 0x00
    public static let keepaliveInterval: TimeInterval = 15.0

    // MARK: - Timeouts

    public static let reassemblyTimeout: TimeInterval = 30.0
    public static let handshakeTimeout: TimeInterval = 30.0
    public static let connectionTimeout: TimeInterval = 30.0
    public static let zombieTimeout: TimeInterval = 45.0
    public static let zombieCheckInterval: TimeInterval = 15.0
    public static let zombieGracePeriod: TimeInterval = 5.0

    // MARK: - Blacklist / Backoff

    public static let blacklistBaseInterval: TimeInterval = 60.0
    public static let blacklistMaxMultiplier = 8

    // MARK: - Connection Limits

    public static let maxConnections = 7
    public static let minRSSI: Int = -85
    public static let evictionMargin: Double = 0.15

    // MARK: - RSSI Poll

    public static let rssiPollInterval: TimeInterval = 10.0

    // MARK: - MAC Rotation

    /// If a "connected" peer has no activity for this long, treat it as stale
    /// and allow replacement by a new connection with the same identity.
    /// Set to 2x keepalive interval.
    public static let staleConnectionThreshold: TimeInterval = 30.0
}
