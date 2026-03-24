// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  BLEConstants.swift
//  ReticulumSwift
//
//  Nordic UART Service (NUS) UUIDs and BLE configuration constants
//  for RNode device communication via Bluetooth Low Energy.
//

import Foundation

// MARK: - BLE Constants

/// Constants for Bluetooth Low Energy communication with RNode devices.
///
/// RNode devices expose the Nordic UART Service (NUS) for serial-like
/// communication over BLE. The NUS service provides two characteristics:
/// - TX (RNode -> iOS): notifications for receiving data
/// - RX (iOS -> RNode): write-without-response for sending data
public enum BLEConstants {

    // MARK: - Nordic UART Service UUIDs

    /// Nordic UART Service UUID.
    ///
    /// RNode devices advertise this service UUID, enabling discovery
    /// via filtered scanning.
    public static let NUS_SERVICE_UUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"

    /// Nordic UART Service TX characteristic UUID.
    ///
    /// RNode -> iOS (notifications enabled).
    /// Used for receiving data from the RNode device.
    public static let NUS_TX_CHAR_UUID = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"

    /// Nordic UART Service RX characteristic UUID.
    ///
    /// iOS -> RNode (write without response).
    /// Used for sending data to the RNode device.
    public static let NUS_RX_CHAR_UUID = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"

    // MARK: - Configuration

    /// Default MTU floor for safe data chunking.
    ///
    /// iOS 16+ dynamically negotiates MTU, but we use a safe floor
    /// of 20 bytes (BLE 4.0 minimum) to handle degraded connections.
    /// Actual MTU is queried via `maximumWriteValueLength(for:)`.
    public static let DEFAULT_MTU = 20

    /// CoreBluetooth state preservation identifier.
    ///
    /// Enables background BLE persistence when the app is backgrounded.
    /// System can wake the app when peripheral connects/disconnects.
    public static let RESTORE_IDENTIFIER_KEY = "com.columba.ble.central"

    /// Connection timeout in seconds.
    ///
    /// If a peripheral is not discovered or does not connect within
    /// this timeout, the connection attempt fails.
    public static let CONNECTION_TIMEOUT: TimeInterval = 15.0
}

// MARK: - BLE Error

/// Errors specific to BLE transport operations.
public enum BLEError: Error, Sendable, Equatable {

    /// Bluetooth is not in `.poweredOn` state.
    ///
    /// Common causes: Bluetooth disabled, airplane mode, hardware issue.
    case bluetoothNotReady

    /// User denied Bluetooth permission.
    ///
    /// App cannot scan for or connect to peripherals without authorization.
    case bluetoothUnauthorized

    /// Device does not support Bluetooth Low Energy.
    ///
    /// Rare on modern iOS devices (BLE available since iPhone 4S).
    case bluetoothUnsupported

    /// Connection attempt timed out.
    ///
    /// Peripheral was not discovered or did not connect within the timeout period.
    case connectionTimedOut

    /// No RNode peripheral found during scan.
    ///
    /// Either no RNode is in range or the device is not advertising NUS.
    case peripheralNotFound

    /// Nordic UART Service not found on peripheral.
    ///
    /// Peripheral does not expose the expected NUS service UUID.
    case serviceDiscoveryFailed

    /// TX or RX characteristic not found on NUS service.
    ///
    /// Service exists but is missing required characteristics.
    case characteristicDiscoveryFailed

    /// Write buffer is full (canSendWriteWithoutResponse returned false).
    ///
    /// System cannot accept more writes until buffer drains.
    case bufferFull

    /// Attempted to send data while disconnected.
    ///
    /// Call `connect()` before sending data.
    case notConnected
}

// MARK: - LocalizedError

extension BLEError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .bluetoothNotReady:
            return "Bluetooth is not ready (check if Bluetooth is enabled)"
        case .bluetoothUnauthorized:
            return "Bluetooth permission denied (check Settings > Privacy > Bluetooth)"
        case .bluetoothUnsupported:
            return "Bluetooth Low Energy is not supported on this device"
        case .connectionTimedOut:
            return "Connection timed out (no RNode found within \(BLEConstants.CONNECTION_TIMEOUT)s)"
        case .peripheralNotFound:
            return "No RNode peripheral discovered during scan"
        case .serviceDiscoveryFailed:
            return "Nordic UART Service not found on peripheral"
        case .characteristicDiscoveryFailed:
            return "TX or RX characteristic not found on NUS service"
        case .bufferFull:
            return "BLE write buffer full (wait for buffer to drain)"
        case .notConnected:
            return "BLE transport is not connected"
        }
    }
}
