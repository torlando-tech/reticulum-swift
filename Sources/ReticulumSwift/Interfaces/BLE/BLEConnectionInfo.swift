// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  BLEConnectionInfo.swift
//  ReticulumSwift
//
//  Snapshot of a single BLE peer connection for UI display.
//

import Foundation

/// Snapshot of a BLE peer connection's state and statistics.
///
/// Created by `BLEInterface.getConnectionInfos()` for UI consumption.
/// All values are captured at the time of creation and do not update live.
public struct BLEConnectionInfo: Identifiable, Sendable {
    public var id: String { identityHash }

    /// Remote peer's 32-char hex identity hash
    public let identityHash: String

    /// Whether we initiated this connection (central role)
    public let isOutgoing: Bool

    /// Latest RSSI reading (dBm). 0 if unavailable.
    public let rssi: Int

    /// Negotiated MTU in bytes
    public let mtu: Int

    /// When this connection was established
    public let connectedAt: Date

    /// Last time data was received from this peer
    public let lastActivity: Date

    /// Total bytes sent to this peer
    public let bytesSent: Int

    /// Total bytes received from this peer
    public let bytesReceived: Int

    /// Total packets sent to this peer
    public let packetsSent: Int

    /// Total packets received from this peer
    public let packetsReceived: Int

    /// Connection type label for display
    public var connectionType: String {
        isOutgoing ? "Central" : "Peripheral"
    }

    /// Signal quality rating based on RSSI
    public var signalQuality: SignalQuality {
        if rssi == 0 { return .unknown }
        if rssi >= -60 { return .excellent }
        if rssi >= -70 { return .good }
        if rssi >= -80 { return .fair }
        return .poor
    }

    /// Duration since connection was established
    public var connectionDuration: TimeInterval {
        Date().timeIntervalSince(connectedAt)
    }
}

/// Signal quality rating for BLE connections.
public enum SignalQuality: String, Sendable {
    case excellent = "Excellent"
    case good = "Good"
    case fair = "Fair"
    case poor = "Poor"
    case unknown = "N/A"
}
