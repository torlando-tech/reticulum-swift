// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  DiscoveredPeer.swift
//  ReticulumSwift
//
//  Discovered BLE mesh peer with connection scoring.
//  Port of DiscoveredPeer.kt from reticulum-kt.
//

import Foundation

// MARK: - Discovered Peer

/// A BLE mesh peer discovered during scanning.
///
/// Tracks RSSI, connection history, and last-seen time to compute
/// a connection score used for peer selection and eviction.
public struct DiscoveredPeer: Sendable {

    /// BLE address or peripheral identifier
    public let address: String

    /// Signal strength at discovery
    public var rssi: Int

    /// When this peer was last seen
    public var lastSeen: Date

    /// Remote identity hash (16 bytes), set after handshake
    public var identity: Data?

    /// Number of connection attempts
    public var attempts: Int

    /// Number of successful connections
    public var successes: Int

    public init(
        address: String,
        rssi: Int,
        lastSeen: Date = Date(),
        identity: Data? = nil,
        attempts: Int = 0,
        successes: Int = 0
    ) {
        self.address = address
        self.rssi = rssi
        self.lastSeen = lastSeen
        self.identity = identity
        self.attempts = attempts
        self.successes = successes
    }

    /// Compute a connection score in [0, 1].
    ///
    /// Weighted: RSSI (60%) + success rate (30%) + recency (10%).
    ///
    /// - RSSI: normalized from [-100, -40] to [0, 1]
    /// - Success rate: successes / attempts (0 if no attempts)
    /// - Recency: decays over 60 seconds
    public func connectionScore() -> Double {
        // RSSI component: map [-100, -40] → [0, 1], clamped
        let rssiNorm = min(1.0, max(0.0, (Double(rssi) + 100.0) / 60.0))

        // Success rate component
        let successRate: Double
        if attempts > 0 {
            successRate = Double(successes) / Double(attempts)
        } else {
            successRate = 0.5 // Neutral for unknown peers
        }

        // Recency component: 1.0 if just seen, decays to 0 over 60s
        let age = Date().timeIntervalSince(lastSeen)
        let recency = max(0.0, 1.0 - age / 60.0)

        return 0.6 * rssiNorm + 0.3 * successRate + 0.1 * recency
    }
}
