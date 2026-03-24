// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  AutoInterfaceConstants.swift
//  ReticulumSwift
//
//  Constants and multicast address computation for AutoInterface.
//  All values match Python RNS/Interfaces/AutoInterface.py.
//

import Foundation
import CryptoKit

// MARK: - AutoInterface Constants

public enum AutoInterfaceConstants {
    /// Default group ID for peer discovery
    public static let defaultGroupId = "reticulum"

    /// Default multicast discovery port
    public static let defaultDiscoveryPort: UInt16 = 29716

    /// Unicast discovery port (always discoveryPort + 1)
    public static let defaultUnicastDiscoveryPort: UInt16 = 29717

    /// Default data transfer port
    public static let defaultDataPort: UInt16 = 42671

    /// Hardware MTU for AutoInterface
    public static let hwMTU: Int = 1196

    /// Peering timeout — remove peer after this long without hearing from them
    public static let peeringTimeout: TimeInterval = 22.0

    /// Multicast announce interval
    public static let announceInterval: TimeInterval = 1.6

    /// Peer maintenance job interval
    public static let peerJobInterval: TimeInterval = 4.0

    /// Multicast echo timeout for carrier detection
    public static let multicastEchoTimeout: TimeInterval = 6.5

    /// Deduplication buffer length
    public static let multiIfDequeLen: Int = 48

    /// Deduplication buffer TTL
    public static let multiIfDequeTTL: TimeInterval = 0.75

    /// Estimated bitrate for AutoInterface (10 Mbps)
    public static let bitrateGuess: Int = 10_000_000

    /// Warmup time multiplier before starting peer jobs (announceInterval * 1.2)
    public static let warmupMultiplier: Double = 1.2

    /// Reverse peering interval (~5.2 seconds, matching Python)
    public static let reversePeeringInterval: TimeInterval = 5.2
}

// MARK: - Multicast Address Computation

extension AutoInterfaceConstants {
    /// Compute the IPv6 multicast group address from a group ID.
    ///
    /// The address format is `ff12:0:<6 hex segments from SHA-256>`.
    /// - `ff` = multicast prefix
    /// - `1` = temporary (transient) flag
    /// - `2` = link-local scope
    ///
    /// Each 16-bit segment is computed as `hash[odd] + hash[even] << 8`
    /// (little-endian pairs from bytes 2-13 of the SHA-256 digest).
    ///
    /// This must match Python exactly for interoperability:
    /// ```python
    /// addr_bytes = hashlib.sha256(AutoInterface.DEFAULT_GROUP_ID.encode("utf-8")).digest()
    /// "ff12:0" + ":" + hex(b[3]+b[2]<<8) + ...
    /// ```
    ///
    /// - Parameter groupId: Group identifier string (default: "reticulum")
    /// - Returns: IPv6 multicast address string (e.g., "ff12:0:abcd:ef01:...")
    public static func multicastAddress(for groupId: String = defaultGroupId) -> String {
        let groupData = groupId.data(using: .utf8) ?? Data()
        let hash = Hashing.fullHash(groupData)
        let b = Array(hash)

        // Build 6 segments from bytes 2-13, using little-endian pairs
        // Python: hex(b[3]+b[2]*256), hex(b[5]+b[4]*256), ...
        let segments = (0..<6).map { i -> String in
            let lo = Int(b[2 + i * 2 + 1])   // odd byte
            let hi = Int(b[2 + i * 2]) << 8   // even byte << 8
            return String(lo + hi, radix: 16)
        }

        return "ff12:0:" + segments.joined(separator: ":")
    }

    /// Compute discovery token for a given group ID and link-local address.
    ///
    /// Token is SHA-256(groupIdBytes + addressString.utf8).
    /// Both the local node and remote peers compute this independently
    /// to validate discovery beacons.
    ///
    /// - Parameters:
    ///   - groupId: Group identifier bytes (UTF-8 encoded group name)
    ///   - address: IPv6 link-local address string
    /// - Returns: 32-byte discovery token
    public static func discoveryToken(groupId: Data, address: String) -> Data {
        var input = groupId
        input.append(address.data(using: .utf8) ?? Data())
        return Hashing.fullHash(input)
    }
}
