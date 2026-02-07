//
//  TransportConstants.swift
//  ReticulumSwift
//
//  Named constants matching Python RNS Transport.py for announce forwarding,
//  path management, and retransmission scheduling.
//

import Foundation

// MARK: - Transport Constants

/// Named constants matching Python RNS Transport.py.
///
/// Reference: Transport.py lines 62-93
public enum TransportConstants {
    // MARK: - Pathfinder (Transport.py:62-72)

    /// Maximum number of hops a packet can traverse
    public static let PATHFINDER_M: UInt8 = 128

    /// Number of retransmit retries for announce rebroadcast
    public static let PATHFINDER_R: Int = 1

    /// Grace period (seconds) before next retransmit attempt
    public static let PATHFINDER_G: TimeInterval = 5.0

    /// Random window (seconds) for jittered announce rebroadcast timing
    public static let PATHFINDER_RW: TimeInterval = 0.5

    /// Standard path expiration: 7 days (seconds)
    public static let PATHFINDER_E: TimeInterval = 604_800

    /// Access point path expiration: 1 day (seconds)
    public static let AP_PATH_TIME: TimeInterval = 86_400

    /// Roaming path expiration: 6 hours (seconds)
    public static let ROAMING_PATH_TIME: TimeInterval = 21_600

    // MARK: - Announce (Transport.py:76-93)

    /// Maximum local rebroadcasts of an announce before removal
    public static let LOCAL_REBROADCASTS_MAX: Int = 2

    /// Maximum random blobs per destination kept in memory
    public static let MAX_RANDOM_BLOBS: Int = 64

    /// Announce bandwidth cap fraction (2% of bitrate)
    public static let ANNOUNCE_CAP: Double = 0.02

    /// Maximum rate timestamps kept per destination for rate limiting
    public static let MAX_RATE_TIMESTAMPS: Int = 16

    // MARK: - Path States (Transport.py:83-85)

    /// Path state unknown (default)
    public static let PATH_STATE_UNKNOWN: Int = 0x00

    /// Path marked unresponsive after failed communication
    public static let PATH_STATE_UNRESPONSIVE: Int = 0x01

    /// Path confirmed responsive
    public static let PATH_STATE_RESPONSIVE: Int = 0x02
}
