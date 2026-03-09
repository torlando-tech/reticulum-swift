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

    // MARK: - Transport Table Timeouts (Transport.py:86-93)

    /// Reverse table entry timeout (8 minutes, Python REVERSE_TIMEOUT)
    public static let REVERSE_TIMEOUT: TimeInterval = 480

    /// Link table stale timeout (Python STALE_TIME * 1.25 ≈ 15 min)
    public static let LINK_TIMEOUT: TimeInterval = 900

    /// Maximum packet hashes tracked for deduplication (Python hashlist_maxsize)
    public static let HASHLIST_MAXSIZE: Int = 1_000_000

    // MARK: - Path Request (Transport.py:73-75)

    /// Minimum interval between path requests for same destination (seconds)
    /// Python reference: Transport.PATH_REQUEST_MI = 20
    public static let PATH_REQUEST_MI: TimeInterval = 20.0

    /// Extra grace delay for path requests on roaming interfaces (seconds)
    /// Python reference: Transport.PATH_REQUEST_RG = 1.5
    public static let PATH_REQUEST_RG: TimeInterval = 1.5

    /// Interface modes eligible for path discovery forwarding.
    /// When a path request arrives on one of these interface modes and the path
    /// is unknown, the transport node will forward the request on all other
    /// interfaces to proactively discover the path.
    /// Python reference: Interface.DISCOVER_PATHS_FOR = [MODE_ACCESS_POINT, MODE_GATEWAY, MODE_ROAMING]
    /// Note: MODE_FULL is NOT included — full-mode interfaces do not trigger proactive discovery.
    public static let DISCOVER_PATHS_FOR: [InterfaceMode] = [.accessPoint, .gateway, .roaming]

    // MARK: - Announce Queue (Transport.py:94-95)

    /// Maximum queued announces per interface when bandwidth capped
    /// Python reference: Transport.MAX_QUEUED_ANNOUNCES = 16384
    public static let MAX_QUEUED_ANNOUNCES: Int = 16384

    /// Maximum age of queued announce before expiry (seconds)
    /// Python reference: Transport.QUEUED_ANNOUNCE_LIFE = 86400
    public static let QUEUED_ANNOUNCE_LIFE: TimeInterval = 86400

    // MARK: - IFAC (Reticulum.py:151-154)

    /// Minimum IFAC size in bytes
    /// Python reference: Reticulum.IFAC_MIN_SIZE = 1
    public static let IFAC_MIN_SIZE: Int = 1

    /// Default IFAC size in bytes (128 bits)
    /// Python reference: TCPInterface.DEFAULT_IFAC_SIZE = 16
    public static let DEFAULT_IFAC_SIZE: Int = 16

    /// IFAC salt for HKDF derivation
    /// Python reference: Reticulum.IFAC_SALT
    public static let IFAC_SALT: Data = Data([
        0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80,
        0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
        0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f,
        0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8
    ])

    // MARK: - Path States (Transport.py:83-85)

    /// Path state unknown (default)
    public static let PATH_STATE_UNKNOWN: Int = 0x00

    /// Path marked unresponsive after failed communication
    public static let PATH_STATE_UNRESPONSIVE: Int = 0x01

    /// Path confirmed responsive
    public static let PATH_STATE_RESPONSIVE: Int = 0x02
}
