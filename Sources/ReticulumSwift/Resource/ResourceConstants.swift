// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ResourceConstants.swift
//  ReticulumSwift
//
//  RNS-compatible constants for resource operations.
//  Values match Python RNS Resource.py exactly for interoperability.
//

import Foundation

// MARK: - Resource Constants

/// Constants for RNS resource operations.
///
/// These values are designed to match Python RNS Resource.py exactly,
/// ensuring interoperability between Swift and Python implementations.
public enum ResourceConstants {

    // MARK: - Window Constants

    /// Initial window size at transfer start.
    ///
    /// Resources begin with a conservative window and expand based on
    /// measured performance to avoid overwhelming slow links.
    public static let WINDOW_INITIAL: Int = 4

    /// Minimum window size.
    ///
    /// Even under poor conditions, at least this many parts can be
    /// outstanding to maintain forward progress.
    public static let WINDOW_MIN: Int = 2

    /// Maximum window size for slow connections.
    ///
    /// This is the default ceiling for most transfers. Fast connections
    /// can be upgraded to WINDOW_MAX_FAST after sustained good performance.
    public static let WINDOW_MAX_SLOW: Int = 10

    /// Maximum window size for fast connections.
    ///
    /// After demonstrating sustained fast transfer rates, the window
    /// can expand to this size for maximum throughput.
    public static let WINDOW_MAX_FAST: Int = 75

    /// Maximum window size for very slow connections.
    ///
    /// Extremely slow links are restricted to this smaller window
    /// to avoid excessive buffering and timeouts.
    public static let WINDOW_MAX_VERY_SLOW: Int = 4

    /// Window flexibility factor.
    ///
    /// Used in window size calculations to provide headroom for
    /// rate fluctuations.
    public static let WINDOW_FLEXIBILITY: Int = 4

    // MARK: - Rate Thresholds

    /// Threshold for considering a connection "fast" (bytes/second).
    ///
    /// Links sustaining this rate or higher are eligible for window
    /// upgrade to WINDOW_MAX_FAST. This is 50 Kbps / 8 = 6250 bytes/sec.
    public static let RATE_FAST: Double = 50000.0 / 8.0  // 6250 bytes/sec

    /// Threshold for considering a connection "very slow" (bytes/second).
    ///
    /// Links below this rate are restricted to WINDOW_MAX_VERY_SLOW.
    /// This is 2 Kbps / 8 = 250 bytes/sec.
    public static let RATE_VERY_SLOW: Double = 2000.0 / 8.0  // 250 bytes/sec

    /// Number of consecutive fast rounds required to upgrade window.
    ///
    /// The connection must sustain fast rates for this many measurement
    /// rounds before the window is expanded to WINDOW_MAX_FAST.
    /// Calculated as: WINDOW_MAX_SLOW - WINDOW_INITIAL - 2 = 10 - 4 - 2 = 4
    public static let FAST_RATE_THRESHOLD: Int = 4

    /// Number of consecutive very slow rounds to downgrade window.
    ///
    /// If the connection is very slow for this many rounds, the window
    /// is reduced to WINDOW_MAX_VERY_SLOW.
    public static let VERY_SLOW_RATE_THRESHOLD: Int = 2

    // MARK: - Size Constants

    /// Size of hashmap entry per part (bytes).
    ///
    /// Each part's hash is truncated SHA-256, using the first 4 bytes.
    /// The hashmap allows the receiver to validate each part's integrity.
    public static let MAPHASH_LEN: Int = 4

    /// Size of random hash appended to resource data (bytes).
    ///
    /// A 4-byte random value is appended to the data before hashing
    /// to create the resource hash, preventing hash collisions.
    public static let RANDOM_HASH_SIZE: Int = 4

    /// Resource data unit size (bytes).
    ///
    /// This will be computed from Link.MDU at runtime. The SDU is the
    /// maximum size of each resource part transmitted in a DATA packet.
    /// Set to 0 as a placeholder; actual value depends on link MTU.
    public static let SDU: Int = 0

    /// Maximum size for efficient resource transfer (bytes).
    ///
    /// Resources larger than this are still supported but may experience
    /// degraded performance due to overhead. This is 1 MB - 1 byte.
    public static let MAX_EFFICIENT_SIZE: Int = 1 * 1024 * 1024 - 1  // 1048575 bytes

    /// Maximum size for automatic compression (bytes).
    ///
    /// Resources larger than this will not be automatically compressed,
    /// as the compression operation would consume excessive memory and time.
    /// This is 64 MB.
    public static let AUTO_COMPRESS_MAX_SIZE: Int = 64 * 1024 * 1024

    // MARK: - Timing Constants

    /// Timeout waiting for resource proof (seconds).
    ///
    /// After all parts are transmitted, the receiver must send a proof
    /// within this timeout to confirm successful assembly.
    public static let PROOF_TIMEOUT: TimeInterval = 3.0

    /// Timeout waiting for a part acknowledgment (seconds).
    ///
    /// If a part is not acknowledged within this timeout, it is
    /// considered lost and will be retransmitted.
    public static let PART_TIMEOUT: TimeInterval = 3.0

    /// Maximum number of retransmission attempts per part.
    ///
    /// After this many failed attempts, the resource transfer is
    /// considered failed and the resource is closed.
    public static let RETRY_LIMIT: Int = 16

    /// Maximum grace time for delayed responses (seconds).
    ///
    /// Additional time allowed for response packets to arrive beyond
    /// the normal timeout, accounting for network jitter.
    public static let RESPONSE_MAX_GRACE_TIME: TimeInterval = 10.0

    // MARK: - Advertisement Constants

    /// Overhead bytes for resource advertisement structure.
    ///
    /// The MessagePack-encoded advertisement dict has fixed overhead
    /// for field names and structure. This constant is used to calculate
    /// how many part hashes can fit in a single advertisement packet.
    public static let ADVERTISEMENT_OVERHEAD: Int = 134

    // MARK: - Resource Flags

    /// Flag bit: Resource data is encrypted.
    ///
    /// When set, the resource data has been encrypted with the link key.
    public static let FLAG_ENCRYPTED: UInt8 = 0x01

    /// Flag bit: Resource data is compressed.
    ///
    /// When set, the resource data has been compressed with bz2.
    public static let FLAG_COMPRESSED: UInt8 = 0x02

    /// Flag bit: Resource hashmap is split across multiple advertisements.
    ///
    /// When set, the hashmap is too large for a single advertisement
    /// and requires multiple segments.
    public static let FLAG_SPLIT: UInt8 = 0x04

    /// Flag bit: Resource is a request.
    ///
    /// Used with Link.request() to identify request resources.
    public static let FLAG_REQUEST: UInt8 = 0x08

    /// Flag bit: Resource is a response.
    ///
    /// Used with Link.response() to identify response resources.
    public static let FLAG_RESPONSE: UInt8 = 0x10

    /// Flag bit: Resource contains metadata.
    ///
    /// Reserved for future use.
    public static let FLAG_METADATA: UInt8 = 0x20
}
