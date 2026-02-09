//
//  LinkConstants.swift
//  ReticulumSwift
//
//  RNS-compatible constants for link operations.
//  Values match Python RNS Link.py exactly for interoperability.
//

import Foundation

// MARK: - Link Constants

/// Constants for RNS link operations.
///
/// These values are designed to match Python RNS Link.py exactly,
/// ensuring interoperability between Swift and Python implementations.
public enum LinkConstants {

    // MARK: - Timing Constants

    /// Timeout per hop for link establishment.
    ///
    /// The total establishment timeout is calculated as:
    /// `ESTABLISHMENT_TIMEOUT_PER_HOP * (hops + 1)`
    public static let ESTABLISHMENT_TIMEOUT_PER_HOP: TimeInterval = 6.0

    /// Minimum keep-alive interval in seconds.
    ///
    /// Even on very fast links, keep-alive packets are not sent
    /// more frequently than this interval.
    public static let KEEPALIVE_MIN: TimeInterval = 5.0

    /// Maximum keep-alive interval in seconds.
    ///
    /// Even on very slow links, keep-alive packets are sent
    /// at least this frequently.
    public static let KEEPALIVE_MAX: TimeInterval = 360.0

    /// Maximum RTT used for keep-alive calculation.
    ///
    /// RTT values are capped at this when computing the keep-alive
    /// interval to prevent excessive delays on high-latency links.
    public static let KEEPALIVE_MAX_RTT: TimeInterval = 1.75

    /// Grace period after link becomes stale before closing.
    ///
    /// When a link enters stale state, this additional period is
    /// allowed for traffic to resume before the link is closed.
    public static let STALE_GRACE: TimeInterval = 5.0

    /// Maximum sleep time for link watchdog.
    ///
    /// The watchdog timer will wake at least this frequently
    /// to check link health, even if no packets are expected.
    public static let WATCHDOG_MAX_SLEEP: TimeInterval = 5.0

    // MARK: - Size Constants

    /// Link MDU — max plaintext payload for link-encrypted packets.
    ///
    /// Python: `floor((MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1`
    /// = `floor((500 - 1 - 19 - 48) / 16) * 16 - 1 = 431`
    ///
    /// This is smaller than `Reticulum.MDU` (464) because link-encrypted packets
    /// have additional overhead from AES-CBC IV (16B) + HMAC (32B) + PKCS7 padding.
    /// Used for hashmap segmentation (advertisements/HMU must fit in one encrypted packet).
    public static let LINK_MDU: Int = 431

    /// Size of elliptic curve public keys in bytes.
    ///
    /// This is 64 bytes total: 32 bytes for the encryption public key
    /// (X25519) plus 32 bytes for the signing public key (Ed25519).
    public static let ECPUBSIZE: Int = 64

    /// Size of symmetric encryption keys in bytes.
    ///
    /// Used for the 256-bit AES key derived via HKDF.
    public static let KEYSIZE: Int = 32

    /// Size of MTU signaling data in bytes.
    ///
    /// The MTU is encoded as a 3-byte big-endian integer in
    /// the link establishment exchange.
    public static let LINK_MTU_SIZE: Int = 3

    /// Size of Ed25519 signatures in bytes.
    public static let SIGNATURE_SIZE: Int = 64

    // MARK: - Magic Bytes

    /// Keep-alive marker byte sent by link initiator.
    ///
    /// The initiator sends this byte as the packet body to signal
    /// a keep-alive message. The responder echoes with its own marker.
    public static let KEEPALIVE_INITIATOR: UInt8 = 0xFF

    /// Keep-alive marker byte sent by link responder.
    ///
    /// The responder sends this byte as the packet body in response
    /// to an initiator keep-alive.
    public static let KEEPALIVE_RESPONDER: UInt8 = 0xFE

    // MARK: - Packet Context Values
    //
    // These values match Python RNS Packet.py exactly for interoperability.

    /// Context for keep-alive packets (0xFA).
    ///
    /// Keep-alive packets maintain link liveness and are sent periodically
    /// based on the calculated keepalive interval.
    public static let CONTEXT_KEEPALIVE: UInt8 = 0xFA

    /// Context for link peer identification proof (0xFB).
    ///
    /// Used when a link initiator proves their identity to the responder
    /// via the Link.identify() method.
    public static let CONTEXT_LINKIDENTIFY: UInt8 = 0xFB

    /// Context for link close message (0xFC).
    ///
    /// Sent when gracefully closing a link to notify the peer.
    public static let CONTEXT_LINKCLOSE: UInt8 = 0xFC

    /// Context for RTT measurement packet during link establishment (0xFE).
    ///
    /// After receiving and validating a PROOF, the initiator sends
    /// an LRRTT packet containing the msgpack-encoded RTT value.
    /// This triggers the responder's link_established callback.
    public static let CONTEXT_LRRTT: UInt8 = 0xFE

    /// Context for PROOF packet during link establishment (0xFF).
    ///
    /// This is the LRPROOF context used by the responder
    /// when sending the PROOF packet to the initiator.
    public static let CONTEXT_LRPROOF: UInt8 = 0xFF

    // MARK: - Link Encryption Modes

    /// AES-128-CBC encryption mode (not enabled in standard RNS)
    public static let MODE_AES128_CBC: UInt8 = 0

    /// AES-256-CBC encryption mode (default and only enabled mode in standard RNS)
    public static let MODE_AES256_CBC: UInt8 = 1

    /// AES-256-GCM encryption mode (reserved for future use)
    public static let MODE_AES256_GCM: UInt8 = 2

    /// Default encryption mode - AES-256-CBC as required by Python RNS
    public static let MODE_DEFAULT: UInt8 = MODE_AES256_CBC

    // MARK: - Default Values

    /// Default MTU signaling data.
    ///
    /// The 3-byte signaling encodes both the encryption mode and MTU:
    /// - Bits 23-21: Encryption mode (3 bits)
    /// - Bits 20-0: MTU value (21 bits)
    ///
    /// For mode=1 (AES_256_CBC) and MTU=500:
    /// - (1 << 21) | 500 = 0x2001F4
    /// - Bytes: [0x20, 0x01, 0xF4]
    ///
    /// Python RNS only enables mode 1 (AES_256_CBC), so we must use that mode.
    public static let DEFAULT_MTU_SIGNALING: Data = Data([0x20, 0x01, 0xF4])

    // MARK: - Computed Functions

    /// Calculate the keep-alive interval for a given RTT.
    ///
    /// The keep-alive interval scales with RTT to avoid excessive
    /// overhead on slow links while maintaining reasonable responsiveness.
    ///
    /// Formula: `max(min(rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MAX), KEEPALIVE_MIN)`
    ///
    /// - Parameter rtt: The measured round-trip time in seconds.
    /// - Returns: The keep-alive interval to use in seconds.
    public static func keepaliveInterval(forRTT rtt: TimeInterval) -> TimeInterval {
        let calculated = rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)
        return max(min(calculated, KEEPALIVE_MAX), KEEPALIVE_MIN)
    }
}
