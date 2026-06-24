// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  InterfaceConfig.swift
//  ReticulumSwift
//
//  Configuration struct for Reticulum interfaces.
//  Supports persistence via PropertyList encoding/decoding.
//

import Foundation

// MARK: - Interface Type

/// Type of network interface.
///
/// Different interface types use different underlying transport mechanisms:
/// - `tcp`: TCP socket connection (Phase 4 focus)
/// - `udp`: UDP datagram interface (future)
/// - `i2p`: I2P anonymous network interface (future)
/// - `rnode`: RNode BLE interface (Phase 11)
public enum InterfaceType: String, Codable, Sendable, Equatable {
    case tcp
    case udp
    case i2p
    case autoInterface
    case rnode
    case ble
    case multipeerConnectivity
}

// MARK: - Interface Configuration

/// Configuration for a Reticulum network interface.
///
/// InterfaceConfig captures all settings needed to establish and manage
/// a network interface connection. Configurations are persisted as property
/// lists for runtime-independent storage.
///
/// Example usage:
/// ```swift
/// let config = InterfaceConfig(
///     id: "relay1",
///     name: "Primary Relay",
///     type: .tcp,
///     enabled: true,
///     mode: .full,
///     host: "relay.example.com",
///     port: 4242,
///     ifac: nil
/// )
/// try InterfaceConfig.saveToFile(config, url: configURL)
/// ```
public struct InterfaceConfig: Codable, Sendable, Equatable {

    // MARK: - Properties

    /// Unique identifier for this interface
    public let id: String

    /// Human-readable name for display
    public let name: String

    /// Type of interface (tcp, udp, i2p)
    public let type: InterfaceType

    /// Whether this interface is enabled
    public var enabled: Bool

    /// Interface mode controlling announce propagation
    public let mode: InterfaceMode

    /// Host address to connect to
    public let host: String

    /// Port number to connect to
    public let port: UInt16

    /// Optional Interface Access Code for authentication
    public let ifac: Data?

    /// Optional announce rate target: minimum interval (seconds) between announces
    /// from the same destination. nil = no rate limiting.
    /// Reference: Python Interface.announce_rate_target
    public var announceRateTarget: TimeInterval?

    /// Number of rate violations allowed before blocking (default 0).
    /// Reference: Python Interface.announce_rate_grace
    public var announceRateGrace: Int

    /// Penalty time (seconds) added when rate limit is exceeded (default 0).
    /// Reference: Python Interface.announce_rate_penalty
    public var announceRatePenalty: TimeInterval

    /// C14: Estimated bitrate (bits/second) for announce bandwidth cap calculation.
    /// 0 means unknown/unlimited (no cap applied).
    /// Reference: Python Interface.bitrate
    public var bitrate: Int

    /// C14: Per-interface announce bandwidth cap as a FRACTION of link bandwidth.
    /// Used in the egress-spacing calc `announce_allowed_at = now + (tx_time / announce_cap)`.
    /// Defaults to RNS `Reticulum.ANNOUNCE_CAP/100 = 0.02` (Reticulum.py:1052), but a
    /// per-interface config can override it (a smaller cap widens the spacing).
    /// Reference: Python Interface.announce_cap (Transport.py:1257 / Interface.py:347).
    public var announceCap: Double

    /// E8: IFAC (Interface Access Code) signature size in bytes.
    /// 0 means no IFAC validation on this interface.
    /// Reference: Python Interface.ifac_size
    public var ifacSize: Int

    /// E8: IFAC key material for HKDF-derived authentication.
    /// nil means no IFAC on this interface.
    /// Reference: Python Interface.ifac_key
    public var ifacKey: Data?

    /// Configured fixed hardware MTU (`fixed_mtu`) in bytes, or nil to
    /// autoconfigure. When set, `FIXED_MTU` is true and `AUTOCONFIGURE_MTU`
    /// is forced false (see `init`): the interface's live `hwMtu` is exactly
    /// this value rather than the bitrate-autoconfigured one. Must be
    /// `>= Reticulum.MTU` (500); a smaller value is rejected by the
    /// constructing interface's throwing initializer.
    /// Reference: Python TCPInterface.fixed_mtu / FIXED_MTU (TCPInterface.py:110-116).
    public var fixedMtu: Int?

    /// Whether this interface autoconfigures its hardware MTU from its bitrate
    /// (`AUTOCONFIGURE_MTU`). Defaults true to match the TCP*Interface class
    /// constant (TCPInterface.py:78, :455). Forced false when `fixedMtu` is set.
    /// Reference: Python Interface.AUTOCONFIGURE_MTU (Interface.py:89).
    public var autoconfigureMtu: Bool

    // MARK: - Initialization

    /// Create a new interface configuration.
    ///
    /// - Parameters:
    ///   - id: Unique identifier
    ///   - name: Human-readable name
    ///   - type: Interface type
    ///   - enabled: Whether interface is enabled
    ///   - mode: Interface mode
    ///   - host: Host address
    ///   - port: Port number
    ///   - ifac: Optional Interface Access Code
    ///   - announceRateTarget: Optional minimum interval between announces
    ///   - announceRateGrace: Rate violations before blocking
    ///   - announceRatePenalty: Penalty time on rate limit
    public init(
        id: String,
        name: String,
        type: InterfaceType,
        enabled: Bool,
        mode: InterfaceMode,
        host: String,
        port: UInt16,
        ifac: Data? = nil,
        announceRateTarget: TimeInterval? = nil,
        announceRateGrace: Int = 0,
        announceRatePenalty: TimeInterval = 0,
        bitrate: Int = 0,
        announceCap: Double = TransportConstants.ANNOUNCE_CAP,
        ifacSize: Int = 0,
        ifacKey: Data? = nil,
        fixedMtu: Int? = nil,
        autoconfigureMtu: Bool = true
    ) {
        self.id = id
        self.name = name
        self.type = type
        self.enabled = enabled
        self.mode = mode
        self.host = host
        self.port = port
        self.ifac = ifac
        self.announceRateTarget = announceRateTarget
        self.announceRateGrace = announceRateGrace
        self.announceRatePenalty = announceRatePenalty
        self.bitrate = bitrate
        self.announceCap = announceCap
        self.ifacSize = ifacSize
        self.ifacKey = ifacKey
        self.fixedMtu = fixedMtu
        // Mirror TCPInterface.py:112-114: a configured fixed_mtu forces
        // FIXED_MTU=true / AUTOCONFIGURE_MTU=false regardless of the requested
        // autoconfigure flag.
        self.autoconfigureMtu = fixedMtu != nil ? false : autoconfigureMtu
    }

    // MARK: - Codable backward compatibility

    /// Custom decoder handles missing rate-limit keys from old plists.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        type = try container.decode(InterfaceType.self, forKey: .type)
        enabled = try container.decode(Bool.self, forKey: .enabled)
        mode = try container.decode(InterfaceMode.self, forKey: .mode)
        host = try container.decode(String.self, forKey: .host)
        port = try container.decode(UInt16.self, forKey: .port)
        ifac = try container.decodeIfPresent(Data.self, forKey: .ifac)
        announceRateTarget = try container.decodeIfPresent(TimeInterval.self, forKey: .announceRateTarget)
        announceRateGrace = try container.decodeIfPresent(Int.self, forKey: .announceRateGrace) ?? 0
        announceRatePenalty = try container.decodeIfPresent(TimeInterval.self, forKey: .announceRatePenalty) ?? 0
        bitrate = try container.decodeIfPresent(Int.self, forKey: .bitrate) ?? 0
        announceCap = try container.decodeIfPresent(Double.self, forKey: .announceCap) ?? TransportConstants.ANNOUNCE_CAP
        ifacSize = try container.decodeIfPresent(Int.self, forKey: .ifacSize) ?? 0
        ifacKey = try container.decodeIfPresent(Data.self, forKey: .ifacKey)
        // Backward-compatible: old plists predate the MTU fields. Default
        // fixedMtu=nil / autoconfigureMtu=true (the TCP class default), then
        // re-apply the fixed-MTU invariant (TCPInterface.py:112-114).
        fixedMtu = try container.decodeIfPresent(Int.self, forKey: .fixedMtu)
        let decodedAutoconfigure = try container.decodeIfPresent(Bool.self, forKey: .autoconfigureMtu) ?? true
        autoconfigureMtu = fixedMtu != nil ? false : decodedAutoconfigure
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, type, enabled, mode, host, port, ifac
        case announceRateTarget, announceRateGrace, announceRatePenalty
        case bitrate, announceCap, ifacSize, ifacKey
        case fixedMtu, autoconfigureMtu
    }

    // MARK: - Persistence

    /// Save configuration to a property list file.
    ///
    /// - Parameters:
    ///   - config: Configuration to save
    ///   - url: File URL to save to
    /// - Throws: Encoding or file write errors
    public static func saveToFile(_ config: InterfaceConfig, url: URL) throws {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .xml
        let data = try encoder.encode(config)
        try data.write(to: url)
    }

    /// Load configuration from a property list file.
    ///
    /// - Parameter url: File URL to load from
    /// - Returns: Decoded configuration
    /// - Throws: Decoding or file read errors
    public static func loadFromFile(url: URL) throws -> InterfaceConfig {
        let data = try Data(contentsOf: url)
        let decoder = PropertyListDecoder()
        return try decoder.decode(InterfaceConfig.self, from: data)
    }
}

// MARK: - CustomStringConvertible

extension InterfaceConfig: CustomStringConvertible {
    public var description: String {
        let status = enabled ? "enabled" : "disabled"
        return "InterfaceConfig<\(id): \(name) \(type)://\(host):\(port) mode:\(mode) \(status)>"
    }
}
