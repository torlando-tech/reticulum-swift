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

    /// E8: IFAC (Interface Access Code) signature size in bytes.
    /// 0 means no IFAC validation on this interface.
    /// Reference: Python Interface.ifac_size
    public var ifacSize: Int

    /// E8: IFAC key material for HKDF-derived authentication.
    /// nil means no IFAC on this interface.
    /// Reference: Python Interface.ifac_key
    public var ifacKey: Data?

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
        ifacSize: Int = 0,
        ifacKey: Data? = nil
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
        self.ifacSize = ifacSize
        self.ifacKey = ifacKey
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
        ifacSize = try container.decodeIfPresent(Int.self, forKey: .ifacSize) ?? 0
        ifacKey = try container.decodeIfPresent(Data.self, forKey: .ifacKey)
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, type, enabled, mode, host, port, ifac
        case announceRateTarget, announceRateGrace, announceRatePenalty
        case bitrate, ifacSize, ifacKey
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
