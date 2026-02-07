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
    public init(
        id: String,
        name: String,
        type: InterfaceType,
        enabled: Bool,
        mode: InterfaceMode,
        host: String,
        port: UInt16,
        ifac: Data? = nil
    ) {
        self.id = id
        self.name = name
        self.type = type
        self.enabled = enabled
        self.mode = mode
        self.host = host
        self.port = port
        self.ifac = ifac
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
