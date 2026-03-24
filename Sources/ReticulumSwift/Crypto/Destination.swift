// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Destination.swift
//  ReticulumSwift
//
//  Reticulum destination with full state management.
//  Destinations identify message recipients and are derived from identity public keys
//  and name aspects.
//
//  Matches Python RNS Destination.py for byte-perfect interoperability.
//

import Foundation

// MARK: - Destination Types

/// Destination types matching RNS
public enum DestType: UInt8, Sendable {
    case single = 0x00   // Single destination (specific identity)
    case group = 0x01    // Group destination (shared key)
    case plain = 0x02    // Plain destination (unencrypted)
    case link = 0x03     // Link destination (for link establishment)
}

/// Direction for callback registration
public enum DestinationDirection: Sendable {
    case `in`   // Incoming packets
    case out    // Outgoing packets
}

// MARK: - Destination Errors

/// Errors during destination operations
public enum DestinationError: Error, Sendable, Equatable {
    /// SINGLE/GROUP destination requires an identity
    case identityRequired

    /// PLAIN destinations cannot announce (no identity to sign)
    case plainCannotAnnounce

    /// Invalid app name (empty or contains invalid characters)
    case invalidAppName

    /// Callback manager not set
    case callbackManagerNotSet
}

// MARK: - Callback Types

/// Packet callback type - receives decrypted data and original packet
public typealias PacketCallback = @Sendable (Data, Packet) -> Void

/// Protocol for destination callback manager
public protocol DestinationCallbackManager: AnyObject, Sendable {
    func register(destinationHash: Data, callback: @escaping PacketCallback)
    func createStream(for destinationHash: Data) -> AsyncStream<(Data, Packet)>
}

// MARK: - Destination Class

/// Reticulum destination with full state management.
///
/// A Destination identifies a message recipient and is derived from an identity
/// and name aspects. It holds all state needed for announcing, receiving packets,
/// and managing callbacks.
///
/// Destination types:
/// - **SINGLE**: One-to-one encrypted communication with a specific identity
/// - **PLAIN**: Unencrypted broadcast (no identity required)
/// - **GROUP**: Shared-key encrypted group communication
/// - **LINK**: Over an established link (special case)
public final class Destination: @unchecked Sendable {

    // MARK: - Properties

    /// The identity this destination belongs to (nil for PLAIN destinations)
    public let identity: Identity?

    /// Application name (first aspect of the destination name)
    public let appName: String

    /// Additional name aspects (e.g., ["delivery"] for lxmf.delivery)
    public let aspects: [String]

    /// Destination type (single, plain, group, link)
    public let destinationType: DestType

    /// Direction for callback registration
    public var direction: DestinationDirection

    /// Optional application data to include in announces
    public var appData: Data?

    /// Callback manager for packet delivery (weak reference, set externally)
    public weak var callbackManager: (any DestinationCallbackManager)?

    /// Ratchet manager for forward secrecy (nil if ratchets not enabled)
    public var ratchetManager: RatchetManager?

    /// Whether ratchets are enabled for this destination
    public private(set) var ratchetsEnabled: Bool = false

    /// Whether ratchets are enforced (reject non-ratcheted messages)
    public private(set) var ratchetsEnforced: Bool = false

    // MARK: - Computed Properties

    /// 16-byte destination hash
    ///
    /// Computed based on destination type:
    /// - SINGLE: truncated_hash(nameHash + identityHash)
    /// - PLAIN/GROUP: truncated_hash(nameHash)
    public var hash: Data {
        switch destinationType {
        case .single, .link:
            guard let identity = identity else {
                // Fallback to plain hash if no identity (shouldn't happen for SINGLE)
                return computePlainHash()
            }
            return Destination.hash(identity: identity, appName: appName, aspects: aspects)

        case .plain, .group:
            return computePlainHash()
        }
    }

    /// 64-byte concatenated public keys (encryption || signing)
    /// Returns nil for PLAIN destinations (no identity)
    public var publicKeys: Data? {
        return identity?.publicKeys
    }

    /// 10-byte name hash for destination hash computation.
    ///
    /// Computes SHA-256 of the full dotted name (e.g., "lxmf.delivery") and returns
    /// the first 10 bytes (NAME_HASH_LENGTH = 80 bits).
    ///
    /// This is used for computing destination hashes. For announce payloads,
    /// use `announceNameHash` instead which uses concatenated 16-byte aspect hashes.
    ///
    /// Python RNS equivalent:
    /// ```python
    /// self.name_hash = RNS.Identity.full_hash(
    ///     self.expand_name(None, app_name, *aspects).encode("utf-8")
    /// )[:(RNS.Identity.NAME_HASH_LENGTH//8)]
    /// ```
    public var nameHash: Data {
        return Hashing.destinationNameHash(appName: appName, aspects: aspects)
    }

    /// Full destination name as a dot-separated string
    ///
    /// Format: "appName.aspect1.aspect2...."
    public var fullName: String {
        if aspects.isEmpty {
            return appName
        }
        return appName + "." + aspects.joined(separator: ".")
    }

    /// Name hash for use in announce packets.
    ///
    /// Concatenated 16-byte truncated hashes of each aspect (including app name).
    /// This matches Python RNS announce format for the name_hash field in announce payloads.
    /// Total length = 16 bytes * number of aspects (app_name counts as first aspect).
    ///
    /// Note: This is DIFFERENT from the `nameHash` property which is used for
    /// destination hash computation (10 bytes of full name hash).
    public var announceNameHash: Data {
        return Hashing.aspectNameHash(appName: appName, aspects: aspects)
    }

    /// Hex string representation of the destination hash
    public var hexHash: String {
        hash.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Initialization

    /// Create a destination with identity (for SINGLE, GROUP, LINK types)
    ///
    /// - Parameters:
    ///   - identity: The identity this destination belongs to
    ///   - appName: Application name (first aspect)
    ///   - aspects: Additional name aspects
    ///   - type: Destination type (defaults to .single)
    ///   - direction: Direction for callbacks (defaults to .in)
    public init(
        identity: Identity,
        appName: String,
        aspects: [String] = [],
        type: DestType = .single,
        direction: DestinationDirection = .in
    ) {
        self.identity = identity
        self.appName = appName
        self.aspects = aspects
        self.destinationType = type
        self.direction = direction
        self.appData = nil
        self.callbackManager = nil
    }

    /// Create a PLAIN destination (no identity required)
    ///
    /// - Parameters:
    ///   - appName: Application name (first aspect)
    ///   - aspects: Additional name aspects
    ///   - direction: Direction for callbacks (defaults to .in)
    public init(
        plainAppName appName: String,
        aspects: [String] = [],
        direction: DestinationDirection = .in
    ) {
        self.identity = nil
        self.appName = appName
        self.aspects = aspects
        self.destinationType = .plain
        self.direction = direction
        self.appData = nil
        self.callbackManager = nil
    }

    // MARK: - Private Helpers

    private func computePlainHash() -> Data {
        return Destination.plainHash(appName: appName, aspects: aspects)
    }

    // MARK: - Callback Management

    /// Set the callback manager for packet delivery
    ///
    /// - Parameter manager: The callback manager to use
    public func setCallbackManager(_ manager: any DestinationCallbackManager) {
        self.callbackManager = manager
    }

    /// Register a callback for incoming packets
    ///
    /// - Parameter callback: Callback to invoke when packets arrive
    /// - Throws: `DestinationError.callbackManagerNotSet` if no manager configured
    public func registerCallback(_ callback: @escaping PacketCallback) throws {
        guard let manager = callbackManager else {
            throw DestinationError.callbackManagerNotSet
        }
        manager.register(destinationHash: self.hash, callback: callback)
    }

    /// Create an async stream of incoming packets
    ///
    /// - Returns: AsyncStream of (decrypted data, original packet) tuples,
    ///            or nil if no callback manager is set
    public func createPacketStream() -> AsyncStream<(Data, Packet)>? {
        guard let manager = callbackManager else {
            return nil
        }
        return manager.createStream(for: self.hash)
    }

    // MARK: - Ratchet Management

    /// Enable ratchets for forward secrecy.
    ///
    /// Loads existing ratchets from disk or generates an initial ratchet.
    /// Once enabled, announces will include the current ratchet public key,
    /// and the decrypt path will try ratchet keys before the base identity key.
    ///
    /// - Parameter storagePath: File path for persistent ratchet storage
    public func enableRatchets(storagePath: String) async throws {
        guard let identity = identity, identity.hasPrivateKeys else { return }
        let manager = RatchetManager(storagePath: storagePath, identity: identity)
        try await manager.loadOrCreate()
        self.ratchetManager = manager
        self.ratchetsEnabled = true
    }

    /// Enforce ratchets — reject messages not encrypted to a ratchet key.
    ///
    /// Only effective if ratchets are already enabled.
    /// When enforced, messages encrypted to the base identity key will be dropped.
    public func enforceRatchets() {
        guard ratchetsEnabled else { return }
        self.ratchetsEnforced = true
    }

    // MARK: - Static Hash Methods (Backward Compatibility)

    /// Calculate destination hash from identity and name aspects.
    ///
    /// Hash = truncated_hash(name_hash(10 bytes) || identity_hash(16 bytes))
    /// where name_hash = full_hash("appName.aspect1.aspect2...")[:10]
    ///
    /// The destination hash uniquely identifies a recipient in the Reticulum network.
    /// It combines the identity's cryptographic hash with the hashed full name to allow
    /// multiple destinations per identity (e.g., different apps on the same device).
    ///
    /// - Parameters:
    ///   - identity: The identity this destination belongs to
    ///   - appName: Application name (first aspect)
    ///   - aspects: Additional name aspects
    /// - Returns: 16-byte destination hash
    public static func hash(
        identity: Identity,
        appName: String,
        aspects: [String] = []
    ) -> Data {
        // Compute 10-byte name hash from full dotted name
        let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)

        // Combine name hash (10 bytes) with identity hash (16 bytes)
        var combined = nameHash
        combined.append(identity.hash)

        // Final destination hash is truncated hash of combined (16 bytes)
        return Hashing.truncatedHash(combined)
    }

    /// Calculate destination hash for a plain destination (no identity).
    /// Used for broadcast/multicast destinations.
    ///
    /// Plain destinations don't have an associated identity, so the hash is
    /// computed only from the name hash (10 bytes).
    ///
    /// - Parameters:
    ///   - appName: Application name
    ///   - aspects: Additional name aspects
    /// - Returns: 16-byte destination hash
    public static func plainHash(
        appName: String,
        aspects: [String] = []
    ) -> Data {
        // Plain destinations use name hash only (10 bytes)
        let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)
        return Hashing.truncatedHash(nameHash)
    }

    /// Calculate destination hash from raw public keys and name aspects.
    ///
    /// This variant is useful when you have public keys but not a full Identity object
    /// (e.g., received from a network announce).
    ///
    /// - Parameters:
    ///   - encryptionPublicKey: 32-byte X25519 public key
    ///   - signingPublicKey: 32-byte Ed25519 public key
    ///   - appName: Application name (first aspect)
    ///   - aspects: Additional name aspects
    /// - Returns: 16-byte destination hash
    public static func hash(
        encryptionPublicKey: Data,
        signingPublicKey: Data,
        appName: String,
        aspects: [String] = []
    ) -> Data {
        // Compute identity hash from public keys (16 bytes)
        let identityHash = Hashing.identityHash(
            encryptionPublicKey: encryptionPublicKey,
            signingPublicKey: signingPublicKey
        )

        // Compute 10-byte name hash from full dotted name
        let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)

        // Combine name hash (10 bytes) with identity hash (16 bytes)
        var combined = nameHash
        combined.append(identityHash)

        // Final destination hash is truncated hash of combined (16 bytes)
        return Hashing.truncatedHash(combined)
    }
}

// MARK: - CustomStringConvertible

extension Destination: CustomStringConvertible {
    public var description: String {
        let typeStr: String
        switch destinationType {
        case .single: typeStr = "SINGLE"
        case .group: typeStr = "GROUP"
        case .plain: typeStr = "PLAIN"
        case .link: typeStr = "LINK"
        }

        var name = appName
        if !aspects.isEmpty {
            name += "." + aspects.joined(separator: ".")
        }

        return "Destination<\(typeStr):\(name):\(hexHash.prefix(8))...>"
    }
}
