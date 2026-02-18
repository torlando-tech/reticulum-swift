//
//  Announce.swift
//  ReticulumSwift
//
//  Reticulum announce packet construction.
//  Announces broadcast a destination's identity to the network.
//
//  Matches Python RNS Packet.py announce format for byte-perfect interoperability.
//

import Foundation

// MARK: - Announce Constants

/// Random hash length in announce packets (10 bytes)
public let ANNOUNCE_RANDOM_HASH_LENGTH = 10

/// Ed25519 signature length (64 bytes)
public let SIGNATURE_LENGTH = 64

/// Public keys length (64 bytes: 32 encryption + 32 signing)
public let PUBLIC_KEYS_LENGTH = 64

/// X25519 ratchet public key length (32 bytes)
public let RATCHET_KEY_LENGTH = 32

// MARK: - Announce Errors

/// Errors during announce construction
public enum AnnounceError: Error, Sendable, Equatable {
    /// PLAIN destinations cannot announce (no identity to sign)
    case plainCannotAnnounce

    /// Destination has no identity
    case missingIdentity

    /// Signature generation failed
    case signatureFailed
}

// MARK: - Announce

/// Reticulum announce packet construction.
///
/// Announces broadcast a destination's identity to the network, allowing
/// other nodes to discover and communicate with the destination.
///
/// Announce payload structure (without ratchet):
/// ```
/// [public_keys 64B][name_hash 16*N B][random_hash 10B][signature 64B][app_data optional]
/// ```
///
/// Announce payload structure (with ratchet):
/// ```
/// [public_keys 64B][name_hash 16*N B][random_hash 10B][ratchet 32B][signature 64B][app_data optional]
/// ```
/// where N = number of aspects (app_name + aspects.count)
///
/// For PLAIN destinations (no identity):
/// ```
/// [name_hash 16*N B][random_hash 10B][app_data optional]
/// ```
///
/// Signature covers (in order):
/// ```
/// destination_hash || public_keys || name_hash || random_hash [|| ratchet] [|| app_data]
/// ```
public struct Announce: Sendable {

    // MARK: - Properties

    /// The destination being announced
    public let destination: Destination

    /// Application data to include in the announce (overrides destination.appData)
    public let appData: Data?

    /// Random hash for uniqueness (10 bytes)
    /// Can be set explicitly for testing, otherwise random
    public let randomHash: Data

    /// Optional 32-byte X25519 ratchet public key for forward secrecy.
    /// When present, the announce includes the ratchet and sets context_flag=0x01.
    /// Peers will encrypt messages to this ratchet key instead of the base identity key.
    public let ratchet: Data?

    /// Whether this announce is a path response (answering a path request).
    /// When true, context = PATH_RESPONSE (0x0B) which tells receiving nodes
    /// NOT to rebroadcast this announce further.
    /// Reference: Python Destination.py:309 (`path_response` parameter)
    public let pathResponse: Bool

    // MARK: - Initialization

    /// Create an announce for a destination.
    ///
    /// - Parameters:
    ///   - destination: The destination to announce
    ///   - appData: Optional application data (overrides destination.appData)
    ///   - randomHash: Optional random hash for testing (10 bytes, defaults to random)
    ///   - ratchet: Optional 32-byte X25519 ratchet public key for forward secrecy
    ///   - pathResponse: Whether this is a path response announce (context=0x0B)
    public init(
        destination: Destination,
        appData: Data? = nil,
        randomHash: Data? = nil,
        ratchet: Data? = nil,
        pathResponse: Bool = false
    ) {
        self.destination = destination
        self.appData = appData
        self.randomHash = randomHash ?? Announce.generateRandomHash()
        self.ratchet = ratchet
        self.pathResponse = pathResponse
    }

    // MARK: - Building

    /// Build the announce payload data.
    ///
    /// This constructs the announce data (NOT the complete packet with header).
    ///
    /// For SINGLE/GROUP destinations with identity (no ratchet):
    /// ```
    /// public_keys || name_hash || random_hash || signature [|| app_data]
    /// ```
    ///
    /// For SINGLE/GROUP destinations with identity (with ratchet):
    /// ```
    /// public_keys || name_hash || random_hash || ratchet || signature [|| app_data]
    /// ```
    ///
    /// For PLAIN destinations:
    /// ```
    /// name_hash || random_hash [|| app_data]
    /// ```
    ///
    /// - Returns: Announce payload data
    /// - Throws: `AnnounceError` if construction fails
    public func build() throws -> Data {
        // PLAIN destinations have a simpler announce format (no signature)
        if destination.destinationType == .plain {
            return buildPlainAnnounce()
        }

        // SINGLE/GROUP/LINK require identity for signature
        guard let identity = destination.identity else {
            throw AnnounceError.missingIdentity
        }

        let publicKeys = identity.publicKeys
        let nameHash = destination.nameHash  // 10 bytes = full_hash(full_name)[:10]
        let effectiveAppData = appData ?? destination.appData ?? Data()

        // Build signed data: dest_hash || public_keys || name_hash || random_hash [|| ratchet] [|| app_data]
        var signedData = Data()
        signedData.append(destination.hash)
        signedData.append(publicKeys)
        signedData.append(nameHash)
        signedData.append(randomHash)
        if let ratchet = ratchet {
            signedData.append(ratchet)
        }
        if !effectiveAppData.isEmpty {
            signedData.append(effectiveAppData)
        }

        // Generate signature
        let signature: Data
        do {
            signature = try identity.sign(signedData)
        } catch {
            throw AnnounceError.signatureFailed
        }

        // Build announce payload: public_keys || name_hash || random_hash [|| ratchet] || signature [|| app_data]
        var payload = Data()
        payload.append(publicKeys)
        payload.append(nameHash)
        payload.append(randomHash)
        if let ratchet = ratchet {
            payload.append(ratchet)
        }
        payload.append(signature)
        if !effectiveAppData.isEmpty {
            payload.append(effectiveAppData)
        }

        return payload
    }

    /// Build a complete announce Packet with header.
    ///
    /// Creates a Packet ready to be sent over the network.
    ///
    /// Header configuration for announces:
    /// - headerType: .header1 (single address)
    /// - hasContext: true if ratchet present (context_flag=0x01)
    /// - hasIFAC: false
    /// - transportType: .broadcast
    /// - destinationType: from destination
    /// - packetType: .announce
    /// - hopCount: 0
    ///
    /// - Returns: Complete Packet with announce data
    /// - Throws: `AnnounceError` if construction fails
    public func buildPacket() throws -> Packet {
        let payload = try build()

        // Map DestType to DestinationType
        let headerDestType: DestinationType
        switch destination.destinationType {
        case .single:
            headerDestType = .single
        case .group:
            headerDestType = .group
        case .plain:
            headerDestType = .plain
        case .link:
            headerDestType = .link
        }

        let header = PacketHeader(
            headerType: .header1,
            hasContext: ratchet != nil,
            hasIFAC: false,
            transportType: .broadcast,
            destinationType: headerDestType,
            packetType: .announce,
            hopCount: 0
        )

        return Packet(
            header: header,
            destination: destination.hash,
            transportAddress: nil,
            context: pathResponse ? PacketContext.PATH_RESPONSE : PacketContext.NONE,
            data: payload
        )
    }

    // MARK: - Private Helpers

    /// Build announce for PLAIN destinations (no signature).
    private func buildPlainAnnounce() -> Data {
        let nameHash = destination.nameHash  // 10 bytes = full_hash(full_name)[:10]
        let effectiveAppData = appData ?? destination.appData ?? Data()

        // PLAIN announce: name_hash(10) || random_hash(10) [|| app_data]
        var payload = Data()
        payload.append(nameHash)
        payload.append(randomHash)
        if !effectiveAppData.isEmpty {
            payload.append(effectiveAppData)
        }

        return payload
    }

    /// Generate random hash for announce uniqueness.
    ///
    /// Python reference: RNS/Destination.py line 282
    ///   `random_hash = RNS.Identity.get_random_hash()[0:5] + int(time.time()).to_bytes(5, "big")`
    ///
    /// Format: [5 random bytes][5-byte big-endian Unix timestamp]
    ///
    /// The timestamp in bytes [5:10] is critical for relay announce ordering.
    /// Transport.announce_emitted() extracts it to determine if an announce
    /// is newer than a previously seen one. Without a proper timestamp, the
    /// relay's deduplication logic will reject our announces.
    private static func generateRandomHash() -> Data {
        var bytes = [UInt8](repeating: 0, count: ANNOUNCE_RANDOM_HASH_LENGTH)

        // First 5 bytes: random
        for i in 0..<5 {
            bytes[i] = UInt8.random(in: 0...255)
        }

        // Last 5 bytes: big-endian Unix timestamp
        // Matches Python's int(time.time()).to_bytes(5, "big")
        let timestamp = UInt64(Date().timeIntervalSince1970)
        bytes[5] = UInt8((timestamp >> 32) & 0xFF)
        bytes[6] = UInt8((timestamp >> 24) & 0xFF)
        bytes[7] = UInt8((timestamp >> 16) & 0xFF)
        bytes[8] = UInt8((timestamp >> 8) & 0xFF)
        bytes[9] = UInt8(timestamp & 0xFF)

        return Data(bytes)
    }
}

// MARK: - CustomStringConvertible

extension Announce: CustomStringConvertible {
    public var description: String {
        let hasAppData = (appData ?? destination.appData) != nil
        let hasRatchet = ratchet != nil
        return "Announce<\(destination.destinationType), appData:\(hasAppData), ratchet:\(hasRatchet)>"
    }
}
