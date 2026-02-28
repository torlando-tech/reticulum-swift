//
//  PathEntry.swift
//  ReticulumSwift
//
//  Path entry data structure for routing table.
//  Stores information about learned routes from received announces.
//
//  When an announce is validated, the path information is stored in the path table.
//  This enables routing packets to known destinations.
//

import Foundation

// MARK: - Path Entry

/// Path entry storing routing information for a destination.
///
/// A PathEntry captures all information needed to route packets to a destination:
/// - The destination hash identifies the target
/// - Public keys enable encryption
/// - Interface and hop count determine the best path
/// - Expiration ensures stale paths are removed
/// - Random blob enables replay detection
///
/// Path entries are created when announces are received and validated.
/// The path table uses them to route outgoing packets.
public struct PathEntry: Codable, Sendable, Equatable {

    // MARK: - Properties

    /// 16-byte destination hash this path reaches
    public let destinationHash: Data

    /// 64-byte concatenated public keys (encryption || signing)
    public let publicKeys: Data

    /// Identifier of the interface this path was learned on
    public let interfaceId: String

    /// Number of hops to reach the destination
    public let hopCount: UInt8

    /// When this path was learned
    public let timestamp: Date

    /// When this path should be considered stale
    public let expires: Date

    /// List of seen random blobs for this destination (replay detection).
    /// Each blob is 10 bytes. Capped at MAX_RANDOM_BLOBS.
    /// The most recent blob is last in the array.
    public var randomBlobs: [Data]

    /// Backward-compatible accessor: returns the most recent random blob.
    public var randomBlob: Data {
        randomBlobs.last ?? Data()
    }

    /// Path responsiveness state (matches Python Transport.path_states).
    /// - PATH_STATE_UNKNOWN (0x00): Default
    /// - PATH_STATE_UNRESPONSIVE (0x01): Failed communication attempt
    /// - PATH_STATE_RESPONSIVE (0x02): Confirmed responsive
    public var pathState: Int

    /// Optional 32-byte ratchet public key for forward secrecy.
    /// When present, messages should be encrypted using this key instead of
    /// the base encryption public key. Used by RNS 1.1+ for ratcheted announces.
    public let ratchet: Data?

    /// Application data from announce (may contain display name)
    public let appData: Data?

    /// Optional 16-byte next hop transport node hash for routed paths.
    /// When present (from HEADER_2 announces), packets to this destination
    /// must be sent as HEADER_2 with this address as transportAddress.
    /// This enables multi-hop routing through transport nodes.
    public let nextHop: Data?

    /// Cached raw announce payload data for path response retransmission.
    /// Stored when the path is learned from an announce, used to answer
    /// path requests from other nodes without reconstructing the announce.
    /// Reference: Python Transport.py path_request() uses cached announce.
    public let announceData: Data?

    // MARK: - Expiration Constants

    /// Standard path expiration (7 days)
    /// Used for normal stationary destinations
    public static let standardExpiration: TimeInterval = 7 * 24 * 3600

    /// Access point expiration (1 day)
    /// Used for destinations that may change location occasionally
    public static let accessPointExpiration: TimeInterval = 24 * 3600

    /// Roaming expiration (6 hours)
    /// Used for mobile destinations that change location frequently
    public static let roamingExpiration: TimeInterval = 6 * 3600

    // MARK: - Computed Properties

    /// Whether this path has expired
    public var isExpired: Bool {
        expires < Date()
    }

    /// Whether this destination matches any LXMF aspect (delivery or propagation).
    ///
    /// Recomputes the expected destination hash for `lxmf.delivery` and
    /// `lxmf.propagation` using the stored public keys and compares with
    /// the actual destination hash. Non-LXMF destinations (NomadNet nodes,
    /// transport nodes, etc.) will not match.
    public var isLXMFDestination: Bool {
        guard publicKeys.count >= 64 else { return false }
        let identityHash = Hashing.truncatedHash(publicKeys)
        for aspect in [["delivery"], ["propagation"]] {
            let nameHash = Hashing.destinationNameHash(appName: "lxmf", aspects: aspect)
            var combined = nameHash
            combined.append(identityHash)
            if Hashing.truncatedHash(combined) == destinationHash {
                return true
            }
        }
        return false
    }

    /// Whether this destination is specifically an LXMF propagation node (relay).
    public var isLXMFPropagationNode: Bool {
        guard publicKeys.count >= 64 else { return false }
        let identityHash = Hashing.truncatedHash(publicKeys)
        let nameHash = Hashing.destinationNameHash(appName: "lxmf", aspects: ["propagation"])
        var combined = nameHash
        combined.append(identityHash)
        return Hashing.truncatedHash(combined) == destinationHash
    }

    /// Whether this destination is an LXST telephony (voice call) endpoint.
    public var isLXSTTelephony: Bool {
        guard publicKeys.count >= 64 else { return false }
        let identityHash = Hashing.truncatedHash(publicKeys)
        let nameHash = Hashing.destinationNameHash(appName: "lxst", aspects: ["telephony"])
        var combined = nameHash
        combined.append(identityHash)
        return Hashing.truncatedHash(combined) == destinationHash
    }

    /// Whether this destination matches any known aspect (LXMF, LXST, NomadNet).
    public var isKnownDestination: Bool {
        detectedAspect != nil
    }

    /// Detected aspect name for this destination.
    ///
    /// Tries known Reticulum aspects against the stored public keys and
    /// destination hash to determine the application type.
    public var detectedAspect: String? {
        guard publicKeys.count >= 64 else { return nil }
        let identityHash = Hashing.truncatedHash(publicKeys)
        let knownAspects: [(String, [String])] = [
            ("lxmf", ["delivery"]),
            ("lxmf", ["propagation"]),
            ("lxst", ["telephony"]),
            ("nomadnetwork", ["node"]),
        ]
        for (appName, aspects) in knownAspects {
            let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)
            var combined = nameHash
            combined.append(identityHash)
            let expectedDestHash = Hashing.truncatedHash(combined)
            if expectedDestHash == destinationHash {
                return appName + "." + aspects.joined(separator: ".")
            }
        }
        return nil
    }

    /// First 32 bytes of publicKeys (X25519 base encryption key)
    public var encryptionPublicKey: Data {
        guard publicKeys.count >= 32 else { return Data() }
        return publicKeys.prefix(32)
    }

    /// Last 32 bytes of publicKeys (Ed25519 signing key)
    public var signingPublicKey: Data {
        guard publicKeys.count >= 64 else { return Data() }
        return publicKeys.suffix(32)
    }

    /// The key to use for encryption (ratchet if available, otherwise base encryption key).
    ///
    /// When a destination announces with a ratchet, messages MUST be encrypted
    /// using the ratchet key for forward secrecy. The recipient will decrypt
    /// using their current ratchet private key.
    public var effectiveEncryptionKey: Data {
        if let ratchet = ratchet, ratchet.count == 32 {
            return ratchet
        }
        return encryptionPublicKey
    }

    /// Time remaining until expiration (can be negative if expired)
    public var timeRemaining: TimeInterval {
        expires.timeIntervalSinceNow
    }

    /// Extract emission timestamp from a random blob (bytes[5:10] as big-endian UInt64).
    /// Matches Python Transport.timebase_from_random_blob().
    public static func emissionTimestamp(from blob: Data) -> UInt64 {
        guard blob.count >= 10 else { return 0 }
        var value: UInt64 = 0
        for i in 5..<10 {
            value = (value << 8) | UInt64(blob[blob.startIndex + i])
        }
        return value
    }

    /// Latest emission timestamp across all seen random blobs.
    /// Matches Python Transport.timebase_from_random_blobs().
    public var latestEmissionTimestamp: UInt64 {
        var maxTimestamp: UInt64 = 0
        for blob in randomBlobs {
            let ts = PathEntry.emissionTimestamp(from: blob)
            if ts > maxTimestamp { maxTimestamp = ts }
        }
        return maxTimestamp
    }

    /// Display name extracted from appData.
    ///
    /// Supports multiple formats:
    /// 1. Raw UTF-8 string (e.g., "RNS Transport US West")
    /// 2. msgpack array `[name, stamp_cost]` used by LXMF (e.g., `92c408...c0`)
    /// 3. NomadNet/propagation node format with name buried in complex structure
    public var displayName: String? {
        guard let data = appData, !data.isEmpty else { return nil }

        // First try raw UTF-8 string
        if let str = String(data: data, encoding: .utf8), !str.isEmpty {
            // Check if it looks like valid text (not binary garbage)
            let isPrintable = str.allSatisfy { $0.isLetter || $0.isNumber || $0.isPunctuation || $0.isWhitespace || $0 == "{" || $0 == "}" || $0 == "[" || $0 == "]" || $0 == ":" || $0 == "\"" }
            if isPrintable {
                return str
            }
        }

        // Try msgpack format: [display_name, stamp_cost]
        // Format: 92 (fixarray 2) | c4 XX (bin8 with XX bytes) | <string bytes> | c0 (nil)
        if data.count >= 4 && data[0] == 0x92 {  // msgpack fixarray with 2 elements
            if let name = extractMsgpackString(from: data, startingAt: 1) {
                return name
            }
        }

        // Try NomadNet format: 97 (fixarray 7) with name in bin8 near the end
        // Format: 97 c2 ce... c3 cd... cd... 93... 81 01 c4 XX <name>
        if data.count >= 10 && data[0] == 0x97 {  // msgpack fixarray with 7 elements
            // Scan for the last bin8 (c4) which typically contains the name
            if let name = findLastBin8String(in: data) {
                return name
            }
        }

        return nil
    }

    /// Extract a msgpack string starting at the given offset.
    private func extractMsgpackString(from data: Data, startingAt offset: Int) -> String? {
        guard offset < data.count else { return nil }
        let typeMarker = data[offset]

        // bin8: c4 followed by length byte
        if typeMarker == 0xc4 && offset + 2 < data.count {
            let length = Int(data[offset + 1])
            if offset + 2 + length <= data.count {
                let stringData = data[(offset + 2)..<(offset + 2 + length)]
                return String(data: stringData, encoding: .utf8)
            }
        }
        // fixstr: a0-bf (5-bit length in lower nibble)
        else if typeMarker >= 0xa0 && typeMarker <= 0xbf {
            let length = Int(typeMarker & 0x1f)
            if offset + 1 + length <= data.count {
                let stringData = data[(offset + 1)..<(offset + 1 + length)]
                return String(data: stringData, encoding: .utf8)
            }
        }
        // str8: d9 followed by length byte
        else if typeMarker == 0xd9 && offset + 2 < data.count {
            let length = Int(data[offset + 1])
            if offset + 2 + length <= data.count {
                let stringData = data[(offset + 2)..<(offset + 2 + length)]
                return String(data: stringData, encoding: .utf8)
            }
        }
        return nil
    }

    /// Find the last bin8 string in the data (used for NomadNet format).
    private func findLastBin8String(in data: Data) -> String? {
        // Scan backwards looking for c4 (bin8) marker
        var i = data.count - 2
        while i >= 1 {
            if data[i] == 0xc4 {
                let length = Int(data[i + 1])
                if i + 2 + length <= data.count {
                    let stringData = data[(i + 2)..<(i + 2 + length)]
                    if let str = String(data: stringData, encoding: .utf8),
                       str.allSatisfy({ $0.isLetter || $0.isNumber || $0.isPunctuation || $0.isWhitespace || $0 == "/" || $0 == "_" || $0 == "-" }) {
                        return str
                    }
                }
            }
            i -= 1
        }
        return nil
    }

    // MARK: - Initialization

    /// Create a path entry with explicit expiration date.
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash
    ///   - publicKeys: 64-byte concatenated public keys
    ///   - interfaceId: Interface identifier where path was learned
    ///   - hopCount: Number of hops to destination
    ///   - timestamp: When the path was learned (defaults to now)
    ///   - expires: When the path expires
    ///   - randomBlob: 10-byte random blob from announce
    ///   - randomBlobs: List of all seen random blobs (overrides randomBlob if provided)
    ///   - pathState: Path responsiveness state (defaults to unknown)
    ///   - ratchet: Optional 32-byte ratchet public key for forward secrecy
    ///   - appData: Optional application data from announce
    ///   - nextHop: Optional 16-byte next hop transport node hash for routing
    ///   - announceData: Optional cached raw announce payload for path responses
    public init(
        destinationHash: Data,
        publicKeys: Data,
        interfaceId: String,
        hopCount: UInt8,
        timestamp: Date = Date(),
        expires: Date,
        randomBlob: Data,
        randomBlobs: [Data]? = nil,
        pathState: Int = TransportConstants.PATH_STATE_UNKNOWN,
        ratchet: Data? = nil,
        appData: Data? = nil,
        nextHop: Data? = nil,
        announceData: Data? = nil
    ) {
        self.destinationHash = destinationHash
        self.publicKeys = publicKeys
        self.interfaceId = interfaceId
        self.hopCount = hopCount
        self.timestamp = timestamp
        self.expires = expires
        self.randomBlobs = randomBlobs ?? [randomBlob]
        self.pathState = pathState
        self.ratchet = ratchet
        self.appData = appData
        self.nextHop = nextHop
        self.announceData = announceData
    }

    /// Create a path entry with expiration interval.
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash
    ///   - publicKeys: 64-byte concatenated public keys
    ///   - interfaceId: Interface identifier where path was learned
    ///   - hopCount: Number of hops to destination
    ///   - expiration: Time interval until expiration (defaults to standard 7 days)
    ///   - randomBlob: 10-byte random blob from announce
    ///   - randomBlobs: List of all seen random blobs (overrides randomBlob if provided)
    ///   - pathState: Path responsiveness state (defaults to unknown)
    ///   - ratchet: Optional 32-byte ratchet public key for forward secrecy
    ///   - appData: Optional application data from announce
    ///   - nextHop: Optional 16-byte next hop transport node hash for routing
    ///   - announceData: Optional cached raw announce payload for path responses
    public init(
        destinationHash: Data,
        publicKeys: Data,
        interfaceId: String,
        hopCount: UInt8,
        expiration: TimeInterval = PathEntry.standardExpiration,
        randomBlob: Data,
        randomBlobs: [Data]? = nil,
        pathState: Int = TransportConstants.PATH_STATE_UNKNOWN,
        ratchet: Data? = nil,
        appData: Data? = nil,
        nextHop: Data? = nil,
        announceData: Data? = nil
    ) {
        let now = Date()
        self.destinationHash = destinationHash
        self.publicKeys = publicKeys
        self.interfaceId = interfaceId
        self.hopCount = hopCount
        self.timestamp = now
        self.expires = now.addingTimeInterval(expiration)
        self.randomBlobs = randomBlobs ?? [randomBlob]
        self.pathState = pathState
        self.ratchet = ratchet
        self.appData = appData
        self.nextHop = nextHop
        self.announceData = announceData
    }
}

// MARK: - CustomStringConvertible

extension PathEntry: CustomStringConvertible {
    public var description: String {
        let hashPrefix = destinationHash.prefix(4).map { String(format: "%02x", $0) }.joined()
        let status = isExpired ? "expired" : "valid"
        return "PathEntry<\(hashPrefix)... hops:\(hopCount) \(status)>"
    }
}
