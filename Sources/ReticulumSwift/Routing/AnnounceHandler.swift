//
//  AnnounceHandler.swift
//  ReticulumSwift
//
//  Processes received announce packets according to Reticulum protocol rules.
//  Validates signatures, records paths, and determines rebroadcast behavior.
//
//  The AnnounceHandler implements:
//  - Deduplication via announce hash tracking
//  - Hop limit enforcement (128 max)
//  - Signature validation using AnnounceValidator
//  - Path recording with mode-specific expiration
//  - Mode-based rebroadcast decisions
//

import Foundation
import CryptoKit

// MARK: - Process Result

/// Result of processing an announce packet.
public enum AnnounceProcessResult: Sendable, Equatable {
    /// Packet was ignored (not processed).
    case ignored(reason: AnnounceIgnoreReason)

    /// Path was recorded but not rebroadcast.
    case recorded(destinationHash: Data)

    /// Path was recorded and packet should be rebroadcast.
    case recordedAndRebroadcast(destinationHash: Data, packet: Packet)
}

/// Reason why an announce was ignored.
public enum AnnounceIgnoreReason: Sendable, Equatable {
    /// Announce was already seen (duplicate).
    case alreadySeen

    /// Hop count exceeds maximum limit.
    case hopLimitExceeded

    /// Signature verification failed.
    case invalidSignature

    /// Packet format is invalid.
    case invalidFormat
}

// MARK: - Announce Handler

/// Actor that processes received announce packets.
///
/// AnnounceHandler implements the Reticulum announce processing protocol:
/// 1. Deduplication: Tracks seen announce hashes to ignore duplicates
/// 2. Hop limit: Enforces maximum 128 hops
/// 3. Validation: Verifies signatures for SINGLE/GROUP/LINK destinations
/// 4. Path recording: Updates path table with learned routes
/// 5. Rebroadcast: Determines whether to propagate based on interface mode
///
/// Example usage:
/// ```swift
/// let handler = AnnounceHandler(pathTable: pathTable)
/// let result = try await handler.process(
///     packet: announcePacket,
///     from: "tcp-1",
///     interfaceMode: .full
/// )
/// switch result {
/// case .ignored(let reason):
///     print("Announce ignored: \(reason)")
/// case .recorded(let hash):
///     print("Path recorded for \(hash.hexDescription)")
/// case .recordedAndRebroadcast(let hash, let packet):
///     print("Rebroadcasting announce for \(hash.hexDescription)")
///     // Send packet to other interfaces
/// }
/// ```
public actor AnnounceHandler {

    // MARK: - Properties

    /// Path table for recording learned routes.
    private let pathTable: PathTable

    /// Set of seen announce hashes for deduplication.
    private var seenAnnounces: Set<Data> = []

    /// Maximum hop count allowed (Reticulum standard is 128).
    public let maxHops: UInt8 = 128

    /// Maximum size of seenAnnounces set before pruning.
    public let seenAnnouncesMaxSize: Int = 10000

    // MARK: - Initialization

    /// Create an announce handler with the specified path table.
    ///
    /// - Parameter pathTable: Path table for recording paths.
    public init(pathTable: PathTable) {
        self.pathTable = pathTable
    }

    // MARK: - Processing

    /// Process a received announce packet.
    ///
    /// Processing steps:
    /// 1. Compute announce hash for deduplication
    /// 2. Check if already seen (return .ignored if so)
    /// 3. Check hop limit (return .ignored if exceeded)
    /// 4. Parse and validate announce (signature verification)
    /// 5. Record path in path table with mode-specific expiration
    /// 6. Add to seen announces
    /// 7. Determine rebroadcast based on interface mode
    ///
    /// - Parameters:
    ///   - packet: The announce packet to process
    ///   - interfaceId: ID of the interface that received the packet
    ///   - interfaceMode: Mode of the receiving interface
    /// - Returns: Processing result indicating action taken
    /// - Throws: Never (errors are returned as .ignored results)
    public func process(
        packet: Packet,
        from interfaceId: String,
        interfaceMode: InterfaceMode
    ) async -> AnnounceProcessResult {
        print("[ANNOUNCE] Processing announce from \(interfaceId), hops=\(packet.header.hopCount), data=\(packet.data.count) bytes")

        // 1. Compute announce hash for deduplication
        let announceHash = computeAnnounceHash(packet)

        // 2. Check deduplication
        if seenAnnounces.contains(announceHash) {
            print("[ANNOUNCE] Ignored: already seen")
            return .ignored(reason: .alreadySeen)
        }

        // 3. Check hop limit
        if packet.header.hopCount >= maxHops {
            print("[ANNOUNCE] Ignored: hop limit exceeded (\(packet.header.hopCount) >= \(maxHops))")
            return .ignored(reason: .hopLimitExceeded)
        }

        // 4. Parse and validate announce
        let parsed: ParsedAnnounce
        let isPlain = packet.header.destinationType == .plain
        print("[ANNOUNCE] Parsing announce, isPlain=\(isPlain)")

        do {
            parsed = try AnnounceValidator.parseAndValidate(packet: packet, isPlain: isPlain)
            print("[ANNOUNCE] Parsed successfully: destHash=\(parsed.destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined())")
        } catch {
            print("[ANNOUNCE] Parse/validate error: \(error)")
            // Determine if it's a format or signature error
            if error is AnnounceValidationError {
                let validationError = error as! AnnounceValidationError
                if validationError == .signatureInvalid {
                    return .ignored(reason: .invalidSignature)
                }
            }
            return .ignored(reason: .invalidFormat)
        }

        // 5. Record path in path table
        // For PLAIN destinations, we need to handle missing public keys
        let publicKeys = parsed.publicKeys ?? Data(repeating: 0, count: 64)

        // Extract nextHop from announces
        // - HEADER_2 packets: use transportAddress (the transport node that relayed)
        // - HEADER_1 packets with hops > 0: use destination hash (mirrors Python's received_from = destination_hash)
        //   This enables HEADER_2 conversion for multi-hop routing even when transport node is unknown
        let nextHop: Data?
        if packet.header.headerType == .header2, let transportAddr = packet.transportAddress {
            nextHop = transportAddr
        } else if packet.header.hopCount > 0 {
            // Python behavior: for HEADER_1 announces, received_from = destination_hash
            // This allows HEADER_2 routing to work - the relay will forward appropriately
            nextHop = parsed.destinationHash
        } else {
            nextHop = nil
        }

        // Debug: Log announce header type and nextHop extraction
        let destHex = parsed.destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[ANNOUNCE_DEBUG] ===== ANNOUNCE PROCESSING =====")
        print("[ANNOUNCE_DEBUG] dest=\(destHex), headerType=\(packet.header.headerType), hopCount=\(packet.header.hopCount)")
        if let nh = nextHop {
            let nhHex = nh.prefix(8).map { String(format: "%02x", $0) }.joined()
            if packet.header.headerType == .header2 {
                print("[ANNOUNCE_DEBUG] HEADER_2 announce: nextHop=\(nhHex) (from transportAddress)")
            } else {
                print("[ANNOUNCE_DEBUG] HEADER_1 announce with hops>0: nextHop=\(nhHex) (set to destHash for relay forwarding)")
            }
        } else {
            print("[ANNOUNCE_DEBUG] Direct announce (hops=0): no nextHop needed")
        }

        let pathRecorded = await pathTable.record(
            destinationHash: parsed.destinationHash,
            publicKeys: publicKeys,
            randomBlob: parsed.randomHash,
            interfaceId: interfaceId,
            hopCount: packet.header.hopCount + 1, // Increment for next hop
            expiration: interfaceMode.pathExpiration,
            ratchet: parsed.ratchet,  // Pass ratchet for forward secrecy encryption
            appData: parsed.appData,
            nextHop: nextHop  // Pass transport address for multi-hop routing
        )

        // Only proceed if path was actually recorded (not a replay or worse path)
        guard pathRecorded else {
            // Path was rejected (replay or worse hop count), but still mark as seen
            addToSeenAnnounces(announceHash)
            return .ignored(reason: .alreadySeen)
        }

        // 6. Add announce hash to seen set
        addToSeenAnnounces(announceHash)

        // 7. Determine rebroadcast based on interface mode
        if interfaceMode.shouldPropagateAnnounces {
            // Create rebroadcast packet with incremented hop count
            let rebroadcastPacket = createRebroadcastPacket(from: packet)
            return .recordedAndRebroadcast(
                destinationHash: parsed.destinationHash,
                packet: rebroadcastPacket
            )
        } else {
            return .recorded(destinationHash: parsed.destinationHash)
        }
    }

    // MARK: - Private Helpers

    /// Compute announce hash for deduplication.
    ///
    /// The hash is computed as SHA256(destination || data) to uniquely
    /// identify this specific announce.
    ///
    /// - Parameter packet: Packet to hash
    /// - Returns: SHA256 hash of destination and data
    private func computeAnnounceHash(_ packet: Packet) -> Data {
        var hashInput = Data()
        hashInput.append(packet.destination)
        hashInput.append(packet.data)
        let digest = SHA256.hash(data: hashInput)
        return Data(digest)
    }

    /// Add an announce hash to the seen set, pruning if needed.
    ///
    /// - Parameter hash: Hash to add
    private func addToSeenAnnounces(_ hash: Data) {
        // Prune if over max size (remove oldest by removing arbitrary element)
        if seenAnnounces.count >= seenAnnouncesMaxSize {
            // Remove approximately 10% of entries to avoid frequent pruning
            let removeCount = seenAnnouncesMaxSize / 10
            for _ in 0..<removeCount {
                if let first = seenAnnounces.first {
                    seenAnnounces.remove(first)
                }
            }
        }
        seenAnnounces.insert(hash)
    }

    /// Create a rebroadcast packet with incremented hop count.
    ///
    /// - Parameter original: Original packet to rebroadcast
    /// - Returns: New packet with hop count + 1
    private func createRebroadcastPacket(from original: Packet) -> Packet {
        // Create new header with incremented hop count
        let newHeader = PacketHeader(
            headerType: original.header.headerType,
            hasContext: original.header.hasContext,
            hasIFAC: original.header.hasIFAC,
            transportType: original.header.transportType,
            destinationType: original.header.destinationType,
            packetType: original.header.packetType,
            hopCount: original.header.hopCount + 1
        )

        return Packet(
            header: newHeader,
            destination: original.destination,
            transportAddress: original.transportAddress,
            context: original.context,
            data: original.data
        )
    }

    // MARK: - Testing Support

    /// Number of seen announces (for testing).
    public var seenCount: Int {
        seenAnnounces.count
    }

    /// Check if an announce hash has been seen (for testing).
    ///
    /// - Parameter packet: Packet to check
    /// - Returns: true if the announce hash has been seen
    public func hasSeen(packet: Packet) -> Bool {
        let hash = computeAnnounceHash(packet)
        return seenAnnounces.contains(hash)
    }

    /// Clear all seen announces (for testing).
    public func clearSeen() {
        seenAnnounces.removeAll()
    }
}
