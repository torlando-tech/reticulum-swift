//
//  AnnounceTable.swift
//  ReticulumSwift
//
//  Manages scheduled announce retransmission matching Python Transport.py:518-579
//  (retransmission loop) and 1754-1764 (announce table structure).
//
//  Implements:
//  - Queued announce retransmission as HEADER_2 with transport_id
//  - Local rebroadcast detection (hearing our own rebroadcast back)
//  - Pass-on detection (another node forwarded before our retry)
//  - Announce rate limiting per source interface
//

import Foundation

// MARK: - Retransmit Action

/// Action to take when an announce retransmission is due.
public struct RetransmitAction: Sendable {
    /// Destination hash for this announce
    public let destinationHash: Data

    /// The packet to retransmit (will be sent as HEADER_2)
    public let packet: Packet

    /// Hop count from original announce
    public let hops: UInt8

    /// Whether this should be sent as PATH_RESPONSE context
    public let blockRebroadcasts: Bool

    /// Optional specific interface to send on (nil = all)
    public let attachedInterfaceId: String?
}

// MARK: - Announce Table

/// Manages scheduled announce retransmissions.
///
/// When an announce is accepted and transport is enabled, it's inserted into this table.
/// A periodic timer calls `processRetransmissions()` which returns packets that are due
/// for rebroadcast as HEADER_2 with the local transport identity hash.
///
/// Reference: Python Transport.py:518-579, 1754-1764
public actor AnnounceTable {

    // MARK: - Entry

    /// An entry in the announce table for scheduled retransmission.
    struct Entry {
        /// When this entry was created
        var timestamp: Date

        /// When the next retransmission should occur
        var retransmitTimeout: Date

        /// Number of retransmission attempts so far
        var retries: Int

        /// Transport ID or destination hash of the sender
        var receivedFrom: Data

        /// Hop count from the original announce
        var hops: UInt8

        /// The announce packet (original data for reconstruction)
        var packet: Packet

        /// Number of times we've heard our own rebroadcast back
        var localRebroadcasts: Int

        /// Force PATH_RESPONSE context (blocks further rebroadcasts)
        var blockRebroadcasts: Bool

        /// Override interface for retransmission (nil = all)
        var attachedInterfaceId: String?
    }

    // MARK: - Rate Limiting

    /// Rate limiting entry per destination hash.
    public struct RateEntry {
        /// Last time an announce was seen from this destination
        var lastSeen: Date

        /// Number of rate violations
        var rateViolations: Int

        /// Blocked until this time
        var blockedUntil: Date

        /// Recent announce timestamps for rate calculation
        var timestamps: [Date]
    }

    // MARK: - Properties

    /// Announce entries indexed by destination hash
    private var entries: [Data: Entry] = [:]

    /// Rate limiting table indexed by destination hash
    private var rateTable: [Data: RateEntry] = [:]

    // MARK: - Insert

    /// Insert an announce into the table for scheduled retransmission.
    ///
    /// - Parameters:
    ///   - destinationHash: Destination hash of the announce
    ///   - packet: The announce packet
    ///   - hops: Hop count from the original announce
    ///   - receivedFrom: Transport ID or destination hash of sender
    ///   - blockRebroadcasts: Whether to use PATH_RESPONSE context
    ///   - attachedInterfaceId: Optional specific interface to retransmit on
    ///   - isLocalClient: Whether the announce originated from a local client
    public func insert(
        destinationHash: Data,
        packet: Packet,
        hops: UInt8,
        receivedFrom: Data,
        blockRebroadcasts: Bool = false,
        attachedInterfaceId: String? = nil,
        isLocalClient: Bool = false
    ) {
        let now = Date()
        var retransmitTimeout: Date
        var retries: Int

        if isLocalClient {
            // Local client announces are sent immediately but only once
            retransmitTimeout = now
            retries = TransportConstants.PATHFINDER_R
        } else {
            // Random jitter before first retransmission
            retransmitTimeout = now.addingTimeInterval(Double.random(in: 0...TransportConstants.PATHFINDER_RW))
            retries = 0
        }

        let entry = Entry(
            timestamp: now,
            retransmitTimeout: retransmitTimeout,
            retries: retries,
            receivedFrom: receivedFrom,
            hops: hops,
            packet: packet,
            localRebroadcasts: 0,
            blockRebroadcasts: blockRebroadcasts,
            attachedInterfaceId: attachedInterfaceId
        )

        entries[destinationHash] = entry
    }

    // MARK: - Retransmission Processing

    /// Process all announce entries and return any that are due for retransmission.
    ///
    /// Matching Python Transport.py:518-579:
    /// - If retries > 0 && localRebroadcasts >= LOCAL_REBROADCASTS_MAX → remove
    /// - If retries > PATHFINDER_R → remove
    /// - If now > retransmitTimeout → retransmit, increment retries
    ///
    /// - Returns: Array of actions for packets that should be retransmitted
    public func processRetransmissions() -> [RetransmitAction] {
        let now = Date()
        var actions: [RetransmitAction] = []
        var toRemove: [Data] = []

        for (destHash, var entry) in entries {
            // Check if completed: local rebroadcast limit reached
            if entry.retries > 0 && entry.localRebroadcasts >= TransportConstants.LOCAL_REBROADCASTS_MAX {
                toRemove.append(destHash)
                continue
            }

            // Check if completed: retry limit reached
            if entry.retries > TransportConstants.PATHFINDER_R {
                toRemove.append(destHash)
                continue
            }

            // Check if retransmission is due
            if now > entry.retransmitTimeout {
                // Schedule next retransmission
                entry.retransmitTimeout = now.addingTimeInterval(
                    TransportConstants.PATHFINDER_G + Double.random(in: 0...TransportConstants.PATHFINDER_RW)
                )
                entry.retries += 1
                entries[destHash] = entry

                actions.append(RetransmitAction(
                    destinationHash: destHash,
                    packet: entry.packet,
                    hops: entry.hops,
                    blockRebroadcasts: entry.blockRebroadcasts,
                    attachedInterfaceId: entry.attachedInterfaceId
                ))
            }
        }

        for hash in toRemove {
            entries.removeValue(forKey: hash)
        }

        return actions
    }

    // MARK: - Local Rebroadcast Detection

    /// Record that we heard our own announce rebroadcast back.
    ///
    /// Matching Python Transport.py:1581-1597:
    /// - If incoming hops-1 == entry.hops → local rebroadcast detected
    /// - If incoming hops-1 == entry.hops+1 and before timeout → passed on, remove
    ///
    /// - Parameters:
    ///   - destinationHash: Destination hash of the announce
    ///   - incomingHops: Hop count of the incoming announce
    /// - Returns: true if a local rebroadcast was detected
    @discardableResult
    public func recordLocalRebroadcast(destinationHash: Data, incomingHops: UInt8) -> Bool {
        guard var entry = entries[destinationHash] else { return false }

        // Check for local rebroadcast: incoming hops-1 == our entry's hops
        if incomingHops > 0 && incomingHops - 1 == entry.hops {
            entry.localRebroadcasts += 1
            entries[destinationHash] = entry

            if entry.retries > 0 && entry.localRebroadcasts >= TransportConstants.LOCAL_REBROADCASTS_MAX {
                entries.removeValue(forKey: destinationHash)
            }
            return true
        }

        // Check for pass-on: incoming hops-1 == entry.hops + 1, before timeout
        if incomingHops > 0 && incomingHops - 1 == entry.hops + 1 && entry.retries > 0 {
            let now = Date()
            if now < entry.retransmitTimeout {
                entries.removeValue(forKey: destinationHash)
                return true
            }
        }

        return false
    }

    // MARK: - Rate Limiting

    /// Check if an announce from a destination is rate-blocked.
    ///
    /// Matching Python Transport.py:1691-1720.
    ///
    /// - Parameters:
    ///   - destinationHash: Destination hash of the announce
    ///   - rateTarget: Minimum interval between announces (seconds)
    ///   - rateGrace: Number of violations before blocking
    ///   - ratePenalty: Additional penalty time (seconds)
    /// - Returns: true if the announce should be blocked due to rate limiting
    public func isRateBlocked(
        destinationHash: Data,
        rateTarget: TimeInterval,
        rateGrace: Int,
        ratePenalty: TimeInterval
    ) -> Bool {
        let now = Date()

        guard var rateEntry = rateTable[destinationHash] else {
            // First announce from this destination - not blocked, create entry
            rateTable[destinationHash] = RateEntry(
                lastSeen: now,
                rateViolations: 0,
                blockedUntil: .distantPast,
                timestamps: [now]
            )
            return false
        }

        rateEntry.timestamps.append(now)
        while rateEntry.timestamps.count > TransportConstants.MAX_RATE_TIMESTAMPS {
            rateEntry.timestamps.removeFirst()
        }

        let currentRate = now.timeIntervalSince(rateEntry.lastSeen)

        if now > rateEntry.blockedUntil {
            if currentRate < rateTarget {
                rateEntry.rateViolations += 1
            } else {
                rateEntry.rateViolations = max(0, rateEntry.rateViolations - 1)
            }

            if rateEntry.rateViolations > rateGrace {
                rateEntry.blockedUntil = rateEntry.lastSeen.addingTimeInterval(rateTarget + ratePenalty)
                rateTable[destinationHash] = rateEntry
                return true
            } else {
                rateEntry.lastSeen = now
                rateTable[destinationHash] = rateEntry
                return false
            }
        } else {
            rateTable[destinationHash] = rateEntry
            return true
        }
    }

    // MARK: - Query

    /// Check if a destination hash has an entry in the announce table.
    public func contains(_ destinationHash: Data) -> Bool {
        return entries[destinationHash] != nil
    }

    /// Number of entries in the table.
    public var count: Int {
        entries.count
    }

    /// Remove an entry from the table.
    public func remove(_ destinationHash: Data) {
        entries.removeValue(forKey: destinationHash)
    }
}
