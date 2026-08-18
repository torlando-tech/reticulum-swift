// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

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

    /// C13: Interface ID that originally received the announce (for sourceMode filtering)
    public let receivingInterfaceId: String?
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

        /// C13: Interface ID that originally received the announce
        var receivingInterfaceId: String?
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
    /// - Parameters:
    ///   - extraDelay: E6: Additional delay before retransmission (e.g., PATH_REQUEST_RG for roaming)
    public func insert(
        destinationHash: Data,
        packet: Packet,
        hops: UInt8,
        receivedFrom: Data,
        blockRebroadcasts: Bool = false,
        attachedInterfaceId: String? = nil,
        isLocalClient: Bool = false,
        receivingInterfaceId: String? = nil,
        pathRequestAnswer: Bool = false,
        extraDelay: TimeInterval = 0
    ) {
        let now = Date()
        var retransmitTimeout: Date
        var retries: Int

        if isLocalClient {
            // Local client announces are sent immediately but only once
            retransmitTimeout = now
            retries = TransportConstants.PATHFINDER_R
        } else if pathRequestAnswer {
            // Answering a path request with a cached announce: the retransmit is
            // scheduled at a *fixed* `now + extraDelay` with NO PATHFINDER_RW
            // random window, and retries starts at PATHFINDER_R so the entry is
            // rebroadcast exactly once then culled. `extraDelay` already carries
            // the answering-context grace (0 for a local-client requestor,
            // PATH_REQUEST_GRACE for FULL, +PATH_REQUEST_RG for ROAMING).
            // Python Transport.py:2967-2987 (retransmit_timeout = now [+ GRACE
            // [+ RG]]; retries = PATHFINDER_R) — distinct from the heard-announce
            // reinsert at Transport.py:1871 which uses the random window.
            retransmitTimeout = now.addingTimeInterval(extraDelay)
            retries = TransportConstants.PATHFINDER_R
        } else {
            // Random jitter before first retransmission, plus any extra delay (E6).
            // Python Transport.py:1728: retransmit_timeout = now + rand() * PATHFINDER_RW
            // (PATHFINDER_G is added by Python only on *subsequent* retries after a
            // successful rebroadcast, not on the initial insert.)
            retransmitTimeout = now.addingTimeInterval(extraDelay + Double.random(in: 0...TransportConstants.PATHFINDER_RW))
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
            attachedInterfaceId: attachedInterfaceId,
            receivingInterfaceId: receivingInterfaceId
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
                // Reschedule to now + PATHFINDER_G + PATHFINDER_RW (fixed, no jitter),
                // matching Python Transport.py:588 exactly. The reference uses the
                // full random window deterministically here, NOT a fresh rand().
                entry.retransmitTimeout = now.addingTimeInterval(
                    TransportConstants.PATHFINDER_G + TransportConstants.PATHFINDER_RW
                )
                entry.retries += 1
                entries[destHash] = entry

                actions.append(RetransmitAction(
                    destinationHash: destHash,
                    packet: entry.packet,
                    hops: entry.hops,
                    blockRebroadcasts: entry.blockRebroadcasts,
                    attachedInterfaceId: entry.attachedInterfaceId,
                    receivingInterfaceId: entry.receivingInterfaceId
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

    /// Timestamp (as seconds-since-epoch) of an announce table entry, or nil if absent.
    ///
    /// Exposed for conformance bridge observables — tests distinguish
    /// "entry is the original retransmit slot" from "entry was replaced
    /// by a path-request answer" by comparing timestamps before/after a PR.
    public func entryTimestamp(_ destinationHash: Data) -> Date? {
        return entries[destinationHash]?.timestamp
    }

    /// Full packet hash of an announce table entry's stored packet, or nil if absent.
    ///
    /// Mirrors the RNS `announce_table[dest][IDX_AT_PACKET].packet_hash` field
    /// (Transport.py:3559-3567). The stored packet is the rebroadcast packet
    /// (hops+1), but `Packet.getHashablePart` excludes the hop byte, so its
    /// `getFullHash()` equals the dispatched original announce's packet hash — the
    /// invariant `test_callback_arity_packet_hash` cross-checks (a 4-param
    /// handler's `announce_packet_hash` must equal this table value). Exposed for
    /// conformance bridge observables, following the `entryTimestamp` precedent.
    public func entryPacketHash(_ destinationHash: Data) -> Data? {
        return entries[destinationHash]?.packet.getFullHash()
    }

    // MARK: - Entry field accessors (conformance observability)
    //
    // Mirror the RNS announce_table[dest] tuple fields (IDX_AT_*,
    // Transport.py:3559-3567) so the conformance bridge can read the full entry
    // shape. The Entry struct itself is module-internal; these expose the
    // individual fields the bridge surfaces in behavioral_read_announce_table.

    /// IDX_AT_RETRIES: retransmission attempts so far, or nil if absent.
    public func entryRetries(_ destinationHash: Data) -> Int? {
        return entries[destinationHash]?.retries
    }

    /// IDX_AT_HOPS: hop count from the original announce, or nil if absent.
    public func entryHops(_ destinationHash: Data) -> UInt8? {
        return entries[destinationHash]?.hops
    }

    /// IDX_AT_RTRNS_TMO: next scheduled retransmission time, or nil if absent.
    public func entryRetransmitTimeout(_ destinationHash: Data) -> Date? {
        return entries[destinationHash]?.retransmitTimeout
    }

    /// IDX_AT_BLCK_RBRD: PATH_RESPONSE-context flag, or nil if absent.
    public func entryBlockRebroadcasts(_ destinationHash: Data) -> Bool? {
        return entries[destinationHash]?.blockRebroadcasts
    }

    /// IDX_AT_RCVD_IF: received_from hash (transport_id or destination_hash;
    /// despite the index name it is a HASH, not an interface), or nil if absent.
    public func entryReceivedFrom(_ destinationHash: Data) -> Data? {
        return entries[destinationHash]?.receivedFrom
    }

    /// IDX_AT_LCL_RBRD: count of heard-back local rebroadcasts, or nil if absent.
    public func entryLocalRebroadcasts(_ destinationHash: Data) -> Int? {
        return entries[destinationHash]?.localRebroadcasts
    }

    /// IDX_AT_ATTCHD_IF: the attached interface id (or nil when broadcast / the
    /// entry is absent).
    public func entryAttachedInterface(_ destinationHash: Data) -> String? {
        return entries[destinationHash]?.attachedInterfaceId
    }

    /// Read the announce-rate-limiter state for a destination (the swift analogue
    /// of RNS.Transport.announce_rate_table[dest], Transport.py:1838-1858), or nil
    /// if no entry exists. Mirrors the {"last","rate_violations","blocked_until",
    /// "timestamps"} dict the reference reads.
    public func rateEntry(for destinationHash: Data)
        -> (last: Date, rateViolations: Int, blockedUntil: Date, timestamps: [Date])? {
        guard let e = rateTable[destinationHash] else { return nil }
        return (e.lastSeen, e.rateViolations, e.blockedUntil, e.timestamps)
    }

    /// Age an entry's retransmit_timeout and/or timestamp for deterministic
    /// retransmit tests (RNS IDX_AT_RTRNS_TMO / IDX_AT_TIMESTAMP, the fields
    /// behavioral_set_announce_timestamp rewinds, Transport.py:587/3000). Both are
    /// absolute instants; either may be omitted to leave it unchanged.
    ///
    /// - Returns: true if an entry existed and was mutated.
    @discardableResult
    public func ageEntry(
        _ destinationHash: Data,
        retransmitTimeout: Date? = nil,
        timestamp: Date? = nil
    ) -> Bool {
        guard var entry = entries[destinationHash] else { return false }
        if let retransmitTimeout { entry.retransmitTimeout = retransmitTimeout }
        if let timestamp { entry.timestamp = timestamp }
        entries[destinationHash] = entry
        return true
    }

    /// Number of entries in the table.
    public var count: Int {
        entries.count
    }

    /// Remove an entry from the table.
    public func remove(_ destinationHash: Data) {
        entries.removeValue(forKey: destinationHash)
    }

    /// E3: Remove and return an entry's packet from the table.
    ///
    /// Used by held_announces lifecycle: when a path request response is about to be
    /// inserted, any existing announce for that destination is moved to heldAnnounces.
    ///
    /// - Parameter destinationHash: Destination hash to remove
    /// - Returns: The packet from the removed entry, or nil if not found
    public func removeAndReturn(_ destinationHash: Data) -> Packet? {
        guard let entry = entries.removeValue(forKey: destinationHash) else { return nil }
        return entry.packet
    }
}
