// Behavioral+Announce.swift — conformance bridge behavioral sub-handler cluster: B-ANNOUNCE (announce handler/rate/table, hold_and_release, register_announce_handler)
//
// Ports from reticulum-conformance reference/behavioral_transport.py. Shares the
// behavioralInstances registry + behavioralLock + requireBehavioralInstance()
// (internal in Behavioral.swift). Returns nil for commands it doesn't own
// (dispatch chain: handleBehavioralExtensionCommand in Ext+Dispatch.swift).
// Keep python-faithful; report library gaps; reconstruct logic inline rather
// than bailing (see /tmp/bridge_behavioral_spec.md DO-NOT-BAIL rule).
import Foundation
import ReticulumSwift

// MARK: - Per-(handle,iface) ingress-control held-announce queue
//
// reticulum-swift has no per-interface ingress control: there is no equivalent
// of RNS Interfaces/Interface.py hold_announce / process_held_announces /
// ic_held_release / held_announces. The Transport's `heldAnnounces` is a single
// private dest->Packet map used for path-request deferral, not the per-interface
// ingress-control queue these tests exercise. So the queue itself AND the
// lowest-hops-first release selection (Interface.py:240-251) are reconstructed
// here against genuine RNS.Packet parsing. State is keyed by handle+iface_id and
// persists across bridge calls because the test holds three announces on one
// call and releases the remaining two on a later call with announces=[].
final class BAnnounceHeldQueue: @unchecked Sendable {
    // Dest hashes in first-insertion order (mirrors Python dict key order, which
    // drives the first-wins tie-break in the lowest-hops selection).
    var order: [Data] = []
    // Dest hash -> held packet hop count (kept at the minimum, per hold_announce).
    var hops: [Data: UInt8] = [:]
}
let bAnnounceHeldLock = NSLock()
nonisolated(unsafe) var bAnnounceHeldQueues: [String: BAnnounceHeldQueue] = [:]

// MARK: - Recording announce-handler registry
//
// A real RNS-style external announce handler driven by the LIVE library dispatch
// loop. ReticulumTransport.registerAnnounceHandler + dispatchAnnounceToHandlers
// (Transport.py:2034-2087, :2476-2477) now own all matching / path-response
// gating / arity selection / exception isolation; this object only RECORDS the
// arguments the dispatch hands it (mirroring the python reference's duck-typed
// _RecordingAnnounceHandler in behavioral_transport.py:1965-2025). It is held both
// by the transport's `announceHandlers` (for dispatch) and by `bAnnounceHandlers`
// (for read-back) — the SAME object.
final class BAnnounceRecordingHandler: AnnounceHandlerProtocol, @unchecked Sendable {
    // `handler.aspect_filter` value (nil == match-all). Absent entirely when
    // omitAspectFilter (models a handler with no aspect_filter attribute).
    let aspectFilter: String?
    private let receivePathResponsesParam: Bool?
    private let numParams: Int
    private let raiseOnCall: Bool
    private let omitAspectFilter: Bool
    // Set from registerAnnounceHandler's return (== hasAspectFilter); read by
    // behavioral_read_announce_handler_calls. Written once on the bridge serial
    // thread before the handler is published into the registry map.
    var registered: Bool = false

    // The transport actor appends to `calls` during synchronous dispatch while the
    // serial bridge command loop reads it — guard with a per-handler lock (the
    // module-level bAnnounceHandlerLock only guards the registry map).
    let callsLock = NSLock()
    private var calls: [JSONValue] = []

    init(aspectFilter: String?, receivePathResponses: Bool?, numParams: Int,
         raiseOnCall: Bool, omitAspectFilter: Bool) {
        self.aspectFilter = aspectFilter
        self.receivePathResponsesParam = receivePathResponses
        self.numParams = numParams
        self.raiseOnCall = raiseOnCall
        self.omitAspectFilter = omitAspectFilter
    }

    // MARK: AnnounceHandlerProtocol

    // Models hasattr(handler, "aspect_filter") — the registration guard
    // (Transport.py:2476-2477). False only when omit_aspect_filter was requested.
    var hasAspectFilter: Bool { !omitAspectFilter }
    var receivePathResponses: Bool { receivePathResponsesParam ?? false }
    var callbackParameterCount: Int { numParams }

    func receivedAnnounce(
        destinationHash: Data,
        announcedIdentity: Identity?,
        appData: Data?,
        announcePacketHash: Data?,
        isPathResponse: Bool?
    ) throws {
        // Mirror behavioral_transport.py:1982-1996 `_record`: destination_hash hex,
        // announced_identity.hash hex (or null), app_data hex (or null), and the
        // announce_packet_hash key ONLY when the dispatch delivered one (>=4 params).
        var rec: [String: JSONValue] = [
            "destination_hash": str(bytesToHex(destinationHash)),
            "announced_identity_hash": announcedIdentity.map { str(bytesToHex($0.hash)) } ?? .null,
            "app_data": appData.map { str(bytesToHex($0)) } ?? .null,
        ]
        if let announcePacketHash {
            rec["announce_packet_hash"] = str(bytesToHex(announcePacketHash))
        }
        callsLock.lock()
        calls.append(.dict(rec))
        callsLock.unlock()

        // Record THEN raise (reference order), so the raising handler still
        // appended its call and the dispatch loop's per-handler isolation
        // (Transport.py:2083-2086) is what protects the next handler.
        if raiseOnCall {
            throw BridgeError.invalidData("recording announce handler deliberately raised")
        }
    }

    /// Snapshot of recorded calls under the per-handler lock.
    func snapshotCalls() -> [JSONValue] {
        callsLock.lock(); defer { callsLock.unlock() }
        return calls
    }
}
let bAnnounceHandlerLock = NSLock()
nonisolated(unsafe) var bAnnounceHandlers: [String: BAnnounceRecordingHandler] = [:]

func handleBehavioralAnnounceCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // Hold a set of real announce packets on the interface's ingress-control queue,
    // run ONE release pass, and report which destination was released. Mirrors
    // behavioral_hold_and_release_announce: each raw is parsed into a genuine
    // RNS.Packet, held via the lowest-hops-keeping hold_announce rule, then ONE
    // lowest-hops announce is selected and popped (Interface.py:228-251). The
    // release gate (ic_held_release) is treated as always-open, as the harness
    // backdates it to 0.
    case "behavioral_hold_and_release_announce":
        let handle = try getString(p, "handle")
        let inst = try requireBehavioralInstance(handle)
        let ifaceId = try getString(p, "iface_id")
        guard inst.interface(forId: ifaceId) != nil else {
            throw BridgeError.invalidData("Unknown iface_id: \(ifaceId)")
        }
        let announceHexes = getStringArray(p, "announces")

        let queueKey = "\(handle):\(ifaceId)"
        bAnnounceHeldLock.lock()
        defer { bAnnounceHeldLock.unlock() }

        let queue: BAnnounceHeldQueue
        if let existing = bAnnounceHeldQueues[queueKey] {
            queue = existing
        } else {
            queue = BAnnounceHeldQueue()
            bAnnounceHeldQueues[queueKey] = queue
        }

        // hops map for THIS call's announces only (unconditional last-wins, exactly
        // like Python's `hops_map[dest] = packet.hops` inside the loop).
        var hopsResult: [String: JSONValue] = [:]
        for h in announceHexes {
            guard let raw = hexToBytes(h) else {
                throw BridgeError.invalidData("could not unpack supplied announce packet")
            }
            let packet: Packet
            do {
                packet = try Packet(from: raw)
            } catch {
                throw BridgeError.invalidData("could not unpack supplied announce packet")
            }
            let dest = packet.destination
            let hops = packet.header.hopCount

            // hold_announce (Interface.py:228-232): keep the minimum-hops packet per
            // destination, preserving the destination's first-seen position.
            if let existing = queue.hops[dest] {
                if hops < existing { queue.hops[dest] = hops }
            } else {
                queue.order.append(dest)
                queue.hops[dest] = hops
            }
            hopsResult[bytesToHex(dest)] = num(Int(hops))
        }

        let heldBefore = queue.order.map { bytesToHex($0) }

        // process_held_announces (Interface.py:240-251): select the held announce
        // with the FEWEST hops (strict <, so the first-seen wins on ties), pop it,
        // and re-inject. The re-injection does NOT re-hold (a fresh mock interface
        // has no ingress burst active), so it leaves the queue otherwise intact.
        var released: [JSONValue] = []
        if let selected = queue.order.min(by: {
            (queue.hops[$0] ?? UInt8.max) < (queue.hops[$1] ?? UInt8.max)
        }) {
            queue.order.removeAll { $0 == selected }
            queue.hops.removeValue(forKey: selected)
            released.append(str(bytesToHex(selected)))
        }

        let heldAfter = queue.order.map { bytesToHex($0) }

        return [
            "held_before": .array(heldBefore.map { str($0) }),
            "held_after": .array(heldAfter.map { str($0) }),
            "released": .array(released),
            "hops": .dict(hopsResult),
        ]

    // Read RNS.Transport.announce_table[dest] (the local-rebroadcast / retransmit
    // state machine, Transport.py:3559-3567). The real swift announceTable is driven
    // by behavioral_inject; we read presence + the entry timestamp through the only
    // public observables AnnounceTable exposes.
    case "behavioral_read_announce_table":
        let handle = try getString(p, "handle")
        let inst = try requireBehavioralInstance(handle)
        let dest = try getHex(p, "dest")

        // Snapshot every announce_table[dest] field (IDX_AT_*, Transport.py:
        // 3559-3567) through the AnnounceTable accessors in a single hop.
        struct ATProbe {
            var found = false
            var ts: Double?
            var packetHash: Data?
            var retries: Int?
            var hops: UInt8?
            var retransmitTimeout: Double?
            var localRebroadcasts: Int?
            var blockRebroadcasts: Bool?
            var receivedFrom: Data?
            var attachedInterface: String?
        }
        let probe: ATProbe = try blockingAsync {
            let table = await inst.transport.getAnnounceTable()
            var p = ATProbe()
            p.found = await table.contains(dest)
            guard p.found else { return p }
            p.ts = (await table.entryTimestamp(dest)).map { $0.timeIntervalSince1970 }
            // Real announce_table[dest][IDX_AT_PACKET].packet_hash via the library
            // accessor — the stored packet is the rebroadcast packet (hops+1) but
            // getHashablePart excludes the hop byte, so this equals the dispatched
            // announce's packet hash (test_callback_arity_packet_hash cross-check).
            p.packetHash = await table.entryPacketHash(dest)
            p.retries = await table.entryRetries(dest)
            p.hops = await table.entryHops(dest)
            p.retransmitTimeout = (await table.entryRetransmitTimeout(dest)).map { $0.timeIntervalSince1970 }
            p.localRebroadcasts = await table.entryLocalRebroadcasts(dest)
            p.blockRebroadcasts = await table.entryBlockRebroadcasts(dest)
            p.receivedFrom = await table.entryReceivedFrom(dest)
            p.attachedInterface = await table.entryAttachedInterface(dest)
            return p
        }

        guard probe.found else { return ["found": boolean(false)] }

        var r: Result = ["found": boolean(true)]
        r["timestamp"] = probe.ts.map { num($0) } ?? .null
        r["packet_hash"] = probe.packetHash.map { hex($0) } ?? .null
        // RNS announce_table fields (Transport.py:3559-3567). IDX_AT_RCVD_IF
        // holds received_from — a HASH (transport_id or destination_hash), not an
        // interface — so it is surfaced as a hex hash; IDX_AT_ATTCHD_IF is the
        // attached interface's id (or null on a broadcast retransmit).
        r["retries"] = probe.retries.map { num($0) } ?? .null
        r["hops"] = probe.hops.map { num(Int($0)) } ?? .null
        r["retransmit_timeout"] = probe.retransmitTimeout.map { num($0) } ?? .null
        r["local_rebroadcasts"] = probe.localRebroadcasts.map { num($0) } ?? .null
        r["block_rebroadcasts"] = probe.blockRebroadcasts.map { boolean($0) } ?? .null
        r["received_from"] = probe.receivedFrom.map { hex($0) } ?? .null
        r["attached_interface"] = probe.attachedInterface.map { str($0) } ?? .null
        return r

    // Read RNS.Transport.announce_rate_table[dest] (the inbound announce-rate limiter
    // state, Transport.py:1830-1860).
    case "behavioral_read_announce_rate":
        let handle = try getString(p, "handle")
        let inst = try requireBehavioralInstance(handle)
        let dest = try getHex(p, "dest")

        // Read the real AnnounceTable rate state (the swift analogue of
        // RNS.Transport.announce_rate_table[dest], Transport.py:1838-1858),
        // driven by the production isRateBlocked() on inbound.
        let rate: (last: Double, rateViolations: Int, blockedUntil: Double, timestamps: [Double])?
            = try blockingAsync {
            let table = await inst.transport.getAnnounceTable()
            guard let e = await table.rateEntry(for: dest) else { return nil }
            return (e.last.timeIntervalSince1970, e.rateViolations,
                    e.blockedUntil.timeIntervalSince1970,
                    e.timestamps.map { $0.timeIntervalSince1970 })
        }

        guard let rate else { return ["found": boolean(false)] }
        return [
            "found": boolean(true),
            "last": num(rate.last),
            "rate_violations": num(rate.rateViolations),
            "blocked_until": num(rate.blockedUntil),
            "timestamps": .array(rate.timestamps.map { num($0) }),
        ]

    // Age an announce_table[dest] entry for deterministic retransmit tests by setting
    // its retransmit_timeout and/or timestamp (Transport.py:587).
    case "behavioral_set_announce_timestamp":
        let handle = try getString(p, "handle")
        let inst = try requireBehavioralInstance(handle)
        let dest = try getHex(p, "dest")

        // Age the entry's IDX_AT_RTRNS_TMO / IDX_AT_TIMESTAMP in place (mirrors
        // cmd_behavioral_set_announce_timestamp, Transport.py:587/3000). The values
        // are absolute epoch seconds; either may be omitted. Setting
        // retransmit_timeout into the past makes the entry due so a force_cull
        // retransmit pass fires deterministically.
        let rtmo = p["retransmit_timeout"]?.doubleValue
        let tstamp = p["timestamp"]?.doubleValue
        let set: Bool = try blockingAsync {
            let table = await inst.transport.getAnnounceTable()
            return await table.ageEntry(
                dest,
                retransmitTimeout: rtmo.map { Date(timeIntervalSince1970: $0) },
                timestamp: tstamp.map { Date(timeIntervalSince1970: $0) }
            )
        }
        return ["set": boolean(set)]

    // Register a recording announce handler on the REAL transport
    // (RNS.Transport.register_announce_handler, Transport.py:2465/:2476-2477). The
    // live dispatch loop drives the handler's receivedAnnounce; we return the
    // transport's own registered verdict (true iff the handler had an aspect_filter).
    case "behavioral_register_announce_handler":
        let handle = try getString(p, "handle")
        let inst = try requireBehavioralInstance(handle)

        let aspectFilter = getStringOptional(p, "aspect_filter")
        let receivePathResponses = getBoolOptional(p, "receive_path_responses")
        let numParams = getIntOptional(p, "num_params") ?? 3
        let raiseOnCall = getBoolOptional(p, "raise_on_call") ?? false
        let omitAspectFilter = getBoolOptional(p, "omit_aspect_filter") ?? false

        let handler = BAnnounceRecordingHandler(
            aspectFilter: aspectFilter,
            receivePathResponses: receivePathResponses,
            numParams: numParams,
            raiseOnCall: raiseOnCall,
            omitAspectFilter: omitAspectFilter
        )

        // RNS only registers a handler that HAS an aspect_filter attribute; the
        // library guards on handler.hasAspectFilter and returns the verdict
        // (registered = handler in Transport.announce_handlers in python).
        let registered = try blockingAsync {
            await inst.transport.registerAnnounceHandler(handler)
        }
        handler.registered = registered

        // secrets.token_hex(8) -> 8 random bytes, 16 hex chars.
        let handlerId = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
            .map { String(format: "%02x", $0) }.joined()

        // Keep the SAME object the transport now holds so read-back sees its calls.
        bAnnounceHandlerLock.lock()
        bAnnounceHandlers["\(handle):\(handlerId)"] = handler
        bAnnounceHandlerLock.unlock()

        return ["handler_id": str(handlerId), "registered": boolean(registered)]

    // Return the calls a registered recording announce-handler has received —
    // populated by the live library dispatch (Transport.py:2055-2069). Pure read
    // of the per-handler-locked recorded list.
    case "behavioral_read_announce_handler_calls":
        let handle = try getString(p, "handle")
        _ = try requireBehavioralInstance(handle)
        let handlerId = try getString(p, "handler_id")

        bAnnounceHandlerLock.lock()
        let handler = bAnnounceHandlers["\(handle):\(handlerId)"]
        bAnnounceHandlerLock.unlock()

        guard let handler else {
            throw BridgeError.invalidData("Unknown announce handler_id: \(handlerId)")
        }
        return [
            "calls": .array(handler.snapshotCalls()),
            "registered": boolean(handler.registered),
        ]

    default:
        return nil
    }
}
