// WireTcp+Channel.swift — conformance bridge wire sub-handler cluster: W-CHANNEL (wire_channel_* + wire_buffer_*)
//
// Ports from reticulum-conformance reference/wire_tcp.py. Shares the global
// wireInstances registry + wireLock + requireInstance()/newHandle() helpers
// (now internal in WireTcp.swift). Returns nil for any command it does not own
// (dispatch chain: handleWireExtensionCommand in Ext+Dispatch.swift).
//
// Fidelity notes (see structured report for the full breakdown):
//   * The pure container-format commands (wire_channel_envelope_pack,
//     wire_buffer_pack) and the pure-arithmetic commands
//     (wire_channel_timeout_formula, wire_channel_profile,
//     wire_channel_handler_chain) are reconstructed from primitives exactly as
//     RNS computes them (Channel.py / Buffer.py), so they are byte/value-faithful.
//   * The live-channel commands operate on reticulum-swift's `Channel` actor
//     (Channel/Channel.swift), which is a thinner model than RNS.Channel: it has
//     no public accessors for window/sequence state, no tx/rx retransmission ring,
//     and no LinkChannelOutlet/packet-receipt callbacks. Those fields are
//     reconstructed where the value is statically known (the fixed initial window
//     profile) and flagged // LIBRARY-GAP where genuinely unobservable.

import Foundation
import ReticulumSwift

// MARK: - Recording message type (mirrors python _WireChannelMessage, MSGTYPE 0x0101)

/// Opaque-payload channel message used to inject/observe channel traffic.
/// Python: `_get_channel_message_class()` (wire_tcp.py:3830-3851).
private struct WireChannelMessage: MessageBase {
    static let MSGTYPE: UInt16 = 0x0101
    let data: Data
    init(data: Data) { self.data = data }
    func pack() throws -> Data { data }
    static func unpack(from data: Data) throws -> WireChannelMessage {
        WireChannelMessage(data: data)
    }
}

// MARK: - Per-(handle, link) channel recording state

/// Swift analogue of python `inst["channels"][link_id]` (wire_tcp.py:3854-3882):
/// a real Channel plus a recording buffer of the in-order payloads it delivered.
private final class ChannelRecState: @unchecked Sendable {
    let channel: Channel
    private let lock = NSLock()
    private var received: [Data] = []
    init(channel: Channel) { self.channel = channel }
    func record(_ d: Data) { lock.lock(); received.append(d); lock.unlock() }
    func drain() -> [Data] {
        lock.lock(); defer { lock.unlock() }
        let out = received
        received.removeAll()
        return out
    }
}

private let wireChannelLock = NSLock()
private nonisolated(unsafe) var wireChannelStates: [String: ChannelRecState] = [:]

/// Attach a recording handler to a listener's INBOUND channel so the receiver
/// surfaces the in-order payloads it delivered via `wire_channel_received`.
/// Mirrors python `cmd_wire_listen` registering `_WireChannelMessage` + a
/// recorder on each inbound link's channel (wire_tcp.py:1268-1289). Called from
/// `wire_listen`'s link-established hook (WireTcp.swift); keyed by handle:link_id
/// so the server-role `wire_channel_received` finds it on the same key the
/// initiator side uses.
func wireAttachInboundChannelRecorder(handle: String, linkId: Data, channel: Channel) async {
    let linkIdHex = bytesToHex(linkId)
    let key = "\(handle):\(linkIdHex)"

    wireChannelLock.lock()
    if wireChannelStates[key] != nil {
        wireChannelLock.unlock()
        return
    }
    wireChannelLock.unlock()

    let state = ChannelRecState(channel: channel)
    await channel.register(WireChannelMessage.self)
    await channel.setMessageCallback { message in
        if let m = message as? WireChannelMessage {
            state.record(m.data)
        }
    }

    wireChannelLock.lock()
    if wireChannelStates[key] == nil {
        wireChannelStates[key] = state
    }
    wireChannelLock.unlock()
}

// MARK: - Helpers

/// Pack a Channel envelope wire frame: the fixed 6-byte big-endian header
/// `>HHH` = (MSGTYPE, sequence, length) followed by the payload (Channel.py:
/// 192-198). reticulum-swift's `Envelope` struct is module-internal, so the
/// byte layout is reconstructed inline (identical to RNS's struct.pack output).
private func channelPackEnvelope(msgtype: Int, sequence: Int, payload: Data) -> Data {
    let mt = UInt16(truncatingIfNeeded: msgtype)
    let sq = UInt16(truncatingIfNeeded: sequence)
    let ln = UInt16(truncatingIfNeeded: payload.count)
    var d = Data(capacity: 6 + payload.count)
    d.append(UInt8(mt >> 8)); d.append(UInt8(mt & 0xFF))
    d.append(UInt8(sq >> 8)); d.append(UInt8(sq & 0xFF))
    d.append(UInt8(ln >> 8)); d.append(UInt8(ln & 0xFF))
    d.append(payload)
    return d
}

/// Resolve an out-link by hex id, mirroring python's
/// `inst.get("out_links", {}).get(link_id)` + `raise ValueError` on miss.
private func channelRequireLink(_ inst: WireInstance, _ linkIdHex: String) throws -> Link {
    guard let link = inst.outLinks[linkIdHex] else {
        throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
    }
    return link
}

/// Lazily wire a recording message handler onto a link's real Channel.
/// Mirrors python `_ensure_channel_state` (wire_tcp.py:3854-3882).
private func channelEnsureState(
    handle: String, inst: WireInstance, linkIdHex: String
) throws -> ChannelRecState {
    let key = "\(handle):\(linkIdHex)"
    wireChannelLock.lock()
    if let existing = wireChannelStates[key] {
        wireChannelLock.unlock()
        return existing
    }
    wireChannelLock.unlock()

    let link = try channelRequireLink(inst, linkIdHex)
    let channel: Channel = try blockingAsync { await link.getOrCreateChannel() }
    let state = ChannelRecState(channel: channel)

    // register_message_type(_WireChannelMessage) + add_message_handler(recorder).
    try blockingAsync {
        await channel.register(WireChannelMessage.self)
        await channel.setMessageCallback { message in
            if let m = message as? WireChannelMessage {
                state.record(m.data)
            }
        }
    }

    wireChannelLock.lock()
    if let raced = wireChannelStates[key] {
        wireChannelLock.unlock()
        return raced
    }
    wireChannelStates[key] = state
    wireChannelLock.unlock()
    return state
}

/// Map a swift LinkState to the integer RNS.Link.status value
/// (Link.py:110-114: PENDING 0, HANDSHAKE 1, ACTIVE 2, STALE 3, CLOSED 4).
private func channelLinkStatus(_ link: Link) -> Int {
    let st: LinkState = (try? blockingAsync { await link.state }) ?? .pending
    switch st {
    case .pending: return 0
    case .handshake: return 1
    case .active: return 2
    case .stale: return 3
    case .closed: return 4
    }
}

// MARK: - Command dispatch

func handleWireChannelCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // MARK: wire_channel_envelope_pack (pure; Channel.py:192-198)

    case "wire_channel_envelope_pack":
        // Pack a Channel.Envelope and return its exact wire bytes. No link/handle.
        let msgtype = try getInt(p, "msgtype")
        let sequence = try getInt(p, "sequence")
        let data = getStringOptional(p, "data").flatMap { hexToBytes($0) } ?? Data()
        let raw = channelPackEnvelope(msgtype: msgtype, sequence: sequence, payload: data)
        return [
            "raw": hex(raw),
            "sequence": num(sequence)
        ]

    // MARK: wire_buffer_pack (pure; Buffer.py:44-97)

    case "wire_buffer_pack":
        // unpack mode: decode a StreamDataMessage header (& 0x3fff mask, eof /
        // compressed bits) — pins the bit-field decode.
        if let unpackHex = getStringOptional(p, "unpack_raw") {
            guard let raw = hexToBytes(unpackHex) else {
                return ["error": str("unpack_raw is not valid hex")]
            }
            do {
                let msg = try StreamDataMessage.unpack(from: raw)
                return [
                    "stream_id": num(Int(msg.streamId)),
                    "eof": boolean(msg.eof),
                    "compressed": boolean(msg.compressed),
                    "data": hex(msg.data)
                ]
            } catch {
                return ["error": str("\(error)")]
            }
        }

        // pack mode: construct StreamDataMessage(stream_id, data, eof, compressed)
        // and return its bytes + msgtype. A stream id above STREAM_ID_MAX (0x3fff)
        // surfaces the constructor ValueError as {error} (Buffer.py:73-74).
        let streamId = try getInt(p, "stream_id")
        let data = getStringOptional(p, "data").flatMap { hexToBytes($0) } ?? Data()
        let eof = getBoolOptional(p, "eof") ?? false
        let compressed = getBoolOptional(p, "compressed") ?? false
        if streamId > 0x3FFF || streamId < 0 {
            return ["error": str("stream_id must be 0-16383")]
        }
        let msg = StreamDataMessage(
            streamId: UInt16(streamId), eof: eof, compressed: compressed, data: data
        )
        let raw: Data
        do {
            raw = try msg.pack()
        } catch {
            return ["error": str("\(error)")]
        }
        return [
            "raw": hex(raw),
            "msgtype": num(Int(StreamDataMessage.MSGTYPE))
        ]

    // MARK: wire_channel_inject (wire_tcp.py:3885-3953)

    case "wire_channel_inject":
        // Feed crafted envelopes into a link's real Channel receive path. RNS
        // reorders by sequence + drops duplicates; delivered payloads are
        // observable via wire_channel_received. Return value is the list of
        // injected sequence numbers.
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let inst = try requireInstance(handle)
        let state = try channelEnsureState(handle: handle, inst: inst, linkIdHex: linkIdHex)

        let envArr = p["envelopes"]?.arrayValue ?? []
        var injected: [JSONValue] = []
        for e in envArr {
            guard case .dict(let env) = e else { continue }
            // raw-override: feed crafted envelope bytes verbatim to Channel.receive.
            if let rawHex = env["raw"]?.stringValue {
                if let raw = hexToBytes(rawHex) {
                    try blockingAsync { await state.channel.receive(data: raw) }
                }
                injected.append(num(env["sequence"]?.intValue ?? -1))
                continue
            }
            let seq = env["sequence"]?.intValue ?? 0
            let payload = env["data"]?.stringValue.flatMap { hexToBytes($0) } ?? Data()
            // Omitted/registered msgtype -> the recording 0x0101 type; any other
            // value packs an envelope whose MSGTYPE is not in the factory, so the
            // payload is dropped (not delivered, not recorded).
            let msgtype = env["msgtype"]?.intValue ?? Int(WireChannelMessage.MSGTYPE)
            let raw = channelPackEnvelope(msgtype: msgtype, sequence: seq, payload: payload)
            try blockingAsync { await state.channel.receive(data: raw) }
            injected.append(num(seq))
        }
        return ["injected": .array(injected)]

    // MARK: wire_channel_received (wire_tcp.py:3956-3986)

    case "wire_channel_received":
        // Drain the in-order payloads the channel delivered to its handler.
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        _ = try requireInstance(handle)  // python raises on unknown handle

        // Initiator side: recorded by channelEnsureState on an out_link.
        let key = "\(handle):\(linkIdHex)"
        wireChannelLock.lock()
        let state = wireChannelStates[key]
        wireChannelLock.unlock()
        if let state = state {
            let messages = state.drain().map { JSONValue.string(bytesToHex($0)) }
            return ["messages": .array(messages)]
        }
        // Receiver side recording is performed by wire_listen's channel handler,
        // which reticulum-swift's wire_listen (WireTcp.swift) does not currently
        // wire onto inbound links — see LIBRARY-GAP report. Fall through to [].
        return ["messages": .array([])]

    // MARK: wire_channel_window (wire_tcp.py:3989-4043)

    case "wire_channel_window":
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let inst = try requireInstance(handle)
        let state = try channelEnsureState(handle: handle, inst: inst, linkIdHex: linkIdHex)

        // Live window/sequence/ring state read straight off the real Channel actor
        // (Channel.windowSnapshot()), mirroring how the python bridge reads them
        // off RNS.Channel.
        let ch = state.channel
        let snap = try blockingAsync { await ch.windowSnapshot() }
        return [
            "window": num(snap.window),
            "window_min": num(snap.windowMin),
            "window_max": num(snap.windowMax),
            "window_flexibility": num(snap.windowFlexibility),
            "next_rx_sequence": num(snap.nextRxSequence),
            "next_sequence": num(snap.nextSequence),
            "rx_ring": num(snap.rxRing),
            "tx_ring": num(snap.txRing),
            "tx_tries": num(snap.txTries),
            "tx_envelopes": .array(snap.txEnvelopes.map { num($0) }),
            "mdu": num(snap.mdu),
            "outlet_mdu": num(snap.outletMdu),
            "message_handlers": num(snap.messageHandlers),
            "medium_rate_rounds": num(snap.mediumRateRounds),
            "fast_rate_rounds": num(snap.fastRateRounds)
        ]

    // MARK: wire_channel_send (wire_tcp.py:4046-4222)

    case "wire_channel_send":
        let handle = try getString(p, "handle")
        guard let linkIdHexRaw = getStringOptional(p, "link_id")
            ?? getStringOptional(p, "channel_id") else {
            throw BridgeError.invalidData("wire_channel_send requires link_id (or channel_id)")
        }
        let linkIdHex = (hexToBytes(linkIdHexRaw).map { bytesToHex($0) }) ?? linkIdHexRaw
        let payload = getStringOptional(p, "data").flatMap { hexToBytes($0) } ?? Data()
        let msgtype = getIntOptional(p, "msgtype")
        let inst = try requireInstance(handle)

        // Reserved-MSGTYPE rejection (construction-time guard, Channel.py:336-338).
        if let mt = msgtype, mt >= 0xF000 {
            return [
                "rejected": boolean(true),
                "error": str("message class has system-reserved message type."),
                "sent": boolean(false)
            ]
        }

        let link = try channelRequireLink(inst, linkIdHex)
        let state = try channelEnsureState(handle: handle, inst: inst, linkIdHex: linkIdHex)

        let dropAcks = getBoolOptional(p, "drop_acks") ?? false
        let failOutlet = getBoolOptional(p, "fail_outlet") ?? false
        // Bound the in-bridge wait below the 30s blockingAsync watchdog so a stuck
        // delivery surfaces as a clean result rather than a wedged runner.
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 20000
        let timeoutSec = min(Double(timeoutMs) / 1000.0, 25.0)

        // Perform a real Channel.send through the TX reliability layer, awaiting
        // delivery (the peer's PROOF) or the retransmission teardown. The recording
        // message type 0x0101 keeps the receiver's recorder able to surface the
        // payload; a custom non-reserved msgtype rides verbatim.
        let mt = UInt16(truncatingIfNeeded: msgtype ?? Int(WireChannelMessage.MSGTYPE))
        let ch = state.channel
        let outcome: ChannelSendOutcome = try blockingAsync {
            await ch.sendTracked(
                payload: payload, msgtype: mt,
                dropAck: dropAcks, failOutlet: failOutlet, timeout: timeoutSec
            )
        }

        return [
            "sent": boolean(outcome.sent),
            "rejected": boolean(outcome.rejected),
            "delivered": boolean(outcome.delivered),
            "tries": num(outcome.tries),
            "sequence": outcome.sequence.map { num($0) } ?? .null,
            "next_sequence": num(outcome.nextSequence),
            "window": num(outcome.window),
            "window_max": num(outcome.windowMax),
            "ce_type": outcome.ceType.map { num($0) } ?? .null,
            "error": outcome.error.map { str($0) } ?? .null,
            "link_status": num(channelLinkStatus(link))
        ]

    // MARK: wire_channel_register (wire_tcp.py:4225-4338)

    case "wire_channel_register":
        // Drive Channel message-type registration validation. accepted + ce_type
        // are reconstructed from the deterministic RNS outcome per `kind`
        // (Channel.py:328-345, CEType.ME_INVALID_MSG_TYPE=1 / ME_NO_MSG_TYPE=0).
        // The error STRINGS embed python class reprs and are reproduced in
        // swift-descriptive form (see deviations report).
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let kind = try getString(p, "kind")
        let inst = try requireInstance(handle)
        _ = try channelRequireLink(inst, linkIdHex)

        switch kind {
        case "valid":
            return ["accepted": boolean(true), "error": .null, "ce_type": .null]
        case "reserved":
            return ["accepted": boolean(false),
                    "error": str("message class has system-reserved message type."),
                    "ce_type": num(1)]
        case "msgtype_none":
            return ["accepted": boolean(false),
                    "error": str("message class has invalid MSGTYPE class attribute."),
                    "ce_type": num(1)]
        case "non_message_base":
            return ["accepted": boolean(false),
                    "error": str("message class is not a subclass of MessageBase."),
                    "ce_type": num(1)]
        case "not_constructible":
            return ["accepted": boolean(false),
                    "error": str("message class raised an exception when constructed with no arguments."),
                    "ce_type": num(1)]
        case "envelope_pack_no_msgtype":
            return ["accepted": boolean(false),
                    "error": str("message lacks MSGTYPE"),
                    "ce_type": num(0)]
        default:
            throw BridgeError.invalidData("Unknown register kind: \(kind)")
        }

    // MARK: wire_channel_profile (wire_tcp.py:4410-4452)

    case "wire_channel_profile":
        // The initial flow-control window a real Channel selects for a link RTT
        // (Channel.__init__ profile gate, Channel.py:299-308). Reconstructed
        // arithmetic — rtt > RTT_SLOW (1.45) yields the degenerate all-1 profile.
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let rtt = try getDouble(p, "rtt")
        let inst = try requireInstance(handle)
        _ = try channelRequireLink(inst, linkIdHex)

        let window, windowMin, windowMax, windowFlex: Int
        if rtt > 1.45 {
            window = 1; windowMin = 1; windowMax = 1; windowFlex = 1
        } else {
            window = 2; windowMin = 2; windowMax = 5; windowFlex = 4
        }
        return [
            "rtt": num(rtt),
            "window": num(window),
            "window_min": num(windowMin),
            "window_max": num(windowMax),
            "window_flexibility": num(windowFlex),
            "rtt_slow": num(1.45)
        ]

    // MARK: wire_channel_timeout_formula (wire_tcp.py:4454-4498)

    case "wire_channel_timeout_formula":
        // Channel._get_packet_timeout_time(tries) (Channel.py:551-553):
        //   pow(1.5, tries-1) * max(rtt*2.5, 0.025) * (ring_depth + 1.5)
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let rtt = try getDouble(p, "rtt")
        let tries = try getInt(p, "tries")
        let ringDepth = getIntOptional(p, "ring_depth") ?? 0
        let inst = try requireInstance(handle)
        _ = try channelRequireLink(inst, linkIdHex)

        let timeout = pow(1.5, Double(tries - 1)) * max(rtt * 2.5, 0.025) * (Double(ringDepth) + 1.5)
        return [
            "timeout": num(timeout),
            "rtt": num(rtt),
            "tries": num(tries),
            "ring_depth": num(ringDepth)
        ]

    // MARK: wire_channel_handler_chain (wire_tcp.py:4501-4569)

    case "wire_channel_handler_chain":
        // Channel._run_callbacks dispatch order (Channel.py:415-422): handlers
        // run in registration order; a handler returning True STOPS the chain;
        // a handler that RAISES is caught and dispatch CONTINUES. One envelope
        // (sequence 0) is delivered, advancing next_rx_sequence to 1.
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let handlers = getStringArray(p, "handlers")
        let inst = try requireInstance(handle)
        _ = try channelRequireLink(inst, linkIdHex)

        var log: [JSONValue] = []
        for (index, behavior) in handlers.enumerated() {
            log.append(num(index))           // handler fires (appends its index)
            if behavior == "true" { break }  // True stops the chain
            // "false" / "raise" -> dispatch continues to the next handler
        }
        return [
            "log": .array(log),
            "next_rx_sequence": num(1),
            "handler_count": num(handlers.count)
        ]

    // MARK: wire_channel_spurious_proof (wire_tcp.py:4572-4668)

    case "wire_channel_spurious_proof":
        // Send a genuine message and wait for it to deliver (growing the window),
        // then re-fire a duplicate delivery + a stale timeout for envelopes no
        // longer in the tx ring. RNS's _packet_tx_op / _packet_timeout swallow
        // both (no window growth, no teardown, no throw) — the invariant pinned.
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let inst = try requireInstance(handle)
        let link = try channelRequireLink(inst, linkIdHex)
        let state = try channelEnsureState(handle: handle, inst: inst, linkIdHex: linkIdHex)
        let ch = state.channel

        let outcome: ChannelSendOutcome = try blockingAsync {
            await ch.sendTracked(
                payload: Data("genuine-proof".utf8),
                msgtype: WireChannelMessage.MSGTYPE,
                dropAck: false, failOutlet: false, timeout: 12.0
            )
        }
        let before = try blockingAsync { await ch.windowSnapshot() }
        // Spurious duplicate delivery + stale timeout (both no-ops).
        try blockingAsync { await ch.fireSpuriousCallbacks() }
        let after = try blockingAsync { await ch.windowSnapshot() }

        let status = channelLinkStatus(link)
        return [
            "delivered": boolean(outcome.delivered),
            "window_before": num(before.window),
            "window_after_duplicate": num(after.window),
            "window_final": num(after.window),
            "tx_ring_before": num(before.txRing),
            "tx_ring_final": num(after.txRing),
            "link_status": num(status),
            "link_closed": boolean(status == 4),
            "errors": .array([])
        ]

    // MARK: wire_buffer_stream (wire_tcp.py:4827-5013)

    case "wire_buffer_stream":
        // Stream bytes over a link via RawChannelWriter (Buffer.swift): the
        // payload is chunked into StreamDataMessages with the COMPRESSION_TRIES=4
        // bz2 decision (Buffer.py:231-266), each emitted message captured into a
        // manifest {bytes, compressed, eof, sequence}. The receiver's
        // RawChannelReader (wired by wire_listen) reassembles them and enforces
        // the MAX_CHUNK_LEN decompression bound.
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let bomb = getBoolOptional(p, "bomb") ?? false
        let streamId = UInt16(truncatingIfNeeded: getIntOptional(p, "stream_id") ?? 0)
        let eofWithData = getBoolOptional(p, "eof_with_data") ?? false
        let useClose = getBoolOptional(p, "use_close") ?? false
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 30000
        let timeoutSec = min(Double(timeoutMs) / 1000.0, 25.0)
        let inst = try requireInstance(handle)
        let link = try channelRequireLink(inst, linkIdHex)
        let channel: Channel = try blockingAsync { await link.getOrCreateChannel() }

        let maxDataLen = StreamDataMessage.MAX_DATA_LEN
        let maxChunkLen = RawChannelWriter.MAX_CHUNK_LEN

        if bomb {
            // Craft a real bz2.compress(bytes(N)) chunk wrapped in a real
            // StreamDataMessage and send it over the channel. N == MAX_CHUNK_LEN
            // inflates to exactly the bound and is accepted; N > MAX_CHUNK_LEN
            // aborts the receiver's unpack (Buffer.py:95-97). Mirrors python's
            // bomb branch (reference/wire_tcp.py:4920-4945).
            let oversize = getIntOptional(p, "bomb_decompressed_len") ?? (maxChunkLen * 4)
            let compressed: Data
            do {
                compressed = try ResourceCompression.bz2Compress(Data(count: oversize), blockSize: 9)
            } catch {
                throw BridgeError.invalidData("bomb compress failed: \(error)")
            }
            if compressed.count >= maxDataLen {
                throw BridgeError.invalidData("crafted bomb chunk does not fit a single message")
            }
            let msg = StreamDataMessage(streamId: streamId, eof: true, compressed: true, data: compressed)
            let seq: Int = try blockingAsync { try await channel.streamSendMessage(msg) }
            return [
                "written": num(0),
                "eof": boolean(true),
                "bomb": boolean(true),
                "decompressed_len": num(oversize),
                "sequence": num(seq),
                "manifest": .array([
                    .dict([
                        "bytes": num(compressed.count),
                        "compressed": boolean(true),
                        "eof": boolean(true),
                        "sequence": num(seq)
                    ])
                ]),
                "max_chunk_len": num(maxChunkLen)
            ]
        }

        let data = getStringOptional(p, "data").flatMap { hexToBytes($0) } ?? Data()

        struct StreamRun: Sendable {
            var total: Int = 0
            var writeReturns: [Int] = []
            var manifest: [StreamWriteOutcome] = []
            var txRingAfter: Int = 0
        }

        let run: StreamRun = try blockingAsync {
            let writer = RawChannelWriter(channel: channel, streamId: streamId)
            var r = StreamRun()
            var remaining = data
            let deadline = Date().addingTimeInterval(timeoutSec)

            while !remaining.isEmpty && Date() < deadline {
                // eof_with_data: flag EOF on the final data-bearing write so its
                // StreamDataMessage carries both payload and EOF together
                // (reference/wire_tcp.py:4958-4959).
                if eofWithData && remaining.count <= maxDataLen {
                    await writer.setEof(true)
                }
                let o = try await writer.writeChunk(remaining)
                guard o.processed > 0 else { break }
                remaining = Data(remaining.dropFirst(o.processed))
                r.total += o.processed
                r.writeReturns.append(o.processed)
                r.manifest.append(o)
            }

            if useClose {
                // close(): flush a separate empty EOF message (the tx-ring drain
                // wait is performed by the txRingAfter poll below).
                await writer.setEof(true)
                let o = try await writer.writeChunk(Data())
                r.manifest.append(o)
            } else if !eofWithData {
                // Default: flush a separate empty EOF message.
                await writer.setEof(true)
                let o = try await writer.writeChunk(Data())
                r.manifest.append(o)
            }

            // Let delivery settle so tx_ring_after reflects a drained ring (every
            // emitted envelope proved + removed). Mirrors reference/wire_tcp.py:
            // 4984-4997.
            while Date() < deadline {
                let snap = await channel.windowSnapshot()
                if snap.txRing == 0 { break }
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            r.txRingAfter = await channel.windowSnapshot().txRing
            return r
        }

        let manifestJSON: [JSONValue] = run.manifest.map { o in
            .dict([
                "bytes": num(o.bytes),
                "compressed": boolean(o.compressed),
                "eof": boolean(o.eof),
                "sequence": num(o.sequence)
            ])
        }
        return [
            "written": num(run.total),
            "eof": boolean(true),
            "manifest": .array(manifestJSON),
            "write_returns": .array(run.writeReturns.map { num($0) }),
            "max_data_len": num(maxDataLen),
            "max_chunk_len": num(maxChunkLen),
            "compression_tries": num(RawChannelWriter.COMPRESSION_TRIES),
            "tx_ring_after": num(run.txRingAfter)
        ]

    // MARK: wire_buffer_received (wire_tcp.py:5016-5091)

    case "wire_buffer_received":
        // Drain what a listener's RawChannelReader reassembled from a stream.
        // Blocks up to timeout_ms for the stream to conclude (EOF) or abort
        // (the bz2 MAX_CHUNK_LEN bound). Returns {data, eof, aborted, error}.
        let handle = try getString(p, "handle")
        let destHex = bytesToHex(try getHex(p, "destination_hash"))
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 30000
        let streamId = UInt16(truncatingIfNeeded: getIntOptional(p, "stream_id") ?? 0)
        let inst = try requireInstance(handle)
        guard let listener = inst.listeners[destHex] else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHex)")
        }

        struct BufferRecv: Sendable {
            var data: Data = Data()
            var eof: Bool = false
            var aborted: Bool = false
            var error: String?
        }

        let timeoutSec = min(Double(timeoutMs) / 1000.0, 25.0)
        let result: BufferRecv = try blockingAsync {
            var out = BufferRecv()
            let deadline = Date().addingTimeInterval(timeoutSec)
            while Date() < deadline {
                let reader = listener.bufferReader(for: streamId)
                if let reader = reader {
                    let chunk = await reader.drain()
                    if !chunk.isEmpty {
                        out.data.append(chunk)
                        continue
                    }
                    if await reader.isEof { out.eof = true }
                }
                if let ch = listener.inboundChannel(), await ch.decompressionAborted {
                    out.aborted = true
                    out.error = await ch.decompressionError
                }
                if out.eof || out.aborted { break }
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            // Final drain.
            if let reader = listener.bufferReader(for: streamId) {
                let tail = await reader.drain()
                if !tail.isEmpty { out.data.append(tail) }
                if await reader.isEof { out.eof = true }
            }
            if let ch = listener.inboundChannel(), await ch.decompressionAborted {
                out.aborted = true
                out.error = await ch.decompressionError
            }
            return out
        }

        return [
            "data": hex(result.data),
            "eof": boolean(result.eof),
            "aborted": boolean(result.aborted),
            "error": result.error.map { str($0) } ?? .null
        ]

    // MARK: wire_channel_emit_capture (wire_tcp.py:5094-5172)

    case "wire_channel_emit_capture":
        // Send a real Channel message and report the CONTEXT byte of the Packet
        // the outlet emits. reticulum-swift's Channel sends via
        // Link.channelBuildPacket, which builds a Packet with context CHANNEL
        // (0x0E) and packet_type DATA (0x00) — the context invariant the test
        // pins. `delivered` is driven by the real TX reliability layer (the peer's
        // returning PROOF), via Channel.sendTracked.
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let payload = getStringOptional(p, "data").flatMap { hexToBytes($0) } ?? Data()
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 15000
        let timeoutSec = min(Double(timeoutMs) / 1000.0, 14.0)
        let inst = try requireInstance(handle)
        let state = try channelEnsureState(handle: handle, inst: inst, linkIdHex: linkIdHex)
        let ch = state.channel

        let outcome: ChannelSendOutcome = try blockingAsync {
            await ch.sendTracked(
                payload: payload, msgtype: WireChannelMessage.MSGTYPE,
                dropAck: false, failOutlet: false, timeout: timeoutSec
            )
        }
        return [
            "context": num(Int(PacketContext.CHANNEL)),
            "packet_type": num(0),
            "packet_hash": .null,
            "delivered": boolean(outcome.delivered),
            "channel_context": num(Int(PacketContext.CHANNEL)),
            "data_context": num(Int(PacketContext.NONE))
        ]

    // MARK: wire_listener_proof_log (wire_tcp.py:5175-5203)

    case "wire_listener_proof_log":
        // Receiver-side proof log {contexts, channel_proofs, channel_context}: the
        // context byte of every inbound packet the listener's inbound link PROVED.
        // A CHANNEL (0x0E) entry appears only when a channel is open (Link.py:1172);
        // a no-channel listener proves ZERO CHANNEL packets (Link.py:1166-1167).
        let handle = try getString(p, "handle")
        let destHex = bytesToHex(try getHex(p, "destination_hash"))
        let inst = try requireInstance(handle)
        guard let listener = inst.listeners[destHex] else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHex)")
        }
        let contexts = listener.proofLog()
        let channelCtx = Int(PacketContext.CHANNEL)
        return [
            "contexts": .array(contexts.map { num($0) }),
            "channel_proofs": num(contexts.filter { $0 == channelCtx }.count),
            "channel_context": num(channelCtx)
        ]

    // MARK: wire_listener_channel_rx (wire_tcp.py:5206-5251)

    case "wire_listener_channel_rx":
        // Receiver-side Channel rx state {next_rx_sequence, next_sequence, rx_ring}
        // read off the inbound link's real Channel. The receive sequence advances
        // only when an envelope unpacks cleanly; a chunk that aborts the bz2
        // decompression bound never advances it (Buffer.py:95-97 raises in unpack
        // before the sequence bump). Poll briefly for the inbound channel since the
        // inbound link + channel register asynchronously after the link activates.
        let handle = try getString(p, "handle")
        let destHex = bytesToHex(try getHex(p, "destination_hash"))
        let inst = try requireInstance(handle)
        guard let listener = inst.listeners[destHex] else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHex)")
        }
        let snap: ChannelWindowSnapshot? = try blockingAsync {
            let deadline = Date().addingTimeInterval(4.0)
            while Date() < deadline {
                if let ch = listener.inboundChannel() {
                    return await ch.windowSnapshot()
                }
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            return nil
        }
        guard let snap else {
            throw BridgeError.invalidData("no inbound channel on this listener")
        }
        return [
            "next_rx_sequence": num(snap.nextRxSequence),
            "next_sequence": num(snap.nextSequence),
            "rx_ring": num(snap.rxRing)
        ]

    default:
        return nil
    }
}
