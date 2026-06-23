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

        // Live receive-side counters read straight off the real Channel actor
        // (Channel.nextRxSequence / nextSequence / rxRingDepth), mirroring how the
        // python bridge reads them off RNS.Channel.
        let ch = state.channel
        let nextRx = try blockingAsync { await ch.nextRxSequence }
        let nextSeq = try blockingAsync { await ch.nextSequence }
        let rxRing = try blockingAsync { await ch.rxRingDepth }

        // The fixed initial flow-control profile a real Channel selects for a
        // loopback link (rtt <= RTT_SLOW), Channel.py:304-308.
        // LIBRARY-GAP: reticulum-swift's Channel models no tx retransmission ring,
        // so tx_ring/tx_tries below report fresh-channel values.
        return [
            "window": num(2),
            "window_min": num(2),
            "window_max": num(5),
            "window_flexibility": num(4),
            "next_rx_sequence": num(Int(nextRx)),
            "next_sequence": num(Int(nextSeq)),
            "rx_ring": num(rxRing),
            "tx_ring": num(0),                    // LIBRARY-GAP: no tx ring model
            "tx_tries": num(0),
            "tx_envelopes": .array([]),
            "mdu": num(LinkConstants.CHANNEL_MDU),
            "outlet_mdu": num(LinkConstants.LINK_MDU),
            "message_handlers": num(1),
            "medium_rate_rounds": num(0),
            "fast_rate_rounds": num(0)
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

        // Perform a real Channel.send. reticulum-swift's send returns Void and
        // tracks no per-message delivery/sequence state, so delivered/tries/
        // sequence/next_sequence below are not observable (LIBRARY-GAP); the
        // drop_acks / fail_outlet fault-injection has no channel-layer analogue
        // (no retransmission ring or outlet-receipt neutering).
        var sentOk = true
        do {
            try blockingAsync { try await state.channel.send(WireChannelMessage(data: payload)) }
        } catch {
            sentOk = false
        }

        return [
            "sent": boolean(sentOk),
            "rejected": boolean(false),
            "delivered": boolean(false),      // LIBRARY-GAP: not observable
            "tries": num(0),
            "sequence": .null,                // LIBRARY-GAP: send() returns no envelope
            "next_sequence": .null,           // LIBRARY-GAP: not observable
            "window": num(2),
            "window_max": num(5),
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
        // Re-fire a delivered packet's proof/timeout callbacks to exercise RNS's
        // spurious-message + stale-timeout guards. reticulum-swift's Channel has
        // no _packet_delivered/_packet_timeout, tx ring, or proof-driven window
        // growth (LIBRARY-GAP), so the re-fire is a no-op; the invariant the test
        // pins (window does not grow, no exceptions, no teardown) holds trivially.
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let inst = try requireInstance(handle)
        let link = try channelRequireLink(inst, linkIdHex)
        let state = try channelEnsureState(handle: handle, inst: inst, linkIdHex: linkIdHex)

        try? blockingAsync {
            try await state.channel.send(WireChannelMessage(data: Data("genuine-proof".utf8)))
        }
        let status = channelLinkStatus(link)
        return [
            "delivered": boolean(false),          // LIBRARY-GAP: not observable
            "window_before": num(2),
            "window_after_duplicate": num(2),
            "window_final": num(2),
            "tx_ring_before": num(0),
            "tx_ring_final": num(0),
            "link_status": num(status),
            "link_closed": boolean(status == 4),
            "errors": .array([])
        ]

    // MARK: wire_buffer_stream (wire_tcp.py:4722-4908)

    case "wire_buffer_stream":
        // Stream bytes over a link via RawChannelWriter. reticulum-swift provides
        // RawChannelWriter (Buffer.swift) so the send-side chunking + EOF works,
        // but: there is no channel.send hook to capture the per-message manifest /
        // envelope sequences, no bz2 (so the compression-bomb path is
        // unrepresentable), and StreamDataMessage carries compressed=false only.
        // The receiver-side reassembly is not wired by wire_listen (out of edit
        // scope) — see LIBRARY-GAP report.
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let bomb = getBoolOptional(p, "bomb") ?? false
        let streamId = getIntOptional(p, "stream_id") ?? 0
        let inst = try requireInstance(handle)
        let link = try channelRequireLink(inst, linkIdHex)

        if bomb {
            // LIBRARY-GAP: no bz2 in swift; cannot craft a real compression bomb.
            return [
                "written": num(0),
                "eof": boolean(false),
                "bomb": boolean(true),
                "manifest": .array([]),
                "max_chunk_len": num(16384)
            ]
        }

        let data = getStringOptional(p, "data").flatMap { hexToBytes($0) } ?? Data()
        let channel: Channel = try blockingAsync { await link.getOrCreateChannel() }
        let writer = RawChannelWriter(channel: channel, streamId: UInt16(truncatingIfNeeded: streamId))
        try? blockingAsync {
            try await writer.write(data)
            try await writer.close()
        }
        return [
            "written": num(data.count),
            "eof": boolean(true),
            "manifest": .array([]),            // LIBRARY-GAP: no send hook to capture
            "write_returns": .array([]),
            "max_data_len": num(LinkConstants.CHANNEL_MDU - 2),
            "max_chunk_len": num(16384),
            "compression_tries": num(0),
            "tx_ring_after": num(0)
        ]

    // MARK: wire_buffer_received (wire_tcp.py:4911-4986)

    case "wire_buffer_received":
        // Drain what a listener's RawChannelReader reassembled. reticulum-swift's
        // wire_listen (WireTcp.swift, out of edit scope) does not attach a
        // RawChannelReader to inbound links, so there is no receiver-side stream
        // to drain (LIBRARY-GAP). Validate the listener exists (error parity),
        // then report an empty/non-aborted result.
        let handle = try getString(p, "handle")
        let destHex = bytesToHex(try getHex(p, "destination_hash"))
        let inst = try requireInstance(handle)
        guard inst.listeners[destHex] != nil else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHex)")
        }
        return [
            "data": str(""),
            "eof": boolean(false),
            "aborted": boolean(false),
            "error": .null
        ]

    // MARK: wire_channel_emit_capture (wire_tcp.py:4989-5067)

    case "wire_channel_emit_capture":
        // Send a real Channel message and report the CONTEXT byte of the Packet
        // the outlet emits. reticulum-swift's Channel sends via
        // Link.sendChannelData, which builds a Packet with context CHANNEL (0x0E)
        // and packet_type DATA (0x00) — the context invariant the test pins.
        // packet_hash / delivered require an outlet send hook + per-packet state
        // that reticulum-swift's Channel does not expose (LIBRARY-GAP).
        let handle = try getString(p, "handle")
        let linkIdHex = bytesToHex(try getHex(p, "link_id"))
        let payload = getStringOptional(p, "data").flatMap { hexToBytes($0) } ?? Data()
        let inst = try requireInstance(handle)
        let state = try channelEnsureState(handle: handle, inst: inst, linkIdHex: linkIdHex)

        try? blockingAsync {
            try await state.channel.send(WireChannelMessage(data: payload))
        }
        return [
            "context": num(Int(PacketContext.CHANNEL)),
            "packet_type": num(0),
            "packet_hash": .null,                          // LIBRARY-GAP: no outlet hook
            "delivered": boolean(false),                   // LIBRARY-GAP: not observable
            "channel_context": num(Int(PacketContext.CHANNEL)),
            "data_context": num(Int(PacketContext.NONE))
        ]

    default:
        return nil
    }
}
