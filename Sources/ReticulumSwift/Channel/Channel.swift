// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Channel.swift
//  ReticulumSwift
//
//  Typed, bidirectional message channel over a Link with windowed flow control.
//  Matches Python RNS/Channel.py for interoperability.
//
//  Wire format: [MSGTYPE:2BE][SEQ:2BE][LEN:2BE][payload]
//  Channel context byte: 0x0E
//
//  NOTE: Python Channel does NOT use application-level ACK/NACK messages.
//  Delivery confirmation is handled by the Link layer's packet receipt system.
//  Sending ACK envelopes would cause ME_NOT_REGISTERED errors on the Python side.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "net.reticulum", category: "Channel")

// MARK: - ChannelException type codes (RNS CEType, Channel.py:101-110)

/// Mirrors `RNS.Channel.CEType` — the type codes carried by a `ChannelException`.
public enum ChannelExceptionType: Int, Sendable {
    case meNoMsgType      = 0
    case meInvalidMsgType = 1
    case meNotRegistered  = 2
    case meLinkNotReady   = 3
    case meAlreadySent    = 4
    case meTooBig         = 5
}

// MARK: - Envelope

/// Internal envelope for channel messages on the wire.
///
/// Wire format: `[MSGTYPE:2BE][SEQ:2BE][LEN:2BE][payload]` = 6 bytes overhead.
struct Envelope: Sendable {
    let msgtype: UInt16
    let sequence: UInt16
    let payload: Data
    var tries: Int = 0
    var sentAt: Date? = nil

    /// Serialize to wire format.
    func pack() -> Data {
        var d = Data(capacity: 6 + payload.count)
        d.append(UInt8(msgtype >> 8))
        d.append(UInt8(msgtype & 0xFF))
        d.append(UInt8(sequence >> 8))
        d.append(UInt8(sequence & 0xFF))
        let len = UInt16(payload.count)
        d.append(UInt8(len >> 8))
        d.append(UInt8(len & 0xFF))
        d.append(payload)
        return d
    }

    /// Deserialize from wire format.
    ///
    /// Mirrors `Channel.Envelope.unpack` (Channel.py:180-181): the 6-byte
    /// `>HHH` header carries (MSGTYPE, sequence, length), but the payload on
    /// receive is ALL bytes after the header (`raw[6:]`) — the on-wire length
    /// field is read but NEVER used to slice the payload. Slicing by the length
    /// field would truncate a payload whose advertised length is wrong.
    static func unpack(from data: Data) throws -> Envelope {
        guard data.count >= 6 else { throw ChannelError.envelopeTooShort }
        let base = data.startIndex
        let msgtype = UInt16(data[base]) << 8 | UInt16(data[base + 1])
        let seq = UInt16(data[base + 2]) << 8 | UInt16(data[base + 3])
        // Bytes 4-5 are the advertised length; RNS does not consult it on receive.
        let payload = Data(data[(base + 6)...])
        return Envelope(msgtype: msgtype, sequence: seq, payload: payload)
    }
}

// MARK: - TX envelope (RNS Channel.Envelope tx-ring entry, Channel.py:172-205)

/// A tracked outbound envelope held in the channel TX ring until the peer proves
/// it (delivery) or the channel retransmits/tears down (RNS Channel `_tx_ring`).
///
/// `@unchecked Sendable`: every field is mutated ONLY from inside the `Channel`
/// actor. The reference escapes into a detached timeout `Task` and the transport
/// delivery callback, but those merely hand the reference (or its hash) back to an
/// actor-isolated method — they never touch its fields off-actor — so the lack of
/// internal synchronization is safe.
private final class TxEnvelope: @unchecked Sendable {
    let sequence: UInt16
    /// Packed (plaintext) envelope bytes (for re-pack/logging).
    let raw: Data
    /// Encoded CHANNEL packet wire bytes — packed ONCE, reused for every resend so
    /// the outlet packet id (hash) is stable across tries (RNS resends the same
    /// already-packed Packet).
    var wirePacket: Data?
    /// Outlet packet id = the CHANNEL packet's full hash (RNS `get_packet_id`).
    var packetHash: Data?
    /// Number of transmissions so far (RNS `Envelope.tries`).
    var tries: Int = 0
    /// Whether the peer has proved this envelope (RNS receipt DELIVERED).
    var delivered: Bool = false
    /// When true, the delivery callback is never registered, so the returning
    /// PROOF can never resolve this envelope (fault injection for the
    /// retransmission/teardown tests; mirrors the harness's drop_acks).
    let dropAck: Bool
    /// In-flight retransmission timer.
    var timeoutTask: Task<Void, Never>?
    /// Continuation for a caller awaiting this envelope's final outcome.
    var waiter: CheckedContinuation<Bool, Never>?
    var resolved = false
    var outcomeDelivered = false

    init(sequence: UInt16, raw: Data, dropAck: Bool) {
        self.sequence = sequence
        self.raw = raw
        self.dropAck = dropAck
    }
}

// MARK: - Send outcome (bridge-facing)

/// The observable result of a tracked `Channel.send`, mirroring the fields the
/// conformance harness reads off `RNS.Channel.send` + the live channel state.
public struct ChannelSendOutcome: Sendable {
    public var sent: Bool
    public var delivered: Bool
    public var rejected: Bool
    public var ceType: Int?
    public var error: String?
    public var tries: Int
    public var sequence: Int?
    public var nextSequence: Int
    public var window: Int
    public var windowMax: Int
}

/// A snapshot of the channel's window / sequence / ring state (RNS `channel_window`).
public struct ChannelWindowSnapshot: Sendable {
    public var window: Int
    public var windowMin: Int
    public var windowMax: Int
    public var windowFlexibility: Int
    public var nextRxSequence: Int
    public var nextSequence: Int
    public var rxRing: Int
    public var txRing: Int
    public var txTries: Int
    public var txEnvelopes: [Int]
    public var mdu: Int
    public var outletMdu: Int
    public var messageHandlers: Int
    public var mediumRateRounds: Int
    public var fastRateRounds: Int
}

// MARK: - Channel

/// Typed, bidirectional message channel over a Link.
///
/// Channel provides sequenced envelope framing, in-order delivery,
/// and typed message dispatch via MessageFactory.
///
/// Delivery confirmation is handled by the Link layer's packet receipt system,
/// NOT by application-level ACK/NACK messages. This matches Python RNS/Channel.py.
public actor Channel {

    // MARK: - Constants (RNS Channel.py:242-280)

    /// The initial window size at channel setup (RNS `Channel.WINDOW`).
    public static let WINDOW = 2
    /// Absolute minimum window size (RNS `Channel.WINDOW_MIN`).
    public static let WINDOW_MIN = 2
    /// Minimum window floor once the medium rate is reached (`WINDOW_MIN_LIMIT_MEDIUM`).
    public static let WINDOW_MIN_LIMIT_MEDIUM = 5
    /// Minimum window floor once the fast rate is reached (`WINDOW_MIN_LIMIT_FAST`).
    public static let WINDOW_MIN_LIMIT_FAST = 16
    /// Maximum window for slow links (RTT > 0.75s or unknown).
    public static let WINDOW_MAX_SLOW = 5
    /// Maximum window for medium links (0.18s < RTT < 0.75s).
    public static let WINDOW_MAX_MEDIUM = 12
    /// Maximum window for fast links (RTT < 0.18s).
    public static let WINDOW_MAX_FAST = 48
    /// Window flexibility — the guaranteed gap between window_max and window_min.
    public static let WINDOW_FLEXIBILITY = 4
    /// Sustained-rate rounds before a faster window profile is allowed.
    public static let FAST_RATE_THRESHOLD = 10
    /// RTT band thresholds (RNS `RTT_FAST` / `RTT_MEDIUM` / `RTT_SLOW`).
    public static let RTT_FAST = 0.18
    public static let RTT_MEDIUM = 0.75
    public static let RTT_SLOW = 1.45
    /// Maximum retransmission attempts per envelope.
    public static let MAX_TRIES = 5
    /// Envelope overhead in bytes.
    public static let ENVELOPE_OVERHEAD = 6
    /// Maximum 16-bit sequence value (Channel.py:278 SEQ_MAX).
    public static let SEQ_MAX = 0xFFFF
    /// Sequence modulus = SEQ_MAX + 1 (Channel.py:279 SEQ_MODULUS).
    public static let SEQ_MODULUS = 0x10000

    // MARK: - Properties

    /// Owning link (unowned to avoid retain cycle — Channel lifetime <= Link lifetime).
    private unowned let link: Link

    /// Message type registry.
    public let messageFactory: MessageFactory

    // Outbound flow-control state (RNS Channel window fields, Channel.py:296-308)
    private var txSequence: UInt16 = 0
    private var window: Int = WINDOW
    private var windowMax: Int = WINDOW_MAX_SLOW
    private var windowMin: Int = WINDOW_MIN
    private var windowFlexibility: Int = WINDOW_FLEXIBILITY
    private var mediumRateRounds: Int = 0
    private var fastRateRounds: Int = 0
    private var maxTries: Int = MAX_TRIES
    /// The window profile is chosen once from the link RTT (RNS does this in
    /// `__init__`; the swift channel is created lazily and cannot read the actor's
    /// RTT synchronously, so the profile is realized on first send / first window
    /// read). The stored defaults already match the common non-degenerate profile.
    private var profileInitialized = false
    /// Set once `_shutdown` has run (RNS clears handlers + rings on teardown).
    private var shutDown = false

    /// Send serialization, mirroring RNS `self._send_lock` (Channel.py:288/606).
    /// RNS holds `_send_lock` across the WHOLE `send()` — reserve, outlet transmit,
    /// and tx-ring emplace — so only one send runs end-to-end at a time. The swift
    /// actor's isolation is the `_lock` (RLock) equivalent for synchronous regions,
    /// but the outlet transmit is `await`-based, so the actor would let a second
    /// `performSend` interleave at a suspension point. This FIFO hand-off mutex is
    /// the language-necessity equivalent that a threading.Lock can't express here.
    /// Documented in port-deviations.md. `false` = free; ownership is handed
    /// directly to the next waiter on release (the resumed waiter does not re-check).
    private var sendLocked = false
    private var sendLockWaiters: [CheckedContinuation<Void, Never>] = []

    /// TX retransmission ring (RNS `_tx_ring`).
    private var txRing: [TxEnvelope] = []

    // Inbound state. The rx ring caches the CONSTRUCTED message (RNS unpacks the
    // envelope's inner message at receive time, Channel.py:429, and re-uses the
    // cached message when the contiguous run is delivered, Channel.py:460-463).
    private var rxSequence: UInt16 = 0
    private var inboundBuffer: [UInt16: any MessageBase] = [:]

    /// Set when a compressed StreamDataMessage chunk decompressed past the
    /// MAX_CHUNK_LEN bound (Buffer.py:95-97). RNS swallows the raised IOError in
    /// `_receive`; the conformance recorder surfaces the abort via this flag.
    public private(set) var decompressionAborted = false
    public private(set) var decompressionError: String?

    // Callbacks
    private var messageCallback: (@Sendable (any MessageBase) async -> Void)?

    // Stream readers for Buffer support, keyed by local stream id.
    var streamReaders: [UInt16: RawChannelReader] = [:]

    // MARK: - Initialization

    /// Create a channel over a link.
    public init(link: Link) {
        self.link = link
        self.messageFactory = MessageFactory()
    }

    // MARK: - Public API

    /// Register a message type for this channel.
    public func register<T: MessageBase>(_ type: T.Type) {
        messageFactory.register(type)
    }

    /// Set the callback for inbound messages.
    public func setMessageCallback(_ callback: (@escaping @Sendable (any MessageBase) async -> Void)) {
        messageCallback = callback
    }

    /// Send a typed message over the channel (fire-and-forget; the buffer writer
    /// and other in-library callers use this). Throws on rejection so callers see
    /// ME_TOO_BIG / ME_LINK_NOT_READY as `ChannelError`. To observe delivery and
    /// the full TX outcome, use `sendTracked`.
    ///
    /// - Parameter message: Message conforming to MessageBase
    /// - Throws: ChannelError on rejection
    public func send(_ message: any MessageBase) async throws {
        let payload = try message.pack()
        let result = await performSend(
            payload: payload,
            msgtype: type(of: message).MSGTYPE,
            dropAck: false,
            failOutlet: false
        )
        if result.rejected {
            switch result.ceType {
            case ChannelExceptionType.meTooBig.rawValue:
                throw ChannelError.messageTooLarge(size: payload.count, max: await link.channelOutletMdu - Channel.ENVELOPE_OVERHEAD)
            default:
                throw ChannelError.channelNotReady
            }
        }
    }

    /// Stream-writer send (RNS `RawChannelWriter.write`, Buffer.py:231-264): wait
    /// (bounded) until the window admits another envelope, then send. RNS's writer
    /// is non-blocking and relies on the caller retrying on ME_LINK_NOT_READY; the
    /// swift writer is a simple loop, so it throttles itself to the window here
    /// (mirroring the `is_ready_to_send()` gate RNS polls in `close()`, Buffer.py:275)
    /// instead of bouncing off ME_LINK_NOT_READY.
    public func sendStream(_ message: any MessageBase) async throws {
        let payload = try message.pack()
        let msgtype = type(of: message).MSGTYPE
        await initializeProfileIfNeeded()

        let deadline = Date().addingTimeInterval(15)
        while !isReadyToSend() && Date() < deadline {
            // Yield the actor so in-flight deliveries can drain the tx ring.
            try? await Task.sleep(nanoseconds: 50_000_000) // 0.05s, matching RNS
        }

        let result = await performSend(
            payload: payload, msgtype: msgtype, dropAck: false, failOutlet: false
        )
        if result.rejected {
            switch result.ceType {
            case ChannelExceptionType.meTooBig.rawValue:
                throw ChannelError.messageTooLarge(size: payload.count, max: await link.channelOutletMdu - Channel.ENVELOPE_OVERHEAD)
            default:
                throw ChannelError.channelNotReady
            }
        }
    }

    /// Send a message and report the full TX outcome, awaiting delivery (the peer's
    /// PROOF) or link teardown. Mirrors `RNS.Channel.send` (Channel.py:586-625)
    /// plus the harness's wait-for-delivery loop. Used by the conformance bridge.
    ///
    /// - Parameters:
    ///   - payload: packed message payload bytes
    ///   - msgtype: the message MSGTYPE (placed in the envelope header)
    ///   - dropAck: suppress this message's delivery callback (fault injection)
    ///   - failOutlet: simulate the outlet failing to transmit (fault injection)
    ///   - timeout: max seconds to await delivery/teardown before returning
    public func sendTracked(
        payload: Data,
        msgtype: UInt16,
        dropAck: Bool,
        failOutlet: Bool,
        timeout: TimeInterval
    ) async -> ChannelSendOutcome {
        let result = await performSend(
            payload: payload, msgtype: msgtype, dropAck: dropAck, failOutlet: failOutlet
        )

        guard result.sent, let tx = result.envelope else {
            return ChannelSendOutcome(
                sent: false,
                delivered: false,
                rejected: result.rejected,
                ceType: result.ceType,
                error: result.error,
                tries: 0,
                sequence: result.sequence.map { Int($0) },
                nextSequence: Int(txSequence),
                window: window,
                windowMax: windowMax
            )
        }

        let delivered = await awaitEnvelope(tx, timeout: timeout)
        return ChannelSendOutcome(
            sent: true,
            delivered: delivered,
            rejected: false,
            ceType: nil,
            error: nil,
            tries: tx.tries,
            sequence: Int(tx.sequence),
            nextSequence: Int(txSequence),
            window: window,
            windowMax: windowMax
        )
    }

    /// Process inbound channel data (decrypted plaintext from link).
    ///
    /// Unpacks the envelope, buffers out-of-order messages, and delivers
    /// in-order messages to registered handlers.
    ///
    /// Called by Link.handleChannelData() when context 0x0E is received.
    public func receive(data: Data) async {
        do {
            let envelope = try Envelope.unpack(from: data)

            // (1) Validate the envelope is constructable (its MSGTYPE is
            // registered) BEFORE touching any receive-sequence state. RNS unpacks
            // the envelope at Channel.py:429; an unregistered MSGTYPE raises
            // ME_NOT_REGISTERED, caught at Channel.py:468-469, so the whole
            // receive aborts WITHOUT advancing _next_rx_sequence. Advancing on an
            // unhandled type would permanently stall the channel at that gap.
            guard messageFactory.isRegistered(envelope.msgtype) else {
                logger.debug("Dropping channel envelope with unregistered MSGTYPE \(envelope.msgtype)")
                return
            }

            // (1b) Construct (unpack) the inner message NOW, before any sequence
            // bookkeeping. RNS unpacks the message inside the lock at
            // Channel.py:429 BEFORE the stale-drop / emplace / next_rx_sequence
            // advance; a raising unpack (notably the bz2 MAX_CHUNK_LEN
            // decompression bound, Buffer.py:95-97) is caught by the outer
            // try/except (Channel.py:468) so the receive aborts WITHOUT advancing
            // _next_rx_sequence. The constructed message is cached on the rx ring
            // and re-used at delivery (Channel.py:460-463).
            let message: any MessageBase
            do {
                guard let m = try messageFactory.create(msgtype: envelope.msgtype, data: envelope.payload) else {
                    return
                }
                message = m
            } catch ChannelError.decompressionBoundExceeded {
                // Record the over-bound abort so the receiver can surface it
                // (the conformance recorder reads `decompressionAborted`), then
                // abort WITHOUT advancing the sequence — matching RNS, where the
                // raised IOError unwinds _receive before the next_rx_sequence bump.
                decompressionAborted = true
                decompressionError = "Decompressed buffer chunk exceeds maximum legitimate size"
                logger.debug("Dropping channel envelope: decompression bound exceeded")
                return
            } catch {
                logger.debug("Dropping channel envelope: message unpack failed: \(error)")
                return
            }

            // (2) Stale-drop window (Channel.py:431-439). Only sequences strictly
            // below next_rx_sequence (plain 16-bit comparison) are drop candidates.
            if envelope.sequence < rxSequence {
                let windowOverflow = UInt16(
                    (UInt32(rxSequence) + UInt32(Channel.WINDOW_MAX_FAST)) % UInt32(Channel.SEQ_MODULUS)
                )
                if windowOverflow < rxSequence {
                    // next_rx + WINDOW_MAX wrapped the modulus: sequences in
                    // (windowOverflow, rxSequence) are stale, but sequences
                    // <= windowOverflow are wrapped-forward and kept.
                    if envelope.sequence > windowOverflow {
                        logger.debug("Dropping stale channel sequence \(envelope.sequence)")
                        return
                    }
                } else {
                    // No wrap: any sequence below next_rx is unconditionally stale.
                    logger.debug("Dropping stale channel sequence \(envelope.sequence)")
                    return
                }
            }

            // (2b) PORT DEVIATION (defensive hardening — see port-deviations.md):
            // bound the forward receive window. RNS's _rx_ring is an unbounded deque
            // (Channel.py:290) with no cap on FORWARD (sequence >= next_rx) emplacement,
            // so a peer ignoring the flow-control window could buffer up to SEQ_MODULUS
            // (64Ki) undelivered messages. A conformant sender never has more than
            // window_max (<= WINDOW_MAX_FAST) envelopes outstanding, so any sequence
            // MORE than WINDOW_MAX_FAST ahead of next_rx_sequence is out-of-window and
            // dropped. This never rejects traffic a reference RNS peer would send (its
            // furthest in-flight sequence is below next_rx + window_max <= next_rx +
            // WINDOW_MAX_FAST), and it keeps the same inclusive boundary as the wrapped
            // stale-drop above. `&-` is the mod-2^16 forward distance (handles wrap).
            let nextRx = rxSequence
            let forwardDistance = envelope.sequence &- nextRx
            if forwardDistance > UInt16(Channel.WINDOW_MAX_FAST) {
                logger.debug("Dropping out-of-window channel sequence \(envelope.sequence) (\(forwardDistance) ahead of \(nextRx))")
                return
            }

            // (3) Emplace with KEEP-FIRST de-duplication (Channel.py:398-400:
            // _emplace_envelope returns False for a sequence already present, so
            // the first-seen envelope is retained and the later copy discarded).
            // The buffer is keyed by sequence, so RNS's half-space modular
            // ordering of its sorted rx_ring (Channel.py:392-413) is unnecessary —
            // the contiguous drain below looks up the next expected sequence
            // directly rather than scanning an ordered deque.
            if inboundBuffer[envelope.sequence] != nil {
                logger.debug("Dropping duplicate channel sequence \(envelope.sequence)")
                return
            }
            inboundBuffer[envelope.sequence] = message

            // (4) Deliver the contiguous run starting at next_rx_sequence,
            // delivering each cached message and advancing the counter as we go
            // (Channel.py:447-466). The wrapping increment crosses the 0xFFFF->0
            // modulus boundary naturally.
            while let next = inboundBuffer.removeValue(forKey: rxSequence) {
                await deliverMessage(next)
                rxSequence = rxSequence &+ 1
            }
        } catch {
            logger.error("Failed to unpack envelope: \(error)")
        }
    }

    /// Create a reader/writer pair for a byte stream.
    ///
    /// Registers StreamDataMessage if not already registered, and stores
    /// the reader keyed by streamId for routing inbound messages.
    ///
    /// - Parameter streamId: Stream identifier (0-16383)
    /// - Returns: Tuple of (reader, writer)
    public func createBuffer(streamId: UInt16 = 0) -> (RawChannelReader, RawChannelWriter) {
        let reader = registerStreamReader(streamId: streamId)
        let writer = RawChannelWriter(channel: self, streamId: streamId)
        return (reader, writer)
    }

    /// Register (idempotently) a RawChannelReader for `streamId`, mirroring
    /// `RawChannelReader.__init__` (Buffer.py:115-129): it registers the
    /// StreamDataMessage system type on the channel and installs the reader so
    /// inbound StreamDataMessages for that stream id are reassembled. Used by the
    /// listener-side receive recorder to attach a reader per buffer_stream_id.
    @discardableResult
    public func registerStreamReader(streamId: UInt16) -> RawChannelReader {
        if let existing = streamReaders[streamId] { return existing }
        if !messageFactory.isRegistered(StreamDataMessage.MSGTYPE) {
            messageFactory.register(StreamDataMessage.self)
        }
        let reader = RawChannelReader(streamId: streamId)
        streamReaders[streamId] = reader
        return reader
    }

    /// The reader registered for `streamId`, if any (bridge drain accessor).
    public func streamReader(for streamId: UInt16) -> RawChannelReader? {
        streamReaders[streamId]
    }

    /// Stream-writer send returning the reserved Channel sequence. Waits
    /// (bounded) for the window to admit another envelope, then performs the
    /// same non-blocking send `sendStream` does. RNS's `RawChannelWriter.write`
    /// calls `channel.send(message)` and reads the returned Envelope's
    /// `.sequence` (Buffer.py:258-261); the bridge records that sequence in the
    /// per-message manifest.
    public func streamSendMessage(_ message: any MessageBase) async throws -> Int {
        let payload = try message.pack()
        let msgtype = type(of: message).MSGTYPE
        await initializeProfileIfNeeded()

        let deadline = Date().addingTimeInterval(15)
        while !isReadyToSend() && Date() < deadline {
            try? await Task.sleep(nanoseconds: 50_000_000) // 0.05s, matching RNS
        }

        let result = await performSend(
            payload: payload, msgtype: msgtype, dropAck: false, failOutlet: false
        )
        if result.rejected {
            switch result.ceType {
            case ChannelExceptionType.meTooBig.rawValue:
                throw ChannelError.messageTooLarge(size: payload.count, max: await link.channelOutletMdu - Channel.ENVELOPE_OVERHEAD)
            default:
                throw ChannelError.channelNotReady
            }
        }
        return result.sequence.map { Int($0) } ?? -1
    }

    // MARK: - Window / sequence observability

    /// Next expected receive sequence — RNS `Channel._next_rx_sequence`.
    public var nextRxSequence: UInt16 { rxSequence }

    /// Next transmit sequence to be assigned — RNS `Channel._next_sequence`.
    public var nextSequence: UInt16 { txSequence }

    /// Number of out-of-order envelopes currently buffered — RNS rx_ring depth.
    public var rxRingDepth: Int { inboundBuffer.count }

    /// Channel MDU = outlet MDU - 6, capped at 0xFFFF (RNS `Channel.mdu`, Channel.py:66-78).
    public var mdu: Int {
        get async {
            let m = await link.channelOutletMdu - 6
            return min(m, 0xFFFF)
        }
    }

    /// Full window/sequence/ring snapshot for the bridge `wire_channel_window`.
    public func windowSnapshot() async -> ChannelWindowSnapshot {
        // Read-only probe: do NOT initialize the rate profile here — that would mutate
        // window/profileInitialized as a side effect of a snapshot read. Report current
        // state (stored defaults before the first send, profile-adjusted values after).
        let outletMdu = await link.channelOutletMdu
        let txTries = txRing.first?.tries ?? 0
        return ChannelWindowSnapshot(
            window: window,
            windowMin: windowMin,
            windowMax: windowMax,
            windowFlexibility: windowFlexibility,
            nextRxSequence: Int(rxSequence),
            nextSequence: Int(txSequence),
            rxRing: inboundBuffer.count,
            txRing: txRing.count,
            txTries: txTries,
            txEnvelopes: txRing.map { Int($0.sequence) },
            mdu: min(outletMdu - 6, 0xFFFF),
            outletMdu: outletMdu,
            messageHandlers: messageCallback != nil ? 1 : 0,
            mediumRateRounds: mediumRateRounds,
            fastRateRounds: fastRateRounds
        )
    }

    /// Re-fire a delivery and a stale timeout for envelopes NOT in the tx ring, to
    /// exercise RNS's spurious-message / stale-timeout guards (Channel.py:531-535,
    /// 555-561). Both must be no-ops: no window growth, no teardown, no throw.
    public func fireSpuriousCallbacks() async {
        // Duplicate/late delivery for an unknown packet id: _packet_tx_op finds no
        // matching envelope and logs "Spurious message" (Channel.py:545-546).
        await packetDelivered(Data(repeating: 0, count: 32))
        // Stale timeout for an already-delivered throwaway envelope:
        // _packet_timeout returns immediately when the packet is DELIVERED
        // (Channel.py:556-557).
        let stale = TxEnvelope(sequence: UInt16(Channel.SEQ_MAX), raw: Data(), dropAck: true)
        stale.delivered = true
        await packetTimeout(stale)
    }

    // MARK: - Internal: send pipeline (RNS Channel.send, Channel.py:586-625)

    private struct SendResult {
        var rejected: Bool = false
        var ceType: Int? = nil
        var error: String? = nil
        var sent: Bool = false
        var sequence: UInt16? = nil
        var envelope: TxEnvelope? = nil
    }

    /// Acquire the send lock (RNS `self._send_lock`, Channel.py:606). Either grabs
    /// the free lock or suspends FIFO until a prior send hands it over. Only the
    /// fresh-send path takes this lock; RNS `_packet_delivered`/`_packet_timeout`
    /// (and their resends) run under `_lock` only, so the swift equivalents
    /// (`packetDelivered`/`packetTimeout`) must NOT acquire it.
    private func acquireSendLock() async {
        if !sendLocked {
            sendLocked = true
            return
        }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            sendLockWaiters.append(cont)
        }
        // Resumed by releaseSendLock, which transfers ownership directly: the lock
        // stays held (sendLocked == true) and is now ours.
    }

    /// Release the send lock. If a waiter is queued, ownership is handed directly to
    /// the next (the lock stays held); otherwise the lock goes free.
    private func releaseSendLock() {
        if sendLockWaiters.isEmpty {
            sendLocked = false
        } else {
            let cont = sendLockWaiters.removeFirst()
            cont.resume()
        }
    }

    /// The synchronous (non-waiting) core of a channel send: window admission,
    /// sequence reservation, ME_TOO_BIG guard, outlet transmit with rollback, and
    /// tx-ring emplacement + timer arming. Returns the emplaced envelope (if sent).
    private func performSend(
        payload: Data, msgtype: UInt16, dropAck: Bool, failOutlet: Bool
    ) async -> SendResult {
        // Serialise the entire send under the send lock (RNS self._send_lock,
        // Channel.py:606): reserve -> outlet transmit -> emplace must run end-to-end
        // without another send interleaving at one of the awaits below. This makes
        // the sequence reservation AND the no-receipt rollback (txSequence = reserved)
        // atomic exactly as RNS's lock does.
        await acquireSendLock()
        defer { releaseSendLock() }

        await initializeProfileIfNeeded()

        // is_ready_to_send (Channel.py:471-491): the outlet is always usable; the
        // gate is purely "outstanding (un-delivered tx-ring envelopes) < window".
        guard isReadyToSend() else {
            return SendResult(
                rejected: true, ceType: ChannelExceptionType.meLinkNotReady.rawValue,
                error: "Link is not ready", sent: false
            )
        }

        // Reserve the next sequence and pack the envelope (Channel.py:592-595).
        // This whole reserve -> size-check -> commit -> transmit -> emplace span is
        // serialised by the send lock acquired at the top of performSend (mirroring
        // RNS's self._send_lock, Channel.py:606), so the `await link.channelOutletMdu`
        // below cannot interleave a concurrent send that reserves the same sequence.
        let reserved = txSequence
        let envelope = Envelope(msgtype: msgtype, sequence: reserved, payload: payload)
        let raw = envelope.pack()

        // ME_TOO_BIG runs BEFORE the sequence increment (Channel.py:596-598), so a
        // rejected oversized send leaves next_sequence untouched.
        let outletMdu = await link.channelOutletMdu
        if raw.count > outletMdu {
            return SendResult(
                rejected: true, ceType: ChannelExceptionType.meTooBig.rawValue,
                error: "Packed message too big for packet: \(raw.count) > \(outletMdu)",
                sent: false
            )
        }

        // Commit the reservation (Channel.py:599).
        txSequence = reserved &+ 1

        // outlet.send(raw): build the CHANNEL packet (encrypt once) — or, under
        // fault injection, pretend the outlet produced no receipt (Channel.py:601).
        var built: (wire: Data, hash: Data)? = nil
        if !failOutlet {
            built = await link.channelBuildPacket(raw)
        }
        guard let packet = built else {
            // "Outlet did not transmit packet" — roll the reservation back and
            // raise ME_LINK_NOT_READY (Channel.py:603-609).
            txSequence = reserved
            return SendResult(
                rejected: true, ceType: ChannelExceptionType.meLinkNotReady.rawValue,
                error: "Outlet did not transmit packet", sent: false
            )
        }

        // Emplace, then register the delivery callback BEFORE transmitting so the
        // returning PROOF can never race ahead of the registration (RNS registers
        // the receipt with Transport synchronously inside Packet.send()).
        let tx = TxEnvelope(sequence: reserved, raw: raw, dropAck: dropAck)
        tx.wirePacket = packet.wire
        tx.packetHash = packet.hash
        txRing.append(tx)
        tx.tries += 1

        if !dropAck {
            let hash = packet.hash
            await link.channelRegisterDelivery(fullHash: hash) { [weak self] in
                await self?.packetDelivered(hash)
            }
        }

        let transmitted = await link.channelTransmit(packet.wire)
        if !transmitted {
            // The outlet failed at the wire: undo emplacement + rollback, matching
            // the no-receipt branch (Channel.py:603-609).
            if let idx = txRing.firstIndex(where: { $0 === tx }) {
                txRing.remove(at: idx)
            }
            if !dropAck {
                await link.channelDeregisterDelivery(fullHash: packet.hash)
            }
            txSequence = reserved
            return SendResult(
                rejected: true, ceType: ChannelExceptionType.meLinkNotReady.rawValue,
                error: "Outlet did not transmit packet", sent: false
            )
        }

        await armTimeout(tx)
        return SendResult(sent: true, sequence: reserved, envelope: tx)
    }

    /// is_ready_to_send (Channel.py:471-491).
    private func isReadyToSend() -> Bool {
        var outstanding = 0
        for env in txRing where !env.delivered {
            outstanding += 1
        }
        return outstanding < window
    }

    /// Suspend until `tx` is delivered (true) or the link tears down (false), or
    /// the bridge-supplied timeout elapses (returns the current delivered state).
    private func awaitEnvelope(_ tx: TxEnvelope, timeout: TimeInterval) async -> Bool {
        if tx.resolved { return tx.outcomeDelivered }
        return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            if tx.resolved {
                cont.resume(returning: tx.outcomeDelivered)
                return
            }
            tx.waiter = cont
            Task { [weak self, tx] in
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                if let self {
                    await self.resolveWaiterTimeout(tx)
                } else if !tx.resolved {
                    // The Channel actor was deallocated while a caller was suspended here.
                    // Resume the continuation directly so it is never abandoned (Swift
                    // requires exactly-once resume). Safe: with the actor gone, no actor
                    // code can race this final resolution (TxEnvelope is actor-confined).
                    tx.resolved = true
                    tx.waiter?.resume(returning: tx.delivered)
                    tx.waiter = nil
                }
            }
        }
    }

    private func resolveWaiterTimeout(_ tx: TxEnvelope) {
        guard !tx.resolved else { return }
        resolveWaiter(tx, delivered: tx.delivered)
    }

    private func resolveWaiter(_ tx: TxEnvelope, delivered: Bool) {
        guard !tx.resolved else { return }
        tx.resolved = true
        tx.outcomeDelivered = delivered
        tx.waiter?.resume(returning: delivered)
        tx.waiter = nil
    }

    // MARK: - Internal: delivery (RNS _packet_delivered / _packet_tx_op)

    /// Called when a PROOF for a sent CHANNEL packet arrives. Mirrors
    /// `_packet_delivered` -> `_packet_tx_op(op=lambda: True)` (Channel.py:507-548).
    private func packetDelivered(_ hash: Data) async {
        // Read RTT up front (the rate-promotion logic consults the live outlet RTT).
        let rtt = await link.channelOutletRtt

        guard let idx = txRing.firstIndex(where: { $0.packetHash == hash }) else {
            // Spurious / duplicate proof: no tracked envelope — do nothing
            // (Channel.py:545-546).
            return
        }
        let env = txRing.remove(at: idx)
        env.delivered = true
        env.timeoutTask?.cancel()
        env.timeoutTask = nil

        // Grow the window by 1, capped at window_max (Channel.py:516-518).
        if window < windowMax {
            window += 1
        }

        // Rate-round promotion (Channel.py:520-543).
        if rtt != 0 {
            if rtt > Channel.RTT_FAST {
                fastRateRounds = 0
                if rtt > Channel.RTT_MEDIUM {
                    mediumRateRounds = 0
                } else {
                    mediumRateRounds += 1
                    if windowMax < Channel.WINDOW_MAX_MEDIUM
                        && mediumRateRounds == Channel.FAST_RATE_THRESHOLD {
                        windowMax = Channel.WINDOW_MAX_MEDIUM
                        windowMin = Channel.WINDOW_MIN_LIMIT_MEDIUM
                    }
                }
            } else {
                fastRateRounds += 1
                if windowMax < Channel.WINDOW_MAX_FAST
                    && fastRateRounds == Channel.FAST_RATE_THRESHOLD {
                    windowMax = Channel.WINDOW_MAX_FAST
                    windowMin = Channel.WINDOW_MIN_LIMIT_FAST
                }
            }
        }

        resolveWaiter(env, delivered: true)
    }

    // MARK: - Internal: timeout / retransmission (RNS _packet_timeout)

    /// Mirrors `_packet_timeout` (Channel.py:563-584): resend with backoff and
    /// shrink the window, tearing the link down after `maxTries` unanswered tries.
    private func packetTimeout(_ tx: TxEnvelope) async {
        // get_packet_state == DELIVERED -> nothing to do (Channel.py:564-565).
        if tx.delivered { return }
        guard txRing.contains(where: { $0 === tx }) else { return }

        if tx.tries >= maxTries {
            // Retry count exceeded: _shutdown() then outlet.timed_out()
            // (Channel.py:578-582). Tear the link down BEFORE resolving the
            // envelope's waiter so an observer that reads link_status the instant
            // the send returns sees CLOSED.
            let pending = txRing
            shutdownInternal()
            // Mirror RNS _clear_rings (Channel.py:382-385), which drops each tx
            // envelope's outlet delivered/timeout callbacks. shutdownInternal cancels
            // the local timeout Tasks but is synchronous, so it cannot await the
            // delivery deregistration; do it here. Without this the Transport keeps
            // the per-packet delivery registration (a leak) and a late PROOF would
            // invoke packetDelivered on the torn-down channel. dropAck envelopes
            // never registered a callback (performSend registers only when !dropAck).
            for e in pending where !e.dropAck {
                if let h = e.packetHash {
                    await link.channelDeregisterDelivery(fullHash: h)
                }
            }
            await link.channelOutletTimedOut()
            for e in pending {
                resolveWaiter(e, delivered: false)
            }
            return
        }

        tx.tries += 1

        // Shrink the window by 1 (floored at window_min), and window_max too but
        // only while the flexibility guard allows it (Channel.py:573-577).
        if window > windowMin {
            window -= 1
            if windowMax > windowMin + windowFlexibility {
                windowMax -= 1
            }
        }

        // Resend the SAME already-packed packet bytes (stable hash) and re-arm.
        if let wire = tx.wirePacket {
            _ = await link.channelTransmit(wire)
        }
        await armTimeout(tx)
    }

    /// Arm (or re-arm) the retransmission timer for `tx`. The timeout grows with
    /// tries and the current ring depth (RNS `_get_packet_timeout_time`).
    private func armTimeout(_ tx: TxEnvelope) async {
        let timeout = await packetTimeoutTime(tries: tx.tries)
        tx.timeoutTask?.cancel()
        tx.timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            if Task.isCancelled { return }
            await self?.packetTimeout(tx)
        }
    }

    /// `_get_packet_timeout_time(tries)` (Channel.py:551-553):
    /// pow(1.5, tries-1) * max(rtt*2.5, 0.025) * (len(tx_ring)+1.5).
    private func packetTimeoutTime(tries: Int) async -> TimeInterval {
        let rtt = await link.channelOutletRtt
        return pow(1.5, Double(tries - 1)) * max(rtt * 2.5, 0.025) * (Double(txRing.count) + 1.5)
    }

    // MARK: - Internal: shutdown (RNS _shutdown / _clear_rings, Channel.py:375-390)

    private func shutdownInternal() {
        shutDown = true
        // Clear message handlers (RNS _shutdown clears _message_callbacks).
        messageCallback = nil
        // Clear the tx + rx rings, cancelling any in-flight retransmission timers.
        for env in txRing {
            env.timeoutTask?.cancel()
            env.timeoutTask = nil
        }
        txRing.removeAll()
        inboundBuffer.removeAll()
    }

    /// One-time window-profile realization from the link RTT (RNS Channel.__init__
    /// gate, Channel.py:296-308). A link RTT above RTT_SLOW collapses the channel
    /// to the degenerate all-1 window; otherwise the non-degenerate slow profile
    /// (already the stored defaults) holds.
    private func initializeProfileIfNeeded() async {
        guard !profileInitialized else { return }
        profileInitialized = true
        let rtt = await link.channelOutletRtt
        if rtt > Channel.RTT_SLOW {
            window = 1
            windowMax = 1
            windowMin = 1
            windowFlexibility = 1
        }
        // else: keep the stored non-degenerate defaults (WINDOW / WINDOW_MAX_SLOW /
        // WINDOW_MIN / WINDOW_FLEXIBILITY).
    }

    // MARK: - Internal

    /// Deliver an already-unpacked message to its stream reader (Buffer) or the
    /// registered message callback. Mirrors `_run_callbacks` dispatch
    /// (Channel.py:415-466) — a StreamDataMessage is routed to the reader whose
    /// stream id matches (RawChannelReader._handle_message, Buffer.py:150-164); a
    /// message addressed to an unregistered stream id is ignored, exactly as the
    /// reader's handler returns False on a non-matching id.
    private func deliverMessage(_ message: any MessageBase) async {
        if let stream = message as? StreamDataMessage {
            if let reader = streamReaders[stream.streamId] {
                await reader.receive(data: stream.data, eof: stream.eof)
            }
            return
        }
        await messageCallback?(message)
    }
}
