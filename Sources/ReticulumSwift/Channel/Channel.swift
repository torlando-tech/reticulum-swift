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

// MARK: - Channel

/// Typed, bidirectional message channel over a Link.
///
/// Channel provides sequenced envelope framing, in-order delivery,
/// and typed message dispatch via MessageFactory.
///
/// Delivery confirmation is handled by the Link layer's packet receipt system,
/// NOT by application-level ACK/NACK messages. This matches Python RNS/Channel.py.
public actor Channel {

    // MARK: - Constants

    /// Minimum window size (initial).
    public static let WINDOW_MIN = 2
    /// Maximum window for slow links (RTT > 0.75s or unknown).
    public static let WINDOW_MAX_SLOW = 5
    /// Maximum window for medium links (0.18s < RTT < 0.75s).
    public static let WINDOW_MAX_MEDIUM = 12
    /// Maximum window for fast links (RTT < 0.18s).
    public static let WINDOW_MAX_FAST = 48
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

    // Outbound state
    private var txSequence: UInt16 = 0
    private var windowSize: Int = WINDOW_MIN
    private var windowMax: Int = WINDOW_MAX_SLOW

    // Inbound state
    private var rxSequence: UInt16 = 0
    private var inboundBuffer: [UInt16: Envelope] = [:]

    // Callbacks
    private var messageCallback: (@Sendable (any MessageBase) async -> Void)?

    // Stream readers for Buffer support
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
    public func setMessageCallback(_ callback: @escaping @Sendable (any MessageBase) async -> Void) {
        messageCallback = callback
    }

    /// Send a typed message over the channel.
    ///
    /// Packs the message into an envelope with the next sequence number
    /// and sends it over the link. Delivery confirmation is handled by the
    /// Link layer's packet receipt system, not by application-level ACKs.
    ///
    /// - Parameter message: Message conforming to MessageBase
    /// - Throws: ChannelError.messageTooLarge if payload exceeds CHANNEL_MDU
    public func send(_ message: any MessageBase) async throws {
        let payload = try message.pack()
        let maxPayload = LinkConstants.CHANNEL_MDU
        guard payload.count <= maxPayload else {
            throw ChannelError.messageTooLarge(size: payload.count, max: maxPayload)
        }

        let envelope = Envelope(
            msgtype: type(of: message).MSGTYPE,
            sequence: txSequence,
            payload: payload
        )
        txSequence = txSequence &+ 1

        let wireData = envelope.pack()
        try await link.sendChannelData(wireData)
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
            inboundBuffer[envelope.sequence] = envelope

            // (4) Deliver the contiguous run starting at next_rx_sequence,
            // constructing and delivering each message and advancing the counter
            // as we go (Channel.py:447-466). The wrapping increment crosses the
            // 0xFFFF->0 modulus boundary naturally.
            while let next = inboundBuffer.removeValue(forKey: rxSequence) {
                await deliverMessage(next)
                rxSequence = rxSequence &+ 1
            }
        } catch {
            logger.error("Failed to unpack envelope: \(error)")
        }
    }

    /// Update window sizing based on link RTT.
    public func updateWindowSize() async {
        let rtt = await link.rtt
        if rtt <= 0 {
            windowMax = Channel.WINDOW_MAX_SLOW
        } else if rtt < 0.18 {
            windowMax = Channel.WINDOW_MAX_FAST
        } else if rtt < 0.75 {
            windowMax = Channel.WINDOW_MAX_MEDIUM
        } else {
            windowMax = Channel.WINDOW_MAX_SLOW
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
        let reader = RawChannelReader()
        let writer = RawChannelWriter(channel: self, streamId: streamId)
        if !messageFactory.isRegistered(StreamDataMessage.MSGTYPE) {
            messageFactory.register(StreamDataMessage.self)
        }
        streamReaders[streamId] = reader
        return (reader, writer)
    }

    // MARK: - Window / sequence observability

    /// Next expected receive sequence — RNS `Channel._next_rx_sequence`.
    public var nextRxSequence: UInt16 { rxSequence }

    /// Next transmit sequence to be assigned — RNS `Channel._next_sequence`.
    public var nextSequence: UInt16 { txSequence }

    /// Number of out-of-order envelopes currently buffered — RNS rx_ring depth.
    public var rxRingDepth: Int { inboundBuffer.count }

    // MARK: - Internal

    /// Deliver a received envelope to the message callback or stream reader.
    private func deliverMessage(_ envelope: Envelope) async {
        // Check if it's a StreamDataMessage for a registered buffer
        if envelope.msgtype == StreamDataMessage.MSGTYPE {
            if let msg = try? StreamDataMessage.unpack(from: envelope.payload),
               let reader = streamReaders[msg.streamId] {
                await reader.receive(data: msg.data, eof: msg.eof)
                return
            }
        }

        // Try to create a typed message via factory
        if let message = try? messageFactory.create(msgtype: envelope.msgtype, data: envelope.payload) {
            await messageCallback?(message)
        }
    }
}
