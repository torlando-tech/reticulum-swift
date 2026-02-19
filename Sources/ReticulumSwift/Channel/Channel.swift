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

import Foundation

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
    static func unpack(from data: Data) throws -> Envelope {
        guard data.count >= 6 else { throw ChannelError.envelopeTooShort }
        let msgtype = UInt16(data[data.startIndex]) << 8 | UInt16(data[data.startIndex + 1])
        let seq = UInt16(data[data.startIndex + 2]) << 8 | UInt16(data[data.startIndex + 3])
        let len = UInt16(data[data.startIndex + 4]) << 8 | UInt16(data[data.startIndex + 5])
        guard data.count >= 6 + Int(len) else { throw ChannelError.payloadTruncated }
        let payload = Data(data[(data.startIndex + 6)..<(data.startIndex + 6 + Int(len))])
        return Envelope(msgtype: msgtype, sequence: seq, payload: payload)
    }
}

// MARK: - Channel

/// Typed, bidirectional message channel over a Link.
///
/// Channel provides windowed flow control, automatic ACK/NACK,
/// in-order delivery, and typed message dispatch via MessageFactory.
///
/// Matches Python RNS/Channel.py for interoperability.
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

    /// System MSGTYPE for ACK.
    public static let MSGTYPE_ACK: UInt16 = 0xffff
    /// System MSGTYPE for NACK.
    public static let MSGTYPE_NACK: UInt16 = 0xfffe

    // MARK: - Properties

    /// Owning link (unowned to avoid retain cycle — Channel lifetime <= Link lifetime).
    private unowned let link: Link

    /// Message type registry.
    public let messageFactory: MessageFactory

    // Outbound state
    private var txSequence: UInt16 = 0
    private var windowSize: Int = WINDOW_MIN
    private var windowMax: Int = WINDOW_MAX_SLOW
    private var outboundRing: [Envelope] = []
    private var outboundPending: [Envelope] = []

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

        outboundPending.append(envelope)
        try await flushOutbound()
    }

    /// Process inbound channel data (decrypted plaintext from link).
    ///
    /// Called by Link.handleChannelData() when context 0x0E is received.
    public func receive(data: Data) async {
        do {
            let envelope = try Envelope.unpack(from: data)

            // Handle system messages (ACK/NACK)
            if envelope.msgtype == Channel.MSGTYPE_ACK {
                handleACK(sequence: envelope.sequence)
                return
            }
            if envelope.msgtype == Channel.MSGTYPE_NACK {
                await handleNACK(sequence: envelope.sequence)
                return
            }

            // Check sequence ordering
            if envelope.sequence == rxSequence {
                // In-order: deliver immediately
                await deliverMessage(envelope)
                rxSequence = rxSequence &+ 1

                // Check for buffered out-of-order messages that are now in sequence
                while let buffered = inboundBuffer.removeValue(forKey: rxSequence) {
                    await deliverMessage(buffered)
                    rxSequence = rxSequence &+ 1
                }
            } else {
                // Out-of-order: buffer for later
                inboundBuffer[envelope.sequence] = envelope
            }

            // Send ACK
            try await sendACK(sequence: envelope.sequence)
        } catch {
            // Malformed envelope - ignore
            print("[CHANNEL] Failed to unpack envelope: \(error)")
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

    // MARK: - Internal

    /// Flush pending envelopes into the outbound ring (up to window capacity).
    private func flushOutbound() async throws {
        while !outboundPending.isEmpty && outboundRing.count < windowSize {
            var envelope = outboundPending.removeFirst()
            envelope.tries += 1
            envelope.sentAt = Date()
            outboundRing.append(envelope)

            let wireData = envelope.pack()
            try await link.sendChannelData(wireData)
        }
    }

    /// Handle an ACK for a sequence number.
    private func handleACK(sequence: UInt16) {
        if let index = outboundRing.firstIndex(where: { $0.sequence == sequence }) {
            outboundRing.remove(at: index)

            // Grow window on successful ACK
            if windowSize < windowMax {
                windowSize += 1
            }

            // Try to flush more
            Task {
                try? await flushOutbound()
            }
        }
    }

    /// Handle a NACK for a sequence number (retransmit).
    private func handleNACK(sequence: UInt16) async {
        if let index = outboundRing.firstIndex(where: { $0.sequence == sequence }) {
            var envelope = outboundRing[index]
            guard envelope.tries < Channel.MAX_TRIES else {
                // Give up on this envelope
                outboundRing.remove(at: index)
                return
            }
            envelope.tries += 1
            envelope.sentAt = Date()
            outboundRing[index] = envelope

            // Shrink window on NACK
            windowSize = max(Channel.WINDOW_MIN, windowSize - 1)

            let wireData = envelope.pack()
            try? await link.sendChannelData(wireData)
        }
    }

    /// Send an ACK envelope for a received sequence.
    private func sendACK(sequence: UInt16) async throws {
        let ackEnvelope = Envelope(
            msgtype: Channel.MSGTYPE_ACK,
            sequence: sequence,
            payload: Data()
        )
        let wireData = ackEnvelope.pack()
        try await link.sendChannelData(wireData)
    }

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
