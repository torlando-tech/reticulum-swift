// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Buffer.swift
//  ReticulumSwift
//
//  Stream I/O layer on top of Channel, providing RawChannelReader/RawChannelWriter
//  for byte-stream communication over a Link.
//
//  Matches Python RNS/Buffer.py for interoperability.
//
//  Wire format: [stream_id+flags:2BE][data] = 2 bytes overhead
//  StreamDataMessage MSGTYPE: 0xff00 (system reserved range)
//

import Foundation

// MARK: - StreamDataMessage

/// System message for byte-stream data over a Channel.
///
/// Wire format: `[flags:2BE][data]` where flags encodes:
/// - Bits 0-13: stream ID (0-16383)
/// - Bit 14: compressed flag
/// - Bit 15: EOF flag
///
/// MSGTYPE 0xff00 (system reserved range).
/// Matches Python RNS/Buffer.py StreamDataMessage.
public struct StreamDataMessage: MessageBase, Sendable {
    public static let MSGTYPE: UInt16 = 0xff00

    /// Stream identifier (14-bit, 0-16383).
    public let streamId: UInt16
    /// End-of-stream marker.
    public let eof: Bool
    /// Compression flag (always false for now — bz2 not available in Swift).
    public let compressed: Bool
    /// Payload data.
    public let data: Data

    public init(streamId: UInt16, eof: Bool, compressed: Bool, data: Data) {
        self.streamId = streamId
        self.eof = eof
        self.compressed = compressed
        self.data = data
    }

    public func pack() throws -> Data {
        var flags: UInt16 = streamId & 0x3FFF
        if eof { flags |= 0x8000 }
        if compressed { flags |= 0x4000 }
        var result = Data(capacity: 2 + data.count)
        result.append(UInt8(flags >> 8))
        result.append(UInt8(flags & 0xFF))
        result.append(data)
        return result
    }

    public static func unpack(from data: Data) throws -> StreamDataMessage {
        guard data.count >= 2 else { throw ChannelError.bufferTooShort }
        let flags = UInt16(data[data.startIndex]) << 8 | UInt16(data[data.startIndex + 1])
        let streamId = flags & 0x3FFF
        let eof = (flags & 0x8000) != 0
        let compressed = (flags & 0x4000) != 0
        let payload = data.count > 2 ? Data(data[(data.startIndex + 2)...]) : Data()
        return StreamDataMessage(streamId: streamId, eof: eof,
                                 compressed: compressed, data: payload)
    }
}

// MARK: - RawChannelReader

/// Async reader for byte-stream data arriving over a Channel.
///
/// Buffers inbound StreamDataMessages and provides an async read() API.
/// Returns nil when EOF is reached and buffer is empty.
public actor RawChannelReader {
    private var buffer: Data = Data()
    private var eof: Bool = false
    private var waiters: [CheckedContinuation<Data?, Never>] = []

    public init() {}

    /// Read up to `count` bytes. Returns nil at EOF with empty buffer.
    public func read(_ count: Int) async -> Data? {
        if !buffer.isEmpty {
            let n = min(count, buffer.count)
            let chunk = Data(buffer.prefix(n))
            buffer.removeFirst(n)
            return chunk
        }
        if eof { return nil }
        return await withCheckedContinuation { cont in
            waiters.append(cont)
        }
    }

    /// Called by Channel when StreamDataMessage arrives.
    func receive(data: Data, eof: Bool) {
        buffer.append(data)
        if eof { self.eof = true }
        if let waiter = waiters.first {
            waiters.removeFirst()
            let n = min(buffer.count, 4096)
            let chunk = Data(buffer.prefix(n))
            buffer.removeFirst(n)
            waiter.resume(returning: chunk)
        }
    }
}

// MARK: - RawChannelWriter

/// Async writer for byte-stream data sent over a Channel.
///
/// Chunks data to fit within Channel MDU and sends as StreamDataMessages.
public actor RawChannelWriter {
    private let channel: Channel
    private let streamId: UInt16
    /// Max data per StreamDataMessage = CHANNEL_MDU - 2 (flags overhead).
    private let maxChunk: Int

    public init(channel: Channel, streamId: UInt16) {
        self.channel = channel
        self.streamId = streamId
        self.maxChunk = LinkConstants.CHANNEL_MDU - 2  // 423
    }

    /// Write data to the stream. Splits into multiple messages if needed.
    public func write(_ data: Data) async throws {
        var offset = 0
        while offset < data.count {
            let end = min(offset + maxChunk, data.count)
            let chunk = Data(data[offset..<end])
            let msg = StreamDataMessage(
                streamId: streamId, eof: false,
                compressed: false, data: chunk
            )
            try await channel.send(msg)
            offset = end
        }
    }

    /// Close the stream by sending an EOF message.
    public func close() async throws {
        let msg = StreamDataMessage(
            streamId: streamId, eof: true,
            compressed: false, data: Data()
        )
        try await channel.send(msg)
    }
}
