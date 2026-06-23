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

    /// The stream id is limited to 2 bytes - 2 bit (Buffer.py:51).
    public static let STREAM_ID_MAX: UInt16 = 0x3fff

    /// Per-StreamDataMessage overhead: 2 (stream header) + 6 (channel envelope)
    /// = 8 bytes (Buffer.py:56).
    public static let OVERHEAD = 2 + 6

    /// Maximum payload bytes a single StreamDataMessage may carry =
    /// `RNS.Link.MDU - OVERHEAD` = 431 - 8 = 423 (Buffer.py:57). RNS computes
    /// this once at import; the swift port pins the resolved literal because the
    /// link MDU is a fixed protocol constant.
    public static let MAX_DATA_LEN = 423

    /// Stream identifier (14-bit, 0-16383).
    public let streamId: UInt16
    /// End-of-stream marker.
    public let eof: Bool
    /// Compression flag (bz2 over the chunk; bit 0x4000).
    public let compressed: Bool
    /// Payload data. For a writer-constructed message this is the (optionally
    /// bz2-compressed) chunk to put on the wire; after `unpack` it is the
    /// decompressed plaintext (RNS does the bz2 inflate inside unpack).
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

    /// Deserialize a StreamDataMessage (Buffer.py:87-97).
    ///
    /// When the compressed bit is set, the chunk is bz2-decompressed with a
    /// `max_length = RawChannelWriter.MAX_CHUNK_LEN` bound; a chunk that would
    /// inflate past that bound raises `ChannelError.decompressionBoundExceeded`
    /// (RNS raises `IOError("Decompressed buffer chunk exceeds maximum
    /// legitimate size")`).
    public static func unpack(from data: Data) throws -> StreamDataMessage {
        guard data.count >= 2 else { throw ChannelError.bufferTooShort }
        let flags = UInt16(data[data.startIndex]) << 8 | UInt16(data[data.startIndex + 1])
        let streamId = flags & 0x3FFF
        let eof = (flags & 0x8000) != 0
        let compressed = (flags & 0x4000) != 0
        var payload = data.count > 2 ? Data(data[(data.startIndex + 2)...]) : Data()

        if compressed {
            // bz2 inflate with the MAX_CHUNK_LEN bound (Buffer.py:94-97). A chunk
            // inflating to exactly MAX_CHUNK_LEN is accepted; one byte over the
            // bound throws (the decompressor never reaches eof within the cap).
            do {
                payload = try ResourceCompression.bz2Decompress(
                    payload,
                    maxDecompressedSize: RawChannelWriter.MAX_CHUNK_LEN
                )
            } catch {
                throw ChannelError.decompressionBoundExceeded
            }
        }
        return StreamDataMessage(streamId: streamId, eof: eof,
                                 compressed: compressed, data: payload)
    }
}

// MARK: - RawChannelReader

/// Receiver for binary stream data sent over a Channel (RNS RawChannelReader).
///
/// Buffers inbound StreamDataMessages whose stream id matches this reader's and
/// reassembles them in Channel sequence order, signalling EOF on the final
/// (empty) message. Mirrors `RawChannelReader._handle_message` (Buffer.py:150-164)
/// — a message addressed to a different stream id is ignored.
public actor RawChannelReader {
    /// Local stream id this reader reassembles (Buffer.py:122).
    public let streamId: UInt16
    private var buffer: Data = Data()
    private var eof: Bool = false
    private var waiters: [CheckedContinuation<Data?, Never>] = []

    public init(streamId: UInt16 = 0) {
        self.streamId = streamId
    }

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

    /// Drain all currently-buffered reassembled bytes (non-blocking). Mirrors the
    /// reference `reader._read(MAX_READ)` drain in cmd_wire_buffer_received.
    public func drain() -> Data {
        let out = buffer
        buffer = Data()
        return out
    }

    /// Whether the writer's EOF marker has been observed.
    public var isEof: Bool { eof }

    /// Called by Channel when a StreamDataMessage for this stream arrives.
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

/// Per-write result the conformance bridge records into the StreamDataMessage
/// manifest (mirrors what the python harness reads off each emitted message +
/// the returned Envelope sequence).
public struct StreamWriteOutcome: Sendable {
    /// Bytes consumed from the input (RawChannelWriter.write return).
    public var processed: Int
    /// Length of the StreamDataMessage payload actually put on the wire.
    public var bytes: Int
    /// Whether the chunk was bz2-compressed.
    public var compressed: Bool
    /// Whether this message carried the EOF marker.
    public var eof: Bool
    /// The Channel sequence assigned to the emitted envelope.
    public var sequence: Int
}

/// Writer for binary stream data sent over a Channel (RNS RawChannelWriter).
///
/// Each `writeChunk` caps the input at MAX_CHUNK_LEN, runs the COMPRESSION_TRIES
/// bz2 decision, emits one StreamDataMessage, and returns the bytes consumed
/// (Buffer.py:200-266).
public actor RawChannelWriter {
    /// Per-write raw chunk ceiling AND the decompression bound (Buffer.py:216).
    public static let MAX_CHUNK_LEN = 1024 * 16
    /// Number of shrinking compression attempts (Buffer.py:217).
    public static let COMPRESSION_TRIES = 4

    private let channel: Channel
    private let streamId: UInt16
    private var eofFlag: Bool = false

    public init(channel: Channel, streamId: UInt16) {
        self.channel = channel
        self.streamId = streamId
    }

    /// Set the EOF flag carried by the next emitted message (RNS `self._eof`).
    public func setEof(_ value: Bool) { eofFlag = value }

    /// Process one chunk and send one StreamDataMessage, returning the per-write
    /// outcome. Mirrors `RawChannelWriter.write` (Buffer.py:231-266): cap at
    /// MAX_CHUNK_LEN, try compression on shrinking segments (chunk_len/1, /2, /3),
    /// pick the compressed chunk iff it is both < MAX_DATA_LEN and smaller than
    /// the segment, else send up to MAX_DATA_LEN raw bytes.
    @discardableResult
    public func writeChunk(_ input: Data) async throws -> StreamWriteOutcome {
        let compTries = RawChannelWriter.COMPRESSION_TRIES   // 4
        var compTry = 1
        var compSuccess = false

        var chunkLen = input.count
        var b = input
        if chunkLen > RawChannelWriter.MAX_CHUNK_LEN {
            chunkLen = RawChannelWriter.MAX_CHUNK_LEN
            b = Data(input.prefix(RawChannelWriter.MAX_CHUNK_LEN))
        }

        var compressedChunk = Data()
        var chunkSegmentLength = 0
        while chunkLen > 32 && compTry < compTries {        // compTry in {1,2,3}
            chunkSegmentLength = chunkLen / compTry
            let segment = Data(b.prefix(chunkSegmentLength))
            let candidate = (try? ResourceCompression.bz2Compress(segment, blockSize: 9)) ?? Data()
            let compressedLength = candidate.count
            if compressedLength > 0
                && compressedLength < StreamDataMessage.MAX_DATA_LEN
                && compressedLength < chunkSegmentLength {
                compSuccess = true
                compressedChunk = candidate
                break
            } else {
                compTry += 1
            }
        }

        let chunk: Data
        let processedLength: Int
        if compSuccess {
            chunk = compressedChunk
            processedLength = chunkSegmentLength
        } else {
            chunk = Data(b.prefix(StreamDataMessage.MAX_DATA_LEN))
            processedLength = chunk.count
        }

        let message = StreamDataMessage(
            streamId: streamId, eof: eofFlag, compressed: compSuccess, data: chunk
        )
        let sequence = try await channel.streamSendMessage(message)
        return StreamWriteOutcome(
            processed: processedLength,
            bytes: chunk.count,
            compressed: compSuccess,
            eof: eofFlag,
            sequence: sequence
        )
    }

    /// Write all of `data`, looping `writeChunk` until consumed (convenience for
    /// in-library callers that do not need the per-message manifest).
    public func write(_ data: Data) async throws {
        var remaining = data
        while !remaining.isEmpty {
            let outcome = try await writeChunk(remaining)
            guard outcome.processed > 0 else { break }
            remaining = Data(remaining.dropFirst(outcome.processed))
        }
    }

    /// Close the stream by flushing a final EOF-flagged (empty) message
    /// (Buffer.py:268-279 `close` sets `_eof` then `write(bytes())`).
    public func close() async throws {
        eofFlag = true
        _ = try await writeChunk(Data())
    }
}
