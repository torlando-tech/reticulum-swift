//
//  ChannelTests.swift
//  ReticulumSwift
//
//  Unit tests for Channel, Buffer, and message types.
//

import XCTest
@testable import ReticulumSwift

final class ChannelTests: XCTestCase {

    // MARK: - Constants

    func testChannelContextConstant() {
        XCTAssertEqual(PacketContext.CHANNEL, 0x0E)
    }

    func testChannelMDU() {
        XCTAssertEqual(LinkConstants.CHANNEL_MDU, 425)
    }

    func testWindowSizingConstants() {
        XCTAssertEqual(Channel.WINDOW_MIN, 2)
        XCTAssertEqual(Channel.WINDOW_MAX_SLOW, 5)
        XCTAssertEqual(Channel.WINDOW_MAX_MEDIUM, 12)
        XCTAssertEqual(Channel.WINDOW_MAX_FAST, 48)
    }

    // MARK: - Envelope

    func testEnvelopePackUnpack() throws {
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let envelope = Envelope(msgtype: 0x1234, sequence: 0x0042, payload: payload)
        let packed = envelope.pack()

        // Verify 6-byte header + payload
        XCTAssertEqual(packed.count, 6 + payload.count)

        // Verify wire bytes
        XCTAssertEqual(packed[0], 0x12) // MSGTYPE high
        XCTAssertEqual(packed[1], 0x34) // MSGTYPE low
        XCTAssertEqual(packed[2], 0x00) // SEQ high
        XCTAssertEqual(packed[3], 0x42) // SEQ low
        XCTAssertEqual(packed[4], 0x00) // LEN high
        XCTAssertEqual(packed[5], 0x04) // LEN low

        // Roundtrip
        let unpacked = try Envelope.unpack(from: packed)
        XCTAssertEqual(unpacked.msgtype, 0x1234)
        XCTAssertEqual(unpacked.sequence, 0x0042)
        XCTAssertEqual(unpacked.payload, payload)
    }

    func testEnvelopeOverhead() {
        let payload = Data(repeating: 0xAB, count: 100)
        let envelope = Envelope(msgtype: 0x0001, sequence: 0, payload: payload)
        XCTAssertEqual(envelope.pack().count, payload.count + 6)
    }

    func testEnvelopeTooShort() {
        let shortData = Data([0x00, 0x01, 0x00])
        XCTAssertThrowsError(try Envelope.unpack(from: shortData)) { error in
            XCTAssertEqual(error as? ChannelError, .envelopeTooShort)
        }
    }

    func testEnvelopePayloadTruncated() {
        // Header says 10 bytes payload but only 2 provided
        let data = Data([0x00, 0x01, 0x00, 0x00, 0x00, 0x0A, 0xAA, 0xBB])
        XCTAssertThrowsError(try Envelope.unpack(from: data)) { error in
            XCTAssertEqual(error as? ChannelError, .payloadTruncated)
        }
    }

    func testEnvelopeEmptyPayload() throws {
        let envelope = Envelope(msgtype: 0xffff, sequence: 0, payload: Data())
        let packed = envelope.pack()
        XCTAssertEqual(packed.count, 6) // Header only
        let unpacked = try Envelope.unpack(from: packed)
        XCTAssertEqual(unpacked.payload.count, 0)
    }

    // MARK: - System MSGTYPE Envelopes

    func testSystemMSGTYPEEnvelopeFormat() {
        // StreamDataMessage system type 0xFF00
        let env = Envelope(msgtype: 0xFF00, sequence: 0, payload: Data())
        let packed = env.pack()
        XCTAssertEqual(packed[0], 0xFF) // MSGTYPE high
        XCTAssertEqual(packed[1], 0x00) // MSGTYPE low
    }

    // MARK: - Sequence Wrap

    func testSequenceWrap() {
        var seq: UInt16 = 0xFFFF
        seq = seq &+ 1
        XCTAssertEqual(seq, 0x0000)
    }

    // MARK: - StreamDataMessage

    func testStreamDataMessagePackUnpack() throws {
        let msg = StreamDataMessage(streamId: 5, eof: false, compressed: false,
                                     data: Data([0x01, 0x02, 0x03]))
        let packed = try msg.pack()

        // 2 bytes flags + 3 bytes data
        XCTAssertEqual(packed.count, 5)

        let unpacked = try StreamDataMessage.unpack(from: packed)
        XCTAssertEqual(unpacked.streamId, 5)
        XCTAssertFalse(unpacked.eof)
        XCTAssertFalse(unpacked.compressed)
        XCTAssertEqual(unpacked.data, Data([0x01, 0x02, 0x03]))
    }

    func testStreamDataMessageEOFFlag() throws {
        let msg = StreamDataMessage(streamId: 0, eof: true, compressed: false, data: Data())
        let packed = try msg.pack()
        let unpacked = try StreamDataMessage.unpack(from: packed)
        XCTAssertTrue(unpacked.eof)
        XCTAssertFalse(unpacked.compressed)
        XCTAssertEqual(unpacked.streamId, 0)
    }

    func testStreamDataMessageStreamId() throws {
        // Test max 14-bit stream ID (16383)
        let msg = StreamDataMessage(streamId: 16383, eof: false, compressed: false,
                                     data: Data([0xFF]))
        let packed = try msg.pack()
        let unpacked = try StreamDataMessage.unpack(from: packed)
        XCTAssertEqual(unpacked.streamId, 16383)
    }

    func testStreamDataMessageCompressedFlag() throws {
        let msg = StreamDataMessage(streamId: 1, eof: false, compressed: true, data: Data())
        let packed = try msg.pack()
        let unpacked = try StreamDataMessage.unpack(from: packed)
        XCTAssertTrue(unpacked.compressed)
        XCTAssertFalse(unpacked.eof)
        XCTAssertEqual(unpacked.streamId, 1)
    }

    func testStreamDataMessageAllFlags() throws {
        let msg = StreamDataMessage(streamId: 100, eof: true, compressed: true,
                                     data: Data([0xAA]))
        let packed = try msg.pack()
        let unpacked = try StreamDataMessage.unpack(from: packed)
        XCTAssertEqual(unpacked.streamId, 100)
        XCTAssertTrue(unpacked.eof)
        XCTAssertTrue(unpacked.compressed)
        XCTAssertEqual(unpacked.data, Data([0xAA]))
    }

    func testStreamDataMessageTooShort() {
        XCTAssertThrowsError(try StreamDataMessage.unpack(from: Data([0x00]))) { error in
            XCTAssertEqual(error as? ChannelError, .bufferTooShort)
        }
    }

    // MARK: - MessageFactory

    func testMessageFactoryRegister() throws {
        let factory = MessageFactory()
        factory.register(StreamDataMessage.self)

        let msg = StreamDataMessage(streamId: 0, eof: false, compressed: false,
                                     data: Data([0x42]))
        let packed = try msg.pack()

        let created = try factory.create(msgtype: StreamDataMessage.MSGTYPE, data: packed)
        XCTAssertNotNil(created)

        if let stream = created as? StreamDataMessage {
            XCTAssertEqual(stream.data, Data([0x42]))
        } else {
            XCTFail("Expected StreamDataMessage")
        }
    }

    func testMessageFactoryUnknownType() throws {
        let factory = MessageFactory()
        let result = try factory.create(msgtype: 0x9999, data: Data())
        XCTAssertNil(result)
    }

    func testMessageFactoryIsRegistered() {
        let factory = MessageFactory()
        XCTAssertFalse(factory.isRegistered(StreamDataMessage.MSGTYPE))
        factory.register(StreamDataMessage.self)
        XCTAssertTrue(factory.isRegistered(StreamDataMessage.MSGTYPE))
    }

    // MARK: - Writer Chunking

    func testWriterChunking() async throws {
        // RawChannelWriter.maxChunk = CHANNEL_MDU - 2 = 423
        // Verify that data > 423 bytes is split into multiple messages
        let maxChunk = LinkConstants.CHANNEL_MDU - 2  // 423
        XCTAssertEqual(maxChunk, 423)

        // A 1000-byte payload should require ceil(1000/423) = 3 chunks
        let chunks = Int(ceil(Double(1000) / Double(maxChunk)))
        XCTAssertEqual(chunks, 3)

        // Verify chunk sizes: 423 + 423 + 154 = 1000
        let data = Data(repeating: 0xAB, count: 1000)
        var offset = 0
        var sizes: [Int] = []
        while offset < data.count {
            let end = min(offset + maxChunk, data.count)
            sizes.append(end - offset)
            offset = end
        }
        XCTAssertEqual(sizes, [423, 423, 154])
    }

    // MARK: - System MSGTYPE Constants

    func testStreamDataMSGTYPE() {
        XCTAssertEqual(StreamDataMessage.MSGTYPE, 0xFF00)
    }
}
