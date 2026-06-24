// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ChannelHardeningTests.swift
//  ReticulumSwiftTests
//
//  Drives the live Channel actor (over a real established Link) to cover the
//  greploop hardening added to Channel.swift (see port-deviations.md):
//
//   - receive(): the forward receive-window bound — a sequence more than
//     WINDOW_MAX_FAST ahead of next_rx_sequence is dropped, never buffered, while
//     the boundary sequence (exactly WINDOW_MAX_FAST ahead) is still accepted.
//     RNS's _rx_ring is unbounded forward (Channel.py:290); the bound is a
//     defensive no-op for conformant traffic (a sender never exceeds window_max
//     outstanding). This pins it so a regression can't silently restore the
//     unbounded buffer.
//   - performSend(): the send lock (RNS self._send_lock, Channel.py:606). Two
//     concurrent sends must reserve DISTINCT sequences; a missing lock lets both
//     read the same txSequence and alias onto one. Asserts nextSequence == 2 after
//     two concurrent sends.
//
//  Every assertion runs REAL production code: Channel.receive / Channel.send /
//  performSend over a Link established with real responder-key derivation.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class ChannelHardeningTests: XCTestCase {

    // MARK: - Fixtures

    /// Minimal app message: one marker byte, so a delivered message's identity is
    /// observable from its payload.
    private struct TestChannelMessage: MessageBase {
        static let MSGTYPE: UInt16 = 0x0101
        let marker: UInt8
        func pack() throws -> Data { Data([marker]) }
        static func unpack(from data: Data) throws -> TestChannelMessage {
            guard let b = data.first else { throw ChannelError.bufferTooShort }
            return TestChannelMessage(marker: b)
        }
    }

    /// Records markers handed to the channel's message callback, in delivery order.
    private actor DeliveredLog {
        private(set) var markers: [UInt8] = []
        func add(_ m: UInt8) { markers.append(m) }
    }

    /// Stand up a responder Link in `.active` with a derived encryption token, so
    /// the Channel outlet (channelBuildPacket encrypt + channelTransmit) works.
    /// Mirrors LinkQueueDrainTests.makeActiveLink().
    private func makeActiveLink() async throws -> Link {
        let identity = Identity()
        let dest = Destination(
            identity: identity, appName: "test", aspects: ["channel-hardening"]
        )
        let encKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let sigKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let signaling = IncomingLinkRequest.encodeSignaling(
            mtu: 500, mode: LinkConstants.MODE_DEFAULT
        )
        var requestData = Data()
        requestData.append(encKey)
        requestData.append(sigKey)
        requestData.append(signaling)
        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .linkRequest,
            hopCount: 0
        )
        let lrPacket = Packet(
            header: header, destination: dest.hash, context: 0x00, data: requestData
        )
        let incoming = try IncomingLinkRequest(data: requestData, packet: lrPacket)
        let link = Link(incomingRequest: incoming, destination: dest, identity: identity)
        try await link.deriveResponderKeys()
        await link._setStateForTesting(.active)
        return link
    }

    /// Pack an inbound channel envelope (the DECRYPTED plaintext Channel.receive
    /// consumes) carrying a TestChannelMessage `marker` at `sequence`.
    private func inboundEnvelope(sequence: UInt16, marker: UInt8) -> Data {
        Envelope(
            msgtype: TestChannelMessage.MSGTYPE, sequence: sequence, payload: Data([marker])
        ).pack()
    }

    // MARK: - receive(): forward window bound (#2)

    /// A sequence MORE than WINDOW_MAX_FAST (48) ahead of next_rx_sequence (0) is
    /// dropped outright — not delivered AND not buffered. The boundary sequence
    /// (exactly 48 ahead) is still accepted into the buffer, matching the inclusive
    /// keep-edge of the wrapped stale-drop branch.
    func testReceiveDropsForwardOutOfWindowSequenceButKeepsBoundary() async throws {
        let link = try await makeActiveLink()
        let channel = await link.getOrCreateChannel()
        await channel.register(TestChannelMessage.self)
        let log = DeliveredLog()
        await channel.setMessageCallback { msg in
            if let m = msg as? TestChannelMessage { await log.add(m.marker) }
        }

        // 49 ahead (> WINDOW_MAX_FAST): out of window -> dropped, not buffered.
        await channel.receive(data: inboundEnvelope(sequence: 49, marker: 0xFF))
        var depth = await channel.rxRingDepth
        var rx = await channel.nextRxSequence
        let markersAfterDrop = await log.markers
        XCTAssertEqual(depth, 0, "Out-of-window sequence 49 must not be buffered")
        XCTAssertEqual(rx, 0, "next_rx_sequence must not advance on a dropped packet")
        XCTAssertTrue(markersAfterDrop.isEmpty, "Out-of-window packet must not be delivered")

        // 48 ahead (== WINDOW_MAX_FAST): in window -> accepted into the buffer
        // (held as an out-of-order gap, since 0..47 have not arrived).
        await channel.receive(data: inboundEnvelope(sequence: 48, marker: 0x30))
        depth = await channel.rxRingDepth
        rx = await channel.nextRxSequence
        XCTAssertEqual(depth, 1, "Boundary sequence 48 (== WINDOW_MAX_FAST ahead) must be accepted")
        XCTAssertEqual(rx, 0, "Buffered out-of-order packet must not advance next_rx_sequence")
    }

    /// In-window out-of-order delivery still drains contiguously once the gap fills:
    /// sequence 1 buffers (gap at 0), then sequence 0 delivers 0 and 1 in order.
    func testReceiveBuffersThenDrainsContiguousRun() async throws {
        let link = try await makeActiveLink()
        let channel = await link.getOrCreateChannel()
        await channel.register(TestChannelMessage.self)
        let log = DeliveredLog()
        await channel.setMessageCallback { msg in
            if let m = msg as? TestChannelMessage { await log.add(m.marker) }
        }

        // Sequence 1 arrives first: buffered, nothing delivered (0 is missing).
        await channel.receive(data: inboundEnvelope(sequence: 1, marker: 0x01))
        let depthAfter1 = await channel.rxRingDepth
        let markersAfter1 = await log.markers
        XCTAssertEqual(depthAfter1, 1)
        XCTAssertTrue(markersAfter1.isEmpty)

        // Sequence 0 fills the gap: 0 then 1 deliver in order, buffer empties.
        await channel.receive(data: inboundEnvelope(sequence: 0, marker: 0x00))
        let delivered = await log.markers
        let depthAfter0 = await channel.rxRingDepth
        let rxAfter0 = await channel.nextRxSequence
        XCTAssertEqual(delivered, [0x00, 0x01], "Contiguous run must deliver in order")
        XCTAssertEqual(depthAfter0, 0)
        XCTAssertEqual(rxAfter0, 2)
    }

    // MARK: - performSend(): send lock (#3)

    /// Two concurrent sends must reserve DISTINCT sequences. The send lock (RNS
    /// self._send_lock) serialises reserve->commit across the channelOutletMdu /
    /// channelBuildPacket awaits, so next_sequence advances to exactly 2. Without
    /// the lock both sends could read the same txSequence and alias onto one
    /// sequence, leaving next_sequence at 1. A fresh link has rtt 0 (< RTT_SLOW),
    /// so the window is the non-degenerate WINDOW (2) and both sends are admitted.
    func testConcurrentSendsReserveUniqueSequences() async throws {
        let link = try await makeActiveLink()
        await link.setSendCallback { _ in }   // accept (and discard) transmitted wire bytes
        let channel = await link.getOrCreateChannel()

        async let a: Void = channel.send(TestChannelMessage(marker: 0xA0))
        async let b: Void = channel.send(TestChannelMessage(marker: 0xB0))
        _ = try await (a, b)

        let next = await channel.nextSequence
        XCTAssertEqual(next, 2,
            "Two concurrent sends must reserve distinct sequences (the send lock " +
            "serialises the reservation); aliasing would leave nextSequence at 1.")
    }

    // MARK: - RawChannelWriter: EOF is a one-shot flag

    /// setEof(true) must mark exactly ONE emitted StreamDataMessage. A sticky flag
    /// (the pre-fix behaviour) would stamp EOF onto every subsequent write too —
    /// wrong for a stream whose final write splits, or any reuse of the writer.
    func testWriterEofFlagIsOneShot() async throws {
        let link = try await makeActiveLink()
        await link.setSendCallback { _ in }
        let channel = await link.getOrCreateChannel()
        let (_, writer) = await channel.createBuffer(streamId: 7)

        await writer.setEof(true)
        let first = try await writer.writeChunk(Data([0x01, 0x02, 0x03]))
        let second = try await writer.writeChunk(Data([0x04, 0x05, 0x06]))

        XCTAssertTrue(first.eof, "First write after setEof(true) must carry EOF")
        XCTAssertFalse(second.eof,
            "EOF must be one-shot — the second write must NOT inherit the flag.")
    }
}
