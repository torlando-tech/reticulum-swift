// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Link+Channel.swift
//  ReticulumSwift
//
//  Link extension wiring Channel into Link lifecycle.
//  Follows the Link+Request.swift / Link+Identify.swift pattern.
//
//  Matches Python RNS Link.py channel property and Channel integration.
//

import Foundation

// MARK: - Link Channel Extension

extension Link {

    /// Get or create the Channel for this link.
    ///
    /// Lazily creates a Channel on first access. Subsequent calls
    /// return the same Channel instance.
    ///
    /// - Returns: The Channel associated with this link
    public func getOrCreateChannel() -> Channel {
        if let ch = channel { return ch }
        let ch = Channel(link: self)
        channel = ch
        return ch
    }

    /// Whether this link currently has an open Channel.
    ///
    /// Mirrors RNS's `if not self._channel` gate in the Link.receive CHANNEL
    /// branch (Link.py:1166-1172): an inbound CHANNEL packet is only processed
    /// (and proved) when the link has an open channel. RNS checks the underlying
    /// `_channel` attribute directly (NOT the lazily-creating property), so this
    /// reports the raw open/closed state without creating a channel.
    public var hasOpenChannel: Bool { channel != nil }

    /// Handle inbound channel data (decrypted plaintext from transport).
    ///
    /// Called by ReticulumTransport.handleLinkData() for context 0x0E.
    /// The transport layer decrypts the packet data before passing it here.
    ///
    /// - Parameter plaintext: Decrypted channel envelope data
    public func handleChannelData(_ plaintext: Data) async {
        guard let ch = channel else { return }
        await ch.receive(data: plaintext)
    }

    /// Send channel envelope data via link encryption.
    ///
    /// Called by Channel.flushOutbound() to send envelope wire data
    /// over the link. Encrypts the data and builds a proper packet
    /// with CHANNEL context (0x0E).
    ///
    /// - Parameter envelopeData: Raw envelope wire data to encrypt and send
    /// - Throws: LinkError if link is not active or encryption fails
    func sendChannelData(_ envelopeData: Data) async throws {
        let ciphertext = try encrypt(envelopeData)

        guard let send = sendCallback else {
            throw LinkError.notActive
        }

        let header = PacketHeader(
            headerType: .header1,
            hasContext: true,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .data,
            hopCount: 0
        )

        let packet = Packet(
            header: header,
            destination: linkId,
            context: PacketContext.CHANNEL,
            data: ciphertext
        )

        try await send(packet.encode())
    }

    // MARK: - Channel outlet (RNS LinkChannelOutlet, Channel.py:658-740)

    /// The Channel outlet MDU — the link MDU (RNS `LinkChannelOutlet.mdu`,
    /// Channel.py:681-683 returns `self.link.mdu`).
    var channelOutletMdu: Int { mdu }

    /// The Channel outlet RTT — the link RTT (RNS `LinkChannelOutlet.rtt`,
    /// Channel.py:685-687 returns `self.link.rtt`). Read live so a channel's
    /// window/rate logic reflects the current measured RTT.
    var channelOutletRtt: TimeInterval { rtt }

    /// Build (but do not transmit) a CHANNEL-context packet for `raw`, returning
    /// its encoded wire bytes and full hash, or nil if the link cannot transmit
    /// (not established). Mirrors `RNS.Packet(link, raw, context=CHANNEL)` whose
    /// `get_hash()` becomes the outlet packet id (Channel.py:671-674, 733-740).
    ///
    /// The packet is encrypted ONCE here and the resulting bytes are reused for
    /// every retransmission (RNS resends the same already-packed Packet, so its
    /// hash is stable across tries — the peer proves the same hash each time).
    func channelBuildPacket(_ raw: Data) -> (wire: Data, hash: Data)? {
        guard state.isEstablished else { return nil }
        guard let ciphertext = try? encrypt(raw) else { return nil }

        let header = PacketHeader(
            headerType: .header1,
            hasContext: true,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .data,
            hopCount: 0
        )
        let packet = Packet(
            header: header,
            destination: linkId,
            context: PacketContext.CHANNEL,
            data: ciphertext
        )
        return (packet.encode(), packet.getFullHash())
    }

    /// Transmit pre-encoded channel packet bytes. Mirrors `RNS.Packet.send()` /
    /// `resend()` on the already-built CHANNEL packet (Channel.py:673, 676-679).
    /// Returns false if the link has no send callback (outlet not usable).
    func channelTransmit(_ wire: Data) async -> Bool {
        guard let send = sendCallback else { return false }
        do {
            try await send(wire)
            return true
        } catch {
            return false
        }
    }

    /// Register a delivery-proof callback for a sent CHANNEL packet, keyed by the
    /// packet's truncated (16-byte) hash. The transport's PROOF handler matches an
    /// inbound link PROOF's leading 32-byte packet hash (truncated to 16) against
    /// this registration (ReticulumTransport.handleDataProof), mirroring how RNS's
    /// `PacketReceipt` resolves on a returning PROOF.
    func channelRegisterDelivery(fullHash: Data, _ cb: @escaping @Sendable () async -> Void) async {
        let truncated = Data(fullHash.prefix(TRUNCATED_HASH_LENGTH))
        await channelProofRegistrar?(truncated, cb)
    }

    /// Remove a previously-registered channel delivery callback (used when a send
    /// is rolled back before it transmits).
    func channelDeregisterDelivery(fullHash: Data) async {
        let truncated = Data(fullHash.prefix(TRUNCATED_HASH_LENGTH))
        await channelProofDeregistrar?(truncated)
    }

    /// Tear the link down because a channel exhausted its retransmissions. Mirrors
    /// `LinkChannelOutlet.timed_out` -> `self.link.teardown()` (Channel.py:710-711).
    func channelOutletTimedOut() async {
        close(reason: .timeout)
    }
}
