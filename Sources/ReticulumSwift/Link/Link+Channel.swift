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

    /// Handle inbound channel data (decrypted plaintext from transport).
    ///
    /// Called by ReticuLumTransport.handleLinkData() for context 0x0E.
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
}
