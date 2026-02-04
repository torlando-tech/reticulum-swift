//
//  Link+Identify.swift
//  ReticulumSwift
//
//  Link extension for peer identity authentication.
//  Allows the initiator to reveal their identity to the remote peer.
//
//  Matches Python RNS Link.py identify() for interoperability.
//

import Foundation

// MARK: - Identify Packet Context

/// Packet context values for link identification.
/// NOTE: Use LinkConstants.CONTEXT_LINKIDENTIFY (0xFB) for wire format.
public enum IdentifyPacketContext {
    /// Initiator revealing identity to responder (legacy - use LinkConstants.CONTEXT_LINKIDENTIFY)
    @available(*, deprecated, message: "Use LinkConstants.CONTEXT_LINKIDENTIFY (0xFB) instead")
    public static let linkIdentify: UInt8 = 0x0A
}

// MARK: - Identify Callbacks

/// Protocol for receiving identity notifications on a link.
///
/// Implement this protocol to be notified when the remote peer
/// identifies themselves over an established link.
public protocol IdentifyCallbacks: AnyObject, Sendable {
    /// Called when the remote peer identifies themselves.
    ///
    /// This is called after receiving and validating a LINKIDENTIFY packet
    /// from the remote peer containing their signed identity proof.
    ///
    /// - Parameter identity: The verified identity of the remote peer
    func remoteIdentified(_ identity: Identity) async
}

// MARK: - Link Identify Extension

extension Link {
    /// Reveal identity to remote peer.
    ///
    /// Sends a signed proof of identity over the encrypted link.
    /// Only the link initiator can call identify(); the responder receives
    /// the identification via the IdentifyCallbacks protocol.
    ///
    /// The proof format is:
    /// - public_keys (64 bytes): encryption public key (32) + signing public key (32)
    /// - signature (64 bytes): Ed25519 signature of (link_id + public_keys)
    ///
    /// Total proof size: 128 bytes
    ///
    /// - Parameter identity: Identity to reveal (must be the link's local identity)
    /// - Throws: LinkError if not initiator, not active, identity mismatch, or send fails
    public func identify(identity: Identity) async throws {
        guard initiator else {
            throw LinkError.invalidState(
                expected: "initiator",
                actual: "responder (only initiator can identify)"
            )
        }

        guard state.isEstablished else {
            throw LinkError.notActive
        }

        guard let send = sendCallback else {
            throw LinkError.notActive
        }

        // Verify this is the link's local identity
        // (prevents sending wrong identity proof)
        guard identity.hash == localIdentity.hash else {
            throw LinkError.invalidState(
                expected: "link identity",
                actual: "different identity provided"
            )
        }

        // Build proof: sign(link_id + public_keys)
        let publicKeys = identity.publicKeys // 64 bytes (enc + sig)
        var signedData = linkId
        signedData.append(publicKeys)

        let signature = try identity.sign(signedData)

        // Build packet payload: public_keys + signature (128 bytes total)
        // NO context byte in payload - context goes in wire format
        var proofData = publicKeys
        proofData.append(signature)

        // Encrypt the proof data
        let encrypted = try encrypt(proofData)

        // Build proper RNS packet with context in wire format
        // This matches Python RNS Link.identify() packet structure
        let header = PacketHeader(
            headerType: .header1,
            hasContext: true,
            hasIFAC: false,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .data,
            hopCount: 0
        )

        let packet = Packet(
            header: header,
            destination: linkId,
            transportAddress: nil,
            context: LinkConstants.CONTEXT_LINKIDENTIFY,  // 0xFB in wire format
            data: encrypted
        )

        let packetBytes = packet.encode()
        let linkIdHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[LINK_IDENTIFY] Sending LINKIDENTIFY packet (\(packetBytes.count) bytes) for link \(linkIdHex)")

        try await send(packetBytes)
    }
}
