// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ReticulumTransport+Tunnels.swift
//  ReticulumSwift
//
//  Tunnel synthesize / validate handshake.
//
//  RNS establishes a "tunnel" between two transport instances so that learned
//  paths can survive an interface reconnect. The handshake is a single PLAIN
//  broadcast packet to the rnstransport/tunnel/synthesize control destination:
//
//      public_key(64) || interface_hash(32) || random_hash(16) || signature(64)
//
//  where the signature is the emitting transport identity's Ed25519 signature
//  over public_key || interface_hash || random_hash, and the derived tunnel id
//  is full_hash(public_key || interface_hash). The receiver re-derives that
//  tunnel id, loads the carried public key, and only establishes the tunnel —
//  bound to the RECEIVING interface — if the signature validates.
//
//  Reference: RNS Transport.py:2282-2345 (synthesize_tunnel /
//  tunnel_synthesize_handler / handle_tunnel), IDX_TT_* at Transport.py:3581-3584.
//

import Foundation

/// One entry in `Transport.tunnels` (RNS list `[tunnel_id, interface, paths,
/// expires]`, IDX_TT_* at Transport.py:3581-3584). `interfaceId` is the
/// receiving interface the tunnel is bound to (`None`/`nil` after the tunnel is
/// voided). `paths` mirrors the per-tunnel cached-path map RNS restores on
/// reconnect; path restoration is not yet ported, so it stays empty and only its
/// count is surfaced.
public struct TunnelTableEntry: Sendable {
    /// `full_hash(public_key || interface_hash)` (32 bytes).
    public let tunnelId: Data
    /// Receiving interface id the tunnel is bound to (`nil` once voided).
    public var interfaceId: String?
    /// Cached paths restored on tunnel reappearance (empty until ported).
    public var paths: [Data: Data]
    /// Expiry instant (`time.time() + TUNNEL_TIMEOUT`).
    public var expires: Date

    public init(tunnelId: Data, interfaceId: String?, paths: [Data: Data], expires: Date) {
        self.tunnelId = tunnelId
        self.interfaceId = interfaceId
        self.paths = paths
        self.expires = expires
    }
}

extension ReticulumTransport {

    /// Register the rnstransport/tunnel/synthesize PLAIN control destination so
    /// inbound synthesize packets reach the validate/establish handler.
    ///
    /// RNS registers this destination at Transport start with
    /// `set_packet_callback(tunnel_synthesize_handler)` (Transport.py:247-250).
    /// The swift port stores the destination and dispatches the handler
    /// synchronously from `handleRegularData` when an inbound PLAIN packet is
    /// addressed to it (see port-deviations.md).
    public func registerTunnelSynthesizeHandler() {
        tunnelSynthesizeDestination = Destination(
            plainAppName: "rnstransport",
            aspects: ["tunnel", "synthesize"]
        )
    }

    /// Validate an inbound tunnel-synthesize packet and, if it validates,
    /// establish the tunnel bound to the receiving interface.
    ///
    /// Mirrors RNS `Transport.tunnel_synthesize_handler` (Transport.py:2306-2327):
    ///   - exact-length gate: `len(data) == KEYSIZE/8 + HASHLENGTH/8 +
    ///     TRUNCATED_HASHLENGTH/8 + SIGLENGTH/8` == 64+32+16+64 == 176;
    ///   - decompose `public_key(64) || interface_hash(32) || random_hash(16) ||
    ///     signature(64)`;
    ///   - `tunnel_id = full_hash(public_key || interface_hash)`;
    ///   - validate the Ed25519 signature over `public_key || interface_hash ||
    ///     random_hash` against the carried public key BEFORE establishing.
    func tunnelSynthesizeHandler(data: Data, receivingInterfaceId: String) {
        // RNS Transport.py:2308 — KEYSIZE/8(64)+HASHLENGTH/8(32)+
        // TRUNCATED_HASHLENGTH/8(16)+SIGLENGTH/8(64). Exact equality gate (:2309).
        let keysizeBytes = 64
        let hashLengthBytes = 32
        let truncatedHashBytes = 16
        let sigBytes = 64
        let expectedLength = keysizeBytes + hashLengthBytes + truncatedHashBytes + sigBytes

        // Re-base to a zero-indexed copy: `packet.data` may be a non-zero-based
        // slice, so subdata(in:) ranges must index a normalized buffer.
        let d = Data(data)
        guard d.count == expectedLength else { return }

        let publicKey = d.subdata(in: 0..<keysizeBytes)
        let interfaceHash = d.subdata(in: keysizeBytes..<(keysizeBytes + hashLengthBytes))
        let randomHashEnd = keysizeBytes + hashLengthBytes + truncatedHashBytes
        let randomHash = d.subdata(in: (keysizeBytes + hashLengthBytes)..<randomHashEnd)
        let signature = d.subdata(in: randomHashEnd..<expectedLength)

        let tunnelIdData = publicKey + interfaceHash         // public_key || interface_hash
        let signedData = tunnelIdData + randomHash           // ... || random_hash

        // RNS loads the carried 64-byte public key and validates with its signing
        // half (Identity.load_public_key splits enc(32) || sig(32); validate uses
        // the signing public key). Mirror that: verify against publicKey[32..64].
        let signingPublicKey = publicKey.subdata(in: (keysizeBytes / 2)..<keysizeBytes)
        let valid = (try? Identity.verify(
            signature: signature,
            for: signedData,
            publicKey: signingPublicKey
        )) ?? false
        guard valid else { return }

        let tunnelId = Hashing.fullHash(tunnelIdData)
        handleTunnel(tunnelId: tunnelId, interfaceId: receivingInterfaceId)
    }

    /// Establish (or refresh) a tunnel bound to the receiving interface.
    ///
    /// Mirrors RNS `Transport.handle_tunnel` (Transport.py:2336-2345): a new
    /// tunnel_id inserts a fresh entry bound to the interface; a reappearing
    /// tunnel_id re-binds the interface and bumps the expiry. (RNS additionally
    /// restores per-tunnel cached paths on reappearance, Transport.py:2346-2391;
    /// path caching is not yet ported, so the paths map stays empty.)
    func handleTunnel(tunnelId: Data, interfaceId: String) {
        let expires = Date().addingTimeInterval(TransportConstants.TUNNEL_TIMEOUT)
        if var entry = tunnels[tunnelId] {
            entry.interfaceId = interfaceId
            entry.expires = expires
            tunnels[tunnelId] = entry
        } else {
            tunnels[tunnelId] = TunnelTableEntry(
                tunnelId: tunnelId,
                interfaceId: interfaceId,
                paths: [:],
                expires: expires
            )
        }
    }

    /// Snapshot the tunnel table for observability. Returns a value copy of the
    /// live `Transport.tunnels` entries.
    public func tunnelsSnapshot() -> [TunnelTableEntry] {
        return Array(tunnels.values)
    }
}
