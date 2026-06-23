// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Link.swift
//  ReticulumSwift
//
//  Actor-based Reticulum link for encrypted peer-to-peer communication.
//  Manages the handshake state machine, ECDH key exchange, and Token encryption.
//
//  Matches Python RNS Link.py for interoperability.
//

import Foundation
import CryptoKit
import os.log

private let linkLogger = Logger(subsystem: "com.columba.app", category: "Link")

/// File-based debug logger for resource diagnostics
private func resourceDebugLog(_ message: String) {
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let line = "[\(timestamp)] \(message)\n"
    let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("columba_resource_debug.log")
    if let handle = try? FileHandle(forWritingTo: url) {
        handle.seekToEndOfFile()
        handle.write(Data(line.utf8))
        handle.closeFile()
    } else {
        try? Data(line.utf8).write(to: url)
    }
}

// MARK: - Link

/// Actor-based Reticulum link for encrypted peer-to-peer communication.
///
/// Link implements the Reticulum link protocol:
/// - ECDH key exchange using X25519
/// - AES-256-CBC encryption via Token
/// - State machine: pending -> handshake -> active -> stale -> closed
/// - AsyncStream for state observation
///
/// Example usage:
/// ```swift
/// let link = Link(destination: remoteDest, identity: localIdentity)
/// let request = try await link.getLinkRequestPacket()
/// await transport.send(request)
/// await link.markRequestSent()
/// // ... receive PROOF packet ...
/// try await link.processProof(proofData)
/// // Link is now active, can encrypt/decrypt
/// let ciphertext = try await link.encrypt(plaintext)
/// ```
public actor Link {

    // MARK: - Identity and Keys

    /// Local identity for signing
    let localIdentity: Identity

    /// Link request containing ephemeral keypairs (for initiator only)
    private let request: LinkRequest?

    /// Target destination for this link (remote for initiator, local for responder)
    public let destination: Destination

    /// Hash of the target destination (for routing lookups)
    public var destinationHash: Data {
        return destination.hash
    }

    /// Whether this side initiated the link
    public let initiator: Bool

    // MARK: - Responder Properties

    /// Peer's ephemeral signing public key (from IncomingLinkRequest for responder)
    private var peerSigningPublicKey: Curve25519.Signing.PublicKey?

    /// Responder's ephemeral encryption private key (for ECDH)
    private var responderEphemeralEncryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey?

    /// Stored link ID (for responder, computed from IncomingLinkRequest)
    private var storedLinkId: Data?

    /// Peer's encryption public key bytes (for responder)
    private var peerEncryptionPublicKeyBytes: Data?

    /// Link establishment callback for responders
    public private(set) var linkEstablishedCallback: ((Link) async -> Void)?

    // MARK: - Link Properties

    /// Unique link identifier (truncated hash of ephemeral public keys)
    public var linkId: Data {
        if let stored = storedLinkId {
            return stored
        }
        guard let req = request else {
            return Data()
        }
        return req.linkId
    }

    /// LINKREQUEST packet data (67 bytes: enc_pub + sig_pub + signaling)
    public var requestData: Data {
        guard let req = request else {
            return Data()
        }
        return req.requestData
    }

    // MARK: - MTU

    /// Negotiated link MTU (default 500, updated during handshake if MTU discovery succeeds)
    public private(set) var mtu: Int = 500

    /// Max usable plaintext payload for link-encrypted packets.
    /// Recalculated when MTU changes via updateMdu().
    public private(set) var mdu: Int = LinkConstants.LINK_MDU  // 431 at default MTU

    /// Recalculate MDU from current MTU.
    /// Python: floor((mtu - IFAC_MIN - HEADER_MIN - TOKEN_OVERHEAD) / AES_BLOCK) * AES_BLOCK - 1
    private func updateMdu() {
        let ifacMin = 1       // IFAC_MIN_SIZE
        let headerMin = 19    // HEADER_MINSIZE (2 header + 16 dest + 1 context)
        let tokenOverhead = 48 // Identity.TOKEN_OVERHEAD (16 IV + 32 HMAC)
        let aesBlock = 16     // AES128_BLOCKSIZE
        mdu = ((mtu - ifacMin - headerMin - tokenOverhead) / aesBlock) * aesBlock - 1
    }

    // MARK: - State

    /// Current link state
    public private(set) var state: LinkState = .pending

    /// State observation stream continuation
    private var stateContinuation: AsyncStream<LinkState>.Continuation?

    // MARK: - Cryptography

    /// Peer's ephemeral encryption public key (after PROOF received)
    private var peerEncryptionPublicKey: Curve25519.KeyAgreement.PublicKey?

    /// Derived 64-byte key from ECDH + HKDF
    private var derivedKey: Data?

    /// Token for encrypt/decrypt (created after key derivation)
    private var token: Token?

    // MARK: - Timing

    /// Timestamp when LINKREQUEST was sent (for RTT measurement)
    private var requestSentAt: Date?

    /// Measured round-trip time
    public private(set) var rtt: TimeInterval = 0.0

    /// Calculated keep-alive interval based on RTT
    public private(set) var keepaliveInterval: TimeInterval = LinkConstants.KEEPALIVE_MIN

    /// RNS Link.STALE_FACTOR (Link.py:98): stale_time = keepalive * 2.
    private static let staleFactor: Double = 2.0

    /// Stale-detection window. Mirrors RNS `self.stale_time` (Link.py:263,
    /// default STALE_TIME == KEEPALIVE * STALE_FACTOR). Kept proportional to
    /// `keepaliveInterval` whenever the keepalive cadence is (re)computed from
    /// RTT (RNS __update_keepalive, Link.py:846) UNLESS explicitly overridden
    /// via `setWatchdog`. Read by `checkLiveness()` so the watchdog window can
    /// be compressed (or extended) at runtime — previously the watchdog used an
    /// inline `keepaliveInterval * 2`, which could not be driven by the peer.
    public private(set) var staleTime: TimeInterval = LinkConstants.KEEPALIVE_MIN * Link.staleFactor

    /// Last inbound traffic timestamp (keepalives included).
    /// Mirrors RNS `self.last_inbound` (Link.py:248/:978).
    private var lastInbound: Date?

    /// Public read-back of the last inbound-traffic timestamp (keepalives
    /// included). Mirrors RNS `self.last_inbound` (Link.py:248). Backs the
    /// bridge's wire_link_status / keepalive-probe observation of inbound
    /// liveness without exposing the mutable field.
    public var lastInboundAt: Date? { lastInbound }

    /// Last outbound traffic timestamp
    private var lastOutbound: Date?

    /// Timestamp of the last keepalive packet WE emitted (initiator periodic
    /// keepalive, or responder 0xFE echo). Mirrors RNS `self.last_keepalive`
    /// (Link.py:250, set by had_outbound(is_keepalive=True), Link.py:692).
    /// A keepalive bumps THIS, not `lastDataAt`.
    public private(set) var lastKeepaliveAt: Date?

    /// Last keepalive byte this link put on the wire — 0xFF when an initiator
    /// emits its periodic keepalive, 0xFE when a non-initiator answers an
    /// inbound 0xFF (RNS send_keepalive Link.py:849 / receive() echo
    /// Link.py:1149-1153). Backs the wire_last_keepalive read-back.
    public private(set) var lastKeepaliveByte: UInt8?

    /// Timestamp of the last PAYLOAD traffic (inbound decrypt or outbound
    /// encrypt), EXCLUDING keepalives. Mirrors RNS `self.last_data`
    /// (Link.py:252, set at Link.py:691 outbound / Link.py:980 inbound). A
    /// keepalive must NOT advance this, which lets the watchdog/bridge tell
    /// "link is alive via keepalives" from "real data is flowing".
    public private(set) var lastDataAt: Date?

    /// Timestamp when the link first transitioned to `.active` (establishment).
    /// Mirrors RNS `self.activated_at` (Link.py:266, set at validate_proof
    /// :430 / rtt_packet :542). Set ONCE; a STALE->ACTIVE recovery does not
    /// reset it. Used by `noInboundForMs()` as the inbound-idle baseline.
    public private(set) var activatedAt: Date?

    /// Last proof received timestamp (for stale detection, L10)
    private var lastProof: Date?

    // MARK: - Physical-layer statistics (RNS Link.py:257-259, 273)

    /// Physical-layer Received Signal Strength Indication, if the interface
    /// reports it and tracking is enabled. nil otherwise. (RNS Link.rssi)
    public private(set) var rssi: Double?
    /// Physical-layer Signal-to-Noise Ratio. (RNS Link.snr)
    public private(set) var snr: Double?
    /// Physical-layer Link Quality. (RNS Link.q)
    public private(set) var q: Double?
    /// Whether physical-layer statistics are tracked for this link
    /// (RNS Link.__track_phy_stats, default False).
    private var trackPhyStatsEnabled: Bool = false

    /// Interface ID this link is attached to (H2: validates DATA delivery source)
    public private(set) var attachedInterfaceId: String?

    // MARK: - Tasks

    /// Task for periodic keep-alive sending
    private var keepaliveTask: Task<Void, Never>?

    /// Task for monitoring link liveness
    private var watchdogTask: Task<Void, Never>?

    /// Callback for sending packets (set by transport integration)
    var sendCallback: ((Data) async throws -> Void)?

    // MARK: - Request Management

    /// Pending requests awaiting response
    var pendingRequests: [RequestReceipt] = []

    // MARK: - Resource Management

    /// Resource acceptance strategy
    public private(set) var resourceStrategy: ResourceStrategy = .acceptNone

    /// Resource callbacks for transfer notifications
    /// Non-weak: handler lifetime is tied to link lifetime, no retain cycle
    /// since the handler doesn't reference the link.
    private var resourceCallbacks: (any ResourceCallbacks)?

    /// Outbound resources indexed by resource hash
    private var outboundResources: [Data: Resource] = [:]

    /// Inbound resources indexed by resource hash
    private var inboundResources: [Data: Resource] = [:]

    /// Window size (parts) of the most recently concluded INBOUND resource.
    /// RNS records the just-finished receiver's window on the link so the NEXT
    /// inbound resource can inherit it and skip slow-start (RNS/Link.py:243 +
    /// resource_concluded bookkeeping :1314-1315). nil until the first inbound
    /// resource concludes. Read via `getLastResourceWindow()`; written by
    /// `resourceConcluded(_:)`.
    private var lastResourceWindow: Int?

    /// FIFO of outbound resources offered while another outgoing transfer is
    /// already in flight. RNS serves ONE outgoing resource at a time
    /// (RNS/Link.py:1328-1330 `ready_for_new_resource`); resources queued here
    /// stay in `.queued` and are advertised+registered as each predecessor
    /// concludes (event-driven drain in `resourceConcluded(_:)`, never polled).
    private var pendingOutgoingQueue: [Resource] = []

    /// Synchronous reservation closing the register-window in the one-at-a-time
    /// outbound gate. `readyForNewResource()` reads `outboundResources.isEmpty`, but
    /// committing a resource as the in-flight outbound requires awaits (the Resource
    /// actor's `state` read, and `await resource.hash` inside registerOutgoingResource)
    /// that release the Link actor while `outboundResources` is STILL empty — a window
    /// where a concurrent `sendResource`/`drainOutgoingQueue` would wrongly see the
    /// link free and advertise a SECOND resource, violating the one-at-a-time invariant
    /// and confusing the receiver's request/hashmap machinery. This is set true
    /// SYNCHRONOUSLY before those awaits and cleared once the resource is registered
    /// (the gate is then held by `outboundResources`). RNS has no such window —
    /// `register_outgoing_resource` runs synchronously. See port-deviations.md.
    private var outgoingReservationActive = false

    /// Resource hashes whose app-facing conclusion callback has already fired, so it
    /// fires AT MOST ONCE per resource regardless of which path reaches the conclusion
    /// first. RNS fires `self.callback(self)` exactly once per resource
    /// (RNS/Resource.py:738/792), but this actor port concludes the same resource from
    /// several racing paths — the inbound handlers (cancel/reject/data/proof), the
    /// outbound segment chain, and `finishClose`'s cancel-on-close detached Task — and
    /// the `await resource.hash` suspensions between "match" and "fire" let two of them
    /// interleave. Routing every app callback through `fireResourceConcludedOnce(_:)`
    /// (which checks+inserts here) collapses all those double-fire windows into one
    /// guard. Bounded by the link's lifetime resource count (cleared on dealloc).
    private var firedResourceConclusions: Set<Data> = []

    // MARK: - Identity

    // MARK: - Close Callback

    /// Callback invoked when the link closes (remote hangup, timeout, or local close).
    /// Receives the TeardownReason explaining why the link was closed.
    private var closeCallback: (@Sendable (TeardownReason) async -> Void)?

    /// Set a callback to be notified when this link closes.
    ///
    /// - Parameter callback: Async callback receiving the close reason, or nil to clear
    public func setCloseCallback(_ callback: (@Sendable (TeardownReason) async -> Void)?) {
        self.closeCallback = callback
    }

    // MARK: - Packet Callback

    /// Generic per-link packet callback matching Python's link.set_packet_callback().
    /// Called for context 0x00 (DATA) packets before LXMF routing.
    /// LXST and other protocols use this for raw link data delivery.
    private var packetCallback: (@Sendable (Data, Packet) async -> Void)?

    /// Whether a packet callback is registered on this link.
    public var hasPacketCallback: Bool {
        packetCallback != nil
    }

    /// Set a generic packet callback for this link.
    ///
    /// Matches Python's `link.set_packet_callback(callback)`.
    /// The callback receives decrypted plaintext and the original packet.
    /// When set, context 0x00 DATA packets are delivered here instead of LXMF routing.
    ///
    /// - Parameter callback: Async callback receiving (plaintext, packet), or nil to clear
    public func setPacketCallback(_ callback: (@Sendable (Data, Packet) async -> Void)?) {
        self.packetCallback = callback
    }

    /// Deliver decrypted data to the packet callback if one is registered.
    ///
    /// - Parameters:
    ///   - data: Decrypted plaintext
    ///   - packet: Original wire packet
    /// - Returns: true if delivered to callback, false if no callback set
    public func deliverToPacketCallback(data: Data, packet: Packet) async -> Bool {
        guard let callback = packetCallback else { return false }
        await callback(data, packet)
        return true
    }

    /// Per-link inbound packet observation hook (additive instrumentation).
    ///
    /// Invoked for an observed inbound packet AFTER link-decryption, carrying the
    /// wire context byte and the decrypted plaintext, so an instrumentation
    /// consumer (the conformance bridge) can capture the RESPONSE (0x0A) frame's
    /// msgpack `[request_id, response]` and the >MDU response fork's RESOURCE_ADV
    /// (0x02) advertisement. RNS routes both through `Link.receive` with no
    /// app-visible wrap point (RNS/Link.py:897-901); this hook adds one WITHOUT
    /// altering routing, ordering, or timing. No-op when unset.
    private var inboundPacketObserver: (@Sendable (UInt8, Data) async -> Void)?

    /// Set (or clear) the inbound packet observation hook. See
    /// `inboundPacketObserver`. Additive instrumentation — documented in
    /// port-deviations.md (no RNS-named equivalent).
    public func setInboundPacketObserver(_ observer: (@Sendable (UInt8, Data) async -> Void)?) {
        self.inboundPacketObserver = observer
    }

    /// Channel for typed message communication (lazy-created via getOrCreateChannel).
    var channel: Channel?

    /// Remote peer's identity (after LINKIDENTIFY received)
    public private(set) var remoteIdentity: Identity?

    /// Identity callbacks delegate for remote identification notifications.
    /// Strong reference: the Link owns the handler for its lifetime.
    private var identifyCallbacks: (any IdentifyCallbacks)?

    /// Whether the remote peer has identified themselves
    public var isRemoteIdentified: Bool {
        remoteIdentity != nil
    }

    // MARK: - Initialization

    /// Create a new outbound link to a destination.
    ///
    /// Generates fresh ephemeral keypairs for ECDH key exchange.
    ///
    /// - Parameters:
    ///   - destination: Target destination for the link
    ///   - identity: Local identity for authentication
    ///   - hwMtu: Hardware MTU of the next-hop interface (signals MTU in LINKREQUEST)
    public init(destination: Destination, identity: Identity, hwMtu: Int? = nil) {
        self.destination = destination
        self.localIdentity = identity
        self.initiator = true

        let signaledMtu = hwMtu ?? 500
        linkLogger.info("Init: hwMtu=\(String(describing: hwMtu), privacy: .public), signaling MTU=\(signaledMtu, privacy: .public)")
        let signaling = IncomingLinkRequest.encodeSignaling(
            mtu: UInt32(signaledMtu),
            mode: LinkConstants.MODE_DEFAULT
        )
        self.request = LinkRequest(destination: destination, signaling: signaling)
    }

    /// Create link with known ephemeral keys (for testing).
    ///
    /// - Parameters:
    ///   - destination: Target destination for the link
    ///   - identity: Local identity for authentication
    ///   - ephemeralEncryptionPrivateKey: X25519 private key for ECDH
    ///   - ephemeralSigningPrivateKey: Ed25519 private key for signing
    public init(
        destination: Destination,
        identity: Identity,
        ephemeralEncryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        ephemeralSigningPrivateKey: Curve25519.Signing.PrivateKey
    ) {
        self.destination = destination
        self.localIdentity = identity
        self.initiator = true
        self.request = LinkRequest(
            destination: destination,
            ephemeralEncryptionPrivateKey: ephemeralEncryptionPrivateKey,
            ephemeralSigningPrivateKey: ephemeralSigningPrivateKey
        )
    }

    // MARK: - Responder Initialization

    /// Create a responder link from an incoming LINKREQUEST.
    ///
    /// This initializer is used when receiving a LINKREQUEST from a remote initiator.
    /// Generates fresh ephemeral keypair for ECDH and stores the peer's public keys.
    ///
    /// After creating the link, call `createProofPacket()` to generate the PROOF
    /// to send back to the initiator.
    ///
    /// - Parameters:
    ///   - incomingRequest: Parsed LINKREQUEST data
    ///   - destination: Our local destination that received the request
    ///   - identity: Our identity for signing the PROOF
    public init(
        incomingRequest: IncomingLinkRequest,
        destination: Destination,
        identity: Identity
    ) {
        self.destination = destination
        self.localIdentity = identity
        self.initiator = false
        self.request = nil  // Responder doesn't have an outgoing request

        // Store link ID from incoming request
        self.storedLinkId = incomingRequest.linkId

        // Store peer's public keys
        self.peerEncryptionPublicKey = incomingRequest.peerEncryptionPublicKey
        self.peerSigningPublicKey = incomingRequest.peerSigningPublicKey
        self.peerEncryptionPublicKeyBytes = incomingRequest.peerEncryptionPublicKeyBytes

        // Generate our ephemeral keypair for ECDH
        self.responderEphemeralEncryptionPrivateKey = Curve25519.KeyAgreement.PrivateKey()

        // Store negotiated MTU from incoming request and compute MDU
        self.mtu = Int(incomingRequest.mtu)
        self.mdu = ((self.mtu - 1 - 19 - 48) / 16) * 16 - 1

        // Start in handshake state (awaiting LRRTT to complete)
        self.state = .handshake
    }

    /// Set the link established callback (for responder links).
    ///
    /// This callback is invoked when the link establishment completes
    /// (after receiving and processing the LRRTT packet).
    ///
    /// - Parameter callback: Async callback to invoke when link is established
    public func setLinkEstablishedCallback(_ callback: @escaping (Link) async -> Void) {
        self.linkEstablishedCallback = callback
    }

    /// Create the PROOF packet to send to the initiator.
    ///
    /// This creates a signed PROOF proving we control the destination,
    /// containing our ephemeral public key for ECDH key exchange.
    ///
    /// - Returns: PROOF packet data (99 bytes)
    /// - Throws: `LinkError.invalidProof` if identity lacks private keys
    public func createProofPacket() throws -> Packet {
        guard !initiator else {
            throw LinkError.invalidState(expected: "responder", actual: "initiator")
        }

        guard let ephemeralKey = responderEphemeralEncryptionPrivateKey else {
            throw LinkError.keyDerivationFailed
        }

        // Create PROOF data — echo the negotiated MTU back to initiator
        let signaling = IncomingLinkRequest.encodeSignaling(
            mtu: UInt32(self.mtu),
            mode: LinkConstants.MODE_DEFAULT
        )
        let proofData = try LinkProof.create(
            linkId: linkId,
            ephemeralEncryptionPublicKey: ephemeralKey.publicKey,
            destinationIdentity: localIdentity,
            signaling: signaling
        )

        // Build PROOF packet
        let header = PacketHeader(
            headerType: .header1,
            hasContext: true,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .proof,
            hopCount: 0
        )

        return Packet(
            header: header,
            destination: linkId,
            context: LinkConstants.CONTEXT_LRPROOF,
            data: proofData
        )
    }

    /// Process received LRRTT packet (for responder).
    ///
    /// When the responder receives the LRRTT packet from the initiator,
    /// it extracts the RTT value and completes the link establishment.
    /// This triggers the link_established callback.
    ///
    /// - Parameter data: Decrypted LRRTT packet data (msgpack-encoded RTT)
    /// - Throws: `LinkError.invalidState` if not in handshake state
    public func processLRRTT(_ data: Data) async throws {
        guard !initiator else {
            throw LinkError.invalidState(expected: "responder", actual: "initiator")
        }

        guard state == .handshake else {
            throw LinkError.invalidState(expected: "handshake", actual: "\(state)")
        }

        // Derive shared key before processing LRRTT
        // (Need to decrypt the packet first in transport, then pass here)
        if token == nil {
            try deriveSharedKey()
        }

        // Parse RTT from msgpack (optional, mainly for stats)
        if let value = try? unpackMsgPack(data), case .double(let rttValue) = value {
            self.rtt = rttValue
            updateKeepalive(forRTT: rttValue)
        }

        // Transition to active
        lastInbound = Date()
        transitionState(to: .active)

        // Start keep-alive and watchdog
        startKeepalive()
        startWatchdog()

        // Trigger link established callback
        if let callback = linkEstablishedCallback {
            await callback(self)
        }
    }

    /// Complete responder key derivation (call before processLRRTT).
    ///
    /// Derives the shared encryption key using ECDH between our ephemeral
    /// private key and the peer's ephemeral public key from the LINKREQUEST.
    ///
    /// - Throws: `LinkError.keyDerivationFailed` on crypto failure
    public func deriveResponderKeys() throws {
        guard !initiator else {
            throw LinkError.invalidState(expected: "responder", actual: "initiator")
        }

        try deriveSharedKey()
    }

    // MARK: - State Observation

    /// AsyncStream for observing link state changes.
    ///
    /// Yields the current state immediately upon subscription, then yields
    /// each subsequent state change. The stream finishes when the link closes.
    ///
    /// - Returns: AsyncStream that yields LinkState values
    public var stateUpdates: AsyncStream<LinkState> {
        AsyncStream { continuation in
            self.stateContinuation = continuation
            continuation.yield(self.state)

            continuation.onTermination = { @Sendable _ in
                // Cleanup if needed
            }
        }
    }

    /// Transition to a new state.
    ///
    /// State transitions are validated to ensure they follow the expected
    /// lifecycle: pending -> handshake -> active -> stale -> closed.
    /// The closed state is terminal; no transitions out of it are allowed.
    ///
    /// - Parameter newState: Target state
    private func transitionState(to newState: LinkState) {
        guard state != newState else { return }

        // Validate transition (pending -> handshake -> active -> stale -> closed)
        // Note: closed is terminal, no transitions out of it
        guard !state.isTerminal else {
            let linkIdHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
            linkLogger.debug("Link \(linkIdHex, privacy: .public) ignoring transition \(String(describing: self.state), privacy: .public) -> \(String(describing: newState), privacy: .public) (terminal state)")
            return
        }

        let linkIdHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        linkLogger.info("Link \(linkIdHex, privacy: .public) transitioning: \(String(describing: self.state), privacy: .public) -> \(String(describing: newState), privacy: .public)")
        state = newState
        // RNS records activated_at exactly once at establishment (validate_proof
        // Link.py:430 / rtt_packet Link.py:542); a later STALE->ACTIVE recovery
        // must NOT reset it (no_inbound_for baselines off it, Link.py:661).
        if newState == .active && activatedAt == nil {
            activatedAt = Date()
        }
        stateContinuation?.yield(newState)
    }

    // MARK: - Handshake

    /// Get the LINKREQUEST packet to send.
    ///
    /// Creates a packet ready for transmission over the transport layer.
    /// This should only be called once when the link is in pending state.
    /// Only valid for initiator links.
    ///
    /// - Returns: Packet ready for transport
    /// - Throws: `LinkError.alreadyEstablished` if link is not pending
    /// - Throws: `LinkError.notActive` if called on a responder link
    public func getLinkRequestPacket() throws -> Packet {
        guard state == .pending else {
            throw LinkError.alreadyEstablished
        }

        guard let req = request else {
            throw LinkError.notActive  // Responder links don't have a request to send
        }

        return req.packet()
    }

    /// Mark LINKREQUEST as sent, start handshake.
    ///
    /// Records the send timestamp for RTT measurement and transitions
    /// the link state to handshake.
    public func markRequestSent() {
        guard state == .pending else { return }

        requestSentAt = Date()
        transitionState(to: .handshake)
    }

    /// Process received PROOF packet.
    ///
    /// Validates the PROOF signature, extracts the peer's ephemeral key,
    /// measures RTT, derives the shared encryption key, sends LRRTT packet,
    /// and transitions to active state.
    ///
    /// The LRRTT (Link Request RTT) packet is essential for link establishment:
    /// it triggers the responder's link_established callback, completing the
    /// handshake from the responder's perspective.
    ///
    /// - Parameter proofData: Raw PROOF packet data (99+ bytes)
    /// - Throws: `LinkError.invalidState` if not in handshake state
    /// - Throws: `LinkError.invalidProof` if validation fails
    /// - Throws: `LinkError.keyDerivationFailed` if ECDH fails
    public func processProof(_ proofData: Data) async throws {
        let linkIdHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        linkLogger.info("processProof called for link \(linkIdHex, privacy: .public), state=\(String(describing: self.state), privacy: .public)")
        linkLogger.debug("proofData length: \(proofData.count, privacy: .public) bytes")

        guard state == .handshake else {
            linkLogger.error("Not in handshake state, currently \(String(describing: self.state), privacy: .public)")
            throw LinkError.invalidState(expected: "handshake", actual: "\(state)")
        }

        // Parse PROOF
        linkLogger.debug("Parsing PROOF data...")
        let proof = try LinkProof(from: proofData)
        linkLogger.debug("PROOF parsed successfully")

        // Validate signature against destination's identity
        guard let destIdentity = destination.identity else {
            linkLogger.error("Destination has no identity")
            throw LinkError.invalidProof(reason: "Destination has no identity for verification")
        }

        linkLogger.debug("Validating PROOF signature against destination identity...")
        try proof.validate(linkId: linkId, destinationIdentity: destIdentity)
        linkLogger.info("PROOF signature validated")

        // Extract confirmed MTU from PROOF signaling
        let (confirmedMtu, _) = IncomingLinkRequest.decodeSignaling(proof.signaling)
        if confirmedMtu > 0 {
            self.mtu = Int(confirmedMtu)
            updateMdu()
            linkLogger.info("MTU negotiated: \(self.mtu, privacy: .public), MDU=\(self.mdu, privacy: .public)")
        }

        // Store peer's ephemeral key
        peerEncryptionPublicKey = proof.peerEncryptionPublicKey
        let peerKeyHex = proof.peerEncryptionPublicKey.rawRepresentation.prefix(8).map { String(format: "%02x", $0) }.joined()
        linkLogger.debug("Peer encryption key stored: \(peerKeyHex, privacy: .public)...")

        // Measure RTT
        if let sentAt = requestSentAt {
            rtt = Date().timeIntervalSince(sentAt)
            updateKeepalive(forRTT: rtt)
            linkLogger.info("RTT measured: \(String(format: "%.3f", self.rtt), privacy: .public)s")
        }

        // Derive shared key
        linkLogger.debug("Deriving shared key...")
        try deriveSharedKey()
        linkLogger.info("Shared key derived successfully")

        // Transition to active
        lastInbound = Date()
        lastProof = Date() // L10: Track proof receipt for stale detection
        linkLogger.debug("Transitioning to active state...")
        transitionState(to: .active)

        // Send LRRTT packet to complete handshake from responder's perspective
        // This triggers the responder's link_established callback
        linkLogger.debug("Sending LRRTT packet...")
        try await sendLRRTT()
        linkLogger.debug("LRRTT sent")

        // Start keep-alive and watchdog
        startKeepalive()
        startWatchdog()
        linkLogger.info("Link \(linkIdHex, privacy: .public) fully established")
    }

    /// Send LRRTT (Link Request RTT) packet to responder.
    ///
    /// The LRRTT packet contains the msgpack-encoded RTT measurement.
    /// When the responder receives and decrypts this packet, it triggers
    /// their link_established callback, completing the handshake.
    ///
    /// - Throws: `LinkError.notActive` if no send callback is set
    /// - Throws: `LinkError.encryptionFailed` if encryption fails
    private func sendLRRTT() async throws {
        let linkIdHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        linkLogger.debug("sendLRRTT called for link \(linkIdHex, privacy: .public), sendCallback set: \(self.sendCallback != nil, privacy: .public)")

        // Encode RTT as msgpack double
        let rttData = packMsgPack(.double(rtt))
        linkLogger.debug("LRRTT rttData=\(rttData.count, privacy: .public) bytes, rtt=\(self.rtt, privacy: .public)")

        // Encrypt the RTT data
        let encrypted = try encrypt(rttData)
        linkLogger.debug("LRRTT encrypted=\(encrypted.count, privacy: .public) bytes")

        // Build LRRTT packet
        // Header: HEADER_1, hasContext, BROADCAST, LINK destination, DATA type
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
            context: LinkConstants.CONTEXT_LRRTT,
            data: encrypted
        )

        let packetBytes = packet.encode()
        linkLogger.debug("LRRTT packet=\(packetBytes.count, privacy: .public) bytes, context=0x\(String(format: "%02x", LinkConstants.CONTEXT_LRRTT), privacy: .public)")

        // Send via callback if available, otherwise store for manual send
        if let send = sendCallback {
            linkLogger.debug("Sending LRRTT via callback...")
            try await send(packetBytes)
            linkLogger.debug("LRRTT sent successfully")
        } else {
            // If no callback, caller must handle sending manually
            // Store packet for getLRRTTPacket() to retrieve
            linkLogger.debug("No sendCallback, storing LRRTT for manual retrieval")
            pendingLRRTTPacket = packet
        }
    }

    /// Pending LRRTT packet when no send callback is set.
    private var pendingLRRTTPacket: Packet?

    /// Get the pending LRRTT packet if no send callback was set.
    ///
    /// When no send callback is configured, the LRRTT packet is stored
    /// for manual retrieval and sending by the caller.
    ///
    /// - Returns: The LRRTT packet, or nil if already sent via callback
    public func getLRRTTPacket() -> Packet? {
        let packet = pendingLRRTTPacket
        pendingLRRTTPacket = nil
        return packet
    }

    // MARK: - Key Derivation

    /// Derive shared key from ECDH exchange.
    ///
    /// Performs X25519 ECDH with our ephemeral private key and the peer's
    /// ephemeral public key, then derives a 64-byte key using HKDF with
    /// the link ID as salt.
    ///
    /// For initiators: Uses request.ephemeralEncryptionPrivateKey
    /// For responders: Uses responderEphemeralEncryptionPrivateKey
    ///
    /// - Throws: `LinkError.keyDerivationFailed` on crypto failure
    private func deriveSharedKey() throws {
        guard let peerPublicKey = peerEncryptionPublicKey else {
            throw LinkError.keyDerivationFailed
        }

        // Get our ephemeral private key (different for initiator vs responder)
        let ourPrivateKey: Curve25519.KeyAgreement.PrivateKey
        if let req = request {
            // Initiator: use request's ephemeral key
            ourPrivateKey = req.ephemeralEncryptionPrivateKey
        } else if let responderKey = responderEphemeralEncryptionPrivateKey {
            // Responder: use responder's ephemeral key
            ourPrivateKey = responderKey
        } else {
            throw LinkError.keyDerivationFailed
        }

        do {
            // Perform ECDH
            let sharedSecret = try ourPrivateKey.sharedSecretFromKeyAgreement(
                with: peerPublicKey
            )

            // Convert SharedSecret to Data for HKDF
            let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }

            // Derive 64-byte key using HKDF
            // Salt: linkId, Context: nil (RNS standard)
            derivedKey = KeyDerivation.deriveKey(
                length: 64,
                inputKeyMaterial: sharedSecretData,
                salt: linkId,
                context: nil
            )

            guard let key = derivedKey else {
                throw LinkError.keyDerivationFailed
            }

            // Create Token for encryption
            token = try Token(derivedKey: key)

        } catch let error as LinkError {
            throw error
        } catch {
            throw LinkError.keyDerivationFailed
        }
    }

    // MARK: - Encryption

    /// Encrypt data for sending over link.
    ///
    /// Uses the Token created after ECDH key exchange to encrypt data
    /// with AES-256-CBC and HMAC-SHA256 authentication.
    ///
    /// - Parameter plaintext: Data to encrypt
    /// - Returns: Encrypted data in Token format
    /// - Throws: `LinkError.notActive` if link not established
    /// - Throws: `LinkError.encryptionNotReady` if Token not created
    /// - Throws: `LinkError.encryptionFailed` if encryption fails
    public func encrypt(_ plaintext: Data) throws -> Data {
        guard state.isEstablished else {
            throw LinkError.notActive
        }

        guard let token = token else {
            throw LinkError.encryptionNotReady
        }

        do {
            let now = Date()
            lastOutbound = now
            // RNS had_outbound(is_keepalive=False) bumps last_data on outbound
            // payload (Link.py:691). Keepalives are never encrypted (raw bytes),
            // so every encrypt() is payload and advances lastDataAt.
            lastDataAt = now
            return try token.encrypt(plaintext)
        } catch {
            throw LinkError.encryptionFailed(reason: error.localizedDescription)
        }
    }

    /// Decrypt data received over link.
    ///
    /// Uses the Token created after ECDH key exchange to verify and decrypt
    /// data received from the peer.
    ///
    /// Note: No state check — the responder must decrypt LRRTT while still
    /// in `.handshake` state (before processLRRTT transitions to `.active`).
    /// Python's Link.decrypt() has no state guard either. The token guard
    /// is sufficient: if keys have been derived, decryption should work.
    ///
    /// - Parameter ciphertext: Encrypted data in Token format
    /// - Returns: Decrypted plaintext
    /// - Throws: `LinkError.encryptionNotReady` if Token not created
    /// - Throws: `LinkError.decryptionFailed` if decryption fails
    public func decrypt(_ ciphertext: Data) throws -> Data {
        guard let token = token else {
            throw LinkError.encryptionNotReady
        }

        do {
            let plaintext = try token.decrypt(ciphertext)
            let now = Date()
            lastInbound = now
            // RNS receive() bumps last_data alongside last_inbound for every
            // non-KEEPALIVE inbound packet (Link.py:979-980). Keepalives are raw
            // bytes routed through processKeepalive() (never decrypt()), so an
            // inbound decrypt is always payload and advances lastDataAt.
            lastDataAt = now
            return plaintext
        } catch {
            throw LinkError.decryptionFailed(reason: error.localizedDescription)
        }
    }

    // MARK: - Send Callback

    /// Set the callback for sending packets over the link.
    ///
    /// This callback is used by the keep-alive mechanism to send encrypted
    /// keep-alive packets over the transport layer.
    ///
    /// - Parameter callback: Async closure that sends data
    public func setSendCallback(_ callback: @escaping (Data) async throws -> Void) {
        self.sendCallback = callback
    }

    /// Set the interface this link is attached to (H2).
    /// Called by transport when link is established (request or proof).
    public func setAttachedInterface(_ id: String) {
        attachedInterfaceId = id
    }

    #if DEBUG
    /// Test-only helper that forces the link's state without running the
    /// full LRRTT handshake. Skips the `transitionState` validity guard
    /// so unit tests can stand a link up directly in `.active` and
    /// exercise APIs (like `provePacket`) that gate on
    /// `state.isEstablished`. Not for production use — wrapping this in
    /// `#if DEBUG` keeps it out of release builds entirely.
    func _setStateForTesting(_ newState: LinkState) {
        state = newState
    }
    #endif

    // MARK: - Keep-Alive

    /// Recompute the keepalive cadence and stale window from a measured RTT.
    /// Mirrors RNS `__update_keepalive` (Link.py:844-846): keepalive is derived
    /// from RTT, then stale_time = keepalive * STALE_FACTOR. The two always move
    /// together unless `setWatchdog` later overrides them.
    private func updateKeepalive(forRTT rtt: TimeInterval) {
        keepaliveInterval = LinkConstants.keepaliveInterval(forRTT: rtt)
        staleTime = keepaliveInterval * Link.staleFactor
    }

    /// Override the watchdog timing windows at runtime.
    ///
    /// RNS exposes `link.keepalive` and `link.stale_time` as plain settable
    /// attributes (Link.py:262-263) that the watchdog reads directly
    /// (Link.py:792-808). Swift's actor encapsulation requires an explicit
    /// setter for the same operation (category (a) language/runtime). Lets the
    /// keepalive cadence and stale window be compressed (or extended) after
    /// establishment without re-measuring RTT — e.g. to force a STALE/timeout
    /// quickly, or to hold a link ACTIVE through a long silence.
    ///
    /// - Parameters:
    ///   - keepalive: New keepalive interval in seconds.
    ///   - staleTime: New stale window in seconds (inbound silence after which
    ///     the link is treated as STALE).
    public func setWatchdog(keepalive: TimeInterval, staleTime: TimeInterval) {
        self.keepaliveInterval = keepalive
        self.staleTime = staleTime
    }

    /// Time in milliseconds since the last inbound packet (keepalives included).
    /// Mirrors RNS `no_inbound_for()` (Link.py:657-663):
    /// `now - max(last_inbound, activated_at)`. Returns nil when the link has no
    /// inbound reference yet (never received and never activated), so the bridge
    /// can report a null rather than a spuriously huge idle time.
    public func noInboundForMs() -> Int? {
        let refs = [lastInbound, activatedAt].compactMap { $0 }
        guard let ref = refs.max() else { return nil }
        return Int(Date().timeIntervalSince(ref) * 1000.0)
    }

    /// Start the keep-alive task.
    ///
    /// Called after link becomes active. Periodically sends encrypted
    /// keep-alive packets to maintain link liveness.
    private func startKeepalive() {
        keepaliveTask?.cancel()
        // H1: Only initiator sends periodic keepalives. Responder echoes on receipt.
        guard initiator else { return }
        let linkHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        linkLogger.info("Starting keepalive for \(linkHex, privacy: .public), interval=\(self.keepaliveInterval, privacy: .public)s, initiator=\(self.initiator, privacy: .public)")

        keepaliveTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self = self else { break }

                // Sleep for keepalive interval
                let interval = await self.keepaliveInterval
                try? await Task.sleep(for: .seconds(interval))

                // Check if still active
                guard !Task.isCancelled else { break }
                let currentState = await self.state
                guard currentState.isEstablished else { break }

                // Send keep-alive
                await self.sendKeepalive()
            }
        }
    }

    /// Send a keep-alive packet.
    ///
    /// Sends a single-byte keep-alive marker (0xFF for initiator,
    /// 0xFE for responder) to the peer. NOT encrypted, matching Python RNS.
    /// Python Packet.pack() treats KEEPALIVE context as passthrough (no encryption).
    private var keepaliveSendCount: Int = 0
    private func sendKeepalive() async {
        guard state.isEstablished else { return }
        guard let send = sendCallback else {
            linkLogger.warning("No sendCallback, can't send keepalive")
            return
        }

        // Keep-alive content: 0xFF for initiator, 0xFE for responder
        // NOT encrypted - Python RNS sends keepalive as raw bytes
        let keepaliveData = Data([initiator ? LinkConstants.KEEPALIVE_INITIATOR : LinkConstants.KEEPALIVE_RESPONDER])

        do {
            // Build keep-alive packet (data is NOT encrypted per Python RNS)
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
                context: LinkConstants.CONTEXT_KEEPALIVE,
                data: keepaliveData
            )

            let encoded = packet.encode()
            try await send(encoded)
            keepaliveSendCount += 1
            // RNS had_outbound(is_keepalive=True): bump last_outbound +
            // last_keepalive but NOT last_data (Link.py:851 → :690-692). Record
            // the emitted byte for the wire_last_keepalive read-back (Link.py:849).
            let now = Date()
            lastOutbound = now
            lastKeepaliveAt = now
            lastKeepaliveByte = keepaliveData[keepaliveData.startIndex]
            let linkHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
            linkLogger.debug("Keepalive sent #\(self.keepaliveSendCount, privacy: .public) for \(linkHex, privacy: .public), byte=0x\(String(format: "%02x", keepaliveData[0]), privacy: .public), pktLen=\(encoded.count, privacy: .public)")
        } catch {
            let linkHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
            linkLogger.error("Keepalive failed for \(linkHex, privacy: .public): \(error, privacy: .public)")
        }
    }

    /// Process received keep-alive packet.
    ///
    /// Updates the last inbound timestamp and recovers from stale state
    /// if a valid keep-alive response is received.
    ///
    /// - Parameter data: Decrypted keep-alive content (1 byte)
    public func processKeepalive(_ data: Data) {
        guard data.count == 1 else { return }

        let byte = data[data.startIndex]

        // Initiator receives 0xFE (responder acknowledgment)
        // Responder receives 0xFF (initiator keep-alive)
        if (initiator && byte == LinkConstants.KEEPALIVE_RESPONDER) ||
           (!initiator && byte == LinkConstants.KEEPALIVE_INITIATOR) {
            lastInbound = Date()

            // If we were stale, recover to active
            if state == .stale {
                transitionState(to: .active)
            }
        }

        // H1: Responder echoes 0xFE when receiving initiator's 0xFF
        // (RNS Link.py:1149-1153). Record the answered byte synchronously so the
        // wire_last_keepalive read-back is race-free even though the echo send is
        // dispatched on a detached Task (sendKeepalive also sets it).
        if !initiator && byte == LinkConstants.KEEPALIVE_INITIATOR {
            lastKeepaliveByte = LinkConstants.KEEPALIVE_RESPONDER
            Task { [weak self] in await self?.sendKeepalive() }
        }
    }

    /// Conformance-probe helper: run `processKeepalive` and report whether THIS
    /// call advanced `lastInbound` / `lastDataAt`, measured atomically within a
    /// single actor execution.
    ///
    /// `processKeepalive` is synchronous and this method takes no suspension point
    /// between the before/after snapshots, so the live keepalive task or a real
    /// inbound 0xFE echo from the peer cannot interleave and perturb the
    /// measurement (the bridge previously compared timestamps captured across
    /// separate `await` hops, which an interleaved inbound keepalive raced). Pure
    /// observation: behaviour of `processKeepalive` itself is unchanged.
    ///
    /// Returns the initiator flag, whether each timestamp advanced, and the link
    /// state before/after (for STALE→ACTIVE recovery observation).
    public func probeKeepalive(_ data: Data)
        -> (initiator: Bool, lastInboundAdvanced: Bool, lastDataAdvanced: Bool,
            stateBefore: LinkState, stateAfter: LinkState) {
        let inboundBefore = lastInbound
        let dataBefore = lastDataAt
        let stateBefore = state
        processKeepalive(data)
        let inboundAfter = lastInbound
        let dataAfter = lastDataAt
        let stateAfter = state
        func advanced(_ b: Date?, _ a: Date?) -> Bool {
            guard let a = a else { return false }
            guard let b = b else { return true }
            return a > b
        }
        return (initiator,
                advanced(inboundBefore, inboundAfter),
                advanced(dataBefore, dataAfter),
                stateBefore, stateAfter)
    }

    /// Stop keep-alive task.
    private func stopKeepalive() {
        keepaliveTask?.cancel()
        keepaliveTask = nil
    }

    // MARK: - Watchdog

    /// Start the watchdog task for stale detection.
    ///
    /// Called after link becomes active. Periodically checks link liveness
    /// and transitions to stale/closed states as needed.
    private func startWatchdog() {
        watchdogTask?.cancel()

        watchdogTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self = self else { break }

                // Sleep for watchdog interval
                try? await Task.sleep(for: .seconds(LinkConstants.WATCHDOG_MAX_SLEEP))

                // Check if still running
                guard !Task.isCancelled else { break }

                await self.checkLiveness()
            }
        }
    }

    /// Check link liveness and transition to stale/closed if needed.
    ///
    /// Called periodically by the watchdog task. Detects stale links based
    /// on elapsed time since last inbound traffic.
    private func checkLiveness() {
        guard state.isEstablished else { return }

        guard let lastIn = lastInbound else {
            // No inbound traffic yet - use request sent time
            guard let sentAt = requestSentAt else { return }

            let elapsed = Date().timeIntervalSince(sentAt)
            let timeout = LinkConstants.ESTABLISHMENT_TIMEOUT_PER_HOP * 5 // Assume 5 hop max

            if elapsed > timeout {
                close(reason: .timeout)
            }
            return
        }

        // L10: Consider lastProof as activity alongside lastInbound. RNS also
        // folds activated_at into the baseline (Link.py:789).
        let lastActivity = [lastInbound, lastProof, activatedAt].compactMap { $0 }.max() ?? lastIn
        let elapsed = Date().timeIntervalSince(lastActivity)
        // RNS watchdog reads self.stale_time directly (Link.py:796), which is
        // settable via setWatchdog. Default == keepaliveInterval * STALE_FACTOR,
        // so an un-driven link behaves exactly as the former inline `* 2.0`.
        let staleWindow = self.staleTime

        if state == .active && elapsed > staleWindow {
            // Transition to stale
            transitionState(to: .stale)
        } else if state == .stale && elapsed > (staleWindow + rtt * LinkConstants.KEEPALIVE_TIMEOUT_FACTOR + LinkConstants.STALE_GRACE) {
            // M8: Stale grace includes RTT-proportional timeout (Python: rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE)
            close(reason: .timeout)
        }
    }

    /// Stop watchdog task.
    private func stopWatchdog() {
        watchdogTask?.cancel()
        watchdogTask = nil
    }

    // MARK: - Teardown

    /// Close the link.
    ///
    /// Sends a LINKCLOSE packet to the remote peer (if link was active),
    /// stops keep-alive and watchdog tasks, transitions to closed state,
    /// and finishes the state observation stream.
    /// Once closed, the link cannot be reused.
    ///
    /// - Parameter reason: Reason for closing (defaults to initiatorClosed)
    public func close(reason: TeardownReason = .initiatorClosed) {
        // Locally-initiated close: emit the LINKCLOSE packet (RNS `teardown()` ->
        // `__teardown_packet`, Link.py:692-704). Received closes go through
        // handleClose, which mirrors `teardown_packet` and emits NOTHING.
        finishClose(reason: reason, emitClose: true)
    }

    /// Handle an inbound LINKCLOSE packet from the peer.
    ///
    /// Faithful port of RNS `Link.teardown_packet` (RNS/Link.py:710-722): validate
    /// the decrypted payload carries our link_id, choose the role-correct teardown
    /// reason, run the `link_closed` cleanup, and — crucially — emit NO LINKCLOSE in
    /// reply (only the locally-initiated `teardown()` sends a packet, Link.py:704).
    /// The previous Transport path called `close(reason: .destinationClosed)`, which
    /// both HARDCODED the reason (mislabeling a responder's received close, which is
    /// really INITIATOR_CLOSED) AND re-emitted a redundant echoed LINKCLOSE.
    ///
    /// - Parameter plaintext: The decrypted LINKCLOSE payload (expected == linkId).
    public func handleClose(_ plaintext: Data) async {
        // RNS teardown_packet only acts when plaintext == self.link_id (Link.py:712).
        guard plaintext == linkId else {
            linkLogger.warning("LINKCLOSE payload mismatch, ignoring")
            return
        }
        guard !state.isTerminal else { return }
        // RNS teardown_packet sets the reason from OUR role (Link.py:714-717): an
        // initiator receiving a close means the DESTINATION closed it; a responder
        // receiving a close means the INITIATOR closed it. (This is the INVERSE of
        // the locally-initiated teardown() reason, Link.py:706-707 — which is exactly
        // why handleClose must NOT reuse close()/its reason.)
        let reason: TeardownReason = initiator ? .destinationClosed : .initiatorClosed
        finishClose(reason: reason, emitClose: false)
    }

    /// Shared teardown body for both locally-initiated `close()` and inbound
    /// `handleClose()`. Mirrors RNS `Link.link_closed` (RNS/Link.py:724-733) with an
    /// `emitClose` gate selecting whether a LINKCLOSE packet is sent first: `close()`
    /// (RNS `teardown` -> `__teardown_packet`) passes `true`; `handleClose()` (RNS
    /// `teardown_packet`, which sends nothing) passes `false`. Every other step —
    /// cancel in-flight resources, transition to `.closed`, finish the state stream,
    /// single-fire the close callback, purge the ephemeral key material — is identical
    /// and order-preserving across both paths.
    ///
    /// - Parameters:
    ///   - reason: The teardown reason recorded on the closed state.
    ///   - emitClose: Whether to send a LINKCLOSE packet first (true only for a
    ///     locally-initiated close).
    private func finishClose(reason: TeardownReason, emitClose: Bool) {
        guard !state.isTerminal else { return }

        // Send LINKCLOSE to the remote peer if this is a LOCAL close and the link
        // is in a teardown-emitting state. RNS teardown() sends the packet for any
        // status != PENDING and != CLOSED (RNS/Link.py:704) — i.e. .handshake too,
        // not just .active/.stale — so a responder still in .handshake (awaiting the
        // initiator's RTT packet) still tells the peer DESTINATION_CLOSED instead of
        // letting it fall back to a watchdog TIMEOUT. Python RNS sends
        // encrypted(link_id) with context LINKCLOSE; the link token exists from the
        // handshake on, so token.encrypt works here.
        if emitClose, state.canEmitTeardown, let send = sendCallback, let token = token {
            let linkIdCopy = linkId
            if let encrypted = try? token.encrypt(linkIdCopy) {
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
                    destination: linkIdCopy,
                    context: LinkConstants.CONTEXT_LINKCLOSE,
                    data: encrypted
                )
                let packetBytes = packet.encode()
                Task {
                    try? await send(packetBytes)
                }
            }
        }

        stopKeepalive()
        stopWatchdog()

        // Mirror python Link.link_closed (Link.py:724-726): cancel in-flight resources
        // on close. With the link already closing, cancel()'s non-corrupt FAILED branch
        // fires the resource-conclusion callback (the LXMF handler ignores non-.complete)
        // and drops the resource; no RESOURCE_ICL is sent because the link is no longer
        // ACTIVE (Resource.py:1088-1092 gates the cancel packet on link status == ACTIVE).
        // Include resources still waiting in the outgoing queue (prepared but not
        // yet advertised under the one-at-a-time gate): the link is going away, so
        // they will never be advertised and must be concluded too.
        let inflightResources = Array(inboundResources.values)
            + Array(outboundResources.values)
            + pendingOutgoingQueue
        inboundResources.removeAll()
        outboundResources.removeAll()
        pendingOutgoingQueue.removeAll()
        if !inflightResources.isEmpty {
            Task { [weak self] in
                for resource in inflightResources {
                    try? await resource.transitionState(to: .failed)
                    // Link is going away — abandon any partial inbound chain.
                    await resource.cleanup(abandonChain: true)
                    // Route through the actor's fire-once guard so a handler that
                    // concludes the same resource concurrently can't double-fire the
                    // app callback (this detached Task is the other half of every
                    // finishClose-vs-handler race).
                    await self?.fireResourceConcludedOnce(resource)
                }
            }
        }

        transitionState(to: .closed(reason: reason))
        stateContinuation?.finish()

        // Fire close callback asynchronously so callers of close() aren't blocked
        if let cb = closeCallback {
            closeCallback = nil  // clear to prevent double-fire
            Task { await cb(reason) }
        }

        // Purge ephemeral key material on close — mirror RNS Link.link_closed
        // (Link.py:729-733: prv/pub/pub_bytes/shared_key/derived_key = None). The
        // LINKCLOSE frame above already captured `token` before this point, and a
        // closed link is terminal (encrypt/decrypt guard on state.isEstablished),
        // so dropping these is safe and ensures the session keys don't outlive the
        // link. (peerEncryptionPublicKey ≙ pub, derivedKey ≙ derived_key, token
        // holds the derived AES/HMAC material ≙ shared_key.)
        peerEncryptionPublicKey = nil
        derivedKey = nil
        token = nil
    }

    /// Graceful-shutdown teardown that AWAITS the LINKCLOSE send inline before
    /// returning.
    ///
    /// `close()` (`finishClose(emitClose: true)`) detaches the LINKCLOSE send in a
    /// `Task { try? await send(...) }` (above) so callers aren't blocked. That detached
    /// task will NOT run if the process exits immediately afterwards (e.g. the
    /// conformance bridge hitting stdin EOF), so the peer never receives the close and
    /// can only fall back to a watchdog TIMEOUT instead of DESTINATION_CLOSED. This
    /// variant builds + encrypts the same LINKCLOSE packet (RNS `__teardown_packet`,
    /// Link.py:692-704), `await`s its delivery via the send callback, and ONLY THEN runs
    /// the shared teardown with `emitClose: false` so the packet is sent exactly once.
    /// Use it from synchronous process-exit / interface-shutdown paths (RNS tears active
    /// links down in its exit handler so peers observe DESTINATION_CLOSED).
    ///
    /// - Parameter reason: Optional override for the teardown reason recorded on the
    ///   local closed state. When nil (the default) it is derived from role exactly like
    ///   RNS `teardown()` (Link.py:706-707): initiator ⇒ INITIATOR_CLOSED, responder ⇒
    ///   DESTINATION_CLOSED. The peer computes its OWN reason in `handleClose`; an
    ///   initiator that receives this close records DESTINATION_CLOSED (Link.py:714-717).
    public func closeAndFlush(reason: TeardownReason? = nil) async {
        guard !state.isTerminal else { return }

        // RNS teardown() sets the local reason from role (Link.py:706-707).
        let teardownReason = reason ?? (initiator ? .initiatorClosed : .destinationClosed)

        // Emit + flush the LINKCLOSE inline (same frame finishClose(emitClose:true)
        // would build), awaiting the send so the bytes are handed to the transport
        // before we proceed to teardown/exit.
        if state.canEmitTeardown, let send = sendCallback, let token = token,
           let encrypted = try? token.encrypt(linkId) {
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
                context: LinkConstants.CONTEXT_LINKCLOSE,
                data: encrypted
            )
            try? await send(packet.encode())
        }

        // Run the shared teardown WITHOUT re-emitting — we already flushed above.
        finishClose(reason: teardownReason, emitClose: false)
    }

    // MARK: - Diagnostic / test instrumentation

    /// Override the link's measured round-trip time. In RNS `link.rtt` is a
    /// plain settable attribute (Link.py); tests and diagnostics assign it
    /// directly (e.g. to drive Channel rate-promotion bands). Swift's actor
    /// encapsulation requires an explicit setter for the same operation —
    /// category (a) language/runtime, no logic change. Does NOT recompute the
    /// keepalive interval (matches RNS, where setting rtt is a raw assignment).
    public func setRtt(_ value: TimeInterval) {
        self.rtt = value
    }

    // MARK: - Physical-layer statistics (RNS Link.py:559-595)

    /// Enable/disable physical-layer statistics tracking for this link
    /// (RNS Link.track_phy_stats, Link.py:559). When disabled, get_rssi/snr/q
    /// return nil even if values were recorded.
    public func setTrackPhyStats(_ track: Bool) {
        trackPhyStatsEnabled = track
    }

    /// Whether physical-layer stats are currently tracked.
    public var isTrackingPhyStats: Bool { trackPhyStatsEnabled }

    /// Record physical-layer statistics for the link — called by an interface
    /// that supports phy-stat reporting when a packet arrives (RNS sets
    /// link.rssi/snr/q directly from the interface). Stored regardless of the
    /// track flag; the getters apply the gate.
    public func updatePhyStats(rssi: Double? = nil, snr: Double? = nil, q: Double? = nil) {
        if let rssi { self.rssi = rssi }
        if let snr { self.snr = snr }
        if let q { self.q = q }
    }

    /// RSSI if phy-stat tracking is enabled, else nil (RNS get_rssi, Link.py:573).
    public func getRssi() -> Double? { trackPhyStatsEnabled ? rssi : nil }
    /// SNR if phy-stat tracking is enabled, else nil (RNS get_snr, Link.py:582).
    public func getSnr() -> Double? { trackPhyStatsEnabled ? snr : nil }
    /// Link quality if phy-stat tracking is enabled, else nil (RNS get_q, Link.py:591).
    public func getQ() -> Double? { trackPhyStatsEnabled ? q : nil }

    // MARK: - Resource Management

    /// Set the resource acceptance strategy.
    ///
    /// - Parameter strategy: ResourceStrategy to use
    public func setResourceStrategy(_ strategy: ResourceStrategy) {
        self.resourceStrategy = strategy
    }

    /// Set the resource callbacks for transfer notifications.
    ///
    /// - Parameter callbacks: Callback handler conforming to ResourceCallbacks
    public func setResourceCallbacks(_ callbacks: (any ResourceCallbacks)?) {
        self.resourceCallbacks = callbacks
    }

    // MARK: - Resource Registry & Conclusion Bookkeeping (RNS Link.py:1281-1330)

    /// Window size (in parts) of the most recently concluded INBOUND resource,
    /// or nil if none has concluded yet. Mirrors RNS `Link.get_last_resource_window`
    /// (RNS/Link.py:1314-1315). A freshly-accepted inbound resource inherits this
    /// value to skip slow-start on a link that already carried a transfer.
    public func getLastResourceWindow() -> Int? {
        lastResourceWindow
    }

    /// Number of inbound resources currently being received.
    ///
    /// Read-only observability over RNS's `incoming_resources` list, which RNS
    /// exposes directly (RNS/Link.py:246). Port-deviation: getter rather than a
    /// public mutable list (see port-deviations.md).
    public var incomingResourceCount: Int { inboundResources.count }

    /// Number of outbound resources currently in flight (advertised, not yet
    /// concluded). Observability over RNS's `outgoing_resources` (RNS/Link.py:245).
    public var outgoingResourceCount: Int { outboundResources.count }

    /// Whether the link can begin a new outgoing resource. RNS serves exactly one
    /// outgoing resource at a time. Mirrors `ready_for_new_resource`
    /// (RNS/Link.py:1328-1330): true only when no outbound resource is in flight.
    public func readyForNewResource() -> Bool { outboundResources.isEmpty && !outgoingReservationActive }

    /// Track an outbound resource as in flight. Mirrors RNS
    /// `register_outgoing_resource` (RNS/Link.py:1302-1303). Per RNS
    /// `Resource.__advertise_job` ordering (RNS/Resource.py:527→534) this MUST run
    /// AFTER the advertisement is sent so `readyForNewResource()` reports the link
    /// empty until the first advertisement has gone out.
    public func registerOutgoingResource(_ resource: Resource) async {
        let hash = await resource.hash ?? Data()
        outboundResources[hash] = resource
    }

    /// Stop tracking an outbound resource. Mirrors RNS `cancel_outgoing_resource`
    /// (RNS/Link.py:1320-1322); warns if the resource was not tracked.
    public func cancelOutgoingResource(_ resource: Resource) async {
        let hash = await resource.hash ?? Data()
        if outboundResources.removeValue(forKey: hash) == nil {
            linkLogger.warning("Attempt to cancel a non-existing outgoing resource")
        } else {
            // Cancelling an in-flight outbound resource frees the one-at-a-time
            // outgoing slot, so advance the pending-outgoing queue. Without this a
            // remote-triggered cancel (e.g. an EXHAUSTED sequence error flowing
            // through request() -> cancel()) on a callback-less Link.sendResource
            // transfer stalls the queue permanently: Resource.cancel() removes the
            // resource HERE, before its callback-gated resourceConcluded, so the
            // drain inside resourceConcluded never sees it (outboundResources[hash]
            // is already nil). RNS drains via the __advertise_job poll once
            // ready_for_new_resource() turns true; this port is event-driven
            // (see port-deviations.md).
            await drainOutgoingQueue()
        }
    }

    /// Track an inbound resource being received. Mirrors RNS
    /// `register_incoming_resource` (RNS/Link.py:1305-1306).
    public func registerIncomingResource(_ resource: Resource) async {
        let hash = await resource.hash ?? Data()
        inboundResources[hash] = resource
    }

    /// Whether an inbound resource with the same hash is already being received.
    /// Mirrors RNS `has_incoming_resource` (matches by hash, RNS/Link.py:1308-1312).
    /// Used to drop duplicate re-delivered advertisements.
    public func hasIncomingResource(_ resource: Resource) async -> Bool {
        let hash = await resource.hash ?? Data()
        return inboundResources[hash] != nil
    }

    /// Stop tracking an inbound resource.
    ///
    /// For `corrupt == false` this mirrors RNS `cancel_incoming_resource`
    /// (RNS/Link.py:1324-1326): plain registry removal, warns if absent.
    ///
    /// `corrupt == true` is a port addition that routes the receiver-side CORRUPT
    /// teardown (RNS `Resource.cancel()` CORRUPT branch sending a reject and the
    /// bz2-overflow path tearing the link down, RNS/Resource.py:688-692 /
    /// :1079-1085) through the Link, so a corrupt inbound assembly never has the
    /// Resource actor re-enter the Link mid-cancel: it emits a RESOURCE_RCL reject
    /// for the resource hash and tears the link down. See port-deviations.md.
    public func cancelIncomingResource(_ resource: Resource, corrupt: Bool = false) async {
        let hash = await resource.hash ?? Data()
        if corrupt {
            // RESOURCE_RCL reject for the resource hash, then teardown (mirrors the
            // RNS bz2-bomb overflow branch, RNS/Resource.py:688-692 → cancel()).
            var rcl = Data([ResourcePacketContext.resourceReject])
            rcl.append(hash)
            try? await sendResourcePacket(rcl)
            inboundResources.removeValue(forKey: hash)
            close()
            return
        }
        if inboundResources.removeValue(forKey: hash) == nil {
            linkLogger.warning("Attempt to cancel a non-existing incoming resource")
        }
    }

    /// Link-internal resource-conclusion bookkeeping. Mirrors RNS
    /// `Link.resource_concluded` (RNS/Link.py:1281-1290): for an inbound resource,
    /// record its final window BEFORE removal so the next inbound transfer can
    /// inherit it; for an outbound resource, remove it and advertise the next
    /// queued outbound resource (event-driven drain of the one-at-a-time gate).
    ///
    /// DISTINCT from the app-facing `resourceCallbacks?.resourceConcluded(_:)`
    /// (different receiver — no Swift name collision). Every conclusion site keeps
    /// firing the app callback and additionally calls this for registry / window /
    /// queue upkeep, replacing the bare `removeValue` it used to do inline.
    ///
    /// Port-deviation: RNS also recomputes `expected_rate` here, which has no
    /// consumer in this port — omitted (see port-deviations.md).
    public func resourceConcluded(_ resource: Resource) async {
        let hash = await resource.hash ?? Data()
        if inboundResources[hash] != nil {
            // Capture the receiver's final window BEFORE removal so the next
            // inbound resource inherits it (RNS/Link.py:1284).
            lastResourceWindow = await resource.windowSize
            inboundResources.removeValue(forKey: hash)
        }
        if outboundResources[hash] != nil {
            outboundResources.removeValue(forKey: hash)
            await drainOutgoingQueue()
        }
    }

    /// Fire the APP-facing resource-conclusion callback at most ONCE per resource.
    ///
    /// Several actor paths can conclude the same resource — the inbound handlers, the
    /// outbound segment chain, and `finishClose`'s cancel-on-close — and the
    /// `await resource.hash` suspension between matching a resource and firing its
    /// callback lets two of them interleave, double-firing the app callback (which the
    /// LXMF layer is not required to tolerate). This dedups on the resource hash
    /// (`firedResourceConclusions`): the FIRST caller to insert wins and fires; later
    /// callers no-op. `Set.insert` is synchronous, so even though both callers may pass
    /// the `await resource.hash` above, exactly one observes `inserted == true`.
    /// Preserves RNS's once-per-resource callback (RNS/Resource.py:738/792). See
    /// port-deviations.md.
    private func fireResourceConcludedOnce(_ resource: Resource) async {
        let hash = await resource.hash ?? Data()
        // No stable identity to dedup on — fire best-effort (does not happen for a
        // real resource, whose hash is always set).
        guard !hash.isEmpty else {
            await resourceCallbacks?.resourceConcluded(resource)
            return
        }
        guard firedResourceConclusions.insert(hash).inserted else { return }
        await resourceCallbacks?.resourceConcluded(resource)
    }

    /// Advertise + register the next queued outbound resource, if any, now that
    /// the link is free. Event-driven replacement for RNS
    /// `Resource.__advertise_job`'s `while not link.ready_for_new_resource():
    /// sleep(0.25)` poll (RNS/Resource.py:522-524) — see port-deviations.md.
    private func drainOutgoingQueue() async {
        guard readyForNewResource(), !pendingOutgoingQueue.isEmpty else { return }
        let next = pendingOutgoingQueue.removeFirst()
        // Reserve the one-at-a-time slot SYNCHRONOUSLY before the awaits below:
        // until `next` lands in outboundResources, readyForNewResource() would
        // otherwise read empty and let a concurrent send/drain advertise a second
        // outbound resource. Cleared once registered (gate then held by
        // outboundResources) or before any early-exit re-drain.
        outgoingReservationActive = true
        // A close/cancel mid-drain may already have terminated the queued resource.
        let nextState = await next.state
        guard !nextState.isTerminal else {
            outgoingReservationActive = false
            await drainOutgoingQueue()
            return
        }
        do {
            // Register BEFORE advertising. RNS advertises-then-registers
            // (RNS/Resource.py:527→534), but those are consecutive SYNCHRONOUS
            // statements — no RESOURCE_REQ can interleave between them. Here
            // `sendAdvertisement` and `registerOutgoingResource` each suspend the
            // Link actor (the latter via `await resource.hash`), so advertising
            // first would leave a window where the advertisement is on the wire
            // but the resource is untracked, and a fast peer's RESOURCE_REQ would
            // not find it in `outboundResources`. Register first to preserve RNS's
            // effective atomicity (advertiseNextSegment already does this,
            // :2495-2501; see port-deviations.md).
            await registerOutgoingResource(next)
            // Registered — the gate is now held by outboundResources; release the
            // synchronous reservation.
            outgoingReservationActive = false
            try await next.sendAdvertisement(linkMDU: LinkConstants.LINK_MDU)
        } catch {
            linkLogger.error("Failed to advertise queued resource: \(error, privacy: .public)")
            // Advertise failed after registration: undo it and conclude — but only
            // if WE still own `next`. The link can close during the await above,
            // and finishClose's cancel-on-close snapshots+concludes registered
            // resources (:1295-1311); re-concluding would be a resourceConcluded
            // double-fire. Actor isolation makes removeValue atomic vs finishClose.
            let nextHash = await next.hash ?? Data()
            if outboundResources.removeValue(forKey: nextHash) != nil {
                await next.cleanup()
                await fireResourceConcludedOnce(next)
            }
            // Move on to the next queued resource (the link is still free).
            await drainOutgoingQueue()
        }
    }

    /// Send a plaintext payload over the link as a single DATA packet.
    ///
    /// Mirrors Python `Link.send(...)`: encrypts the plaintext with the
    /// link's session key, wraps it in a CONTEXT_NONE DATA packet addressed
    /// to `linkId`, and dispatches via `sendCallback`. Used by the
    /// conformance bridge's `wire_link_send` to deliver small single-packet
    /// payloads; for larger arbitrary-size data use `sendResource` instead.
    ///
    /// - Parameter plaintext: Unencrypted payload bytes
    /// - Throws: LinkError if the link is not active or encryption fails
    public func send(_ plaintext: Data) async throws {
        guard state.isEstablished else { throw LinkError.notActive }
        // sendCallback is wired in `initiateLink` / link-establishment paths
        // before the link transitions to .active, so an active link with no
        // callback indicates an internal wiring bug rather than a state
        // problem. Surface that as `transportNotAvailable` so callers can
        // distinguish "link closed" from "callback never set" without
        // having to read the call site.
        guard let sendCallback else { throw LinkError.transportNotAvailable }
        let ciphertext = try encrypt(plaintext)

        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .data,
            hopCount: 0
        )
        let packet = Packet(
            header: header,
            destination: linkId,
            context: 0x00,
            data: ciphertext
        )
        try await sendCallback(packet.encode())
    }

    /// Prove a received packet over the link. Mirrors Python's
    /// `RNS.Link.prove_packet`: signs the packet's full hash with the
    /// destination identity's signing key (the responder reuses
    /// `owner.identity.sig_prv`) and emits an unencrypted PROOF packet
    /// addressed to the link itself, with explicit-format proof data
    /// (32-byte hash + 64-byte signature).
    ///
    /// The python sender's outbound `PacketReceipt.validate_link_proof`
    /// requires explicit format AND verifies the signature with the
    /// peer's signing public key — which, for an outbound link, is the
    /// remote destination identity's key. Sending an implicit (signature
    /// only) proof or signing with a non-identity key would silently
    /// fail validation on python and the message would never reach
    /// `delivered`.
    ///
    /// - Parameter packet: the inbound packet that should be proven
    public func provePacket(_ packet: Packet) async throws {
        // Initiators must not call provePacket. The signature is
        // produced with `localIdentity`, but the Python sender on
        // an initiator-attached link verifies with
        // `link.destination.identity.verify(...)` — i.e., the
        // *responder's* identity public key. An initiator-side
        // proof would sign with the wrong key and silently fail
        // verification on the peer (no thrown error, no callback
        // fired). LXMF DIRECT only ever needs the responder to
        // prove packets, so reject this misuse loudly here rather
        // than letting it become a confusing "messages send but
        // never deliver" failure mode.
        guard !initiator else {
            throw LinkError.invalidState(expected: "responder", actual: "initiator")
        }
        guard state.isEstablished else { throw LinkError.notActive }
        guard let sendCallback else { throw LinkError.transportNotAvailable }

        let packetHash = packet.getFullHash()
        let signature = try localIdentity.sign(packetHash)
        var proofData = Data()
        proofData.append(packetHash)
        proofData.append(signature)

        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .proof,
            hopCount: 0
        )
        let proofPacket = Packet(
            header: header,
            destination: linkId,
            context: 0x00,
            data: proofData
        )
        try await sendCallback(proofPacket.encode())
    }

    /// Send a resource over the link.
    ///
    /// Creates a new outbound resource, prepares it, sends the advertisement,
    /// and manages the transfer. The resource is tracked until completion.
    ///
    /// - Parameters:
    ///   - data: Data to transfer as a resource
    ///   - requestId: Optional request ID (16 bytes) for response tracking
    ///   - isResponse: Whether this is a response resource
    /// - Returns: The created Resource actor
    /// - Throws: LinkError if link is not active
    ///   - autoCompress: Whether to bz2-compress the payload before transfer.
    ///     Defaults to `false` to preserve LXMF/Columba wire behaviour (BZ2 is
    ///     disabled for interop, see the note below); only opt in when the peer
    ///     is known to decode our BZ2 output. Mirrors RNS `auto_compress`
    ///     (RNS/Resource.py:366-372).
    public func sendResource(data: Data, requestId: Data? = nil, isResponse: Bool = false, autoCompress: Bool = false, metadata: Data? = nil) async throws -> Resource {
        guard state.isEstablished else {
            throw LinkError.notActive
        }

        linkLogger.info("Starting resource transfer: \(data.count, privacy: .public) bytes")

        // Create outbound resource. `metadata` (RNS/Resource.py:260-268) is packed
        // into the segment-1 'x' field and advertised via flag bit 5; default nil
        // leaves every existing call site (and its byte layout) unchanged.
        let resource = Resource(
            data: data,
            link: self,
            metadata: metadata,
            requestId: requestId,
            isResponse: isResponse,
            autoCompress: autoCompress
        )

        // Set send callback that creates proper link DATA packets
        await resource.setSendCallback { [weak self] packetData in
            guard let self = self else {
                throw LinkError.notActive
            }
            try await self.sendResourcePacket(packetData)
        }

        // Prepare the resource (compress, encrypt, hash, split into parts)
        // Capture the token directly (not the Link actor) for Sendable closure
        guard let encryptToken = self.token else {
            throw LinkError.encryptionNotReady
        }
        // BZ2 compression disabled: our BZ2 output may not decompress correctly on
        // the Python receiver. Disable until interop is verified with E2E tests.
        //
        // partSize is the RESOURCE SDU, NOT the link MDU. RNS sizes resource
        // parts at `self.sdu = link.mtu - Reticulum.HEADER_MAXSIZE - IFAC_MIN_SIZE`
        // (RNS/Resource.py:338), and the receiver re-derives
        // `total_parts = ceil(size / sdu)` from its OWN sdu (RNS/Resource.py:187),
        // IGNORING the advertised part count. The sender splits at the same sdu
        // (RNS/Resource.py:432 hashmap_entries=ceil(size/sdu), :454 data slice
        // `self.data[i*self.sdu:(i+1)*self.sdu]`).
        //
        // This is DELIBERATELY larger than the link MDU (431 @ MTU 500): resource
        // data parts (context 0x01) are sent UNENCRYPTED at the link layer — the
        // Resource pre-encrypts the whole stream once — so they ride the larger
        // Reticulum-level MDU, not the smaller link-encrypted MDU. Splitting at
        // self.mdu (431) instead of the sdu (464) makes the swift sender's part
        // count diverge from a python receiver's ceil(size/464) allocation; the
        // python receiver's fixed-size hashmap then IndexErrors in hashmap_update
        // for the extra parts ("Could not decode... dropping resource") and the
        // transfer never completes. (swift<->swift only "worked" because both ends
        // agreed on the wrong 431.)
        //
        // HEADER_MAXSIZE = 2 + 1 + (TRUNCATED_HASHLENGTH//8)*2 = 2+1+16*2 = 35
        // (RNS/Reticulum.py:147); IFAC_MIN_SIZE = 1 (RNS/Reticulum.py:148).
        // `self.mtu` is updated by MTU discovery in processProof, so by the time
        // sendResource runs it reflects whatever MTU the peers negotiated.
        // Clamp to >= 1: a pathological MTU below 37 would make partSize <= 0 and
        // trap `resource.prepare`'s parts-count division. No real Reticulum transport
        // negotiates an MTU that small, so for every realistic MTU this is a no-op.
        let partSize = max(1, self.mtu - 35 - TransportConstants.IFAC_MIN_SIZE)
        try await resource.prepare(partSize: partSize, linkEncrypt: { plaintext in
            return try encryptToken.encrypt(plaintext)
        }, autoCompress: autoCompress)
        let numParts = await resource.numParts
        let transferSize = await resource.transferSize
        linkLogger.info("Resource prepared: \(numParts, privacy: .public) parts, partSize=\(partSize, privacy: .public), transferSize=\(transferSize, privacy: .public), compressed=false")

        // Hash is available after prepare.
        let hash = await resource.hash ?? Data()
        let hashHex = hash.prefix(8).map { String(format: "%02x", $0) }.joined()

        // One-outgoing-resource-at-a-time gate (RNS `Resource.__advertise_job`
        // polls `link.ready_for_new_resource()` and stays QUEUED until the link
        // is free, RNS/Resource.py:522-534; RNS/Link.py:1328-1330). Port-deviation:
        // event-driven instead of a 0.25s poll — if the link is free we advertise
        // now, otherwise the resource waits in pendingOutgoingQueue (its prepared,
        // non-advertised state is the swift equivalent of RNS QUEUED) and
        // resourceConcluded drains it on conclusion.
        //
        // Register BEFORE advertising: RNS advertises-then-registers (:527→534) but
        // synchronously (no yield between), so a RESOURCE_REQ can't interleave. Here
        // the two awaits release the Link actor, so advertising first would leave a
        // window where the adv is on the wire but the resource is untracked and a
        // fast peer's RESOURCE_REQ is dropped (see port-deviations.md;
        // advertiseNextSegment/drainOutgoingQueue do the same).
        if readyForNewResource() {
            // Reserve the one-at-a-time slot SYNCHRONOUSLY before the register
            // await: registerOutgoingResource suspends on `await resource.hash`
            // while outboundResources is still empty, so without this a concurrent
            // send/drain would see the link free and advertise a second resource.
            // Cleared once registered (gate then held by outboundResources).
            outgoingReservationActive = true
            await registerOutgoingResource(resource)
            outgoingReservationActive = false
            do {
                try await resource.sendAdvertisement(linkMDU: LinkConstants.LINK_MDU)
            } catch {
                // Advertise failed after registration. If WE still own the resource
                // (finishClose didn't snapshot+cleanup it on a close race), unregister
                // so the one-at-a-time gate isn't left stuck AND unlink the staging
                // tempfile — prepare() may have created one for a multi-segment
                // resource, and without cleanup it leaks (acute under the NE sandbox's
                // limited temp space, compounding across retries). The throw is the
                // caller's conclusion signal, so unlike the fire-and-forget drain
                // paths we do NOT fire resourceConcluded here.
                let h = await resource.hash ?? Data()
                if outboundResources.removeValue(forKey: h) != nil {
                    await resource.cleanup()
                }
                // Advance the pending-outgoing queue before rethrowing: a resource may
                // have queued behind this one while it was (briefly) the in-flight
                // outbound, and this failure is its only release point — without the
                // drain it would stall until link close. (drainOutgoingQueue and
                // advertiseNextSegment drain on their own advertise failures too.)
                // Guarded internally by readyForNewResource(): a close race that already
                // cleared the queue makes this a no-op.
                await drainOutgoingQueue()
                throw error
            }
            linkLogger.info("Advertisement sent for resource \(hashHex, privacy: .public), outboundResources count=\(self.outboundResources.count, privacy: .public)")
        } else {
            pendingOutgoingQueue.append(resource)
            linkLogger.info("Link busy, queued resource \(hashHex, privacy: .public) (\(self.pendingOutgoingQueue.count, privacy: .public) waiting)")
        }

        return resource
    }

    /// Send a resource packet as a proper link DATA packet.
    ///
    /// Resource packets start with a context byte (0x01-0x07) followed by payload.
    /// This method extracts the context, creates a link DATA packet with that context
    /// as the wire context, and sends it through the link's send callback.
    ///
    /// Per Python RNS Packet.pack():
    /// - Context 0x01 (RESOURCE data): NOT link-encrypted (Resource handles own encryption)
    /// - Context 0x02-0x07 (control): Link-encrypted
    ///
    /// - Parameter data: Resource packet data (context byte + payload)
    private func sendResourcePacket(_ data: Data) async throws {
        guard data.count >= 1 else { throw LinkError.notActive }

        let resourceContext = data[data.startIndex]
        let payload = Data(data.dropFirst())

        // Encryption rules per Python Packet.pack():
        // - Resource data parts (0x01): NOT link-encrypted (Resource handles own encryption)
        // - Resource proof (0x05): NOT encrypted (PROOF packets over links are plaintext)
        //   Python: "Packet proofs over links are not encrypted" → ciphertext = data
        // - All other resource packets (0x02-0x04, 0x06-0x07): ARE link-encrypted
        let wirePayload: Data
        if resourceContext == ResourcePacketContext.resource ||
           resourceContext == ResourcePacketContext.resourceProof {
            wirePayload = payload
        } else {
            wirePayload = try encrypt(payload)
        }

        // Resource proof (0x05) uses PROOF packet type per Python
        // Python: RNS.Packet(self.link, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.RESOURCE_PRF)
        // Python's Link.receive() only handles RESOURCE_PRF in the PROOF branch
        let pktType: PacketType = resourceContext == ResourcePacketContext.resourceProof ? .proof : .data

        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            hasIFAC: false,
            transportType: .broadcast,
            destinationType: .link,
            packetType: pktType,
            hopCount: 0
        )

        let packet = Packet(
            header: header,
            destination: linkId,
            transportAddress: nil,
            context: resourceContext,
            data: wirePayload
        )

        guard let send = sendCallback else { throw LinkError.notActive }
        try await send(packet.encode())
        linkLogger.debug("Sent resource packet context=0x\(String(format: "%02x", resourceContext), privacy: .public), payload=\(wirePayload.count, privacy: .public) bytes")
    }

    /// Handle incoming resource packet.
    ///
    /// Routes resource packets to the appropriate handler based on context.
    /// The context comes from the wire packet header, and data is the pure
    /// payload (no context byte prefix).
    ///
    /// - Parameters:
    ///   - context: Resource packet context (0x01-0x07) from wire packet
    ///   - data: Packet payload (no context byte)
    public func handleResourcePacket(context: UInt8, data: Data) async {
        resourceDebugLog("RESOURCE packet: ctx=0x\(String(format: "%02x", context)), data=\(data.count)B")
        linkLogger.debug("Received resource packet: context=0x\(String(format: "%02x", context), privacy: .public), data=\(data.count, privacy: .public) bytes")

        // Inbound packet observation hook (additive; no-op when unset). Surface the
        // RESOURCE_ADV (0x02) advertisement bytes so an instrument can observe the
        // >MDU response-Resource fork (RNS/Link.py:901). Only the advertisement is
        // surfaced (the capture consumer inspects the ADV fork, not the data/control
        // sub-packets). Runs before dispatch and does not alter routing.
        if context == ResourcePacketContext.resourceAdvertisement {
            await inboundPacketObserver?(context, data)
        }

        switch context {
        case ResourcePacketContext.resource:             // 0x01 - RESOURCE data part
            await handleResourceData(data)
        case ResourcePacketContext.resourceAdvertisement: // 0x02 - RESOURCE_ADV
            await handleResourceAdvertisement(data)
        case ResourcePacketContext.resourceRequest:       // 0x03 - RESOURCE_REQ
            await handleResourceRequest(data)
        case ResourcePacketContext.resourceHMU:           // 0x04 - RESOURCE_HMU
            await handleResourceHMU(data)
        case ResourcePacketContext.resourceProof:         // 0x05 - RESOURCE_PRF
            await handleResourceProof(data)
        case ResourcePacketContext.resourceCancel:        // 0x06 - RESOURCE_ICL
            await handleResourceCancel(data)
        case ResourcePacketContext.resourceReject:        // 0x07 - RESOURCE_RCL
            await handleResourceReject(data)
        default:
            linkLogger.warning("Unknown resource context: 0x\(String(format: "%02x", context), privacy: .public)")
            break
        }
    }

    /// Handle resource advertisement packet.
    ///
    /// Called when receiving a resource advertisement from the peer.
    /// Checks strategy and callbacks to decide whether to accept.
    ///
    /// - Parameter data: Advertisement payload (context already stripped by caller)
    private func handleResourceAdvertisement(_ data: Data) async {
        guard data.count > 0 else { return }

        // Data is pure advertisement payload (context already handled by handleResourcePacket).
        do {
            let advertisement = try ResourceAdvertisement.unpack(Data(data))
            let advReqId = advertisement.requestId?.prefix(8).map { String(format: "%02x", $0) }.joined() ?? "nil"
            resourceDebugLog("ADV: size=\(advertisement.dataSize), parts=\(advertisement.numParts), reqId=\(advReqId), segments=\(advertisement.totalSegments)")
            _ = await receiveResourceAdvertisement(advertisement)
        } catch {
            resourceDebugLog("ADV ERROR: Failed to parse: \(error)")
            linkLogger.error("Failed to parse advertisement: \(error, privacy: .public)")
        }
    }

    /// Decide whether to accept an inbound resource advertisement and, if so,
    /// begin receiving it. Typed entry point (the conformance bridge feeds a
    /// pre-unpacked advertisement here).
    ///
    /// Faithful port of the RESOURCE_ADV dispatch in RNS `Link.receive`
    /// (RNS/Link.py:1065-1098). The advertisement's `q`/`u`/`p` fields select the
    /// path:
    ///   - request   (`q != None and u`, RNS/Resource.py:1242-1247): accepted
    ///     UNCONDITIONALLY, ignoring `resourceStrategy` (RNS/Link.py:1070-1071).
    ///   - response  (`q != None and p`, RNS/Resource.py:1251-1257): accepted ONLY
    ///     if it matches a pending request (RNS/Link.py:1072-1085).
    ///   - otherwise: gated by `resourceStrategy` (RNS/Link.py:1087-1098):
    ///     `.acceptNone` → ignore (no reject sent), `.acceptApp` → app callback
    ///     decides (reject sent on decline), `.acceptAll` → accept.
    ///
    /// - Returns: true if the advertisement was accepted (an inbound resource was
    ///   started), false otherwise.
    public func receiveResourceAdvertisement(_ advertisement: ResourceAdvertisement) async -> Bool {
        // Drop a malformed advertisement BEFORE allocating anything: numParts is a
        // peer-controlled msgpack field that feeds Array(repeating:count:) in the
        // Resource init (Resource.swift:519/525). A negative count is an UNCATCHABLE
        // fatalError ("Can't construct Array with count < 0") and a multi-billion count
        // is an allocation trap — a single crafted RESOURCE_ADV could abort the process,
        // even on a resourceStrategy=.acceptNone node (this runs first). A real
        // per-segment part count is far below MAX_EFFICIENT_SIZE (a segment is at most
        // that many BYTES, hence far fewer parts), so reject anything outside
        // [0, MAX_EFFICIENT_SIZE] as nonsensical — mirroring RNS's graceful decode-drop.
        guard advertisement.numParts >= 0,
              advertisement.numParts <= ResourceConstants.MAX_EFFICIENT_SIZE else {
            linkLogger.warning("Dropping resource advertisement: out-of-range numParts=\(advertisement.numParts, privacy: .public)")
            return false
        }

        // Inbound resource scaffold (RNS Resource.accept builds it from the adv).
        let resource = Resource(advertisement: advertisement, link: self)

        let hasReqId = advertisement.requestId != nil
        let isRequest = hasReqId && advertisement.flags.isRequestFlag    // adv.q != None and adv.u
        let isResponse = hasReqId && advertisement.flags.isResponseFlag  // adv.q != None and adv.p

        // Request resources bypass the strategy gate (RNS/Link.py:1070-1071).
        if isRequest {
            await acceptInboundAdvertisement(advertisement, resource: resource)
            return true
        }

        // Response resources are accepted only when they answer a pending request
        // (RNS/Link.py:1072-1085).
        if isResponse {
            if let reqId = advertisement.requestId,
               pendingRequests.contains(where: { $0.requestId == reqId }) {
                resourceDebugLog("ADV: Accepting response resource for pending request \(reqId.prefix(8).map { String(format: "%02x", $0) }.joined())")
                await acceptInboundAdvertisement(advertisement, resource: resource)
                return true
            }
            return false
        }

        // Fallback: advertisements carrying a request_id that matches a pending
        // request but WITHOUT the `p` flag. RNS proper keys response detection on
        // the `p` flag, but this port has historically matched live LXMF/Columba
        // response advertisements by request_id alone — keep accepting them so the
        // live request/response path does not regress (open risk: verify real
        // senders set `p`, see port-deviations.md).
        if let reqId = advertisement.requestId,
           pendingRequests.contains(where: { $0.requestId == reqId }) {
            resourceDebugLog("ADV: Accepting request_id-matched resource (no p flag) for \(reqId.prefix(8).map { String(format: "%02x", $0) }.joined())")
            await acceptInboundAdvertisement(advertisement, resource: resource)
            return true
        }

        // Strategy gate for ordinary resources (RNS/Link.py:1087-1098).
        switch resourceStrategy {
        case .acceptNone:
            // RNS: `pass` — silently ignore, no reject is sent (RNS/Link.py:1087).
            resourceDebugLog("ADV: ignored under acceptNone")
            return false
        case .acceptAll:
            await acceptInboundAdvertisement(advertisement, resource: resource)
            return true
        case .acceptApp:
            let accept = await resourceCallbacks?.resourceAdvertised(resource) ?? false
            if accept {
                await acceptInboundAdvertisement(advertisement, resource: resource)
                return true
            } else {
                // Declined ACCEPT_APP advertisement: send a RESOURCE_RCL reject
                // (RNS/Link.py:1094 → static RNS.Resource.reject(packet),
                // RNS/Resource.py:155-160). The throwaway inbound `resource` built
                // above was never accept()ed, so it has no send callback wired —
                // emit the reject through the Link directly, carrying the advertised
                // resource hash, exactly as RNS's static reject builds the packet
                // straight from the advertisement (rather than resource.reject(),
                // which needs an accepted resource's send callback and would throw).
                resourceDebugLog("ADV: declined by app callback, rejecting (RESOURCE_RCL)")
                var rcl = Data([ResourcePacketContext.resourceReject])
                rcl.append(advertisement.hash)
                try? await sendResourcePacket(rcl)
                return false
            }
        }
    }

    /// Begin receiving an accepted inbound resource: dedup, register, fire the
    /// started callback, wire the send/decrypt callbacks, and accept.
    ///
    /// Mirrors the accept body of RNS `Resource.accept` (RNS/Resource.py:216-235):
    /// inherit the link's last receiver window, dedup via `has_incoming_resource`,
    /// `register_incoming_resource`, fire `resource_started`, then load the initial
    /// hashmap and start the watchdog.
    private func acceptInboundAdvertisement(_ advertisement: ResourceAdvertisement, resource: Resource) async {
        // Drop duplicate re-delivered advertisements (RNS Resource.accept :223-239:
        // `if not link.has_incoming_resource(resource)` ... else ignore).
        if await hasIncomingResource(resource) {
            let h = (await resource.hash ?? Data()).prefix(8).map { String(format: "%02x", $0) }.joined()
            resourceDebugLog("ADV: duplicate, ignoring resource \(h) (already transferring)")
            return
        }

        // Register the inbound resource (RNS Resource.accept :224).
        await registerIncomingResource(resource)

        let hash = await resource.hash ?? Data()
        let hashHex = hash.prefix(8).map { String(format: "%02x", $0) }.joined()
        resourceDebugLog("ACCEPT: resource \(hashHex), size=\(advertisement.dataSize), parts=\(advertisement.numParts)")
        linkLogger.info("Accepted resource \(hashHex, privacy: .public), size=\(advertisement.dataSize, privacy: .public), parts=\(advertisement.numParts, privacy: .public)")

        // resource_started callback (RNS Resource.accept :227-231).
        if let callbacks = resourceCallbacks {
            await callbacks.resourceStarted(resource)
        }

        // Send callback (creates link DATA packets for requests / proof).
        await resource.setSendCallback { [weak self] (packetData: Data) in
            guard let self = self else { throw LinkError.notActive }
            try await self.sendResourcePacket(packetData)
        }

        // Decrypt callback for assembled resource data (capture token directly to
        // avoid actor-isolation issues).
        let linkToken = self.token
        await resource.setDecryptCallback { (ciphertext: Data) in
            guard let token = linkToken else { throw LinkError.encryptionNotReady }
            return try token.decrypt(ciphertext)
        }

        // Starting-window inheritance (RNS Resource.accept :216-219):
        //   previous_window = link.get_last_resource_window()
        //   if previous_window: resource.window = previous_window
        // A second inbound transfer on a link that already carried one skips
        // slow-start by inheriting the prior receiver window. MUST run BEFORE
        // accept() requests the first batch (accept() -> requestNextParts()
        // sizes the request from the window). getLastResourceWindow() returns
        // nil until an inbound resource has concluded (RNS get_last_resource_window,
        // RNS/Link.py:1314-1315), so the first transfer slow-starts as in RNS.
        if let inherited = getLastResourceWindow() {
            await resource.applyInheritedWindow(inherited)
        }

        // NOTE (Plan A integration, still deferred): receiver part-count derivation
        // from this link's own SDU (`deriveReceiverPartCount(self.mdu)`, RNS
        // Resource.accept :187), explicit initial hashmap routing
        // (`hashmapUpdate(0, adv.m)`, RNS :233), and per-instance
        // `maxDecompressedSize` are wired here once Plan A lands. The current
        // `Resource.accept()` already derives the part count from the
        // advertisement and loads the initial hashmap internally, so the existing
        // receive behavior is preserved until then. (Window inheritance above is
        // no longer deferred — applyInheritedWindow / getLastResourceWindow exist.)
        do {
            try await resource.accept()
        } catch {
            resourceDebugLog("ACCEPT ERROR: \(error)")
            linkLogger.error("Resource accept failed: \(error, privacy: .public)")
            await cancelIncomingResource(resource)
        }
    }

    /// Handle resource request packet.
    ///
    /// Called when receiving a part request from the peer for an outbound resource.
    /// Python RESOURCE_REQ format (from Resource.request_next()):
    ///   [1-byte flag] + [32-byte resource hash] + [N×4-byte part hashes]
    /// Where flag: 0x00 = hashmap not exhausted, 0xFF = hashmap exhausted
    /// If exhausted, an additional 4-byte last_map_hash is prepended before the resource hash.
    ///
    /// - Parameter data: Request packet data
    private func handleResourceRequest(_ data: Data) async {
        let resourceHashLen = 32 // RNS.Identity.HASHLENGTH // 8 = 256 // 8 = 32
        let mapHashLen = ResourceConstants.MAPHASH_LEN // 4

        // Minimum: 1 (flag) + 32 (resource hash) = 33 bytes
        guard data.count >= 1 + resourceHashLen else {
            linkLogger.warning("Resource request too short: \(data.count, privacy: .public) bytes")
            return
        }

        // Parse exhaustion flag
        let exhausted = data[data.startIndex] == 0xFF
        let pad = exhausted ? (1 + mapHashLen) : 1

        // Extract resource hash for matching
        guard data.count >= pad + resourceHashLen else {
            linkLogger.warning("Resource request too short for resource hash: \(data.count, privacy: .public) bytes, pad=\(pad, privacy: .public)")
            return
        }
        let resourceHash = Data(data[data.startIndex + pad ..< data.startIndex + pad + resourceHashLen])

        // Extract requested part hashes
        let hashesStart = pad + resourceHashLen
        let requestedHashes = data.count > hashesStart ? Data(data[(data.startIndex + hashesStart)...]) : Data()

        let resHashHex = resourceHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        linkLogger.info("Resource request: resourceHash=\(resHashHex, privacy: .public), exhausted=\(exhausted, privacy: .public), partHashCount=\(requestedHashes.count / mapHashLen, privacy: .public)")

        // Find matching outbound resource by hash
        for (storedHash, resource) in outboundResources {
            guard storedHash == resourceHash else { continue }

            // Transition from advertised to transferring on first request (matches Python)
            let resourceState = await resource.state
            if resourceState == .advertised {
                await resource.transitionToTransferring()
            }

            guard let hashmap = await resource.hashmap else { continue }

            // Send all requested parts
            var offset = 0
            var sentCount = 0
            var missCount = 0
            while offset + mapHashLen <= requestedHashes.count {
                let partHash = Data(requestedHashes[requestedHashes.startIndex + offset ..< requestedHashes.startIndex + offset + mapHashLen])
                if let partIndex = ResourceHashmap.findPartIndex(for: partHash, in: hashmap) {
                    do {
                        try await resource.sendPart(at: partIndex)
                        sentCount += 1
                    } catch {
                        linkLogger.error("Failed to send part \(partIndex, privacy: .public): \(error.localizedDescription, privacy: .public)")
                    }
                } else {
                    missCount += 1
                }
                offset += mapHashLen
            }
            linkLogger.info("Sent \(sentCount, privacy: .public) parts, \(missCount, privacy: .public) hash misses for \(resHashHex, privacy: .public)")

            // Handle hashmap exhaustion (send more hashmap entries)
            // Python RNS computes the HMU segment from last_map_hash rather than
            // using a sequential counter. This handles retransmissions, duplicates,
            // and packet loss correctly.
            if exhausted {
                let lastMapHash = Data(data[data.startIndex + 1 ..< data.startIndex + 1 + mapHashLen])
                let maxLength = ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)

                do {
                    let sent: Bool
                    if let partIndex = ResourceHashmap.findPartIndex(for: lastMapHash, in: hashmap) {
                        // Compute next wire segment from the part that was exhausted
                        let exhaustedSegment = partIndex / maxLength
                        let nextWireSegment = exhaustedSegment + 1
                        linkLogger.info("last_map_hash→part \(partIndex, privacy: .public), exhaustedSeg=\(exhaustedSegment, privacy: .public), nextWireSeg=\(nextWireSegment, privacy: .public)")
                        sent = try await resource.sendHashmapForWireSegment(nextWireSegment, linkMDU: LinkConstants.LINK_MDU)
                    } else {
                        // Fallback to sequential counter if hash lookup fails
                        linkLogger.warning("last_map_hash lookup failed, falling back to sequential")
                        sent = try await resource.sendNextHashmapSegment(linkMDU: LinkConstants.LINK_MDU)
                    }
                    if sent {
                        linkLogger.info("Sent HMU for resource \(resHashHex, privacy: .public)")
                    } else {
                        linkLogger.warning("Hashmap exhausted but no more segments to send")
                    }
                } catch {
                    linkLogger.error("Failed to send HMU: \(error.localizedDescription, privacy: .public)")
                }
            }

            return
        }

        let outboundHashes = outboundResources.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
        linkLogger.error("No matching outbound resource. resHash=\(resHashHex, privacy: .public), have=\(outboundHashes, privacy: .public)")
    }

    /// Handle resource data packet.
    ///
    /// Called when receiving a data part from the peer for an inbound resource.
    /// Parts are identified by content hash SHA256(partData + randomHash)[:4].
    ///
    /// - Parameter data: Part data (no index prefix — identified by content hash)
    private func handleResourceData(_ data: Data) async {
        guard data.count > 0 else { return }

        // Find the inbound resource that's currently transferring
        // (there should typically be only one active at a time per link).
        // Conclusion now flows through resourceConcluded(_:), which re-derives the
        // hash, so the loop no longer needs the dictionary key.
        for (_, resource) in inboundResources {
            let resourceState = await resource.state
            guard resourceState == .transferring else { continue }

            let complete: Bool
            do {
                complete = try await resource.handlePartPacket(data)
            } catch {
                // A bad / duplicate part is not fatal — the window + request machinery
                // re-requests missing parts, so log and let a later packet retry.
                linkLogger.error("Part handling error: \(error, privacy: .public)")
                continue
            }

            let total = await resource.numParts
            let received = await resource.receivedCount
            resourceDebugLog("PART: \(received)/\(total), complete=\(complete), data=\(data.count)B")
            linkLogger.debug("Part received (\(received, privacy: .public)/\(total, privacy: .public)), complete=\(complete, privacy: .public)")

            if complete {
                // All parts received. Assemble; on failure, fail the inbound resource
                // (rather than leak it in .assembling) and tell the sender to stop.
                let assembledData: Data
                do {
                    assembledData = try await resource.assemble()
                } catch {
                    // python Resource.assemble() has TWO distinct CORRUPT exits, and
                    // the swift port surfaces them via `resource.corruptReason`:
                    //
                    //   • .decompressionOverflow — the bz2 stream decompressed past
                    //     max_decompressed_size (RNS/Resource.py:688-692). python sets
                    //     status=CORRUPT and calls cancel(), whose CORRUPT branch sends
                    //     a RESOURCE_RCL reject AND tears the link down, returning early
                    //     WITHOUT running resource_concluded (RNS/Resource.py:1081-1084).
                    //
                    //   • everything else (per-segment hash mismatch / decrypt / size,
                    //     RNS/Resource.py:715/721) — leaves the resource non-COMPLETE and
                    //     falls through to `link.resource_concluded(self)`
                    //     (RNS/Resource.py:723) with NO packet and NO teardown; conclude
                    //     quietly (the LXMF handler ignores a non-.complete resource).
                    if await resource.corruptReason == .decompressionOverflow {
                        // bz2 over-size: reject (RESOURCE_RCL) + teardown via the
                        // CORRUPT-branch helper (RNS/Resource.py:688-692 → cancel()
                        // :1081-1084). The resource stays .corrupt (set by assemble's
                        // markCorrupt); do NOT call resource_concluded — python returns
                        // before :723, so no last-window is recorded for the next
                        // inbound transfer. cleanup() frees the partial storagepath.
                        linkLogger.error("Resource decompression exceeded max size — rejecting (RESOURCE_RCL) and tearing down link (RNS/Resource.py:688-692 → :1081-1084)")
                        await resource.cleanup(abandonChain: true)
                        await cancelIncomingResource(resource, corrupt: true)
                        return
                    }
                    linkLogger.error("Resource assembly failed (corrupt): \(error, privacy: .public) — concluding without delivery")
                    try? await resource.transitionState(to: .failed)
                    // Abandon the whole chain: unlink the partial storagepath
                    // even though this may be a non-final segment.
                    await resource.cleanup(abandonChain: true)
                    // App-facing conclusion callback, then Link-internal bookkeeping
                    // (registry removal + last-window record; RNS resource_concluded,
                    // RNS/Link.py:1281-1290).
                    await fireResourceConcludedOnce(resource)
                    await resourceConcluded(resource)
                    return
                }

                // Segment bookkeeping: python assemble() runs proof for EVERY
                // segment and calls resource_concluded(self) unconditionally
                // (Resource.py:713/723), freeing the inbound slot so the next
                // segment's advertisement can be accepted. Delivery + callback
                // happen ONLY on the final segment (Resource.py:725-747); a
                // non-final segment just logs "waiting for next segment"
                // (Resource.py:748-749).
                let segIndex = await resource.segmentIndex
                let segTotal = await resource.totalSegments
                let isFinalSegment = segIndex >= segTotal

                resourceDebugLog("COMPLETE: segment \(segIndex)/\(segTotal), assembled \(assembledData.count)B, sending proof")
                linkLogger.info("Resource segment \(segIndex, privacy: .public)/\(segTotal, privacy: .public) assembled \(assembledData.count, privacy: .public) bytes, sending proof")
                // Proof is best-effort: the data is fully received, so deliver it even
                // if the proof send fails (the sender re-requests / times out its proof).
                do {
                    try await resource.sendProof()
                } catch {
                    linkLogger.error("Resource proof send failed (delivering anyway): \(error, privacy: .public)")
                }

                if !isFinalSegment {
                    // python Resource.py:748-749: more segments to come. Free the
                    // slot (resource_concluded), but DO NOT deliver, run the
                    // app callback, or unlink the storagepath — the next
                    // segment's fresh Resource appends to the same on-disk file
                    // (keyed by original_hash). Conclude so a fresh advertisement
                    // for the next segment is accepted.
                    await fireResourceConcludedOnce(resource)
                    await resourceConcluded(resource)
                    linkLogger.debug("Segment \(segIndex, privacy: .public)/\(segTotal, privacy: .public) received, awaiting next segment advertisement")
                    return
                }

                // Final segment — deliver the fully assembled resource.
                // If this resource is a response to a pending request,
                // deliver the assembled data as the request response.
                // Python: packed_response = umsgpack.packb([request_id, response])
                // The assembled data IS this msgpack blob.
                if let reqId = resource.requestId {
                    // Fork an inbound REQUEST resource from a RESPONSE resource
                    // (RNS request_resource_concluded vs response_resource_concluded,
                    // Link.py:927-954). A concluded inbound resource is a RESPONSE iff
                    // it carries the response flag (`p`) OR it answers one of our
                    // pending requests; otherwise (request_id set, no pending match) it
                    // is a server-side inbound REQUEST resource and forks to
                    // handleRequest. Forking PRECISELY here keeps a >MDU request out of
                    // the response-delivery branch (where it would be silently dropped),
                    // and is not shadowed by the request_id-match fallback at
                    // receiveResourceAdvertisement (that path only fires when a pending
                    // request matches, i.e. for genuine responses).
                    let isResponseResource = resource.isResponse
                        || pendingRequests.contains(where: { $0.requestId == reqId })

                    if !isResponseResource {
                        // Inbound REQUEST resource (RNS request_resource_concluded,
                        // Link.py:927-937): request_id = truncated_hash(packed_request),
                        // unpacked_request is the [requested_at, path_hash, data] array,
                        // then dispatch to handle_request.
                        let requestId = Hashing.truncatedHash(assembledData)
                        let reqResHex = requestId.prefix(8).map { String(format: "%02x", $0) }.joined()
                        resourceDebugLog("DELIVER: request resource concluded, request_id=\(reqResHex), data=\(assembledData.count)B")
                        linkLogger.info("Request resource complete \(reqResHex, privacy: .public), data=\(assembledData.count, privacy: .public) bytes")
                        if let unpacked = try? unpackMsgPack(assembledData) {
                            await handleRequest(requestId: requestId, unpackedRequest: unpacked)
                        } else {
                            resourceDebugLog("DELIVER: FAILED to unpack request resource")
                            linkLogger.error("Failed to unpack inbound request resource as msgpack array")
                        }
                    } else {
                        let reqHex = reqId.prefix(8).map { String(format: "%02x", $0) }.joined()
                        resourceDebugLog("DELIVER: response resource for request \(reqHex), data=\(assembledData.count)B")
                        linkLogger.info("Response resource complete for request \(reqHex, privacy: .public), data=\(assembledData.count, privacy: .public) bytes")
                        // RNS response_resource_concluded forks on has_metadata
                        // (Link.py:939-954): a metadata-bearing response is a FILE
                        // response — the assembled bytes are the raw payload (NOT
                        // umsgpack([request_id, response])), and request_id comes from
                        // the resource itself, with metadata passed alongside.
                        if let md = await resource.receivedMetadata {
                            resourceDebugLog("DELIVER: file response with metadata=\(md.count)B")
                            await handleRequestResponse(requestId: reqId, data: assembledData, metadata: md)
                        } else if let value = try? unpackMsgPack(assembledData),
                           // Non-file response: unpack msgpack([requestId, responseData])
                           // (Link.py:950-954).
                           case .array(let elements) = value,
                           elements.count >= 2,
                           case .binary(let responseRequestId) = elements[0] {
                            // DOUBLE-FRAME FIX (site #2): extract the RAW response
                            // payload from elements[1] — the send side single-frames
                            // [.binary(request_id), .binary(data)], so element 1 is
                            // already the raw bytes. The previous packMsgPack(elements[1])
                            // re-added a bin frame, so a >MDU response disagreed on the
                            // wire-observable bytes with the sub-MDU RESPONSE packet path
                            // (handleResponsePacket). Both sites must agree, hence the
                            // identical extraction here.
                            let responseData: Data
                            if case .binary(let raw) = elements[1] {
                                responseData = raw
                            } else {
                                responseData = packMsgPack(elements[1])
                            }
                            resourceDebugLog("DELIVER: unpacked OK, responseData=\(responseData.count)B")
                            await handleRequestResponse(requestId: responseRequestId, data: responseData)
                        } else {
                            resourceDebugLog("DELIVER: FAILED to unpack assembled data")
                            linkLogger.error("Failed to unpack assembled data as msgpack([requestId, response])")
                        }
                    }
                }

                // Notify callback (python final-segment callback, Resource.py:738)
                await fireResourceConcludedOnce(resource)

                // Unlink the inbound storagepath now the data is surfaced
                // (python os.unlink(storagepath), Resource.py:744) and close
                // any handles.
                await resource.cleanup()

                // Link-internal conclusion: record final receiver window + remove
                // from inboundResources (RNS resource_concluded, RNS/Link.py:1281-1290).
                await resourceConcluded(resource)
            }
            return
        }
    }

    /// Handle resource proof packet.
    ///
    /// Called when receiving proof of successful transfer from the peer.
    /// Python proof format: resource_hash(32) + SHA256(assembled_data + resource_hash)(32) = 64 bytes
    /// Validation: proof_data[32:] == expected_proof where expected_proof = SHA256(original_data + hash)
    ///
    /// - Parameter data: Proof packet data (64 bytes: hash + proof)
    private func handleResourceProof(_ data: Data) async {
        // Proof should be 64 bytes: resource_hash(32) + proof(32)
        guard data.count >= 64 else {
            linkLogger.warning("Resource proof too short: \(data.count, privacy: .public) bytes (expected 64)")
            return
        }

        let proofHash = data.prefix(32)

        // Find matching outbound resource
        for (hash, resource) in outboundResources {
            // Match by resource hash (first 32 bytes of proof) to locate the
            // outgoing resource this proof answers (RNS/Link.py:1177-1180).
            guard let resourceHash = await resource.hash, Data(proofHash) == resourceHash else {
                continue
            }

            // Validate the proof's INTEGRITY before concluding. Matching the
            // 32-byte resource hash alone is NOT sufficient: RNS `validate_proof`
            // additionally requires `proof_data[32:] == self.expected_proof`
            // before marking COMPLETE (RNS/Resource.py:782-787). Route through the
            // faithful port `Resource.validate_proof` (Resource.swift:1696), which
            // computes/compares `expectedProof` and sets state=.complete ONLY on a
            // byte-exact match; on a wrong/forged proof it leaves the resource
            // untouched (RNS/Resource.py:822-823 `pass`).
            await resource.validate_proof(data)
            guard await resource.state == .complete else {
                // Forged / wrong proof bytes: RNS does NOT conclude — the resource
                // stays AWAITING_PROOF and the sender's watchdog re-drives the proof
                // exchange (RNS/Resource.py:783-787 fall-through). Do not fire the
                // conclusion callback or advance segments.
                linkLogger.warning("Resource proof validation failed for \(resourceHash.prefix(8).map { String(format: "%02x", $0) }.joined(), privacy: .public) — staying awaiting_proof")
                return
            }

            // Proof valid → COMPLETE. RNS `validate_proof` runs the Link-internal
            // `link.resource_concluded(self)` bookkeeping here for EVERY segment
            // (RNS/Resource.py:787) but fires the app-facing `self.callback(self)`
            // conclusion ONLY on the FINAL segment (RNS/Resource.py:788-792). The
            // app callback is therefore deferred to the final-segment branch below;
            // firing it per-segment (as this port previously did) signalled an
            // outbound multi-segment transfer "concluded" after segment 1, before
            // the later segments had even been advertised.

            // Segment chaining (python validate_proof :788-821):
            // if segment_index == total_segments → done (fire the app callback,
            // close input file via cleanup). Otherwise prepare (if not already)
            // and advertise the next segment, re-keying outboundResources by the
            // next segment's hash.
            let hasMore = await resource.hasMoreSegments
            if hasMore {
                // Non-final segment (RNS/Resource.py:804-821): drop the current
                // segment and advertise the next segment of the SAME logical
                // transfer. Do NOT fire the app-facing conclusion callback (RNS
                // gates it on `segment_index == total_segments`, :788) and do NOT
                // run the Link-internal `resourceConcluded` here — the link is
                // still busy with this multi-segment resource, so the
                // pending-outgoing queue must not advance until the FINAL segment
                // concludes.
                //
                // Gate the advance on actually OWNING the segment (removeValue != nil),
                // mirroring this file's other defended conclusion sites. RESOURCE_PRF is
                // in skipDedup, so a duplicate/retransmitted proof on a lossy BLE/mesh
                // link can drive two concurrent handleResourceProof calls for the same
                // segment; without the gate both would advanceNextSegment and double-
                // advertise the next segment. Actor isolation makes removeValue atomic,
                // so exactly one caller advances.
                if outboundResources.removeValue(forKey: hash) != nil {
                    await advertiseNextSegment(after: resource)
                }
            } else {
                // Final segment concluded (RNS/Resource.py:788-792): fire the
                // app-facing conclusion callback ONCE for the whole transfer, then
                // close + unlink the staging input file (python input_file close,
                // Resource.py:796-797) and run the Link-internal conclusion
                // (registry removal + drain the next queued outbound resource; RNS
                // resource_concluded, RNS/Link.py:1281-1290).
                await fireResourceConcludedOnce(resource)
                await resource.cleanup()
                await resourceConcluded(resource)
            }
            return
        }
    }

    /// Prepare (if needed) and advertise the next segment of a split outbound
    /// resource, after the current segment's proof validated.
    ///
    /// Faithful port of python `validate_proof` segment-continuation branch
    /// (Resource.py:804-821): ensure the next segment is prepared (python
    /// eagerly prepares it on `advertise()`, Resource.py:516-518; this port
    /// prepares lazily here if it wasn't), hand off the shared input file
    /// (python nulls the current segment's `input_file`, Resource.py:816), then
    /// `next_segment.advertise()` (Resource.py:821).
    private func advertiseNextSegment(after current: Resource) async {
        // Hold the one-at-a-time reservation across the whole segment transition.
        // The caller removed `current` from outboundResources just before this call
        // (synchronously, no await between), so without this the gate would read free
        // during the awaits below (prepareNextSegment, hash, register) and a concurrent
        // send/drain could advertise a competing resource. Set here as the first
        // statement (runs synchronously after the caller's removeValue); cleared once
        // `next` is registered or on every early-exit/failure path.
        outgoingReservationActive = true
        do {
            // Ensure the next segment exists & is prepared (python :807-811).
            guard let next = try await current.prepareNextSegment() else {
                linkLogger.warning("No next segment to advertise despite hasMoreSegments")
                outgoingReservationActive = false
                return
            }

            // Hand off the staging input file so it survives until the final
            // segment concludes (python input_file sharing + null-out :816).
            await current.transferInputFileOwnership(to: next)

            // Wire the next segment's send callback (creates link DATA packets),
            // exactly as sendResource() does for the first segment.
            await next.setSendCallback { [weak self] packetData in
                guard let self = self else { throw LinkError.notActive }
                try await self.sendResourcePacket(packetData)
            }

            // Track and advertise the next segment (python next_segment.advertise()
            // :821). Re-key outboundResources by the next segment's own hash via
            // the registry helper (RNS register_outgoing_resource, RNS/Link.py:1302).
            let nextHash = await next.hash ?? Data()
            await registerOutgoingResource(next)
            // Registered — gate now held by outboundResources; release the reservation.
            outgoingReservationActive = false
            let nextIdx = await next.segmentIndex
            let nextTotal = await next.totalSegments
            let nextHashHex = nextHash.prefix(8).map { String(format: "%02x", $0) }.joined()
            linkLogger.info("Advertising segment \(nextIdx, privacy: .public)/\(nextTotal, privacy: .public) hash=\(nextHashHex, privacy: .public)")
            do {
                try await next.sendAdvertisement(linkMDU: LinkConstants.LINK_MDU)
            } catch {
                // Python __advertise_job calls self.cancel() on an advertise failure
                // (RNS/Resource.py:536-538). `next` is already in outboundResources and
                // owns the staging tempfile (transferInputFileOwnership ran), and the
                // receiver never saw the advertisement — so just logging would stall the
                // whole multi-segment transfer permanently (no retry/self-timeout) and
                // leak the tempfile. Mirror cancel(): drop tracking, unlink the staging
                // file, conclude so the caller observes the failure, and — since this
                // aborted transfer was holding the pending-outgoing queue (released only
                // on the FINAL segment's conclusion, :2438-2445) — drain the queue so
                // resources queued behind it are not stalled until link close.
                //
                // Gate all of that on WE still owning `next`: the link can close during
                // the `await sendAdvertisement` suspension above, and finishClose's
                // cancel-on-close snapshots `next` from outboundResources, clears the
                // dict, and schedules its conclusion in a detached Task (:1295-1311).
                // If that already happened, `removeValue` returns nil — re-cleaning /
                // re-concluding would be a resourceConcluded double-fire. Actor isolation
                // makes this removeValue check atomic with finishClose's removeAll, so
                // exactly one path tears `next` down.
                linkLogger.error("Failed to advertise next segment: \(error, privacy: .public)")
                if outboundResources.removeValue(forKey: nextHash) != nil {
                    await next.cleanup()
                    await fireResourceConcludedOnce(next)
                    await drainOutgoingQueue()
                }
            }
        } catch {
            // A prepareNextSegment failure leaves `current` owning the shared staging
            // tempfile (transferInputFileOwnership never ran), so without this the file
            // leaks. Unlink it (python closes/unlinks input_file on resource failure,
            // RNS/Resource.py). Unlike the sendAdvertisement path above we do NOT fire
            // resourceConcluded here: `current` already concluded `.complete` at the
            // proof-validation site, so re-firing would be a callback double-fire. The
            // remaining-chain-failure signal is a separate per-segment-model gap (no
            // per-resource watchdog yet) — to be addressed by a timeout, not by
            // double-concluding a completed segment.
            linkLogger.error("Failed to prepare next segment: \(error, privacy: .public)")
            // Reservation was set at entry and never cleared (we failed before
            // registering `next`); release it before the drain below so the queue
            // can actually advance.
            outgoingReservationActive = false
            await current.cleanup()
            // The multi-segment transfer that was holding the pending-outgoing queue
            // (released only on the FINAL segment, :2438-2445) has now aborted, so drain
            // the queue — otherwise resources queued behind it stall until link close.
            await drainOutgoingQueue()
        }
    }

    /// Handle resource hashmap update packet.
    ///
    /// Called when receiving additional hashmap segments for a large resource.
    /// HMU format: MessagePack-encoded advertisement with additional hashmap segment.
    ///
    /// - Parameter data: HMU packet data (MessagePack advertisement)
    private func handleResourceHMU(_ data: Data) async {
        // Python HMU wire format (Resource.py line 1000):
        //   resource_hash(32) + msgpack([segment, hashmap_bytes])
        // Python receiver (Resource.py line 442):
        //   update = umsgpack.unpackb(plaintext[HASHLENGTH//8:])
        //   self.hashmap_update(update[0], update[1])
        let hashLen = 32
        guard data.count > hashLen else {
            linkLogger.warning("HMU data too short: \(data.count, privacy: .public) bytes")
            return
        }

        let resourceHash = Data(data.prefix(hashLen))
        let hmuPayload = Data(data.dropFirst(hashLen))

        // Unpack msgpack([segment, hashmap_bytes])
        // Python: update = umsgpack.unpackb(plaintext[HASHLENGTH//8:])
        //         self.hashmap_update(update[0], update[1])
        guard let value = try? unpackMsgPack(hmuPayload),
              case .array(let arr) = value,
              arr.count == 2,
              case .binary(let hashmapChunk) = arr[1] else {
            linkLogger.error("Failed to unpack HMU payload")
            return
        }

        // Extract wire segment number (0-based) from msgpack
        let wireSegment: Int
        switch arr[0] {
        case .int(let i): wireSegment = Int(i)
        case .uint(let u): wireSegment = Int(u)
        default:
            linkLogger.error("Invalid segment number in HMU")
            return
        }

        let resHashHex = resourceHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        linkLogger.info("Received HMU for \(resHashHex, privacy: .public), wireSeg=\(wireSegment, privacy: .public), \(hashmapChunk.count / 4, privacy: .public) new hashes")

        // Find matching inbound resource by hash
        for (_, resource) in inboundResources {
            let storedHash = await resource.hash
            if storedHash == resourceHash {
                await resource.appendHashmapSegment(hashmapChunk, wireSegment: wireSegment)
                return
            }
        }
        linkLogger.warning("No matching inbound resource for \(resHashHex, privacy: .public)")
    }

    /// Handle resource reject packet.
    ///
    /// Called when the peer rejects an outbound resource.
    /// Reject format: resource hash (32 bytes) - optional, may be empty
    ///
    /// - Parameter data: Reject packet data
    private func handleResourceReject(_ data: Data) async {
        // If data contains resource hash, find specific resource
        if data.count >= 32 {
            let rejectHash = data.prefix(32)
            for (_, resource) in outboundResources {
                if let resourceHash = await resource.hash, Data(rejectHash) == resourceHash {
                    // RNS `_rejected()` sets status=REJECTED from ANY status <
                    // COMPLETE (RNS/Resource.py:1106-1117), which for a
                    // decompression-bomb sender is AWAITING_PROOF (all parts sent)
                    // and for an ACCEPT_APP-declined sender is ADVERTISED. The
                    // staged FSM only allows `.advertised → .rejected`, so route
                    // through markRejected() (direct status assignment) rather than
                    // transitionState, which would silently no-op the TRANSFERRING/
                    // AWAITING_PROOF cases and leave the sender un-rejected.
                    await resource.markRejected()
                    await fireResourceConcludedOnce(resource)
                    // Terminal path: close + unlink staging tempfile.
                    await resource.cleanup()
                    // Link-internal conclusion: remove + drain the next queued
                    // outbound (RNS resource_concluded, RNS/Link.py:1281-1290).
                    await resourceConcluded(resource)
                    return
                }
            }
        }

        // Fallback: reject most recently advertised resource (RCL carried no hash).
        if let (_, resource) = outboundResources.first {
            let resourceState = await resource.state
            if resourceState == .advertised {
                await resource.markRejected()  // RNS _rejected() (RNS/Resource.py:1106-1117)
                await fireResourceConcludedOnce(resource)
                await resource.cleanup()
                await resourceConcluded(resource)
            }
        }
    }

    /// Handle resource cancel packet.
    ///
    /// Called when the peer cancels a resource transfer.
    /// Cancel format: resource hash (32 bytes) - optional
    ///
    /// - Parameter data: Cancel packet data
    private func handleResourceCancel(_ data: Data) async {
        // If data contains resource hash, cancel specific resource
        if data.count >= 32 {
            let cancelHash = data.prefix(32)

            // Check outbound resources
            for (_, resource) in outboundResources {
                if let resourceHash = await resource.hash, Data(cancelHash) == resourceHash {
                    do {
                        try await resource.transitionState(to: .cancelled)
                        await fireResourceConcludedOnce(resource)
                    } catch {}
                    await resource.cleanup()
                    // Link-internal conclusion: remove + drain next queued outbound.
                    await resourceConcluded(resource)
                    return
                }
            }

            // Check inbound resources
            for (_, resource) in inboundResources {
                if let resourceHash = await resource.hash, Data(cancelHash) == resourceHash {
                    do {
                        try await resource.transitionState(to: .cancelled)
                        await fireResourceConcludedOnce(resource)
                    } catch {}
                    await resource.cleanup(abandonChain: true)
                    // Link-internal conclusion: record final window + remove
                    // (RNS resource_concluded records last_resource_window for any
                    // incoming conclusion, RNS/Link.py:1283-1286).
                    await resourceConcluded(resource)
                    return
                }
            }
        }
    }

    // MARK: - Request Management

    /// Add a pending request to track.
    ///
    /// Called when a new request is created via Link.request().
    ///
    /// - Parameter receipt: RequestReceipt to track
    func addPendingRequest(_ receipt: RequestReceipt) {
        pendingRequests.append(receipt)
    }

    /// Thin entry point for a sub-MDU inbound REQUEST(0x09) packet.
    ///
    /// Faithful port of the REQUEST branch of RNS `Link.receive`
    /// (RNS/Link.py:1030-1040): unpack the decrypted payload as the
    /// `[requested_at, path_hash, request_data]` msgpack array, then dispatch to
    /// `handle_request`. The `request_id` is computed by the Transport from the WIRE
    /// packet's truncated hash (RNS reads `packet.getTruncatedHash()` on the received
    /// packet, not on the plaintext) and is passed in. The unpack + ALLOW gating +
    /// generator fork live on the Link to keep the wire/RPC logic here, exactly as RNS
    /// does (a daemon thread in RNS; an `await` hop in the actor port — category (a)).
    ///
    /// - Parameters:
    ///   - plaintext: The decrypted REQUEST payload (`umsgpack([requested_at, path_hash, data])`).
    ///   - requestId: `packet.getTruncatedHash()` of the inbound REQUEST packet.
    public func handleRequestPacket(_ plaintext: Data, requestId: Data) async {
        guard let unpacked = try? unpackMsgPack(plaintext) else {
            linkLogger.error("Failed to unpack REQUEST payload as msgpack")
            return
        }
        await handleRequest(requestId: requestId, unpackedRequest: unpacked)
    }

    /// Server-side handler for an inbound request: gate, run the generator, fork the
    /// response onto the existing send paths.
    ///
    /// Faithful port of RNS `Link.handle_request` (RNS/Link.py:853-901). Reached from
    /// two sites: `handleRequestPacket` (sub-MDU REQUEST packet) and the inbound
    /// request-Resource conclude fork (>MDU, `request_id = truncated_hash(packed)`).
    ///
    /// - Parameters:
    ///   - requestId: The request id (packet truncated-hash, or
    ///     `truncated_hash(packed_request)` for a request Resource).
    ///   - unpackedRequest: The unpacked `[requested_at, path_hash, request_data]`
    ///     msgpack array.
    public func handleRequest(requestId: Data, unpackedRequest: MessagePackValue) async {
        // RNS gates the whole handler on `status == Link.ACTIVE` (Link.py:854).
        guard state == .active else {
            linkLogger.debug("Ignoring request on non-active link (state=\(String(describing: self.state), privacy: .public))")
            return
        }

        // unpacked_request = [requested_at, path_hash, request_data] (Link.py:855-857).
        guard case .array(let fields) = unpackedRequest, fields.count >= 3 else {
            linkLogger.error("Malformed request: expected [requested_at, path_hash, data]")
            return
        }

        // requested_at is a unix timestamp; accept any numeric msgpack encoding.
        let requestedAt: Double
        switch fields[0] {
        case .double(let d): requestedAt = d
        case .float(let f): requestedAt = Double(f)
        case .int(let i): requestedAt = Double(i)
        case .uint(let u): requestedAt = Double(u)
        default: requestedAt = 0
        }

        guard case .binary(let pathHash) = fields[1] else {
            linkLogger.error("Malformed request: path_hash is not binary")
            return
        }

        // request_data: RNS passes the raw unpacked value to the generator; the swift
        // ResponseGenerator takes Data, so a binary payload is forwarded as-is and any
        // other msgpack type yields empty Data (ResponseGenerator cross-file contract).
        let requestData: Data
        if case .binary(let b) = fields[2] { requestData = b } else { requestData = Data() }

        // Look up the registered handler by path_hash (Link.py:859). No handler -> the
        // path goes silent (RNS only acts `if path_hash in request_handlers`).
        guard let handler = destination.requestHandler(forPathHash: pathHash) else {
            return
        }

        // ALLOW gating (Link.py:867-877). remoteIdentity is read at INVOCATION time
        // (identify arrives as an async LINKIDENTIFY packet — do not capture an early
        // nil): ALLOW_NONE denies; ALLOW_LIST allows iff remoteIdentity is set and its
        // hash is in allowedList; ALLOW_ALL allows unconditionally.
        var allowed = false
        if handler.allow != Destination.ALLOW_NONE {
            if handler.allow == Destination.ALLOW_LIST {
                if let rid = remoteIdentity, handler.allowedList?.contains(rid.hash) == true {
                    allowed = true
                }
            } else if handler.allow == Destination.ALLOW_ALL {
                allowed = true
            }
        }

        let reqHex = requestId.prefix(8).map { String(format: "%02x", $0) }.joined()
        guard allowed else {
            // RNS logs the request as not-allowed and sends NOTHING (Link.py:898-900).
            let idString = remoteIdentity.map { $0.hash.prefix(8).map { String(format: "%02x", $0) }.joined() } ?? "<Unknown>"
            linkLogger.debug("Request \(reqHex, privacy: .public) from \(idString, privacy: .public) not allowed for path \(handler.path, privacy: .public)")
            return
        }

        linkLogger.debug("Handling request \(reqHex, privacy: .public) for path \(handler.path, privacy: .public)")

        // Run the response generator (Link.py:879-884). The swift port fixes a single
        // 6-argument form (no python runtime arity inspection — category (a)).
        let response = await handler.generator(handler.path, requestData, requestId, linkId, remoteIdentity, requestedAt)

        // Fork on the response (Link.py:886-901):
        //   .none        -> send NOTHING (RNS `if response != None:` guard, Link.py:893).
        //   .bytes       -> respond(to:with:): packs umsgpack([request_id, response]) and
        //                   picks a sub-MDU RESPONSE packet vs a >MDU response Resource.
        //   .file        -> respond(to:file:metadata:): a metadata-bearing Resource,
        //                   never umsgpack-wrapped (Link.py:889-890).
        switch response {
        case .none:
            return
        case .bytes(let data):
            do {
                try await respond(to: requestId, with: data)
            } catch {
                linkLogger.error("Failed to send response for request \(reqHex, privacy: .public): \(error, privacy: .public)")
            }
        case .file(let content, let metadata):
            do {
                try await respond(to: requestId, file: content, metadata: metadata)
            } catch {
                linkLogger.error("Failed to send file response for request \(reqHex, privacy: .public): \(error, privacy: .public)")
            }
        }
    }

    /// Handle response for a pending request.
    ///
    /// Called when a response packet is received for one of our pending requests.
    /// Mirrors RNS `handle_response` (Link.py:906-925): matches the receipt by
    /// request_id, delivers the response (with optional metadata for file
    /// responses), and removes it from the pending list.
    ///
    /// - Parameters:
    ///   - requestId: Request ID from response packet
    ///   - data: Response data
    ///   - metadata: Optional response metadata (set only for (file, metadata)
    ///     responses; nil for plain bytes/structured responses). RNS passes
    ///     `resource.metadata` to `pending_request.response_received(..., metadata)`
    ///     (Link.py:918/:945).
    public func handleRequestResponse(requestId: Data, data: Data, metadata: Data? = nil) async {
        if let index = pendingRequests.firstIndex(where: { receipt in
            // Compare request IDs (both should be 16-byte truncated hashes)
            receipt.requestId == requestId
        }) {
            let receipt = pendingRequests.remove(at: index)
            await receipt.receiveResponse(data, metadata: metadata)
        }
    }

    /// Handle response resource for a pending request.
    ///
    /// Called when a large response arrives as a Resource transfer.
    ///
    /// - Parameters:
    ///   - requestId: Request ID from resource advertisement
    ///   - resource: Response resource
    public func handleResourceResponse(requestId: Data, resource: Resource) async {
        if let receipt = pendingRequests.first(where: { $0.requestId == requestId }) {
            await receipt.receiveResourceResponse(resource)
        }
    }

    /// Handle an incoming sub-MDU RESPONSE(0x0A) packet.
    ///
    /// Faithful port of the RESPONSE branch of RNS `Link.receive` /
    /// `handle_response` (RNS/Link.py:1042-1054, :906-925): the decrypted payload is
    /// `umsgpack.packb([request_id, response])`, so unpack it, take `request_id` from
    /// element 0 and the RAW response value from element 1, and deliver it.
    ///
    /// DOUBLE-FRAME FIX (site #1): the send side `respond(to:with:)` single-frames
    /// `[.binary(request_id), .binary(data)]`, so `elements[1]` is ALREADY the raw
    /// response bytes. The previous inline Transport path re-packed it
    /// (`packMsgPack(elements[1])`), re-adding an msgpack bin frame so the receipt
    /// held `[0xc4, len, …payload]` instead of the raw payload. We extract the
    /// `.binary` payload directly here (and only re-pack a NON-bytes structured value,
    /// which has no raw byte form), keeping this path byte-for-byte consistent with
    /// the >MDU response-Resource conclude path.
    ///
    /// - Parameter data: Decrypted RESPONSE payload (context byte stripped).
    public func handleResponsePacket(_ data: Data) async {
        // Inbound packet observation hook (additive; no-op when unset). Surface the
        // decrypted RESPONSE (0x0A) plaintext (msgpack [request_id, response]) so an
        // instrument can observe the sub-MDU response path (RNS/Link.py:897-899).
        // Runs before unpack so a malformed payload is still observable.
        await inboundPacketObserver?(RequestPacketContext.response, data)

        guard let value = try? unpackMsgPack(data),
              case .array(let elements) = value,
              elements.count >= 2,
              case .binary(let requestId) = elements[0] else {
            linkLogger.error("Failed to unpack RESPONSE payload as msgpack([request_id, response])")
            return
        }

        let responseData: Data
        if case .binary(let raw) = elements[1] {
            // Raw bytes payload (the wire form produced by respond(to:with:)) — do
            // NOT re-pack (that is the double-frame bug).
            responseData = raw
        } else {
            // Structured (non-bytes) response value: re-pack so the receipt carries a
            // self-describing msgpack blob. RNS hands the unpacked value straight to
            // response_received; the swift receipt stores Data, so a non-bytes value
            // has no raw form and must be re-encoded.
            responseData = packMsgPack(elements[1])
        }

        await handleRequestResponse(requestId: requestId, data: responseData)
    }

    // MARK: - Identity

    /// Set the identity callbacks for remote identification notifications.
    ///
    /// - Parameter callbacks: Callback handler conforming to IdentifyCallbacks
    public func setIdentifyCallbacks(_ callbacks: (any IdentifyCallbacks)?) {
        self.identifyCallbacks = callbacks
    }

    /// Get the remote peer's identity.
    ///
    /// Returns nil if the remote peer has not identified themselves.
    ///
    /// - Returns: The verified identity of the remote peer, or nil
    public func getRemoteIdentity() -> Identity? {
        return remoteIdentity
    }

    /// Handle received LINKIDENTIFY packet.
    ///
    /// Validates the signature and stores the remote peer's identity.
    /// Only responders receive identification from initiators.
    ///
    /// The proof format is:
    /// - public_keys (64 bytes): encryption public key (32) + signing public key (32)
    /// - signature (64 bytes): Ed25519 signature of (link_id + public_keys)
    ///
    /// - Parameter data: Decrypted LINKIDENTIFY packet (context byte stripped)
    /// - Throws: LinkError if validation fails
    public func handleIdentifyPacket(_ data: Data) async throws {
        // Only responder receives identification
        guard !initiator else {
            // Initiator shouldn't receive identify packets
            return
        }

        guard state.isEstablished else {
            throw LinkError.notActive
        }

        // Parse: public_keys (64) + signature (64) = 128 bytes
        guard data.count == 128 else {
            throw LinkError.invalidState(
                expected: "128 bytes",
                actual: "\(data.count) bytes"
            )
        }

        let publicKeys = data[data.startIndex..<data.startIndex + 64]
        let signature = data[data.startIndex + 64..<data.startIndex + 128]

        // Reconstruct signed data: link_id + public_keys
        var signedData = linkId
        signedData.append(publicKeys)

        // Create identity from public keys and verify signature
        guard let identity = try? Identity(publicKeyBytes: Data(publicKeys)) else {
            throw LinkError.invalidState(
                expected: "valid public keys",
                actual: "invalid public key format"
            )
        }

        // Verify signature
        let valid = identity.verify(signature: Data(signature), for: signedData)
        guard valid else {
            throw LinkError.invalidState(
                expected: "valid signature",
                actual: "invalid signature"
            )
        }

        // Store remote identity
        remoteIdentity = identity

        // Notify callback
        await identifyCallbacks?.remoteIdentified(identity)
    }
}
