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
    private var linkEstablishedCallback: ((Link) async -> Void)?

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

    /// Last inbound traffic timestamp
    private var lastInbound: Date?

    /// Last outbound traffic timestamp
    private var lastOutbound: Date?

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

    /// Channel for typed message communication (lazy-created via getOrCreateChannel).
    var channel: Channel?

    /// Remote peer's identity (after LINKIDENTIFY received)
    public private(set) var remoteIdentity: Identity?

    /// Identity callbacks delegate for remote identification notifications
    private weak var identifyCallbacks: (any IdentifyCallbacks)?

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
    public init(destination: Destination, identity: Identity) {
        self.destination = destination
        self.localIdentity = identity
        self.initiator = true
        self.request = LinkRequest(destination: destination)
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

        // Create PROOF data
        let proofData = try LinkProof.create(
            linkId: linkId,
            ephemeralEncryptionPublicKey: ephemeralKey.publicKey,
            destinationIdentity: localIdentity,
            signaling: LinkConstants.DEFAULT_MTU_SIGNALING
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
            self.keepaliveInterval = LinkConstants.keepaliveInterval(forRTT: rttValue)
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
            print("[LINK_STATE] Link \(linkIdHex) ignoring transition \(state) -> \(newState) (terminal state)")
            return
        }

        let linkIdHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[LINK_STATE] Link \(linkIdHex) transitioning: \(state) -> \(newState)")
        state = newState
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
        print("[LINK_PROOF] processProof called for link \(linkIdHex), state=\(state)")
        print("[LINK_PROOF] proofData length: \(proofData.count) bytes")

        guard state == .handshake else {
            print("[LINK_PROOF] ERROR: not in handshake state, currently \(state)")
            throw LinkError.invalidState(expected: "handshake", actual: "\(state)")
        }

        // Parse PROOF
        print("[LINK_PROOF] Parsing PROOF data...")
        let proof = try LinkProof(from: proofData)
        print("[LINK_PROOF] PROOF parsed successfully")

        // Validate signature against destination's identity
        guard let destIdentity = destination.identity else {
            print("[LINK_PROOF] ERROR: Destination has no identity")
            throw LinkError.invalidProof(reason: "Destination has no identity for verification")
        }

        print("[LINK_PROOF] Validating PROOF signature against destination identity...")
        try proof.validate(linkId: linkId, destinationIdentity: destIdentity)
        print("[LINK_PROOF] PROOF signature validated!")

        // Store peer's ephemeral key
        peerEncryptionPublicKey = proof.peerEncryptionPublicKey
        let peerKeyHex = proof.peerEncryptionPublicKey.rawRepresentation.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[LINK_PROOF] Peer encryption key stored: \(peerKeyHex)...")

        // Measure RTT
        if let sentAt = requestSentAt {
            rtt = Date().timeIntervalSince(sentAt)
            keepaliveInterval = LinkConstants.keepaliveInterval(forRTT: rtt)
            print("[LINK_PROOF] RTT measured: \(String(format: "%.3f", rtt))s")
        }

        // Derive shared key
        print("[LINK_PROOF] Deriving shared key...")
        try deriveSharedKey()
        print("[LINK_PROOF] Shared key derived successfully")

        // Transition to active
        lastInbound = Date()
        print("[LINK_PROOF] Transitioning to active state...")
        transitionState(to: .active)

        // Send LRRTT packet to complete handshake from responder's perspective
        // This triggers the responder's link_established callback
        print("[LINK_PROOF] Sending LRRTT packet...")
        try await sendLRRTT()
        print("[LINK_PROOF] LRRTT sent")

        // Start keep-alive and watchdog
        startKeepalive()
        startWatchdog()
        print("[LINK_PROOF] Link \(linkIdHex) fully established!")
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
        print("[LINK] sendLRRTT called for link \(linkIdHex), sendCallback set: \(sendCallback != nil)")

        // Encode RTT as msgpack double
        let rttData = packMsgPack(.double(rtt))
        print("[LINK] LRRTT rttData=\(rttData.count) bytes, rtt=\(rtt)")

        // Encrypt the RTT data
        let encrypted = try encrypt(rttData)
        print("[LINK] LRRTT encrypted=\(encrypted.count) bytes")

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
        print("[LINK] LRRTT packet=\(packetBytes.count) bytes, context=0x\(String(format: "%02x", LinkConstants.CONTEXT_LRRTT))")

        // Send via callback if available, otherwise store for manual send
        if let send = sendCallback {
            print("[LINK] Sending LRRTT via callback...")
            try await send(packetBytes)
            print("[LINK] LRRTT sent successfully")
        } else {
            // If no callback, caller must handle sending manually
            // Store packet for getLRRTTPacket() to retrieve
            print("[LINK] No sendCallback, storing LRRTT for manual retrieval")
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
            lastOutbound = Date()
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
            lastInbound = Date()
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

    // MARK: - Keep-Alive

    /// Start the keep-alive task.
    ///
    /// Called after link becomes active. Periodically sends encrypted
    /// keep-alive packets to maintain link liveness.
    private func startKeepalive() {
        keepaliveTask?.cancel()

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
    private func sendKeepalive() async {
        guard state.isEstablished else { return }
        guard let send = sendCallback else { return }

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

            try await send(packet.encode())
            lastOutbound = Date()
        } catch {
            // Keep-alive send failure - log but don't close link
            // Watchdog will handle stale detection
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

        let elapsed = Date().timeIntervalSince(lastIn)
        let staleTime = keepaliveInterval * 2.0

        if state == .active && elapsed > staleTime {
            // Transition to stale
            transitionState(to: .stale)
        } else if state == .stale && elapsed > (staleTime + LinkConstants.STALE_GRACE) {
            // Stale grace period expired - close link
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
        guard !state.isTerminal else { return }

        // Send LINKCLOSE to remote peer if link was active
        // Python RNS sends encrypted(link_id) with context LINKCLOSE
        // Encrypt BEFORE state transition (encrypt() checks state.isEstablished)
        if state.isEstablished, let send = sendCallback, let token = token {
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

        transitionState(to: .closed(reason: reason))
        stateContinuation?.finish()

        // Fire close callback asynchronously so callers of close() aren't blocked
        if let cb = closeCallback {
            closeCallback = nil  // clear to prevent double-fire
            Task { await cb(reason) }
        }
    }

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
    public func sendResource(data: Data, requestId: Data? = nil, isResponse: Bool = false) async throws -> Resource {
        guard state.isEstablished else {
            throw LinkError.notActive
        }

        print("[RESOURCE_SEND] Starting resource transfer: \(data.count) bytes")

        // Create outbound resource
        let resource = Resource(
            data: data,
            link: self,
            requestId: requestId,
            isResponse: isResponse,
            autoCompress: true
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
        // BZ2 compression enabled: matches Python RNS bz2.compress() for full interop.
        try await resource.prepare(partSize: MDU, linkEncrypt: { plaintext in
            return try encryptToken.encrypt(plaintext)
        }, autoCompress: true)
        let numParts = await resource.numParts
        let transferSize = await resource.transferSize
        linkLogger.info("[RESOURCE_SEND] Prepared: \(numParts) parts, partSize=\(MDU), transferSize=\(transferSize)")
        print("[RESOURCE_SEND] Prepared: \(numParts) parts, partSize=\(MDU)")

        // Store resource (hash is available after prepare)
        let hash = await resource.hash ?? Data()
        outboundResources[hash] = resource
        let hashHex = hash.prefix(8).map { String(format: "%02x", $0) }.joined()
        linkLogger.info("[RESOURCE_SEND] Stored resource hash=\(hashHex), outboundResources count=\(self.outboundResources.count)")

        // Send advertisement to start transfer
        try await resource.sendAdvertisement(linkMDU: LinkConstants.LINK_MDU)
        linkLogger.info("[RESOURCE_SEND] Advertisement sent for resource \(hashHex)")
        print("[RESOURCE_SEND] Advertisement sent for resource \(hashHex)")

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
        print("[RESOURCE_SEND] Sent resource packet context=0x\(String(format: "%02x", resourceContext)), payload=\(wirePayload.count) bytes")
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
        linkLogger.info("[RESOURCE] Received resource packet: context=0x\(String(format: "%02x", context)), data=\(data.count) bytes")
        print("[RESOURCE_RECV] Resource packet: context=0x\(String(format: "%02x", context)), data=\(data.count) bytes")

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
            print("[RESOURCE_RECV] Unknown resource context: 0x\(String(format: "%02x", context))")
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

        // Data is pure advertisement payload (context already handled by handleResourcePacket)
        let advData = data

        do {
            let advertisement = try ResourceAdvertisement.unpack(Data(advData))
            let advReqId = advertisement.requestId?.prefix(8).map { String(format: "%02x", $0) }.joined() ?? "nil"
            resourceDebugLog("ADV: size=\(advertisement.dataSize), parts=\(advertisement.numParts), reqId=\(advReqId), segments=\(advertisement.totalSegments)")

            // Create inbound resource
            let resource = Resource(advertisement: advertisement, link: self)

            // Check acceptance strategy
            // Auto-accept resources with requestId matching a pending request (response resources)
            // This matches Python Link.py behavior where response resources bypass strategy
            let shouldAccept: Bool
            if let reqId = advertisement.requestId,
               pendingRequests.contains(where: { $0.requestId == reqId }) {
                resourceDebugLog("ADV: Auto-accepting response resource for pending request \(reqId.prefix(8).map { String(format: "%02x", $0) }.joined())")
                print("[RESOURCE_RECV] Auto-accepting response resource for pending request \(reqId.prefix(8).map { String(format: "%02x", $0) }.joined())")
                shouldAccept = true
            } else {
                switch resourceStrategy {
                case .acceptNone:
                    shouldAccept = false
                case .acceptAll:
                    shouldAccept = true
                case .acceptApp:
                    if let callbacks = resourceCallbacks {
                        shouldAccept = await callbacks.resourceAdvertised(resource)
                    } else {
                        shouldAccept = false
                    }
                }
            }

            if shouldAccept {
                // Accept the resource
                let hash = await resource.hash ?? Data()
                inboundResources[hash] = resource
                let hashHex = hash.prefix(8).map { String(format: "%02x", $0) }.joined()
                resourceDebugLog("ACCEPT: resource \(hashHex), size=\(advertisement.dataSize), parts=\(advertisement.numParts)")
                linkLogger.error("[RESOURCE_RECV] Accepted resource \(hashHex), size=\(advertisement.dataSize), parts=\(advertisement.numParts)")

                // Notify callback
                if let callbacks = resourceCallbacks {
                    await callbacks.resourceStarted(resource)
                }

                // Set send callback for requests/proof (creates proper link DATA packets)
                await resource.setSendCallback { [weak self] (packetData: Data) in
                    guard let self = self else {
                        throw LinkError.notActive
                    }
                    try await self.sendResourcePacket(packetData)
                }

                // Set decrypt callback for assembled resource data
                // Capture the token directly to avoid actor isolation issues
                let linkToken = self.token
                await resource.setDecryptCallback { (ciphertext: Data) in
                    guard let token = linkToken else {
                        throw LinkError.encryptionNotReady
                    }
                    return try token.decrypt(ciphertext)
                }

                // Accept the resource (starts requesting parts)
                try await resource.accept()
            } else {
                resourceDebugLog("REJECT: resource rejected (strategy=\(resourceStrategy))")
                print("[RESOURCE_RECV] Rejected resource (strategy=\(resourceStrategy))")
                // Reject the resource
                try await resource.reject()
            }
        } catch {
            resourceDebugLog("ADV ERROR: Failed to parse: \(error)")
            print("[RESOURCE_RECV] Failed to parse advertisement: \(error)")
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
            print("[RESOURCE_REQ] Too short: \(data.count) bytes")
            return
        }

        // Parse exhaustion flag
        let exhausted = data[data.startIndex] == 0xFF
        let pad = exhausted ? (1 + mapHashLen) : 1

        // Extract resource hash for matching
        guard data.count >= pad + resourceHashLen else {
            print("[RESOURCE_REQ] Too short for resource hash: \(data.count) bytes, pad=\(pad)")
            return
        }
        let resourceHash = Data(data[data.startIndex + pad ..< data.startIndex + pad + resourceHashLen])

        // Extract requested part hashes
        let hashesStart = pad + resourceHashLen
        let requestedHashes = data.count > hashesStart ? Data(data[(data.startIndex + hashesStart)...]) : Data()

        let resHashHex = resourceHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        linkLogger.info("[RESOURCE_REQ] resourceHash=\(resHashHex), exhausted=\(exhausted), partHashCount=\(requestedHashes.count / mapHashLen)")
        print("[RESOURCE_REQ] resourceHash=\(resHashHex)..., exhausted=\(exhausted), partHashes=\(requestedHashes.count / mapHashLen)")

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
            while offset + mapHashLen <= requestedHashes.count {
                let partHash = Data(requestedHashes[requestedHashes.startIndex + offset ..< requestedHashes.startIndex + offset + mapHashLen])
                if let partIndex = ResourceHashmap.findPartIndex(for: partHash, in: hashmap) {
                    do {
                        try await resource.sendPart(at: partIndex)
                        print("[RESOURCE_REQ] Sent part \(partIndex)")
                    } catch {
                        print("[RESOURCE_REQ] Failed to send part \(partIndex): \(error)")
                    }
                }
                offset += mapHashLen
            }

            // Handle hashmap exhaustion (send more hashmap entries)
            if exhausted {
                do {
                    let sent = try await resource.sendNextHashmapSegment(linkMDU: LinkConstants.LINK_MDU)
                    if sent {
                        linkLogger.info("[RESOURCE_REQ] Sent HMU for resource \(resHashHex)")
                        print("[RESOURCE_REQ] Sent HMU for resource \(resHashHex)")
                    } else {
                        linkLogger.warning("[RESOURCE_REQ] Hashmap exhausted but no more segments")
                        print("[RESOURCE_REQ] Hashmap exhausted but no more segments to send")
                    }
                } catch {
                    linkLogger.error("[RESOURCE_REQ] Failed to send HMU: \(error.localizedDescription)")
                    print("[RESOURCE_REQ] Failed to send HMU: \(error)")
                }
            }

            return
        }

        let outboundHashes = outboundResources.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
        linkLogger.error("[RESOURCE_REQ] No matching outbound resource. resHash=\(resHashHex), have=\(outboundHashes)")
        print("[RESOURCE_REQ] No matching outbound resource. Have: \(outboundHashes)")
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
        // (there should typically be only one active at a time per link)
        for (hash, resource) in inboundResources {
            let resourceState = await resource.state
            guard resourceState == .transferring else { continue }

            do {
                let complete = try await resource.handlePartPacket(data)
                let total = await resource.numParts
                let received = await resource.receivedCount
                resourceDebugLog("PART: \(received)/\(total), complete=\(complete), data=\(data.count)B")
                linkLogger.error("[RESOURCE_DATA] Part received (of \(total)), complete=\(complete)")

                if complete {
                    // Resource transfer complete - assemble and send proof
                    let assembledData = try await resource.assemble()
                    resourceDebugLog("COMPLETE: assembled \(assembledData.count)B, sending proof")
                    linkLogger.error("[RESOURCE_DATA] Assembled \(assembledData.count) bytes, sending proof")
                    try await resource.sendProof()

                    // If this resource is a response to a pending request,
                    // deliver the assembled data as the request response.
                    // Python: packed_response = umsgpack.packb([request_id, response])
                    // The assembled data IS this msgpack blob.
                    if let reqId = await resource.requestId {
                        let reqHex = reqId.prefix(8).map { String(format: "%02x", $0) }.joined()
                        resourceDebugLog("DELIVER: response resource for request \(reqHex), data=\(assembledData.count)B")
                        linkLogger.error("[RESOURCE_DATA] Response resource complete for request \(reqHex), data=\(assembledData.count) bytes")
                        // Unpack msgpack([requestId, responseData]) and deliver
                        if let value = try? unpackMsgPack(assembledData),
                           case .array(let elements) = value,
                           elements.count >= 2,
                           case .binary(let responseRequestId) = elements[0] {
                            let responseData = packMsgPack(elements[1])
                            resourceDebugLog("DELIVER: unpacked OK, responseData=\(responseData.count)B")
                            await handleRequestResponse(requestId: responseRequestId, data: responseData)
                        } else {
                            resourceDebugLog("DELIVER: FAILED to unpack assembled data")
                            linkLogger.error("[RESOURCE_DATA] Failed to unpack assembled data as msgpack([requestId, response])")
                        }
                    }

                    // Notify callback
                    await resourceCallbacks?.resourceConcluded(resource)

                    // Remove from tracking
                    inboundResources.removeValue(forKey: hash)
                }
                return
            } catch {
                linkLogger.error("[RESOURCE_DATA] Part handling error: \(error)")
            }
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
            print("[RESOURCE_PROOF] Proof too short: \(data.count) bytes (expected 64)")
            return
        }

        let proofHash = data.prefix(32)

        // Find matching outbound resource
        for (hash, resource) in outboundResources {
            // Match by resource hash (first 32 bytes of proof)
            if let resourceHash = await resource.hash, Data(proofHash) == resourceHash {
                do {
                    // Mark as complete
                    try await resource.transitionState(to: .awaitingProof)
                    try await resource.transitionState(to: .complete)

                    // Notify callback
                    await resourceCallbacks?.resourceConcluded(resource)

                    // Remove from tracking
                    outboundResources.removeValue(forKey: hash)
                } catch {
                    // State transition failed
                }
                return
            }
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
            print("[RESOURCE_HMU] Data too short: \(data.count) bytes")
            return
        }

        let resourceHash = Data(data.prefix(hashLen))
        let hmuPayload = Data(data.dropFirst(hashLen))

        // Unpack msgpack([segment, hashmap_bytes])
        guard let value = try? unpackMsgPack(hmuPayload),
              case .array(let arr) = value,
              arr.count == 2,
              case .binary(let hashmapChunk) = arr[1] else {
            print("[RESOURCE_HMU] Failed to unpack HMU payload")
            return
        }

        let resHashHex = resourceHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[RESOURCE_HMU] Received HMU for \(resHashHex), \(hashmapChunk.count / 4) new hashes")

        // Find matching inbound resource by hash
        for (_, resource) in inboundResources {
            let storedHash = await resource.hash
            if storedHash == resourceHash {
                await resource.appendHashmapSegment(hashmapChunk)
                return
            }
        }
        print("[RESOURCE_HMU] No matching inbound resource for \(resHashHex)")
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
            for (hash, resource) in outboundResources {
                if let resourceHash = await resource.hash, Data(rejectHash) == resourceHash {
                    do {
                        try await resource.transitionState(to: .rejected)
                        await resourceCallbacks?.resourceConcluded(resource)
                    } catch {}
                    outboundResources.removeValue(forKey: hash)
                    return
                }
            }
        }

        // Fallback: reject most recently advertised resource
        if let (hash, resource) = outboundResources.first {
            let resourceState = await resource.state
            if resourceState == .advertised {
                do {
                    try await resource.transitionState(to: .rejected)
                    await resourceCallbacks?.resourceConcluded(resource)
                } catch {}
                outboundResources.removeValue(forKey: hash)
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
            for (hash, resource) in outboundResources {
                if let resourceHash = await resource.hash, Data(cancelHash) == resourceHash {
                    do {
                        try await resource.transitionState(to: .cancelled)
                        await resourceCallbacks?.resourceConcluded(resource)
                    } catch {}
                    outboundResources.removeValue(forKey: hash)
                    return
                }
            }

            // Check inbound resources
            for (hash, resource) in inboundResources {
                if let resourceHash = await resource.hash, Data(cancelHash) == resourceHash {
                    do {
                        try await resource.transitionState(to: .cancelled)
                        await resourceCallbacks?.resourceConcluded(resource)
                    } catch {}
                    inboundResources.removeValue(forKey: hash)
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

    /// Handle response for a pending request.
    ///
    /// Called when a response packet is received for one of our pending requests.
    ///
    /// - Parameters:
    ///   - requestId: Request ID from response packet
    ///   - data: Response data
    public func handleRequestResponse(requestId: Data, data: Data) async {
        if let index = pendingRequests.firstIndex(where: { receipt in
            // Compare request IDs (both should be 16-byte truncated hashes)
            receipt.requestId == requestId
        }) {
            let receipt = pendingRequests.remove(at: index)
            await receipt.receiveResponse(data)
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

    /// Handle incoming request response packet.
    ///
    /// Parses the response and delivers to the appropriate receipt.
    ///
    /// - Parameter data: Decrypted response packet (context byte stripped)
    public func handleResponsePacket(_ data: Data) async {
        guard data.count > 16 else { return }

        // Parse: requestId (16 bytes) + response data
        let requestId = Data(data[data.startIndex..<data.startIndex.advanced(by: 16)])
        let responseData = Data(data[data.startIndex.advanced(by: 16)...])

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
