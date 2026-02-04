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
    private weak var resourceCallbacks: (any ResourceCallbacks)?

    /// Outbound resources indexed by resource hash
    private var outboundResources: [Data: Resource] = [:]

    /// Inbound resources indexed by resource hash
    private var inboundResources: [Data: Resource] = [:]

    // MARK: - Identity

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
    /// - Parameter ciphertext: Encrypted data in Token format
    /// - Returns: Decrypted plaintext
    /// - Throws: `LinkError.notActive` if link not established
    /// - Throws: `LinkError.encryptionNotReady` if Token not created
    /// - Throws: `LinkError.decryptionFailed` if decryption fails
    public func decrypt(_ ciphertext: Data) throws -> Data {
        guard state.isEstablished else {
            throw LinkError.notActive
        }

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
    /// Encrypts and sends a single-byte keep-alive marker (0xFF for initiator,
    /// 0xFE for responder) to the peer.
    private func sendKeepalive() async {
        guard state.isEstablished else { return }
        guard let send = sendCallback else { return }

        // Keep-alive content: 0xFF for initiator, 0xFE for responder
        let keepaliveData = Data([initiator ? LinkConstants.KEEPALIVE_INITIATOR : LinkConstants.KEEPALIVE_RESPONDER])

        do {
            // Encrypt the keep-alive data
            let encrypted = try encrypt(keepaliveData)

            // Build complete keep-alive packet
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
                data: encrypted
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
    /// Stops keep-alive and watchdog tasks, transitions to closed state,
    /// and finishes the state observation stream.
    /// Once closed, the link cannot be reused.
    ///
    /// - Parameter reason: Reason for closing (defaults to initiatorClosed)
    public func close(reason: TeardownReason = .initiatorClosed) {
        guard !state.isTerminal else { return }

        stopKeepalive()
        stopWatchdog()

        transitionState(to: .closed(reason: reason))
        stateContinuation?.finish()
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

        // Create outbound resource
        let resource = Resource(
            data: data,
            link: self,
            requestId: requestId,
            isResponse: isResponse,
            autoCompress: true
        )

        // Set send callback for encrypted transmission
        await resource.setSendCallback { [weak self] packetData in
            guard let self = self else {
                throw LinkError.notActive
            }
            guard let send = await self.sendCallback else {
                throw LinkError.notActive
            }
            try await send(packetData)
        }

        // Store resource
        let hash = await resource.hash ?? Data()
        outboundResources[hash] = resource

        // Resource will be prepared and advertised by caller
        return resource
    }

    /// Handle incoming resource packet.
    ///
    /// Routes resource packets to the appropriate handler based on context.
    ///
    /// - Parameter data: Decrypted packet data (context + payload)
    public func handleResourcePacket(_ data: Data) async {
        guard data.count >= 1 else { return }

        let context = data[data.startIndex]

        switch context {
        case ResourcePacketContext.resourceAdvertisement:
            await handleResourceAdvertisement(data)
        case ResourcePacketContext.resourceRequest:
            await handleResourceRequest(data)
        case ResourcePacketContext.resourceData:
            await handleResourceData(data)
        case ResourcePacketContext.resourceProof:
            await handleResourceProof(data)
        case ResourcePacketContext.resourceHMU:
            await handleResourceHMU(data)
        case ResourcePacketContext.resourceReject:
            await handleResourceReject(data)
        case ResourcePacketContext.resourceCancel:
            await handleResourceCancel(data)
        default:
            // Unknown resource context
            break
        }
    }

    /// Handle resource advertisement packet.
    ///
    /// Called when receiving a resource advertisement from the peer.
    /// Checks strategy and callbacks to decide whether to accept.
    ///
    /// - Parameter data: Advertisement packet data
    private func handleResourceAdvertisement(_ data: Data) async {
        guard data.count > 1 else { return }

        // Parse advertisement (skip context byte)
        let advData = data.dropFirst()

        do {
            let advertisement = try ResourceAdvertisement.unpack(Data(advData))

            // Create inbound resource
            let resource = Resource(advertisement: advertisement, link: self)

            // Check acceptance strategy
            let shouldAccept: Bool
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

            if shouldAccept {
                // Accept the resource
                let hash = await resource.hash ?? Data()
                inboundResources[hash] = resource

                // Notify callback
                if let callbacks = resourceCallbacks {
                    await callbacks.resourceStarted(resource)
                }

                // Set send callback for requests/proof
                await resource.setSendCallback { [weak self] (packetData: Data) in
                    guard let self = self else {
                        throw LinkError.notActive
                    }
                    guard let send = await self.sendCallback else {
                        throw LinkError.notActive
                    }
                    try await send(packetData)
                }

                // Accept the resource (starts requesting parts)
                try await resource.accept()
            } else {
                // Reject the resource
                try await resource.reject()
            }
        } catch {
            // Failed to parse advertisement
        }
    }

    /// Handle resource request packet.
    ///
    /// Called when receiving a part request from the peer for an outbound resource.
    /// Request format: sequence of 4-byte part hashes indicating which parts to send.
    ///
    /// - Parameter data: Request packet data (sequence of 4-byte hashes)
    private func handleResourceRequest(_ data: Data) async {
        // Request contains sequence of 4-byte part hashes
        guard data.count >= ResourceConstants.MAPHASH_LEN else { return }

        // Find matching outbound resource by looking at which resources have matching hashes
        // The resource hash isn't in the request, so we need to search through all outbound resources
        for (_, resource) in outboundResources {
            guard let hashmap = await resource.hashmap else { continue }

            // Try to match first requested hash to find the resource
            let firstHash = data.prefix(ResourceConstants.MAPHASH_LEN)
            if ResourceHashmap.findPartIndex(for: firstHash, in: hashmap) != nil {
                // Found the resource, send all requested parts
                var offset = 0
                while offset + ResourceConstants.MAPHASH_LEN <= data.count {
                    let partHash = data[offset..<(offset + ResourceConstants.MAPHASH_LEN)]
                    if let partIndex = ResourceHashmap.findPartIndex(for: Data(partHash), in: hashmap) {
                        do {
                            try await resource.sendPart(at: partIndex)
                        } catch {
                            // Part send failed, continue with remaining parts
                        }
                    }
                    offset += ResourceConstants.MAPHASH_LEN
                }
                return
            }
        }
    }

    /// Handle resource data packet.
    ///
    /// Called when receiving a data part from the peer for an inbound resource.
    /// Data format: 2-byte big-endian part index + part data
    ///
    /// - Parameter data: Data packet data (index + part data)
    private func handleResourceData(_ data: Data) async {
        // Need at least 2 bytes for index
        guard data.count > 2 else { return }

        // Find the inbound resource that's currently transferring
        // (there should typically be only one active at a time per link)
        for (hash, resource) in inboundResources {
            let resourceState = await resource.state
            guard resourceState == .transferring else { continue }

            do {
                let complete = try await resource.handlePartPacket(data)
                if complete {
                    // Resource transfer complete - assemble and send proof
                    _ = try await resource.assemble()
                    try await resource.sendProof()

                    // Notify callback
                    await resourceCallbacks?.resourceConcluded(resource)

                    // Remove from tracking
                    inboundResources.removeValue(forKey: hash)
                }
                return
            } catch {
                // Part handling failed - resource may retry or fail
            }
        }
    }

    /// Handle resource proof packet.
    ///
    /// Called when receiving proof of successful transfer from the peer.
    /// Proof format: resource hash (32 bytes)
    ///
    /// - Parameter data: Proof packet data (resource hash)
    private func handleResourceProof(_ data: Data) async {
        // Proof should be 32-byte resource hash
        guard data.count >= 32 else { return }

        let proofHash = data.prefix(32)

        // Find matching outbound resource
        for (hash, resource) in outboundResources {
            // Check if proof matches this resource
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
        // Parse as advertisement containing hashmap segment
        guard let advertisement = try? ResourceAdvertisement.unpack(data) else { return }

        // Find matching inbound resource by original hash
        for (_, resource) in inboundResources {
            let resourceHash = await resource.hash
            if resourceHash == advertisement.hash {
                // Append hashmap segment to resource
                await resource.appendHashmapSegment(advertisement.hashmapChunk)
                return
            }
        }
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
