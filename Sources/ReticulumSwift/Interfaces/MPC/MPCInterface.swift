//
//  MPCInterface.swift
//  ReticulumSwift
//
//  Parent orchestrator for Apple Multipeer Connectivity transport.
//  Handles advertising, browsing, session management, and peer lifecycle.
//  Spawns MPCPeerInterface children for each connected peer.
//
//  MPC provides peer-to-peer WiFi between nearby Apple devices without
//  requiring shared WiFi infrastructure — filling the gap between
//  AutoInterface (shared LAN) and BLEInterface (Bluetooth only).
//

#if canImport(MultipeerConnectivity)
import Foundation
import MultipeerConnectivity
import OSLog

// MARK: - MPCInterface

/// Parent interface orchestrating Multipeer Connectivity discovery and sessions.
///
/// Architecture follows the same parent/child pattern as AutoInterface and BLEInterface:
/// - Parent handles discovery (advertise + browse), session management, peer lifecycle
/// - Children (MPCPeerInterface) handle send/receive for individual peers
///
/// Key limitations:
/// - No background operation — MPC disconnects when app is backgrounded
/// - 8-peer session limit (7 remote) — fine for typical Reticulum mesh
/// - No transport selection control — MPC picks BLE vs WiFi automatically
public actor MPCInterface: @preconcurrency NetworkInterface {

    // MARK: - Constants

    /// Default service type for Reticulum MPC discovery.
    /// Must be <=15 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphens.
    public static let defaultServiceType = "reticulum"

    // MARK: - Properties

    public let id: String
    public let config: InterfaceConfig
    public private(set) var state: InterfaceState = .disconnected

    /// Hardware MTU — same as AutoInterface (peer-to-peer WiFi, no practical constraint)
    public var hwMtu: Int { 1196 }

    /// MPC service type for advertising/browsing
    private let serviceType: String

    /// Our local peer identity
    private let localPeerID: MCPeerID

    /// Active session
    private var session: MCSession?

    /// Service advertiser
    private var advertiser: MCNearbyServiceAdvertiser?

    /// Service browser
    private var browser: MCNearbyServiceBrowser?

    /// Session delegate (bridging NSObject delegate to actor)
    private var sessionHandler: SessionHandler?

    /// Connected peer interfaces keyed by MCPeerID.displayName
    private var peers: [String: MPCPeerInterface] = [:]

    /// Peer lifecycle callbacks
    private var onPeerAdded: (@Sendable (MPCPeerInterface) -> Void)?
    private var onPeerRemoved: (@Sendable (String) -> Void)?

    /// Delegate
    private var delegateRef: WeakMPCDelegate?

    private let logger = Logger(subsystem: "net.reticulum", category: "MPCInterface")

    // MARK: - Initialization

    /// Create a new MPCInterface.
    ///
    /// - Parameters:
    ///   - config: Interface configuration. `host` field can override service type.
    ///   - displayName: Local peer display name. Defaults to first 8 hex chars of transport identity.
    public init(config: InterfaceConfig, displayName: String? = nil) {
        self.id = config.id
        self.config = config

        // Use host field as service type if non-empty, otherwise default
        let svcType = config.host.isEmpty ? Self.defaultServiceType : config.host
        self.serviceType = svcType

        // Display name for MCPeerID
        let name = displayName ?? config.id
        self.localPeerID = MCPeerID(displayName: name)
    }

    // MARK: - NetworkInterface Protocol

    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self.delegateRef = WeakMPCDelegate(delegate)
    }

    /// Set peer lifecycle callbacks for transport integration.
    ///
    /// - Parameters:
    ///   - onPeerAdded: Called when a new peer connects and its MPCPeerInterface is ready
    ///   - onPeerRemoved: Called with the peer interface ID when a peer disconnects
    public func setPeerCallbacks(
        onPeerAdded: @escaping @Sendable (MPCPeerInterface) -> Void,
        onPeerRemoved: @escaping @Sendable (String) -> Void
    ) {
        self.onPeerAdded = onPeerAdded
        self.onPeerRemoved = onPeerRemoved
    }

    /// Start advertising and browsing for nearby peers.
    public func connect() async throws {
        guard state == .disconnected else { return }

        logger.info("Starting MPC interface \(self.id, privacy: .public) with service type '\(self.serviceType, privacy: .public)'")

        // Create session with no encryption (Reticulum handles its own)
        let session = MCSession(
            peer: localPeerID,
            securityIdentity: nil,
            encryptionPreference: .none
        )
        self.session = session

        // Create and wire session handler
        let handler = SessionHandler(interface: self)
        session.delegate = handler
        self.sessionHandler = handler

        // Start advertising
        let adv = MCNearbyServiceAdvertiser(
            peer: localPeerID,
            discoveryInfo: nil,
            serviceType: serviceType
        )
        adv.delegate = handler
        adv.startAdvertisingPeer()
        self.advertiser = adv

        // Start browsing
        let brw = MCNearbyServiceBrowser(
            peer: localPeerID,
            serviceType: serviceType
        )
        brw.delegate = handler
        brw.startBrowsingForPeers()
        self.browser = brw

        state = .connected
        delegateRef?.delegate?.interface(id: id, didChangeState: .connected)
        logger.info("MPC interface \(self.id, privacy: .public) connected — advertising and browsing")
    }

    /// Stop advertising, browsing, and disconnect all peers.
    public func disconnect() async {
        logger.info("Disconnecting MPC interface \(self.id, privacy: .public)")

        advertiser?.stopAdvertisingPeer()
        advertiser = nil

        browser?.stopBrowsingForPeers()
        browser = nil

        // Remove all peer interfaces
        for (name, peer) in peers {
            await peer.disconnect()
            onPeerRemoved?(peer.id)
            logger.info("Removed MPC peer \(name, privacy: .public)")
        }
        peers.removeAll()

        session?.disconnect()
        session = nil
        sessionHandler = nil

        state = .disconnected
        delegateRef?.delegate?.interface(id: id, didChangeState: .disconnected)
    }

    /// Parent send is a broadcast to all connected peers.
    public func send(_ data: Data) async throws {
        guard state == .connected, let session = session else {
            throw InterfaceError.notConnected
        }
        let connectedPeers = session.connectedPeers
        guard !connectedPeers.isEmpty else { return }

        do {
            try session.send(data, toPeers: connectedPeers, with: .reliable)
        } catch {
            logger.error("MPC broadcast send failed: \(error.localizedDescription, privacy: .public)")
            throw InterfaceError.sendFailed(underlying: error.localizedDescription)
        }
    }

    // MARK: - Peer Management

    /// Called by SessionHandler when a peer connects.
    fileprivate func handlePeerConnected(_ peerID: MCPeerID) {
        let name = peerID.displayName
        guard peers[name] == nil, let session = session else { return }

        let peer = MPCPeerInterface(
            parentId: id,
            peerID: peerID,
            session: session
        )
        peers[name] = peer

        logger.info("MPC peer connected: \(name, privacy: .public)")
        onPeerAdded?(peer)
    }

    /// Called by SessionHandler when a peer disconnects.
    fileprivate func handlePeerDisconnected(_ peerID: MCPeerID) {
        let name = peerID.displayName
        guard let peer = peers.removeValue(forKey: name) else { return }

        logger.info("MPC peer disconnected: \(name, privacy: .public)")

        Task {
            await peer.disconnect()
        }
        onPeerRemoved?(peer.id)
    }

    /// Called by SessionHandler when data arrives from a peer.
    fileprivate func handleDataReceived(_ data: Data, from peerID: MCPeerID) {
        let name = peerID.displayName
        guard let peer = peers[name] else {
            logger.warning("Received data from unknown MPC peer: \(name, privacy: .public)")
            return
        }
        peer.processIncoming(data)
    }

    // MARK: - Status

    /// Number of currently connected peers.
    public var peerCount: Int { peers.count }

    /// Display names of connected peers.
    public var connectedPeerNames: [String] { Array(peers.keys) }

    // MARK: - Internal Accessors (for SessionHandler)

    /// Returns the active MCSession, if any. Used by SessionHandler for invitations.
    func getSession() -> MCSession? { session }

    /// Report an error through the delegate.
    func reportError(_ error: Error) {
        delegateRef?.delegate?.interface(id: id, didFailWithError: error)
    }
}

// MARK: - SessionHandler

/// Bridges MCSession/MCNearbyServiceAdvertiser/MCNearbyServiceBrowser delegates
/// to the MPCInterface actor.
///
/// MCSession delegates must be NSObject subclasses and are called on arbitrary
/// dispatch queues. This handler dispatches events to the actor via Task.
private final class SessionHandler: NSObject,
    MCSessionDelegate,
    MCNearbyServiceAdvertiserDelegate,
    MCNearbyServiceBrowserDelegate,
    @unchecked Sendable
{
    private weak var interface: MPCInterface?
    private let logger = Logger(subsystem: "net.reticulum", category: "MPCSessionHandler")

    init(interface: MPCInterface) {
        self.interface = interface
    }

    // MARK: - MCSessionDelegate

    func session(
        _ session: MCSession,
        peer peerID: MCPeerID,
        didChange state: MCSessionState
    ) {
        guard let interface = interface else { return }

        switch state {
        case .connected:
            logger.info("MCSession peer connected: \(peerID.displayName, privacy: .public)")
            Task { await interface.handlePeerConnected(peerID) }

        case .notConnected:
            logger.info("MCSession peer disconnected: \(peerID.displayName, privacy: .public)")
            Task { await interface.handlePeerDisconnected(peerID) }

        case .connecting:
            logger.debug("MCSession peer connecting: \(peerID.displayName, privacy: .public)")

        @unknown default:
            logger.warning("MCSession unknown state for \(peerID.displayName, privacy: .public)")
        }
    }

    func session(
        _ session: MCSession,
        didReceive data: Data,
        fromPeer peerID: MCPeerID
    ) {
        guard let interface = interface else { return }
        Task { await interface.handleDataReceived(data, from: peerID) }
    }

    func session(
        _ session: MCSession,
        didReceive stream: InputStream,
        withName streamName: String,
        fromPeer peerID: MCPeerID
    ) {
        // Not used — Reticulum uses message-based transport
        stream.close()
    }

    func session(
        _ session: MCSession,
        didStartReceivingResourceWithName resourceName: String,
        fromPeer peerID: MCPeerID,
        with progress: Progress
    ) {
        // Not used
    }

    func session(
        _ session: MCSession,
        didFinishReceivingResourceWithName resourceName: String,
        fromPeer peerID: MCPeerID,
        at localURL: URL?,
        withError error: Error?
    ) {
        // Not used
    }

    // MARK: - MCNearbyServiceAdvertiserDelegate

    func advertiser(
        _ advertiser: MCNearbyServiceAdvertiser,
        didReceiveInvitationFromPeer peerID: MCPeerID,
        withContext context: Data?,
        invitationHandler: @escaping (Bool, MCSession?) -> Void
    ) {
        // Auto-accept all invitations — IFAC provides Reticulum-layer auth if needed
        guard let interface = interface else {
            invitationHandler(false, nil)
            return
        }

        logger.info("Auto-accepting MPC invitation from \(peerID.displayName, privacy: .public)")
        Task {
            let session = await interface.getSession()
            invitationHandler(true, session)
        }
    }

    func advertiser(
        _ advertiser: MCNearbyServiceAdvertiser,
        didNotStartAdvertisingPeer error: Error
    ) {
        logger.error("MPC advertiser failed: \(error.localizedDescription, privacy: .public)")
        guard let interface = interface else { return }
        Task {
            await interface.reportError(
                InterfaceError.connectionFailed(underlying: error.localizedDescription)
            )
        }
    }

    // MARK: - MCNearbyServiceBrowserDelegate

    func browser(
        _ browser: MCNearbyServiceBrowser,
        foundPeer peerID: MCPeerID,
        withDiscoveryInfo info: [String: String]?
    ) {
        guard let interface = interface else { return }

        logger.info("MPC browser found peer: \(peerID.displayName, privacy: .public)")

        // Auto-invite discovered peers
        Task {
            guard let session = await interface.getSession() else { return }
            browser.invitePeer(peerID, to: session, withContext: nil, timeout: 30)
        }
    }

    func browser(
        _ browser: MCNearbyServiceBrowser,
        lostPeer peerID: MCPeerID
    ) {
        logger.info("MPC browser lost peer: \(peerID.displayName, privacy: .public)")
        // MCSession state change handles actual disconnect
    }

    func browser(
        _ browser: MCNearbyServiceBrowser,
        didNotStartBrowsingForPeers error: Error
    ) {
        logger.error("MPC browser failed: \(error.localizedDescription, privacy: .public)")
        guard let interface = interface else { return }
        Task {
            await interface.reportError(
                InterfaceError.connectionFailed(underlying: error.localizedDescription)
            )
        }
    }
}

// MARK: - WeakMPCDelegate

private final class WeakMPCDelegate: @unchecked Sendable {
    weak var delegate: InterfaceDelegate?

    init(_ delegate: InterfaceDelegate) {
        self.delegate = delegate
    }
}

// MARK: - CustomStringConvertible

extension MPCInterface: CustomStringConvertible {
    nonisolated public var description: String {
        "MPCInterface<\(id)>"
    }
}

#endif
