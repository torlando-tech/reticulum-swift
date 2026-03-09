//
//  MPCPeerInterface.swift
//  ReticulumSwift
//
//  Per-peer sub-interface for Multipeer Connectivity sessions.
//  Each connected MPC peer gets its own MPCPeerInterface instance
//  registered with Transport for individual packet routing.
//

#if canImport(MultipeerConnectivity)
import Foundation
import MultipeerConnectivity
import OSLog

// MARK: - MPCPeerInterface

/// A sub-interface representing a single connected Multipeer Connectivity peer.
///
/// MPCInterface spawns one of these for each peer that joins the MCSession.
/// Each peer interface is registered with ReticulumTransport independently,
/// allowing the transport layer to route packets to specific peers.
///
/// MPC preserves message boundaries — no framing is needed.
public actor MPCPeerInterface: @preconcurrency NetworkInterface {

    // MARK: - Properties

    /// Unique identifier: "mpc-<parentId>-<peerDisplayName>"
    public let id: String

    /// Interface configuration
    public let config: InterfaceConfig

    /// Hardware MTU — same as AutoInterface (peer-to-peer WiFi has no practical constraint)
    public var hwMtu: Int { 1196 }

    /// Current state
    public private(set) var state: InterfaceState = .connected

    /// The MPC peer ID for this peer
    public let peerID: MCPeerID

    /// Reference to the parent's MCSession for sending data
    private let session: MCSession

    /// Delegate for receiving events
    nonisolated(unsafe) private var delegateRef: WeakMPCPeerDelegate?

    private let logger = Logger(subsystem: "net.reticulum", category: "MPCPeerInterface")

    // MARK: - Initialization

    /// Create a new MPC peer sub-interface.
    ///
    /// - Parameters:
    ///   - parentId: Parent MPCInterface's ID
    ///   - peerID: The MCPeerID of the connected peer
    ///   - session: The parent's MCSession used for sending
    public init(
        parentId: String,
        peerID: MCPeerID,
        session: MCSession
    ) {
        self.peerID = peerID
        self.session = session
        let peerName = peerID.displayName
        self.id = "mpc-\(parentId)-\(peerName)"
        self.config = InterfaceConfig(
            id: "mpc-\(parentId)-\(peerName)",
            name: "MPCPeer[\(peerName)]",
            type: .multipeerConnectivity,
            enabled: true,
            mode: .full,
            host: peerName,
            port: 0
        )
    }

    // MARK: - NetworkInterface Protocol

    /// No-op — peers are already connected when spawned.
    public func connect() async throws {
        // Peers are connected upon creation
    }

    /// Mark peer as disconnected.
    public func disconnect() async {
        state = .disconnected
        delegateRef?.delegate?.interface(id: id, didChangeState: .disconnected)
    }

    /// Send raw packet data to this peer via MPC.
    ///
    /// MPC preserves message boundaries — no framing needed.
    ///
    /// - Parameter data: Raw Reticulum packet
    /// - Throws: InterfaceError if send fails
    public func send(_ data: Data) async throws {
        guard state == .connected else {
            throw InterfaceError.notConnected
        }

        do {
            try session.send(data, toPeers: [peerID], with: .reliable)
        } catch {
            logger.error("Send to \(self.peerID.displayName, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            throw InterfaceError.sendFailed(underlying: error.localizedDescription)
        }
    }

    /// Set the delegate for receiving interface events.
    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self.delegateRef = WeakMPCPeerDelegate(delegate)
    }

    // MARK: - Incoming Data

    /// Process an incoming packet routed from the parent MPCInterface.
    ///
    /// Called by the parent when data arrives from this peer.
    /// This is `nonisolated` so the parent can call it without await.
    ///
    /// - Parameter data: Raw received packet data
    nonisolated public func processIncoming(_ data: Data) {
        delegateRef?.delegate?.interface(id: id, didReceivePacket: data)
    }
}

// MARK: - WeakMPCPeerDelegate

private final class WeakMPCPeerDelegate: @unchecked Sendable {
    weak var delegate: InterfaceDelegate?

    init(_ delegate: InterfaceDelegate) {
        self.delegate = delegate
    }
}

// MARK: - CustomStringConvertible

extension MPCPeerInterface: CustomStringConvertible {
    nonisolated public var description: String {
        "MPCPeerInterface<\(id)>"
    }
}

#endif
