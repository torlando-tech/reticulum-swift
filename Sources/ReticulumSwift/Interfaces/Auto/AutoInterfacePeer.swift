//
//  AutoInterfacePeer.swift
//  ReticulumSwift
//
//  Per-peer sub-interface registered with Transport for packet routing.
//  Each discovered LAN peer gets its own AutoInterfacePeer instance so
//  Transport can route packets to specific peers via their interface ID.
//

import Foundation
import OSLog

// MARK: - AutoInterfacePeer

/// A sub-interface representing a single discovered LAN peer.
///
/// AutoInterface spawns one of these for each peer found via multicast
/// discovery. Each peer interface is registered with ReticuLumTransport
/// independently, allowing the transport layer to route packets to
/// specific peers.
///
/// Data is sent/received via the parent AutoInterface's UDP data sockets.
/// No HDLC framing is used — UDP preserves message boundaries natively.
public actor AutoInterfacePeer: @preconcurrency NetworkInterface {

    // MARK: - Properties

    /// Unique identifier: "auto-<parentId>-<peerAddr>"
    public let id: String

    /// Interface configuration
    public let config: InterfaceConfig

    /// Current state (connected while peer is alive)
    public private(set) var state: InterfaceState = .connected

    /// Peer's IPv6 link-local address
    public let peerAddress: String

    /// Physical interface name this peer was discovered on
    public let interfaceName: String

    /// Physical interface index
    public let interfaceIndex: UInt32

    /// Parent's data socket for sending
    private let dataSocket: Int32

    /// Data port for peer communication
    private let dataPort: UInt16

    /// Delegate for receiving events.
    /// nonisolated(unsafe) to allow processIncoming() to be called from the parent actor.
    /// Thread safety: WeakInterfaceDelegate is @unchecked Sendable, delegate methods
    /// dispatch to MainActor internally via TransportDelegateWrapper.
    nonisolated(unsafe) private var delegateRef: WeakInterfaceDelegate?

    private let logger = Logger(subsystem: "net.reticulum", category: "AutoInterfacePeer")

    // MARK: - Initialization

    /// Create a new peer sub-interface.
    ///
    /// - Parameters:
    ///   - parentId: Parent AutoInterface's ID
    ///   - peerAddress: Peer's IPv6 link-local address
    ///   - interfaceName: Physical interface name
    ///   - interfaceIndex: Physical interface index
    ///   - dataSocket: Parent's data socket file descriptor for this interface
    ///   - dataPort: Data transfer port
    public init(
        parentId: String,
        peerAddress: String,
        interfaceName: String,
        interfaceIndex: UInt32,
        dataSocket: Int32,
        dataPort: UInt16
    ) {
        self.id = "auto-\(parentId)-\(peerAddress)"
        self.peerAddress = peerAddress
        self.interfaceName = interfaceName
        self.interfaceIndex = interfaceIndex
        self.dataSocket = dataSocket
        self.dataPort = dataPort
        self.config = InterfaceConfig(
            id: "auto-\(parentId)-\(peerAddress)",
            name: "AutoPeer[\(peerAddress)]",
            type: .autoInterface,
            enabled: true,
            mode: .full,
            host: peerAddress,
            port: dataPort
        )
    }

    // MARK: - NetworkInterface Protocol

    /// No-op — peers are already connected when discovered.
    public func connect() async throws {
        // Peers are connected upon creation
    }

    /// Mark peer as disconnected.
    public func disconnect() async {
        state = .disconnected
        delegateRef?.delegate?.interface(id: id, didChangeState: .disconnected)
    }

    /// Send raw packet data to this peer via UDP.
    ///
    /// No framing is needed — UDP preserves message boundaries.
    ///
    /// - Parameter data: Raw Reticulum packet
    /// - Throws: SocketError if send fails
    public func send(_ data: Data) async throws {
        guard state == .connected else {
            throw InterfaceError.notConnected
        }

        try UDPSocketHelper.sendTo(
            dataSocket,
            data: data,
            address: peerAddress,
            port: dataPort,
            interfaceIndex: interfaceIndex
        )
    }

    /// Set the delegate for receiving interface events.
    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self.delegateRef = WeakInterfaceDelegate(delegate)
    }

    // MARK: - Incoming Data

    /// Process an incoming packet from this peer.
    ///
    /// Called by the parent AutoInterface when data arrives from this
    /// peer's address. Deduplication is handled by the parent before
    /// calling this method.
    ///
    /// This is `nonisolated` so the parent AutoInterface actor can call
    /// it synchronously. The delegate call dispatches to MainActor internally.
    ///
    /// - Parameter data: Raw received packet data
    nonisolated public func processIncoming(_ data: Data) {
        delegateRef?.delegate?.interface(id: id, didReceivePacket: data)
    }
}

// MARK: - WeakInterfaceDelegate

/// Weak delegate wrapper for use within actors.
private final class WeakInterfaceDelegate: @unchecked Sendable {
    weak var delegate: InterfaceDelegate?

    init(_ delegate: InterfaceDelegate) {
        self.delegate = delegate
    }
}

// MARK: - CustomStringConvertible

extension AutoInterfacePeer: CustomStringConvertible {
    nonisolated public var description: String {
        "AutoInterfacePeer<\(id)>"
    }
}
