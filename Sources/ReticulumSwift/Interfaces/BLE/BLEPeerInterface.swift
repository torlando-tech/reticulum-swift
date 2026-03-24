// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  BLEPeerInterface.swift
//  ReticulumSwift
//
//  Per-peer BLE mesh sub-interface registered with Transport.
//  Port of BLEPeerInterface.kt from reticulum-kt.
//
//  Each connected BLE mesh peer gets its own BLEPeerInterface actor
//  so Transport can route packets to specific peers via their interface ID.
//

import Foundation
import OSLog

// MARK: - BLE Peer Interface

/// A sub-interface representing a single connected BLE mesh peer.
///
/// BLEInterface spawns one of these for each peer that completes the
/// handshake. Each peer interface is registered with ReticulumTransport
/// independently, allowing the transport layer to route packets to
/// specific peers.
///
/// Handles fragmentation, reassembly, keepalive, and RSSI polling.
public actor BLEPeerInterface: @preconcurrency NetworkInterface {

    // MARK: - NetworkInterface Properties

    public let id: String
    public let config: InterfaceConfig
    public private(set) var state: InterfaceState = .connected

    // MARK: - Peer Properties

    /// Remote peer's identity hash (16 bytes hex string)
    public let peerIdentityHex: String

    /// Whether this is an outgoing (central) connection
    public private(set) var isOutgoing: Bool

    /// Latest RSSI reading
    public private(set) var rssi: Int = 0

    /// Last time we received any data (fragment or keepalive)
    public private(set) var lastActivity: Date = Date()

    /// When this peer connection was established
    public private(set) var connectedAt: Date = Date()

    /// Total bytes sent to this peer
    public private(set) var bytesSent: Int = 0

    /// Total bytes received from this peer
    public private(set) var bytesReceived: Int = 0

    /// Total packets sent to this peer
    public private(set) var packetsSent: Int = 0

    /// Total packets received from this peer
    public private(set) var packetsReceived: Int = 0

    /// Hardware MTU — matches Python RNodeInterface.HW_MTU for BLE radio
    public var hwMtu: Int { 508 }

    /// Current MTU for this connection
    public var mtu: Int {
        connection.mtu
    }

    // MARK: - Internal

    private var connection: any BLEPeerConnection
    private var fragmenter: BLEFragmenter
    private let reassembler: BLEReassembler

    private var receiveTask: Task<Void, Never>?
    private var keepaliveTask: Task<Void, Never>?
    private var rssiTask: Task<Void, Never>?

    private var delegateRef: WeakBLEPeerDelegate?
    private var onDetach: ((String) -> Void)?

    private let logger = Logger(subsystem: "net.reticulum", category: "BLEPeerInterface")

    // MARK: - Init

    /// Create a new BLE peer interface.
    ///
    /// - Parameters:
    ///   - parentId: Parent BLEInterface's ID
    ///   - peerIdentityHex: Remote peer's identity hash as hex string
    ///   - connection: Established BLE connection to this peer
    ///   - isOutgoing: True if we initiated the connection (central role)
    public init(
        parentId: String,
        peerIdentityHex: String,
        connection: any BLEPeerConnection,
        isOutgoing: Bool
    ) {
        self.id = "ble-\(parentId)-\(peerIdentityHex.prefix(8))"
        self.peerIdentityHex = peerIdentityHex
        self.connection = connection
        self.isOutgoing = isOutgoing
        self.fragmenter = BLEFragmenter(mtu: connection.mtu)
        self.reassembler = BLEReassembler()
        self.config = InterfaceConfig(
            id: "ble-\(parentId)-\(peerIdentityHex.prefix(8))",
            name: "BLEPeer[\(peerIdentityHex.prefix(8))]",
            type: .ble,
            enabled: true,
            mode: .full,
            host: peerIdentityHex,
            port: 0
        )
    }

    // MARK: - NetworkInterface Protocol

    public func connect() async throws {
        // Already connected at creation
    }

    public func disconnect() async {
        detach()
    }

    public func send(_ data: Data) async throws {
        guard state == .connected else {
            throw InterfaceError.notConnected
        }

        let fragments = fragmenter.fragment(data)
        for fragment in fragments {
            try await connection.sendFragment(fragment)
        }
        bytesSent += data.count
        packetsSent += 1
    }

    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self.delegateRef = WeakBLEPeerDelegate(delegate)
    }

    // MARK: - Lifecycle

    /// Set the detach callback (called when this peer should be removed).
    public func setOnDetach(_ callback: @escaping @Sendable (String) -> Void) {
        self.onDetach = callback
    }

    /// Start background loops: receive, keepalive, RSSI polling.
    public func startReceiving() {
        // Capture the stream while still on the actor
        let stream = connection.receivedFragments
        receiveTask = Task { [weak self] in
            for await fragment in stream {
                guard !Task.isCancelled else { break }
                guard let self = self else { break }
                await self.handleFragment(fragment)
            }
            // Stream ended — connection lost
            if !Task.isCancelled {
                await self?.detach()
            }
        }

        keepaliveTask = Task { [weak self] in
            var firstFailure = true
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(BLEMeshConstants.keepaliveInterval))
                } catch { break }

                guard let self = self else { break }
                do {
                    try await self.sendKeepalive()
                    firstFailure = true // Reset grace on success
                } catch {
                    if firstFailure {
                        // Grace period: one failure is OK
                        firstFailure = false
                        await self.logDebug("Keepalive failed (grace period)")
                    } else {
                        await self.logDebug("Keepalive failed twice — detaching")
                        await self.detach()
                        break
                    }
                }
            }
        }

        // Only poll RSSI on outgoing connections
        if isOutgoing {
            rssiTask = Task { [weak self] in
                while !Task.isCancelled {
                    do {
                        try await Task.sleep(for: .seconds(BLEMeshConstants.rssiPollInterval))
                    } catch { break }

                    guard let self = self else { break }
                    await self.pollRssi()
                }
            }
        }
    }

    /// Whether this peer's connection appears stale (no activity for staleConnectionThreshold).
    /// Used by BLEInterface to allow MAC-rotated peers to replace stale connections
    /// without waiting for the disconnect event.
    public var isStale: Bool {
        Date().timeIntervalSince(lastActivity) > BLEMeshConstants.staleConnectionThreshold
    }

    /// Update the underlying connection (e.g., after MAC rotation hot-swap).
    /// Resets stats and restarts background loops on the new connection.
    public func updateConnection(_ newConnection: any BLEPeerConnection, isOutgoing newIsOutgoing: Bool) {
        // Cancel existing loops
        receiveTask?.cancel()
        keepaliveTask?.cancel()
        rssiTask?.cancel()

        connection.close()
        connection = newConnection
        self.isOutgoing = newIsOutgoing
        fragmenter = BLEFragmenter(mtu: newConnection.mtu)
        reassembler.reset()
        lastActivity = Date()
        connectedAt = Date()
        bytesSent = 0
        bytesReceived = 0
        packetsSent = 0
        packetsReceived = 0
        state = .connected

        // Restart loops
        startReceiving()
    }

    /// Tear down this peer interface.
    public func detach() {
        guard state == .connected else { return }
        state = .disconnected

        receiveTask?.cancel()
        keepaliveTask?.cancel()
        rssiTask?.cancel()
        receiveTask = nil
        keepaliveTask = nil
        rssiTask = nil

        connection.close()

        delegateRef?.delegate?.interface(id: id, didChangeState: .disconnected)
        onDetach?(peerIdentityHex)

        logger.info("BLEPeerInterface[\(self.peerIdentityHex.prefix(8), privacy: .public)] detached")
    }

    // MARK: - Fragment Handling

    private func handleFragment(_ fragment: Data) {
        lastActivity = Date()
        bytesReceived += fragment.count

        // Filter keepalives (single 0x00 byte)
        if fragment.count == 1 && fragment[fragment.startIndex] == BLEMeshConstants.keepaliveByte {
            return
        }

        // Filter handshake data (exactly 16 bytes = identity)
        if fragment.count == 16 {
            return
        }

        do {
            if let packet = try reassembler.receiveFragment(fragment, senderId: peerIdentityHex) {
                packetsReceived += 1
                delegateRef?.delegate?.interface(id: id, didReceivePacket: packet)
            }
        } catch {
            logger.warning("Reassembly error from \(self.peerIdentityHex.prefix(8), privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    private func sendKeepalive() async throws {
        let data = Data([BLEMeshConstants.keepaliveByte])
        try await connection.sendFragment(data)
    }

    private func pollRssi() {
        Task {
            do {
                let newRssi = try await connection.readRemoteRssi()
                self.rssi = newRssi
            } catch {
                // RSSI poll failure is not critical
            }
        }
    }

    private func logDebug(_ message: String) {
        logger.debug("\(message, privacy: .public)")
    }

    // MARK: - Testing

    /// Set lastActivity to an arbitrary date (for staleness testing).
    internal func setLastActivityForTesting(_ date: Date) {
        lastActivity = date
    }
}

// MARK: - Weak Delegate

private final class WeakBLEPeerDelegate: @unchecked Sendable {
    weak var delegate: InterfaceDelegate?

    init(_ delegate: InterfaceDelegate) {
        self.delegate = delegate
    }
}

// MARK: - CustomStringConvertible

extension BLEPeerInterface: CustomStringConvertible {
    nonisolated public var description: String {
        "BLEPeerInterface<\(id)>"
    }
}
