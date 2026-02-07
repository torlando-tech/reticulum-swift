//
//  BLEInterface.swift
//  ReticulumSwift
//
//  Parent/server-style BLE mesh interface.
//  Port of BLEInterface.kt from reticulum-kt.
//
//  Follows the AutoInterface pattern: parent orchestrates discovery
//  and spawns child per-peer actors that register independently
//  with Transport.
//

import Foundation
import OSLog

// MARK: - BLE Interface

/// BLE mesh parent interface that orchestrates peer discovery and lifecycle.
///
/// BLEInterface does not directly send or receive data packets. Instead,
/// it advertises, scans, performs handshakes, and spawns `BLEPeerInterface`
/// sub-interfaces for each connected peer. These sub-interfaces are registered
/// with Transport for packet routing.
///
/// Usage:
/// ```swift
/// let driver = CoreBluetoothBLEDriver(identityHash: myIdentity)
/// let config = InterfaceConfig(
///     id: "ble0", name: "BLE Mesh", type: .ble,
///     enabled: true, mode: .full, host: "", port: 0
/// )
/// let ble = BLEInterface(config: config, driver: driver, transportIdentity: myIdentity)
/// await transport.addBLEInterface(ble)
/// ```
public actor BLEInterface: @preconcurrency NetworkInterface {

    // MARK: - NetworkInterface Protocol

    public let id: String
    public let config: InterfaceConfig
    public private(set) var state: InterfaceState = .disconnected

    // MARK: - Configuration

    private let driver: any BLEDriver
    private let transportIdentity: Data  // 16-byte identity hash

    // MARK: - Peer State

    /// Connected peers keyed by identity hex string
    private var peers: [String: BLEPeerInterface] = [:]

    /// Address → identity hex mapping for reverse lookups
    private var addressToIdentity: [String: String] = [:]

    /// Blacklisted addresses with expiry time
    private var blacklist: [String: Date] = [:]

    /// Backoff multipliers for addresses
    private var backoffMultipliers: [String: Int] = [:]

    // MARK: - Background Tasks

    private var discoveryTask: Task<Void, Never>?
    private var incomingTask: Task<Void, Never>?
    private var disconnectionTask: Task<Void, Never>?
    private var cleanupTask: Task<Void, Never>?
    private var zombieTask: Task<Void, Never>?

    // MARK: - Callbacks

    /// Called when a new peer interface is ready for Transport registration.
    private var onPeerAdded: ((BLEPeerInterface) -> Void)?

    /// Called with peer identity hex when a peer is removed.
    private var onPeerRemoved: ((String) -> Void)?

    // MARK: - Delegate

    private var delegateRef: WeakBLEDelegate?

    private let logger = Logger(subsystem: "net.reticulum", category: "BLEInterface")

    // MARK: - Init

    /// Create a new BLE mesh interface.
    ///
    /// - Parameters:
    ///   - config: Interface configuration (type should be .ble)
    ///   - driver: BLE driver for CoreBluetooth operations
    ///   - transportIdentity: Our 16-byte transport identity hash
    public init(
        config: InterfaceConfig,
        driver: any BLEDriver,
        transportIdentity: Data
    ) {
        precondition(transportIdentity.count == 16, "Transport identity must be 16 bytes")
        self.id = config.id
        self.config = config
        self.driver = driver
        self.transportIdentity = transportIdentity
    }

    // MARK: - Delegate Setup

    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self.delegateRef = WeakBLEDelegate(delegate)
    }

    /// Set peer lifecycle callbacks for Transport integration.
    public func setPeerCallbacks(
        onPeerAdded: @escaping @Sendable (BLEPeerInterface) -> Void,
        onPeerRemoved: @escaping @Sendable (String) -> Void
    ) {
        self.onPeerAdded = onPeerAdded
        self.onPeerRemoved = onPeerRemoved
    }

    // MARK: - Connect

    public func connect() async throws {
        guard state != .connected else { return }

        logger.info("BLEInterface[\(self.id, privacy: .public)] starting")
        state = .connecting
        delegateRef?.delegate?.interface(id: id, didChangeState: .connecting)

        // Start advertising first, then scanning with a small delay
        try await driver.startAdvertising()

        // Brief delay before scanning (matches Kotlin 100ms)
        try await Task.sleep(for: .milliseconds(100))

        try await driver.startScanning()

        // Start background tasks
        startDiscoveryCollection()
        startIncomingCollection()
        startDisconnectionCollection()
        startPeriodicCleanup()
        startZombieDetection()

        state = .connected
        delegateRef?.delegate?.interface(id: id, didChangeState: .connected)
        logger.info("BLEInterface[\(self.id, privacy: .public)] connected")
    }

    // MARK: - Disconnect

    public func disconnect() async {
        logger.info("BLEInterface[\(self.id, privacy: .public)] disconnecting")

        // Cancel all background tasks
        discoveryTask?.cancel()
        incomingTask?.cancel()
        disconnectionTask?.cancel()
        cleanupTask?.cancel()
        zombieTask?.cancel()

        // Detach all peers
        for (identityHex, peer) in peers {
            await peer.detach()
            onPeerRemoved?(peer.id)
            logger.info("Removed peer \(identityHex.prefix(8), privacy: .public)")
        }
        peers.removeAll()
        addressToIdentity.removeAll()

        // Shut down driver
        driver.shutdown()

        state = .disconnected
        delegateRef?.delegate?.interface(id: id, didChangeState: .disconnected)
    }

    // MARK: - Send (no-op on parent)

    /// No-op — all data sends go through BLEPeerInterface.send().
    public func send(_ data: Data) async throws {
        // Parent doesn't send. Transport routes via peer sub-interfaces.
    }

    // MARK: - Task 1: Discovered Peers Collection

    private func startDiscoveryCollection() {
        discoveryTask = Task { [weak self] in
            guard let self = self else { return }
            let stream = await self.getDiscoveredPeers()
            for await discovered in stream {
                guard !Task.isCancelled else { break }
                await self.handleDiscoveredPeer(discovered)
            }
        }
    }

    private nonisolated func getDiscoveredPeers() -> AsyncStream<DiscoveredPeer> {
        driver.discoveredPeers
    }

    private func handleDiscoveredPeer(_ discovered: DiscoveredPeer) async {
        let address = discovered.address

        // Skip if blacklisted
        if let expiry = blacklist[address], Date() < expiry {
            return
        }

        // Skip if RSSI too weak
        guard discovered.rssi >= BLEMeshConstants.minRSSI else { return }

        // Skip if already connected at this address
        if addressToIdentity[address] != nil { return }

        // Check capacity
        if peers.count >= BLEMeshConstants.maxConnections {
            // Try eviction: find weakest peer, evict if new peer is significantly better
            guard let (weakestKey, weakestPeer) = await findWeakestPeer() else { return }
            let weakScore = await weakestPeer.rssi
            let weakRssiNorm = min(1.0, max(0.0, (Double(weakScore) + 100.0) / 60.0))
            let newRssiNorm = min(1.0, max(0.0, (Double(discovered.rssi) + 100.0) / 60.0))

            guard newRssiNorm > weakRssiNorm + BLEMeshConstants.evictionMargin else { return }
            logger.info("Evicting peer \(weakestKey.prefix(8), privacy: .public) for stronger peer at \(address, privacy: .public)")
            await removePeer(identityHex: weakestKey)
        }

        // Connect
        do {
            let connection = try await driver.connect(address: address)
            let identityHex = try await performCentralHandshake(connection: connection)
            await addPeer(identityHex: identityHex, connection: connection, isOutgoing: true)
        } catch {
            logger.debug("Connection to \(address, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            applyBackoff(address: address)
        }
    }

    // MARK: - Task 2: Incoming Connections Collection

    private func startIncomingCollection() {
        incomingTask = Task { [weak self] in
            guard let self = self else { return }
            let stream = await self.getIncomingConnections()
            for await connection in stream {
                guard !Task.isCancelled else { break }
                await self.handleIncomingConnection(connection)
            }
        }
    }

    private nonisolated func getIncomingConnections() -> AsyncStream<any BLEPeerConnection> {
        driver.incomingConnections
    }

    private func handleIncomingConnection(_ connection: any BLEPeerConnection) async {
        let address = connection.address

        // Skip if already connected at this address
        if addressToIdentity[address] != nil {
            connection.close()
            return
        }

        // Check capacity
        guard peers.count < BLEMeshConstants.maxConnections else {
            connection.close()
            return
        }

        // Peripheral handshake: wait for central to write its identity
        do {
            let identityHex = try await performPeripheralHandshake(connection: connection)
            await addPeer(identityHex: identityHex, connection: connection, isOutgoing: false)
        } catch {
            logger.debug("Incoming handshake failed from \(address, privacy: .public): \(error.localizedDescription, privacy: .public)")
            connection.close()
        }
    }

    // MARK: - Task 3: Disconnection Collection

    private func startDisconnectionCollection() {
        disconnectionTask = Task { [weak self] in
            guard let self = self else { return }
            let stream = await self.getConnectionLost()
            for await address in stream {
                guard !Task.isCancelled else { break }
                await self.handleDisconnection(address: address)
            }
        }
    }

    private nonisolated func getConnectionLost() -> AsyncStream<String> {
        driver.connectionLost
    }

    private func handleDisconnection(address: String) async {
        guard let identityHex = addressToIdentity[address] else { return }
        logger.info("Connection lost to \(identityHex.prefix(8), privacy: .public) at \(address, privacy: .public)")
        await removePeer(identityHex: identityHex)
        applyBackoff(address: address)
    }

    // MARK: - Task 4: Periodic Cleanup

    private func startPeriodicCleanup() {
        cleanupTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(30))
                } catch { break }

                guard let self = self else { break }
                await self.cleanupExpired()
            }
        }
    }

    private func cleanupExpired() {
        let now = Date()

        // Expire blacklist entries
        for (address, expiry) in blacklist where now >= expiry {
            blacklist.removeValue(forKey: address)
            backoffMultipliers.removeValue(forKey: address)
        }
    }

    // MARK: - Task 5: Zombie Detection

    private func startZombieDetection() {
        zombieTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(BLEMeshConstants.zombieCheckInterval))
                } catch { break }

                guard let self = self else { break }
                await self.checkZombies()
            }
        }
    }

    private func checkZombies() async {
        let now = Date()
        var zombies: [String] = []

        for (identityHex, peer) in peers {
            let lastActivity = await peer.lastActivity
            if now.timeIntervalSince(lastActivity) > BLEMeshConstants.zombieTimeout {
                zombies.append(identityHex)
            }
        }

        for identityHex in zombies {
            logger.info("Zombie detected: \(identityHex.prefix(8), privacy: .public) — no activity for \(BLEMeshConstants.zombieTimeout)s")
            await removePeer(identityHex: identityHex)
        }
    }

    // MARK: - Handshake

    /// Central-side handshake: read remote identity, write ours.
    private func performCentralHandshake(connection: any BLEPeerConnection) async throws -> String {
        // Read remote identity
        let remoteIdentity = try await withTimeout(seconds: BLEMeshConstants.handshakeTimeout) {
            try await connection.readIdentity()
        }

        guard remoteIdentity.count == 16 else {
            throw InterfaceError.connectionFailed(underlying: "Invalid identity length: \(remoteIdentity.count)")
        }

        let identityHex = remoteIdentity.map { String(format: "%02x", $0) }.joined()

        // Don't connect to ourselves
        guard remoteIdentity != transportIdentity else {
            throw InterfaceError.connectionFailed(underlying: "Connected to self")
        }

        // Write our identity
        try await connection.writeIdentity(transportIdentity)

        return identityHex
    }

    /// Peripheral-side handshake: wait for central to write its identity.
    private func performPeripheralHandshake(connection: any BLEPeerConnection) async throws -> String {
        // Wait for the central to write its 16-byte identity to our RX characteristic
        let remoteIdentity = try await withTimeout(seconds: BLEMeshConstants.handshakeTimeout) {
            for await fragment in connection.receivedFragments {
                if fragment.count == 16 {
                    return fragment
                }
            }
            throw InterfaceError.connectionFailed(underlying: "Handshake stream ended without identity")
        }

        guard remoteIdentity.count == 16 else {
            throw InterfaceError.connectionFailed(underlying: "Invalid identity length: \(remoteIdentity.count)")
        }

        let identityHex = remoteIdentity.map { String(format: "%02x", $0) }.joined()

        // Don't connect to ourselves
        guard remoteIdentity != transportIdentity else {
            throw InterfaceError.connectionFailed(underlying: "Connected to self")
        }

        return identityHex
    }

    // MARK: - Peer Management

    private func addPeer(
        identityHex: String,
        connection: any BLEPeerConnection,
        isOutgoing: Bool
    ) async {
        // MAC rotation check: if same identity exists at different address
        if let existingPeer = peers[identityHex] {
            let existingState = await existingPeer.state
            if existingState == .connected {
                // Healthy existing connection — reject new one
                logger.debug("Rejecting duplicate connection for \(identityHex.prefix(8), privacy: .public) (already connected)")
                connection.close()
                return
            } else {
                // Dead connection — replace
                logger.info("Replacing dead connection for \(identityHex.prefix(8), privacy: .public)")
                await existingPeer.detach()
                onPeerRemoved?(existingPeer.id)
            }
        }

        let peer = BLEPeerInterface(
            parentId: id,
            peerIdentityHex: identityHex,
            connection: connection,
            isOutgoing: isOutgoing
        )

        await peer.setOnDetach { [weak self] identityHex in
            guard let self = self else { return }
            Task {
                await self.removePeer(identityHex: identityHex)
            }
        }

        peers[identityHex] = peer
        addressToIdentity[connection.address] = identityHex

        await peer.startReceiving()

        let direction = isOutgoing ? "outgoing" : "incoming"
        logger.info("Added BLE peer \(identityHex.prefix(8), privacy: .public) (\(direction, privacy: .public)) — \(self.peers.count)/\(BLEMeshConstants.maxConnections) connections")

        onPeerAdded?(peer)
    }

    private func removePeer(identityHex: String) async {
        guard let peer = peers.removeValue(forKey: identityHex) else { return }

        // Remove address mapping
        let address = addressToIdentity.first { $0.value == identityHex }?.key
        if let address = address {
            addressToIdentity.removeValue(forKey: address)
        }

        await peer.detach()
        onPeerRemoved?(peer.id)

        logger.info("Removed BLE peer \(identityHex.prefix(8), privacy: .public) — \(self.peers.count)/\(BLEMeshConstants.maxConnections) connections")
    }

    // MARK: - Backoff / Blacklist

    private func applyBackoff(address: String) {
        let multiplier = backoffMultipliers[address] ?? 1
        let duration = BLEMeshConstants.blacklistBaseInterval * Double(multiplier)
        blacklist[address] = Date().addingTimeInterval(duration)
        backoffMultipliers[address] = min(multiplier * 2, BLEMeshConstants.blacklistMaxMultiplier)
    }

    // MARK: - Eviction

    private func findWeakestPeer() async -> (String, BLEPeerInterface)? {
        var weakest: (String, BLEPeerInterface, Int)?

        for (identityHex, peer) in peers {
            let peerRssi = await peer.rssi
            if weakest == nil || peerRssi < weakest!.2 {
                weakest = (identityHex, peer, peerRssi)
            }
        }

        if let (key, peer, _) = weakest {
            return (key, peer)
        }
        return nil
    }

    // MARK: - Status

    /// Number of connected peers.
    public var peerCount: Int {
        peers.count
    }

    /// List of connected peer identity hex strings.
    public var connectedPeerIdentities: [String] {
        Array(peers.keys)
    }

    // MARK: - Timeout Helper

    private func withTimeout<T: Sendable>(
        seconds: TimeInterval,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask {
                try await operation()
            }
            group.addTask {
                try await Task.sleep(for: .seconds(seconds))
                throw InterfaceError.connectionFailed(underlying: "Handshake timed out after \(Int(seconds))s")
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }
}

// MARK: - Weak Delegate

private final class WeakBLEDelegate: @unchecked Sendable {
    weak var delegate: InterfaceDelegate?

    init(_ delegate: InterfaceDelegate) {
        self.delegate = delegate
    }
}

// MARK: - CustomStringConvertible

extension BLEInterface: CustomStringConvertible {
    nonisolated public var description: String {
        "BLEInterface<\(id)>"
    }
}
