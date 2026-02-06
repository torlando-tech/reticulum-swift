//
//  AutoInterface.swift
//  ReticulumSwift
//
//  Zero-configuration LAN peer discovery via IPv6 link-local multicast.
//  Equivalent to Python RNS/Interfaces/AutoInterface.py.
//
//  AutoInterface is the parent coordinator that:
//  1. Enumerates local network interfaces for IPv6 link-local addresses
//  2. Creates multicast/unicast/data UDP sockets per physical interface
//  3. Sends periodic discovery beacons (SHA-256 tokens)
//  4. Spawns AutoInterfacePeer sub-interfaces for discovered peers
//  5. Runs peer maintenance (timeout, reverse peering, carrier detection)
//
//  Data transfer happens through AutoInterfacePeer instances, not through
//  this parent interface directly.
//

import Foundation
import OSLog
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// MARK: - Peer Info

/// Tracking information for a discovered peer.
struct PeerInfo {
    let address: String
    let interfaceName: String
    let interfaceIndex: UInt32
    var lastHeard: Date
    var lastReversePeer: Date
}

// MARK: - Deduplication Entry

private struct DedupeEntry {
    let hash: Data
    let time: Date
}

// MARK: - AutoInterface

/// Zero-configuration LAN peer discovery interface.
///
/// AutoInterface discovers peers on the local network using IPv6 link-local
/// multicast. It does not directly send or receive data packets — instead,
/// it spawns `AutoInterfacePeer` sub-interfaces for each discovered peer,
/// which are registered with Transport for packet routing.
///
/// Usage:
/// ```swift
/// let config = InterfaceConfig(
///     id: "auto0", name: "Auto", type: .autoInterface,
///     enabled: true, mode: .full, host: "reticulum", port: 0
/// )
/// let auto = AutoInterface(config: config)
/// await transport.addAutoInterface(auto)
/// ```
public actor AutoInterface: @preconcurrency NetworkInterface {

    // MARK: - NetworkInterface Protocol Properties

    public let id: String
    public let config: InterfaceConfig
    public private(set) var state: InterfaceState = .disconnected

    // MARK: - Configuration

    /// Group ID for discovery (from config.host, default "reticulum")
    private let groupId: Data
    private let groupIdString: String

    /// Computed multicast address from group ID hash
    private let multicastAddress: String

    /// Port configuration
    private let discoveryPort: UInt16
    private let unicastDiscoveryPort: UInt16
    private let dataPort: UInt16

    // MARK: - Per-Interface Sockets

    /// Adopted physical interfaces: [ifname: linkLocalAddress]
    private var adoptedInterfaces: [String: String] = [:]

    /// Multicast discovery sockets (one per physical interface): [ifname: fd]
    private var multicastSockets: [String: Int32] = [:]

    /// Unicast discovery sockets (one per physical interface): [ifname: fd]
    private var unicastSockets: [String: Int32] = [:]

    /// Data transfer sockets (one per physical interface): [ifname: fd]
    private var dataSockets: [String: Int32] = [:]

    // MARK: - Peering State

    /// Known peers: [address: PeerInfo]
    private var peers: [String: PeerInfo] = [:]

    /// Spawned peer sub-interfaces: [address: AutoInterfacePeer]
    private var spawnedInterfaces: [String: AutoInterfacePeer] = [:]

    /// Multicast echo tracking for carrier detection: [ifname: lastEchoTime]
    private var multicastEchoes: [String: Date] = [:]

    /// Our own link-local addresses (for filtering own beacons)
    private var ownAddresses: Set<String> = []

    // MARK: - Deduplication

    private var dedupeBuffer: [DedupeEntry] = []

    // MARK: - Delegate & Callbacks

    private var delegateRef: WeakAutoDelegate?

    /// Callback when a new peer interface is spawned — Transport registers it
    private var onPeerAdded: ((AutoInterfacePeer) -> Void)?

    /// Callback when a peer interface is removed — Transport unregisters it
    private var onPeerRemoved: ((String) -> Void)?

    // MARK: - Background Tasks

    private var announceTask: Task<Void, Never>?
    private var peerJobsTask: Task<Void, Never>?
    private var mcastReceiveTasks: [String: Task<Void, Never>] = [:]
    private var ucastReceiveTasks: [String: Task<Void, Never>] = [:]
    private var dataReceiveTasks: [String: Task<Void, Never>] = [:]

    /// Dedicated queue for blocking socket I/O (poll/recvfrom).
    /// Keeps blocking calls off the actor's cooperative executor.
    private let socketQueue = DispatchQueue(label: "net.reticulum.autointerface.sockets", attributes: .concurrent)

    private let logger = Logger(subsystem: "net.reticulum", category: "AutoInterface")

    // MARK: - Initialization

    /// Create a new AutoInterface.
    ///
    /// - Parameter config: Interface configuration.
    ///   - `config.host`: Group ID (default "reticulum")
    ///   - `config.port`: Discovery port override (0 = use default 29716)
    public init(config: InterfaceConfig) {
        self.id = config.id
        self.config = config

        let gid = config.host.isEmpty ? AutoInterfaceConstants.defaultGroupId : config.host
        self.groupIdString = gid
        self.groupId = gid.data(using: .utf8) ?? Data()
        self.multicastAddress = AutoInterfaceConstants.multicastAddress(for: gid)

        self.discoveryPort = config.port > 0 ? config.port : AutoInterfaceConstants.defaultDiscoveryPort
        self.unicastDiscoveryPort = self.discoveryPort + 1
        self.dataPort = AutoInterfaceConstants.defaultDataPort
    }

    // MARK: - Delegate Setup

    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self.delegateRef = WeakAutoDelegate(delegate)
    }

    /// Set peer lifecycle callbacks for Transport integration.
    ///
    /// - Parameters:
    ///   - onPeerAdded: Called when a new peer is discovered and its interface is ready
    ///   - onPeerRemoved: Called with the peer interface ID when a peer times out
    public func setPeerCallbacks(
        onPeerAdded: @escaping @Sendable (AutoInterfacePeer) -> Void,
        onPeerRemoved: @escaping @Sendable (String) -> Void
    ) {
        self.onPeerAdded = onPeerAdded
        self.onPeerRemoved = onPeerRemoved
    }

    // MARK: - Connect

    /// Start the AutoInterface.
    ///
    /// Enumerates network interfaces, creates sockets, waits for warmup,
    /// then starts discovery and maintenance loops.
    public func connect() async throws {
        guard state != .connected else { return }

        logger.info("AutoInterface[\(self.id, privacy: .public)] starting with group '\(self.groupIdString, privacy: .public)'")
        logger.info("Multicast address: \(self.multicastAddress, privacy: .public)")

        state = .connecting
        delegateRef?.delegate?.interface(id: id, didChangeState: .connecting)

        // Enumerate interfaces
        let interfaces = NetworkInterfaceInfo.enumerateInterfaces()
        guard !interfaces.isEmpty else {
            logger.warning("No suitable network interfaces found")
            state = .connected // Still "connected" — will re-check interfaces periodically
            delegateRef?.delegate?.interface(id: id, didChangeState: .connected)
            return
        }

        logger.info("Found \(interfaces.count) interface(s): \(interfaces.map(\.name).joined(separator: ", "), privacy: .public)")

        // Setup sockets per interface
        for ifInfo in interfaces {
            do {
                try setupInterface(ifInfo)
                adoptedInterfaces[ifInfo.name] = ifInfo.linkLocalAddress
                ownAddresses.insert(ifInfo.linkLocalAddress)
                logger.info("Adopted interface \(ifInfo.name, privacy: .public) with \(ifInfo.linkLocalAddress, privacy: .public)")
            } catch {
                logger.error("Failed to setup \(ifInfo.name, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }

        guard !adoptedInterfaces.isEmpty else {
            throw InterfaceError.connectionFailed(underlying: "No interfaces could be adopted")
        }

        // Warmup: wait before starting peer jobs so we hear initial beacons
        let warmup = AutoInterfaceConstants.announceInterval * AutoInterfaceConstants.warmupMultiplier
        logger.info("Warmup: waiting \(warmup, privacy: .public)s before starting peer jobs")

        // Start receive loops immediately (to collect beacons during warmup)
        startReceiveLoops()

        // Start announce loop immediately
        startAnnounceLoop()

        // Wait for warmup
        try await Task.sleep(for: .seconds(warmup))

        // Start peer maintenance
        startPeerJobsLoop()

        state = .connected
        delegateRef?.delegate?.interface(id: id, didChangeState: .connected)
        logger.info("AutoInterface[\(self.id, privacy: .public)] connected with \(self.adoptedInterfaces.count) interface(s)")
    }

    // MARK: - Disconnect

    public func disconnect() async {
        logger.info("AutoInterface[\(self.id, privacy: .public)] disconnecting")

        // Cancel all background tasks
        announceTask?.cancel()
        peerJobsTask?.cancel()
        for task in mcastReceiveTasks.values { task.cancel() }
        for task in ucastReceiveTasks.values { task.cancel() }
        for task in dataReceiveTasks.values { task.cancel() }
        mcastReceiveTasks.removeAll()
        ucastReceiveTasks.removeAll()
        dataReceiveTasks.removeAll()

        // Teardown spawned peers
        for (addr, peer) in spawnedInterfaces {
            await peer.disconnect()
            onPeerRemoved?(peer.id)
            logger.info("Removed peer \(addr, privacy: .public)")
        }
        spawnedInterfaces.removeAll()
        peers.removeAll()

        // Close all sockets
        for (_, fd) in multicastSockets { UDPSocketHelper.close(fd) }
        for (_, fd) in unicastSockets { UDPSocketHelper.close(fd) }
        for (_, fd) in dataSockets { UDPSocketHelper.close(fd) }
        multicastSockets.removeAll()
        unicastSockets.removeAll()
        dataSockets.removeAll()
        adoptedInterfaces.removeAll()
        ownAddresses.removeAll()

        state = .disconnected
        delegateRef?.delegate?.interface(id: id, didChangeState: .disconnected)
    }

    // MARK: - Send (no-op on parent)

    /// No-op — all data sends go through AutoInterfacePeer.send().
    ///
    /// The parent AutoInterface coordinates discovery only. Data is routed
    /// through the per-peer sub-interfaces that Transport manages directly.
    public func send(_ data: Data) async throws {
        // Broadcast: send to all peers via their data sockets
        for (_, peer) in spawnedInterfaces {
            try? await peer.send(data)
        }
    }

    // MARK: - Socket Setup

    /// Setup multicast, unicast, and data sockets for one physical interface.
    private func setupInterface(_ ifInfo: NetworkInterfaceInfo) throws {
        // 1. Multicast discovery socket
        let mcastFd = try UDPSocketHelper.createIPv6Socket()
        try UDPSocketHelper.setMulticastInterface(mcastFd, interfaceIndex: ifInfo.index)
        try UDPSocketHelper.setMulticastLoopback(mcastFd, enabled: true)
        try UDPSocketHelper.joinMulticastGroup(mcastFd, group: multicastAddress, interfaceIndex: ifInfo.index)
        try UDPSocketHelper.bindAny(mcastFd, port: discoveryPort)
        try UDPSocketHelper.setNonBlocking(mcastFd)
        multicastSockets[ifInfo.name] = mcastFd

        // 2. Unicast discovery socket
        let ucastFd = try UDPSocketHelper.createIPv6Socket()
        try UDPSocketHelper.bind(ucastFd, address: ifInfo.linkLocalAddress, port: unicastDiscoveryPort, interfaceIndex: ifInfo.index)
        try UDPSocketHelper.setNonBlocking(ucastFd)
        unicastSockets[ifInfo.name] = ucastFd

        // 3. Data socket
        let dataFd = try UDPSocketHelper.createIPv6Socket()
        try UDPSocketHelper.bind(dataFd, address: ifInfo.linkLocalAddress, port: dataPort, interfaceIndex: ifInfo.index)
        try UDPSocketHelper.setNonBlocking(dataFd)
        dataSockets[ifInfo.name] = dataFd
    }

    // MARK: - Announce Loop

    /// Periodically send discovery beacons to the multicast group.
    private func startAnnounceLoop() {
        announceTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(AutoInterfaceConstants.announceInterval))
                } catch {
                    break
                }

                guard let self = self else { break }
                await self.sendAnnounces()
            }
        }
    }

    /// Send discovery beacons on all adopted interfaces.
    private func sendAnnounces() {
        for (ifname, address) in adoptedInterfaces {
            guard let mcastFd = multicastSockets[ifname] else { continue }

            let token = AutoInterfaceConstants.discoveryToken(groupId: groupId, address: address)

            do {
                // Find interface index
                let ifIndex = if_nametoindex(ifname)
                try UDPSocketHelper.sendTo(
                    mcastFd,
                    data: token,
                    address: multicastAddress,
                    port: discoveryPort,
                    interfaceIndex: ifIndex
                )
            } catch {
                logger.debug("Announce send failed on \(ifname, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    // MARK: - Receive Loops

    /// Start receive loops for all socket types on all interfaces.
    ///
    /// Runs blocking poll()/recvfrom() on a dedicated DispatchQueue to avoid
    /// starving the actor's cooperative executor.
    private func startReceiveLoops() {
        for (ifname, _) in adoptedInterfaces {
            // Multicast discovery receive
            if let fd = multicastSockets[ifname] {
                let name = ifname
                mcastReceiveTasks[ifname] = Task { [weak self] in
                    await self?.receiveLoop(socket: fd, ifname: name, isDiscovery: true)
                }
            }

            // Unicast discovery receive
            if let fd = unicastSockets[ifname] {
                let name = ifname
                ucastReceiveTasks[ifname] = Task { [weak self] in
                    await self?.receiveLoop(socket: fd, ifname: name, isDiscovery: true)
                }
            }

            // Data receive
            if let fd = dataSockets[ifname] {
                let name = ifname
                dataReceiveTasks[ifname] = Task { [weak self] in
                    await self?.receiveLoop(socket: fd, ifname: name, isDiscovery: false)
                }
            }
        }
    }

    /// Generic receive loop for a single socket.
    ///
    /// Runs blocking poll()/recvfrom() on a DispatchQueue, then hops to the
    /// actor only for processing received data. This prevents the blocking
    /// POSIX calls from starving the actor's cooperative executor.
    private func receiveLoop(socket fd: Int32, ifname: String, isDiscovery: Bool) async {
        while !Task.isCancelled {
            // Run blocking poll+recv on a dedicated queue, not the actor
            let result: (Data, String)? = await withCheckedContinuation { continuation in
                socketQueue.async {
                    var pollFd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                    let pollResult = poll(&pollFd, 1, 500) // 500ms timeout

                    guard pollResult > 0 else {
                        continuation.resume(returning: nil)
                        return
                    }

                    do {
                        let (data, sourceAddr, _) = try UDPSocketHelper.receiveFrom(fd)
                        continuation.resume(returning: (data, sourceAddr))
                    } catch {
                        continuation.resume(returning: nil)
                    }
                }
            }

            // Process on the actor
            if let (data, sourceAddr) = result {
                if isDiscovery {
                    handleDiscoveryPacket(data: data, sourceAddress: sourceAddr, ifname: ifname)
                } else {
                    handleDataPacket(data: data, sourceAddress: sourceAddr, ifname: ifname)
                }
            }
        }
    }

    // MARK: - Discovery Handling

    /// Process an incoming discovery beacon.
    ///
    /// Validates the 32-byte token against SHA-256(groupId + sourceAddress).
    /// If the source is our own address, tracks it as a multicast echo for
    /// carrier detection. Otherwise, adds the source as a peer.
    private func handleDiscoveryPacket(data: Data, sourceAddress: String, ifname: String) {
        // Discovery tokens are exactly 32 bytes (SHA-256)
        guard data.count == 32 else { return }

        // Validate token: should be SHA256(groupId + sourceAddress)
        let expectedToken = AutoInterfaceConstants.discoveryToken(groupId: groupId, address: sourceAddress)
        guard data == expectedToken else {
            logger.debug("Invalid discovery token from \(sourceAddress, privacy: .public)")
            return
        }

        // Check if this is our own echo
        if ownAddresses.contains(sourceAddress) {
            multicastEchoes[ifname] = Date()
            return
        }

        // Add or refresh peer
        let ifIndex = if_nametoindex(ifname)
        addPeer(address: sourceAddress, ifname: ifname, ifIndex: ifIndex)
    }

    // MARK: - Data Handling

    /// Process an incoming data packet.
    ///
    /// Routes the packet to the appropriate peer sub-interface after
    /// deduplication.
    private func handleDataPacket(data: Data, sourceAddress: String, ifname: String) {
        guard !data.isEmpty else { return }

        // Deduplicate
        guard !isDuplicate(data) else { return }

        // Route to peer
        if let peer = spawnedInterfaces[sourceAddress] {
            peer.processIncoming(data)
        } else {
            // Data from unknown peer — might be a new peer that we haven't
            // discovered yet. Accept and add peer.
            let ifIndex = if_nametoindex(ifname)
            addPeer(address: sourceAddress, ifname: ifname, ifIndex: ifIndex)

            // Process the data through the newly created peer
            if let peer = spawnedInterfaces[sourceAddress] {
                peer.processIncoming(data)
            }
        }
    }

    // MARK: - Peer Management

    /// Add or refresh a peer.
    ///
    /// If the peer is new, spawns an AutoInterfacePeer sub-interface and
    /// notifies Transport via the onPeerAdded callback.
    private func addPeer(address: String, ifname: String, ifIndex: UInt32) {
        let now = Date()

        if var existing = peers[address] {
            // Refresh existing peer
            existing.lastHeard = now
            peers[address] = existing
            return
        }

        // New peer
        logger.info("Discovered peer \(address, privacy: .public) on \(ifname, privacy: .public)")

        peers[address] = PeerInfo(
            address: address,
            interfaceName: ifname,
            interfaceIndex: ifIndex,
            lastHeard: now,
            lastReversePeer: .distantPast
        )

        // Spawn peer sub-interface
        guard let dataFd = dataSockets[ifname] else {
            logger.error("No data socket for \(ifname, privacy: .public), cannot spawn peer")
            return
        }

        let peer = AutoInterfacePeer(
            parentId: id,
            peerAddress: address,
            interfaceName: ifname,
            interfaceIndex: ifIndex,
            dataSocket: dataFd,
            dataPort: dataPort
        )

        spawnedInterfaces[address] = peer
        onPeerAdded?(peer)

        // Send reverse unicast peering immediately
        sendReversePeering(to: address, on: ifname, ifIndex: ifIndex)
    }

    /// Remove a timed-out peer.
    private func removePeer(address: String) {
        guard let peer = spawnedInterfaces[address] else { return }
        logger.info("Peer timed out: \(address, privacy: .public)")

        Task { await peer.disconnect() }
        onPeerRemoved?(peer.id)
        spawnedInterfaces.removeValue(forKey: address)
        peers.removeValue(forKey: address)
    }

    /// Send a unicast discovery token to a specific peer (reverse peering).
    ///
    /// This ensures the remote peer also discovers us, even if it missed
    /// our multicast beacon.
    private func sendReversePeering(to address: String, on ifname: String, ifIndex: UInt32) {
        guard let ucastFd = unicastSockets[ifname],
              let ownAddress = adoptedInterfaces[ifname] else { return }

        let token = AutoInterfaceConstants.discoveryToken(groupId: groupId, address: ownAddress)

        do {
            try UDPSocketHelper.sendTo(
                ucastFd,
                data: token,
                address: address,
                port: unicastDiscoveryPort,
                interfaceIndex: ifIndex
            )
        } catch {
            logger.debug("Reverse peering to \(address, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - Peer Maintenance Loop

    /// Periodically check peer timeouts and send reverse peering.
    private func startPeerJobsLoop() {
        peerJobsTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(AutoInterfaceConstants.peerJobInterval))
                } catch {
                    break
                }

                guard let self = self else { break }
                await self.runPeerJobs()
            }
        }
    }

    /// Run peer maintenance: timeout check, reverse peering, carrier detection.
    private func runPeerJobs() {
        let now = Date()

        // Check peer timeouts
        var timedOut: [String] = []
        for (addr, info) in peers {
            if now.timeIntervalSince(info.lastHeard) > AutoInterfaceConstants.peeringTimeout {
                timedOut.append(addr)
            }
        }
        for addr in timedOut {
            removePeer(address: addr)
        }

        // Send reverse peering to live peers periodically
        for (addr, info) in peers {
            if now.timeIntervalSince(info.lastReversePeer) > AutoInterfaceConstants.reversePeeringInterval {
                sendReversePeering(to: addr, on: info.interfaceName, ifIndex: info.interfaceIndex)
                peers[addr]?.lastReversePeer = now
            }
        }

        // Check multicast echo timeouts (carrier detection)
        for (ifname, lastEcho) in multicastEchoes {
            if now.timeIntervalSince(lastEcho) > AutoInterfaceConstants.multicastEchoTimeout {
                logger.debug("Multicast echo timeout on \(ifname, privacy: .public) — carrier may be lost")
                multicastEchoes.removeValue(forKey: ifname)
            }
        }
    }

    // MARK: - Deduplication

    /// Check if a packet is a duplicate (seen within TTL window).
    ///
    /// Uses a ring buffer of packet hashes with time-based expiry.
    /// Matching Python: MULTI_IF_DEQUE_LEN = 48, MULTI_IF_DEQUE_TTL = 0.75s
    private func isDuplicate(_ data: Data) -> Bool {
        let hash = Hashing.fullHash(data)
        let now = Date()

        // Prune expired entries
        dedupeBuffer.removeAll { now.timeIntervalSince($0.time) > AutoInterfaceConstants.multiIfDequeTTL }

        // Check for match
        if dedupeBuffer.contains(where: { $0.hash == hash }) {
            return true
        }

        // Add to buffer
        dedupeBuffer.append(DedupeEntry(hash: hash, time: now))
        if dedupeBuffer.count > AutoInterfaceConstants.multiIfDequeLen {
            dedupeBuffer.removeFirst()
        }

        return false
    }

    // MARK: - Status

    /// Number of discovered peers.
    public var peerCount: Int {
        peers.count
    }

    /// Number of adopted physical interfaces.
    public var adoptedInterfaceCount: Int {
        adoptedInterfaces.count
    }

    /// List of currently known peer addresses.
    public var peerAddresses: [String] {
        Array(peers.keys)
    }
}

// MARK: - WeakAutoDelegate

private final class WeakAutoDelegate: @unchecked Sendable {
    weak var delegate: InterfaceDelegate?

    init(_ delegate: InterfaceDelegate) {
        self.delegate = delegate
    }
}

// MARK: - CustomStringConvertible

extension AutoInterface: CustomStringConvertible {
    nonisolated public var description: String {
        "AutoInterface<\(id)>"
    }
}
