//
//  ReticuLumTransport.swift
//  ReticulumSwift
//
//  Central transport actor for Reticulum packet routing.
//  Dispatches outbound packets to interfaces and routes inbound packets
//  to local destinations.
//
//  This is the core routing engine that connects:
//  - Interfaces (TCP connections to relays)
//  - PathTable (routing information from announces)
//  - Destinations (local registered destinations)
//  - CallbackManager (packet delivery to app)
//

import Foundation
import OSLog
import Security

// MARK: - Interface Protocol

/// Protocol for network interfaces that can send and receive packets.
///
/// This protocol abstracts the interface layer so ReticuLumTransport
/// can work with any interface type (TCP, UDP, etc.).
///
/// TCPInterface (created in Plan 04-03) will implement this protocol.
public protocol NetworkInterface: AnyObject, Sendable {
    /// Unique identifier for this interface
    var id: String { get }

    /// Interface configuration
    var config: InterfaceConfig { get }

    /// Current connection state
    var state: InterfaceState { get }

    /// Connect to the interface
    func connect() async throws

    /// Disconnect from the interface
    func disconnect() async

    /// Send data through the interface
    func send(_ data: Data) async throws

    /// Set the delegate for receiving events
    func setDelegate(_ delegate: InterfaceDelegate) async
}

// MARK: - ReticuLumTransport Actor

/// Central transport actor for Reticulum packet routing.
///
/// ReticuLumTransport is the core routing engine that:
/// - Dispatches outbound broadcast packets (HEADER_1) to all interfaces
/// - Dispatches outbound routed packets (HEADER_2) via path table lookup
/// - Routes inbound packets to registered local destinations
/// - Manages interface lifecycle (add/remove)
/// - Registers destinations for packet delivery
///
/// Example usage:
/// ```swift
/// let transport = ReticuLumTransport()
///
/// // Add an interface
/// let interface = await TCPInterface(config: config)
/// await transport.addInterface(interface)
///
/// // Register a destination
/// let dest = Destination(identity: myIdentity, appName: "myapp")
/// await transport.registerDestination(dest)
///
/// // Send a packet
/// try await transport.send(packet: myPacket)
/// ```
public actor ReticuLumTransport {

    // MARK: - Properties

    /// Path table for routing lookups
    private let pathTable: PathTable

    /// Callback manager for packet delivery
    private let callbackManager: DefaultCallbackManager

    /// Announce handler for processing received announces
    private let announceHandler: AnnounceHandler

    /// Announce table for scheduled retransmissions (Python Transport.announce_table)
    private let announceTable = AnnounceTable()

    /// Whether this node acts as a transport/relay node.
    /// When enabled, all valid announces are rebroadcast.
    /// When disabled, only announces for local destinations are rebroadcast.
    /// Reference: Python Transport.py:1741 (RNS.Reticulum.transport_enabled())
    public var transportEnabled: Bool = false

    /// Local transport identity hash (16 bytes).
    /// Used as transport_id in HEADER_2 retransmissions.
    /// Set when transport mode is enabled.
    public var transportIdentityHash: Data?

    /// Task handle for periodic announce retransmission
    private var retransmissionTask: Task<Void, Never>?

    /// Registered interfaces by ID
    private var interfaces: [String: any NetworkInterface] = [:]

    /// Delegate wrappers for each interface (needed to prevent deallocation)
    private var delegateWrappers: [String: TransportDelegateWrapper] = [:]

    /// Registered local destinations by hash
    private var destinations: [Data: Destination] = [:]

    /// Logger for transport events
    private let logger: Logger

    // MARK: - Link Management Properties

    /// Active links indexed by link ID
    private var activeLinks: [Data: Link] = [:]

    /// Pending link requests awaiting PROOF (indexed by link ID)
    private var pendingLinks: [Data: Link] = [:]

    // MARK: - Packet Proof Properties

    /// Pending packet proof callbacks (key = full 32-byte packet hash).
    /// When a link DATA packet proof arrives, the continuation is resumed with `true`.
    /// On timeout, resumed with `false`.
    private var pendingPacketProofs: [Data: CheckedContinuation<Bool, Never>] = [:]

    // MARK: - Path Request Properties

    /// Timestamps of recent path requests for throttling
    private var pathRequestTimestamps: [Data: Date] = [:]

    /// Cooldown period between path requests for same destination (seconds)
    private let pathRequestCooldown: TimeInterval = 5.0

    /// Packets waiting for path discovery
    private var pendingPackets: [Data: [Packet]] = [:]

    /// Maximum packets to queue per destination
    private let maxPendingPacketsPerDestination: Int = 10

    // MARK: - Initialization

    /// Create a new transport with optional dependency injection.
    ///
    /// - Parameters:
    ///   - pathTable: Path table for routing (defaults to new empty table)
    ///   - callbackManager: Callback manager for delivery (defaults to new manager)
    public init(
        pathTable: PathTable = PathTable(),
        callbackManager: DefaultCallbackManager = DefaultCallbackManager()
    ) {
        self.pathTable = pathTable
        self.callbackManager = callbackManager
        self.announceHandler = AnnounceHandler(pathTable: pathTable)
        self.logger = Logger(subsystem: "com.columba.core", category: "ReticuLumTransport")
    }

    // MARK: - Interface Management

    /// Add a network interface.
    ///
    /// The interface will be connected automatically and registered for events.
    ///
    /// - Parameter interface: Interface to add
    /// - Throws: InterfaceError if connection fails
    public func addInterface(_ interface: any NetworkInterface) async throws {
        let id = interface.id
        logger.info("Adding interface: \(id, privacy: .public)")

        // Store the interface
        interfaces[id] = interface

        // Create and store delegate wrapper to forward events to this actor
        let wrapper = TransportDelegateWrapper(transport: self)
        delegateWrappers[id] = wrapper

        // Set wrapper as delegate
        await interface.setDelegate(wrapper)

        // Connect the interface
        try await interface.connect()

        logger.info("Interface \(id, privacy: .public) added and connected")
    }

    /// Remove a network interface.
    ///
    /// The interface will be disconnected before removal.
    ///
    /// - Parameter id: Interface ID to remove
    public func removeInterface(id: String) async {
        guard let interface = interfaces[id] else {
            logger.warning("Attempted to remove non-existent interface: \(id, privacy: .public)")
            return
        }

        logger.info("Removing interface: \(id, privacy: .public)")
        await interface.disconnect()
        interfaces.removeValue(forKey: id)
        delegateWrappers.removeValue(forKey: id)
    }

    /// Add an AutoInterface with peer lifecycle management.
    ///
    /// AutoInterface spawns sub-interfaces for each discovered peer.
    /// This method registers the parent for state tracking and wires up
    /// callbacks so discovered peers are automatically added to / removed
    /// from this transport.
    ///
    /// - Parameter autoInterface: The AutoInterface to add
    /// - Throws: InterfaceError if connection fails
    public func addAutoInterface(_ autoInterface: AutoInterface) async throws {
        let parentId = autoInterface.id
        logger.info("Adding AutoInterface: \(parentId, privacy: .public)")

        // Register parent for state tracking
        interfaces[parentId] = autoInterface
        let wrapper = TransportDelegateWrapper(transport: self)
        delegateWrappers[parentId] = wrapper
        await autoInterface.setDelegate(wrapper)

        // Wire peer lifecycle callbacks
        await autoInterface.setPeerCallbacks(
            onPeerAdded: { [weak self] peer in
                guard let self = self else { return }
                Task {
                    try? await self.addInterface(peer)
                }
            },
            onPeerRemoved: { [weak self] peerId in
                guard let self = self else { return }
                Task {
                    await self.removeInterface(id: peerId)
                }
            }
        )

        // Start the interface (discovery begins)
        try await autoInterface.connect()
        logger.info("AutoInterface \(parentId, privacy: .public) connected")
    }

    /// Add a BLEInterface with peer lifecycle management.
    ///
    /// BLEInterface spawns sub-interfaces for each connected BLE mesh peer.
    /// This method registers the parent for state tracking and wires up
    /// callbacks so discovered peers are automatically added to / removed
    /// from this transport.
    ///
    /// - Parameter bleInterface: The BLEInterface to add
    /// - Throws: InterfaceError if connection fails
    public func addBLEInterface(_ bleInterface: BLEInterface) async throws {
        let parentId = bleInterface.id
        logger.info("Adding BLEInterface: \(parentId, privacy: .public)")

        // Register parent for state tracking
        interfaces[parentId] = bleInterface
        let wrapper = TransportDelegateWrapper(transport: self)
        delegateWrappers[parentId] = wrapper
        await bleInterface.setDelegate(wrapper)

        // Wire peer lifecycle callbacks
        await bleInterface.setPeerCallbacks(
            onPeerAdded: { [weak self] peer in
                guard let self = self else { return }
                Task {
                    try? await self.addInterface(peer)
                }
            },
            onPeerRemoved: { [weak self] peerId in
                guard let self = self else { return }
                Task {
                    await self.removeInterface(id: peerId)
                }
            }
        )

        // Start the interface (advertising + scanning begins)
        try await bleInterface.connect()
        logger.info("BLEInterface \(parentId, privacy: .public) connected")
    }

    /// Get an interface by ID.
    ///
    /// - Parameter id: Interface ID
    /// - Returns: Interface if found, nil otherwise
    public func getInterface(id: String) -> (any NetworkInterface)? {
        return interfaces[id]
    }

    /// Number of registered interfaces.
    public var interfaceCount: Int {
        interfaces.count
    }

    /// All interface IDs.
    public var interfaceIds: [String] {
        Array(interfaces.keys)
    }

    /// Snapshot of a registered interface's key properties.
    public struct InterfaceSnapshot: Sendable {
        public let id: String
        public let name: String
        public let type: InterfaceType
        public let state: InterfaceState
        /// True if this is an AutoInterfacePeer (spawned sub-interface)
        public let isAutoInterfacePeer: Bool
        /// True if this is a BLEPeerInterface (spawned BLE mesh sub-interface)
        public let isBLEPeerInterface: Bool
        /// For AutoInterfacePeers, the peer's IPv6 link-local address.
        /// For BLEPeerInterfaces, the peer's identity hex.
        public let peerAddress: String?
        /// Last error description (if interface failed to connect)
        public let lastErrorDescription: String?
    }

    /// Resolve an interface ID to a human-readable name.
    ///
    /// Returns the interface config name (e.g. "Relay Server", "Auto Discovery")
    /// or a formatted type name if the interface is no longer registered.
    /// For AutoInterface peers, includes the peer address.
    public func getInterfaceName(for interfaceId: String) async -> String? {
        if let iface = interfaces[interfaceId] {
            if let peer = iface as? AutoInterfacePeer {
                let addr = await peer.peerAddress
                return "AutoInterface [\(addr)]"
            }
            if let blePeer = iface as? BLEPeerInterface {
                let identityHex = await blePeer.peerIdentityHex
                return "BLE [\(identityHex.prefix(8))]"
            }
            let config = iface.config
            return "\(config.name) (\(config.type.rawValue.uppercased()))"
        }
        // Interface might have been removed — try to infer from ID pattern
        if interfaceId.hasPrefix("auto-") {
            // AutoInterface peer: "auto-auto0-fe80::..."
            let parts = interfaceId.split(separator: "-", maxSplits: 2)
            if parts.count >= 3 {
                return "AutoInterface [\(parts[2])]"
            }
            return "AutoInterface"
        }
        if interfaceId.hasPrefix("ble-") {
            let parts = interfaceId.split(separator: "-", maxSplits: 2)
            if parts.count >= 3 {
                return "BLE [\(parts[2])]"
            }
            return "BLE Mesh"
        }
        return nil
    }

    /// Get a snapshot of all registered interfaces and their states.
    public func getInterfaceSnapshots() async -> [InterfaceSnapshot] {
        var snapshots: [InterfaceSnapshot] = []
        for (_, iface) in interfaces {
            let state = await iface.state
            let config = iface.config
            // Get error description from TCPInterface if available
            let errorDesc: String?
            if let tcp = iface as? TCPInterface {
                errorDesc = await tcp.lastErrorDescription
            } else {
                errorDesc = nil
            }
            if let peer = iface as? AutoInterfacePeer {
                let addr = await peer.peerAddress
                snapshots.append(InterfaceSnapshot(
                    id: iface.id,
                    name: config.name,
                    type: config.type,
                    state: state,
                    isAutoInterfacePeer: true,
                    isBLEPeerInterface: false,
                    peerAddress: addr,
                    lastErrorDescription: errorDesc
                ))
            } else if let blePeer = iface as? BLEPeerInterface {
                let identityHex = await blePeer.peerIdentityHex
                snapshots.append(InterfaceSnapshot(
                    id: iface.id,
                    name: config.name,
                    type: config.type,
                    state: state,
                    isAutoInterfacePeer: false,
                    isBLEPeerInterface: true,
                    peerAddress: identityHex,
                    lastErrorDescription: errorDesc
                ))
            } else {
                snapshots.append(InterfaceSnapshot(
                    id: iface.id,
                    name: config.name,
                    type: config.type,
                    state: state,
                    isAutoInterfacePeer: false,
                    isBLEPeerInterface: false,
                    peerAddress: nil,
                    lastErrorDescription: errorDesc
                ))
            }
        }
        return snapshots.sorted { $0.id < $1.id }
    }

    // MARK: - Destination Registration

    /// Register a local destination for packet delivery.
    ///
    /// Once registered, packets addressed to this destination will be
    /// delivered via the callback manager.
    ///
    /// - Parameter destination: Destination to register
    public func registerDestination(_ destination: Destination) {
        let hash = destination.hash
        destinations[hash] = destination
        destination.setCallbackManager(callbackManager)

        let hexFull = hash.map { String(format: "%02x", $0) }.joined()
        print("[LXMF_INBOUND] registerDestination: hash=\(hexFull)")
        print("[LXMF_INBOUND] destinations count=\(destinations.count)")
        logger.info("Registered destination: \(hexFull.prefix(8), privacy: .public)...")
    }

    /// Unregister a local destination.
    ///
    /// Packets addressed to this destination will no longer be delivered.
    ///
    /// - Parameter hash: 16-byte destination hash
    public func unregisterDestination(hash: Data) {
        if destinations.removeValue(forKey: hash) != nil {
            let hexPrefix = hash.prefix(4).map { String(format: "%02x", $0) }.joined()
            logger.info("Unregistered destination: \(hexPrefix, privacy: .public)...")
        }
    }

    /// Check if a destination hash is registered locally.
    ///
    /// - Parameter hash: 16-byte destination hash
    /// - Returns: true if destination is registered
    public func isLocalDestination(_ hash: Data) -> Bool {
        return destinations[hash] != nil
    }

    /// Number of registered destinations.
    public var destinationCount: Int {
        destinations.count
    }

    // MARK: - Link Management

    /// Initiate a link to a destination.
    ///
    /// Creates a new outbound Link, registers it as pending, and sends the
    /// LINKREQUEST packet. The link will be moved to active once PROOF is received.
    ///
    /// - Parameters:
    ///   - destination: Target destination
    ///   - identity: Local identity for authentication
    /// - Returns: The created Link actor
    /// - Throws: TransportError if destination has no known path
    public func initiateLink(to destination: Destination, identity: Identity) async throws -> Link {
        // Check we have a path to the destination
        guard await pathTable.hasPath(for: destination.hash) else {
            throw TransportError.noPathAvailable(destinationHash: destination.hash)
        }

        // Create link
        let link = Link(destination: destination, identity: identity)

        // Set send callback - sends raw packet bytes to all interfaces
        // The Link builds complete packets (with header, context, etc.)
        await link.setSendCallback { [weak self] packetBytes in
            guard let self = self else { throw TransportError.notConnected }
            try await self.sendRawBytes(packetBytes)
        }

        // Get packet FIRST so we can use it to compute link_id
        let packet = try await link.getLinkRequestPacket()
        let packetRaw = packet.encode()

        // Compute link_id from the ACTUAL packet that will be sent
        // Python RNS formula (Link.link_id_from_lr_packet):
        //   hashable_part = packet.get_hashable_part()  # = (raw[0] & 0x0F) + raw[2:]
        //   if len(packet.data) > Link.ECPUBSIZE:       # ECPUBSIZE = 64 bytes
        //       diff = len(packet.data) - Link.ECPUBSIZE
        //       hashable_part = hashable_part[:-diff]   # Trim signaling bytes
        //   return truncated_hash(hashable_part)
        var hashable = Data()
        hashable.append(packetRaw[0] & 0x0F)
        hashable.append(contentsOf: packetRaw[2...])
        let hashablePreTrim = hashable.count

        let ecPubSize = 64
        let dataLength = packetRaw.count - 19  // header(2) + dest(16) + context(1)
        if dataLength > ecPubSize {
            let trimCount = dataLength - ecPubSize
            hashable = hashable.dropLast(trimCount)
        }
        let hashablePostTrim = hashable.count
        let actualLinkId = Hashing.truncatedHash(Data(hashable))

        // Also get the link's cached link_id for comparison
        let cachedLinkId = await link.linkId

        let actualHex = actualLinkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        let cachedHex = cachedLinkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        let packetDestHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
        let packetRawHex = packetRaw.map { String(format: "%02x", $0) }.joined()
        let hashableHex = Data(hashable).map { String(format: "%02x", $0) }.joined()

        print("[TRANSPORT] LINKREQUEST raw len=\(packetRaw.count): \(packetRawHex)")
        print("[TRANSPORT] LINKREQUEST hashable pre=\(hashablePreTrim), post=\(hashablePostTrim): \(hashableHex)")
        print("[TRANSPORT] LINKREQUEST dest=\(packetDestHex), actualLinkId=\(actualHex), cachedLinkId=\(cachedHex)")

        // Use the ACTUAL link_id computed from the packet that will be sent
        let linkId = actualLinkId
        let actualFullHex = actualLinkId.map { String(format: "%02x", $0) }.joined()
        print("[LINK_OUTBOUND] ===== REGISTERING PENDING LINK =====")
        print("[LINK_OUTBOUND] linkId (short): \(actualHex)")
        print("[LINK_OUTBOUND] linkId (full):  \(actualFullHex)")
        print("[LINK_OUTBOUND] pendingLinks before: \(pendingLinks.count)")
        pendingLinks[linkId] = link
        let afterKeys = pendingLinks.keys.map { $0.map { String(format: "%02x", $0) }.joined() }
        print("[LINK_OUTBOUND] pendingLinks after: \(pendingLinks.count), keys=\(afterKeys)")

        await link.markRequestSent()
        let linkState = await link.state
        print("[LINK_OUTBOUND] Link marked as sent, state=\(linkState)")
        print("[LINK_OUTBOUND] Sending LINKREQUEST packet...")
        try await send(packet: packet)
        print("[LINK_OUTBOUND] LINKREQUEST sent successfully, waiting for PROOF")

        return link
    }

    /// Register an existing link (for inbound links - Phase 6+).
    ///
    /// - Parameter link: Link to register as active
    public func registerLink(_ link: Link) async {
        let linkId = await link.linkId
        activeLinks[linkId] = link
    }

    /// Unregister a link.
    ///
    /// Removes the link from both active and pending collections.
    ///
    /// - Parameter linkId: Link identifier (16 bytes)
    public func unregisterLink(linkId: Data) {
        activeLinks.removeValue(forKey: linkId)
        pendingLinks.removeValue(forKey: linkId)
    }

    /// Get a link by ID.
    ///
    /// Searches both active and pending links.
    ///
    /// - Parameter linkId: Link identifier (16 bytes)
    /// - Returns: Link if found, nil otherwise
    public func getLink(linkId: Data) -> Link? {
        return activeLinks[linkId] ?? pendingLinks[linkId]
    }

    /// Number of active links.
    public var activeLinkCount: Int {
        activeLinks.count
    }

    /// Number of pending links.
    public var pendingLinkCount: Int {
        pendingLinks.count
    }

    // MARK: - Packet Proof Handling

    /// Wait for a proof that a link DATA packet was delivered.
    ///
    /// Registers the packet's full hash and suspends until either:
    /// - A matching proof arrives (returns `true`)
    /// - The timeout expires (returns `false`)
    ///
    /// Used by propagation send to confirm the propagation node accepted the message.
    ///
    /// - Parameters:
    ///   - packetHash: Full 32-byte SHA256 hash of the sent packet
    ///   - timeout: Maximum time to wait for proof (seconds)
    /// - Returns: `true` if proof received, `false` on timeout
    public func waitForPacketProof(packetHash: Data, timeout: TimeInterval = 15) async -> Bool {
        return await withCheckedContinuation { continuation in
            pendingPacketProofs[packetHash] = continuation

            // Start timeout task
            Task { [weak self] in
                try? await Task.sleep(for: .seconds(timeout))
                guard let self = self else { return }
                if let cont = await self.removePacketProof(for: packetHash) {
                    cont.resume(returning: false)
                }
            }
        }
    }

    /// Remove and return a pending packet proof continuation (actor-isolated helper).
    private func removePacketProof(for hash: Data) -> CheckedContinuation<Bool, Never>? {
        return pendingPacketProofs.removeValue(forKey: hash)
    }

    /// Handle a DATA packet proof on an active link.
    ///
    /// The proof data contains (NOT encrypted — Python Packet.pack() special-cases
    /// PROOF+LINK to skip encryption):
    /// - packet_hash (32 bytes): Full SHA256 hash of the original packet
    /// - signature (64 bytes): Link.sign(packet_hash) — validates delivery
    ///
    /// We match the packet_hash against pending proof registrations.
    ///
    /// - Parameters:
    ///   - packet: PROOF packet received
    ///   - link: Active link the proof was received on
    private func handleDataProof(_ packet: Packet, link: Link) async {
        // Link PROOF packets are NOT encrypted (Python Packet.py line 198-199:
        // elif packet_type == PROOF and destination.type == LINK: ciphertext = data)
        // proof_data = packet_hash(32) + link.sign(packet_hash)(64) = 96 bytes
        let proofData = packet.data
        guard proofData.count >= 32 else {
            print("[PROOF_DATA] Proof payload too short: \(proofData.count) bytes")
            return
        }

        let proofHash = Data(proofData.prefix(32))
        let proofHex = proofHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[PROOF_DATA] Received DATA proof, packetHash=\(proofHex)..., totalLen=\(proofData.count)")

        // Check against pending packet proofs
        if let continuation = pendingPacketProofs.removeValue(forKey: proofHash) {
            print("[PROOF_DATA] MATCH! Proof confirmed delivery")
            continuation.resume(returning: true)
        } else {
            let pendingHashes = pendingPacketProofs.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
            print("[PROOF_DATA] No pending proof match. Pending hashes: \(pendingHashes)")
        }
    }

    /// Send raw packet bytes to all connected interfaces.
    ///
    /// Used by Link callbacks to send pre-built packets (LRRTT, keepalive, etc.)
    /// The bytes are sent directly without additional wrapping.
    ///
    /// - Parameter bytes: Encoded packet bytes to send
    /// - Throws: TransportError if send fails
    private func sendRawBytes(_ bytes: Data) async throws {
        let bytesHex = bytes.prefix(20).map { String(format: "%02x", $0) }.joined()
        print("[TRANSPORT] sendRawBytes called with \(bytes.count) bytes: \(bytesHex)...")
        var successCount = 0
        var lastError: Error?

        for (id, interface) in interfaces {
            guard interface.state == .connected else {
                print("[TRANSPORT] Skipping disconnected interface '\(id)'")
                continue
            }

            do {
                try await interface.send(bytes)
                successCount += 1
                print("[TRANSPORT] Sent \(bytes.count) bytes via interface '\(id)'")
            } catch {
                lastError = error
                print("[TRANSPORT] Failed to send via '\(id)': \(error)")
                logger.warning("Failed to send raw bytes on interface \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }

        if successCount == 0 {
            if let error = lastError {
                throw TransportError.sendFailed(interfaceId: "all", underlying: error.localizedDescription)
            } else {
                throw TransportError.noInterfacesAvailable
            }
        }
    }

    /// Send encrypted data over a link.
    ///
    /// Creates a link DATA packet and sends it via broadcast transport.
    ///
    /// - Parameters:
    ///   - linkId: Link identifier
    ///   - data: Already-encrypted data to send
    private func sendLinkData(linkId: Data, data: Data) async throws {
        // Create link DATA packet
        let header = PacketHeader(
            headerType: .header1,       // Link packets use HEADER_1
            hasContext: false,
            hasIFAC: false,
            transportType: .broadcast,  // Local broadcast to interface
            destinationType: .link,     // Link destination type
            packetType: .data,
            hopCount: 0
        )

        let packet = Packet(
            header: header,
            destination: linkId,        // Link ID as destination
            transportAddress: nil,
            context: 0x00,
            data: data
        )

        try await send(packet: packet)
    }

    // MARK: - Outbound Packet Dispatch

    /// Send a packet through the transport.
    ///
    /// Packet dispatch depends on header type:
    /// - HEADER_1 (broadcast): May be converted to HEADER_2 if path has nextHop
    /// - HEADER_2 (transport/routed): Sent via path table lookup
    ///
    /// For HEADER_1 packets addressed to destinations with multi-hop paths,
    /// the packet is automatically converted to HEADER_2 with the nextHop
    /// as the transport address.
    ///
    /// - Parameter packet: Packet to send
    /// - Throws: TransportError if send fails
    public func send(packet: Packet) async throws {
        // Check if we have any interfaces
        guard !interfaces.isEmpty else {
            throw TransportError.noInterfacesAvailable
        }

        let destHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[SEND_DEBUG] ===== PACKET SEND =====")
        print("[SEND_DEBUG] dest=\(destHex), packetType=\(packet.header.packetType), transportType=\(packet.header.transportType)")

        // Determine dispatch strategy based on header type
        switch packet.header.transportType {
        case .broadcast:
            // ANNOUNCE packets must ALWAYS be sent as HEADER_1/BROADCAST by the originator.
            // Only relay/transport nodes convert announces to HEADER_2 when re-broadcasting.
            // Converting our own announce to HEADER_2 causes the relay to mishandle it.
            if packet.header.packetType == .announce {
                print("[SEND_DEBUG] ANNOUNCE: sending as HEADER_1 (never convert announces to HEADER_2)")
                try await sendToAllInterfaces(packet)
            } else {
                // HEADER_1: Check if we need to convert to HEADER_2 for multi-hop routing
                // This applies to LINKREQUEST and other packets going to remote destinations
                let pathEntry = await pathTable.lookup(destinationHash: packet.destination)
                if let entry = pathEntry {
                    let nextHopStatus = entry.nextHop != nil ? entry.nextHop!.prefix(8).map { String(format: "%02x", $0) }.joined() : "nil"
                    print("[SEND_DEBUG] PathEntry found: hopCount=\(entry.hopCount), nextHop=\(nextHopStatus), interfaceId='\(entry.interfaceId)'")
                } else {
                    print("[SEND_DEBUG] PathEntry NOT found for dest=\(destHex)")
                }

                // Python converts to HEADER_2 only if hops > 1 (Transport.py line ~500)
                // hops == 1 means destination is one hop away, send HEADER_1 directly
                // hops > 1 means destination needs multi-hop routing via transport node
                if let entry = pathEntry,
                   entry.hopCount > 1,
                   let nextHop = entry.nextHop {
                    // Convert to HEADER_2 for routed delivery (multi-hop)
                    let routedPacket = convertToHeader2(packet: packet, nextHop: nextHop)
                    let nextHopHex = nextHop.prefix(8).map { String(format: "%02x", $0) }.joined()
                    print("[SEND_DEBUG] *** CONVERTING to HEADER_2 *** dest=\(destHex), nextHop=\(nextHopHex), hops=\(entry.hopCount)")
                    try await sendToAllInterfaces(routedPacket)
                } else {
                    // Direct delivery (single hop or no path) - send as HEADER_1
                    // The relay/transport will handle any further routing
                    if let entry = pathEntry {
                        if entry.hopCount > 1 && entry.nextHop == nil {
                            print("[SEND_DEBUG] WARNING: hopCount=\(entry.hopCount) but nextHop is nil! Sending as HEADER_1 (relay will route)")
                        } else if entry.hopCount == 1 {
                            print("[SEND_DEBUG] Single hop (hops=1): sending as HEADER_1")
                        }
                    }
                    print("[SEND_DEBUG] Sending as HEADER_1 (direct broadcast)")
                    try await sendToAllInterfaces(packet)
                }
            }

        case .transport:
            // HEADER_2: Route via path table
            try await sendViaPath(packet)
        }
    }

    /// Send link data packet with explicit destination hash for routing lookup.
    ///
    /// Link DATA packets have linkId as their destination, but we need to look up
    /// the path using the peer's destination hash (not the linkId) to determine
    /// if multi-hop routing is needed.
    ///
    /// - Parameters:
    ///   - packet: Link DATA packet (destination = linkId)
    ///   - destinationHash: The peer's destination hash for path lookup
    /// - Throws: TransportError if no interfaces available or send fails
    public func sendLinkData(packet: Packet, destinationHash: Data) async throws {
        guard !interfaces.isEmpty else {
            throw TransportError.noInterfacesAvailable
        }

        // Look up path using the DESTINATION hash (not the linkId)
        if let pathEntry = await pathTable.lookup(destinationHash: destinationHash),
           pathEntry.hopCount > 0,
           let nextHop = pathEntry.nextHop {
            // Convert to HEADER_2 for routed delivery
            let routedPacket = convertToHeader2(packet: packet, nextHop: nextHop)
            let destHex = destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined()
            let linkIdHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
            let nextHopHex = nextHop.prefix(8).map { String(format: "%02x", $0) }.joined()
            print("[TRANSPORT] Link DATA: converting to HEADER_2, linkId=\(linkIdHex), destHash=\(destHex), nextHop=\(nextHopHex), hops=\(pathEntry.hopCount)")
            try await sendToAllInterfaces(routedPacket)
        } else {
            // Direct delivery (no multi-hop) - send as HEADER_1
            let linkIdHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
            print("[TRANSPORT] Link DATA: sending as HEADER_1, linkId=\(linkIdHex)")
            try await sendToAllInterfaces(packet)
        }
    }

    /// Convert a HEADER_1 packet to HEADER_2 for multi-hop routing.
    ///
    /// This is required when sending packets to destinations that are
    /// reachable via a transport node (learned from HEADER_2 announces).
    ///
    /// Wire format changes:
    /// - HEADER_1: [flags:1][hops:1][dest:16][context:1][data]
    /// - HEADER_2: [flags:1][hops:1][transport:16][dest:16][context:1][data]
    ///
    /// The header byte is modified to set:
    /// - Bit 6 (0x40): HEADER_2 type
    /// - Bit 4 (0x10): Transport type
    ///
    /// - Parameters:
    ///   - packet: Original HEADER_1 packet
    ///   - nextHop: 16-byte transport node hash to route through
    /// - Returns: New packet with HEADER_2 format
    private func convertToHeader2(packet: Packet, nextHop: Data) -> Packet {
        // Create new header with HEADER_2 and transport type
        let newHeader = PacketHeader(
            headerType: .header2,
            hasContext: packet.header.hasContext,
            hasIFAC: packet.header.hasIFAC,
            transportType: .transport,
            destinationType: packet.header.destinationType,
            packetType: packet.header.packetType,
            hopCount: packet.header.hopCount
        )

        // Create new packet with transport address
        let routedPacket = Packet(
            header: newHeader,
            destination: packet.destination,
            transportAddress: nextHop,
            context: packet.context,
            data: packet.data
        )

        let encodedHex = routedPacket.encode().prefix(20).map { String(format: "%02x", $0) }.joined()
        print("[TRANSPORT] HEADER_2 packet encoded: \(encodedHex)...")

        return routedPacket
    }

    /// Send a packet to all connected interfaces (broadcast).
    ///
    /// - Parameter packet: Packet to broadcast
    /// - Throws: TransportError if all sends fail
    private func sendToAllInterfaces(_ packet: Packet) async throws {
        let encoded = packet.encode()
        let destHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
        let contextStr = String(format: "0x%02x", packet.context)
        let headerHex = encoded.prefix(2).map { String(format: "%02x", $0) }.joined()
        let fullHex = encoded.prefix(40).map { String(format: "%02x", $0) }.joined()

        let typeStr: String
        switch packet.header.packetType {
        case .data: typeStr = "DATA"
        case .announce: typeStr = "ANNOUNCE"
        case .linkRequest: typeStr = "LINKREQUEST"
        case .proof: typeStr = "PROOF"
        }
        let sendLog = "[SEND] type=\(typeStr) dest=\(destHex) context=\(contextStr) size=\(encoded.count) interfaces=\(interfaces.count)\n"

        // For ANNOUNCE packets, log the FULL hex for offline validation
        if packet.header.packetType == .announce {
            let allHex = encoded.map { String(format: "%02x", $0) }.joined()
        }

        print("[SEND_BYTES] ===== ACTUAL BYTES BEING SENT =====")
        print("[SEND_BYTES] Total size: \(encoded.count) bytes")
        print("[SEND_BYTES] Header bytes: \(headerHex)")
        print("[SEND_BYTES] dest=\(destHex), context=\(contextStr)")
        print("[SEND_BYTES] headerType=\(packet.header.headerType), transportType=\(packet.header.transportType)")
        print("[SEND_BYTES] destType=\(packet.header.destinationType), packetType=\(packet.header.packetType)")
        print("[SEND_BYTES] First 40 bytes: \(fullHex)")
        print("[SEND_BYTES] interfaces=\(interfaces.count)")
        var successCount = 0
        var lastError: Error?

        for (id, interface) in interfaces {
            // Skip disconnected interfaces
            guard interface.state == .connected else {
                print("[TRANSPORT] Skipping disconnected interface '\(id)'")
                logger.debug("Skipping disconnected interface: \(id, privacy: .public)")
                continue
            }

            do {
                try await interface.send(encoded)
                successCount += 1
                print("[TRANSPORT] Broadcast sent \(encoded.count) bytes via '\(id)'")
                logger.debug("Broadcast sent via interface: \(id, privacy: .public)")
            } catch {
                lastError = error
                print("[TRANSPORT] Broadcast failed on '\(id)': \(error)")
                logger.warning("Broadcast failed on interface \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }

        // If no interfaces succeeded, throw error
        if successCount == 0 {
            print("[TRANSPORT] sendToAllInterfaces FAILED: no interfaces succeeded")
            if let error = lastError {
                throw TransportError.sendFailed(interfaceId: "all", underlying: error.localizedDescription)
            } else {
                throw TransportError.noInterfacesAvailable
            }
        }

        print("[TRANSPORT] Broadcast complete: \(successCount) interface(s)")
        logger.info("Broadcast packet sent to \(successCount, privacy: .public) interface(s)")
    }

    /// Send a packet via path table lookup (routed).
    ///
    /// If no path is available, the packet is queued and a path request is sent.
    /// The packet will be delivered when a path is learned (announce received).
    ///
    /// - Parameter packet: Packet to route
    /// - Throws: TransportError if send fails (but NOT for missing path)
    private func sendViaPath(_ packet: Packet) async throws {
        let destHash = packet.destination
        let destHex = destHash.prefix(8).map { String(format: "%02x", $0) }.joined()

        // Look up path in path table
        guard let pathEntry = await pathTable.lookup(destinationHash: destHash) else {
            // No path available - queue packet and request path
            print("[SENDPATH] No path to \(destHex)..., queuing packet")
            queuePendingPacket(packet, for: destHash)
            try? await requestPath(for: destHash)
            return  // Don't throw - packet is queued for later delivery
        }

        let interfaceId = pathEntry.interfaceId
        print("[SENDPATH] Found path to \(destHex)... via interface '\(interfaceId)'")

        // Get the interface
        guard let interface = interfaces[interfaceId] else {
            print("[SENDPATH] Interface '\(interfaceId)' not found in interfaces dict (have: \(Array(interfaces.keys)))")
            throw TransportError.interfaceNotFound(id: interfaceId)
        }

        // Check interface is connected
        guard interface.state == .connected else {
            print("[SENDPATH] Interface '\(interfaceId)' not connected (state=\(interface.state))")
            throw TransportError.interfaceNotFound(id: interfaceId)
        }

        // Send the packet
        let encoded = packet.encode()
        print("[SENDPATH] Sending \(encoded.count) bytes via '\(interfaceId)' (type=\(packet.header.packetType))")
        do {
            try await interface.send(encoded)
            print("[SENDPATH] Packet sent successfully")
            logger.debug("Routed packet sent via interface: \(interfaceId, privacy: .public)")
        } catch {
            print("[SENDPATH] Send failed: \(error)")
            throw TransportError.sendFailed(interfaceId: interfaceId, underlying: error.localizedDescription)
        }
    }

    /// Send data directly to a specific interface.
    ///
    /// - Parameters:
    ///   - data: Data to send
    ///   - interfaceId: Interface ID
    /// - Throws: TransportError if interface not found or send fails
    public func sendToInterface(_ data: Data, interfaceId: String) async throws {
        guard let interface = interfaces[interfaceId] else {
            throw TransportError.interfaceNotFound(id: interfaceId)
        }

        guard interface.state == .connected else {
            throw TransportError.notConnected
        }

        do {
            try await interface.send(data)
        } catch {
            throw TransportError.sendFailed(interfaceId: interfaceId, underlying: error.localizedDescription)
        }
    }

    // MARK: - Inbound Packet Routing

    /// Receive and route an inbound packet.
    ///
    /// Called by interfaces when a packet is received. Routes the packet to:
    /// - Link (for PROOF and link DATA packets)
    /// - Local destination (for LINKREQUEST and regular DATA)
    /// - Announce handler (for announce packets)
    /// - Forward (if in gateway mode, not yet implemented)
    ///
    /// - Parameters:
    ///   - packet: Received packet
    ///   - interfaceId: ID of interface that received the packet
    public func receive(packet: Packet, from interfaceId: String) async {
        let destHash = packet.destination

        // Route based on packet type
        switch packet.header.packetType {
        case .announce:
            print("[TRANSPORT] Processing ANNOUNCE packet from interface \(interfaceId)")
            logger.info("Received announce packet from interface \(interfaceId, privacy: .public)")
            await processAnnounce(packet: packet, from: interfaceId)

        case .linkRequest:
            // LINKREQUEST goes to registered destination (if we're the target)
            await handleLinkRequest(packet, from: interfaceId)

        case .proof:
            // PROOF could be for announce OR for link
            // If destination is a link ID, route to link
            let proofDestHex = destHash.prefix(8).map { String(format: "%02x", $0) }.joined()
            let proofFullHex = destHash.map { String(format: "%02x", $0) }.joined()
            let pendingKeysHex = pendingLinks.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
            let activeKeysHex = activeLinks.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
            print("[PROOF_RECV] ===== PROOF PACKET RECEIVED =====")
            print("[PROOF_RECV] dest=\(proofDestHex), full=\(proofFullHex)")
            print("[PROOF_RECV] pendingLinks count=\(pendingLinks.count), keys=\(pendingKeysHex)")
            print("[PROOF_RECV] activeLinks count=\(activeLinks.count), keys=\(activeKeysHex)")
            print("[PROOF_RECV] context=0x\(String(format: "%02x", packet.context)), dataLen=\(packet.data.count)")

            if let link = pendingLinks[destHash] {
                print("[PROOF_RECV] MATCH! Found pending link for PROOF, processing...")
                await handleLinkProof(packet, link: link)
            } else if let link = activeLinks[destHash] {
                // DATA packet proof on an active link (e.g., propagation node confirming delivery)
                print("[PROOF_RECV] DATA proof on active link \(proofDestHex)")
                await handleDataProof(packet, link: link)
            } else {
                // Announce PROOF or path request response - existing handling
                print("[PROOF_RECV] No link match, treating as announce PROOF")
                await handleAnnounceProof(packet, from: interfaceId)
            }

        case .data:
            let dataDestHex = destHash.prefix(8).map { String(format: "%02x", $0) }.joined()
            let dataFullHex = destHash.map { String(format: "%02x", $0) }.joined()
            print("[LXMF_INBOUND] DATA packet received: destType=\(packet.header.destinationType), dest=\(dataDestHex), dataLen=\(packet.data.count)")
            if packet.header.destinationType == .link {
                // Link DATA packet - route to link
                print("[LXMF_INBOUND] Routing to handleLinkData()")
                await handleLinkData(packet)
            } else {
                // Regular data - deliver to local destination
                print("[LXMF_INBOUND] Routing to handleRegularData()")
                await handleRegularData(packet, from: interfaceId)
            }
        }
    }

    /// Handle incoming LINKREQUEST (for destinations we own).
    ///
    /// Creates a responder Link, sends PROOF, and sets up for LRRTT receipt.
    ///
    /// - Parameters:
    ///   - packet: LINKREQUEST packet
    ///   - interfaceId: ID of interface that received the packet
    private func handleLinkRequest(_ packet: Packet, from interfaceId: String) async {
        let hexPrefix = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()

        // Check if we have this destination registered
        guard let destination = destinations[packet.destination] else {
            // Not our destination - ignore
            return
        }

        // Parse the incoming LINKREQUEST
        let incomingRequest: IncomingLinkRequest
        do {
            incomingRequest = try IncomingLinkRequest(data: packet.data, packet: packet)
        } catch {
            logger.warning("Failed to parse LINKREQUEST for \(hexPrefix, privacy: .public)...: \(error.localizedDescription, privacy: .public)")
            return
        }

        let linkIdHex = incomingRequest.linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[LINK_RESPONDER] Received LINKREQUEST for dest=\(hexPrefix), linkId=\(linkIdHex)")

        // Get destination's identity for signing PROOF
        guard let identity = destination.identity else {
            logger.warning("Cannot respond to LINKREQUEST: destination \(hexPrefix, privacy: .public)... has no identity")
            return
        }

        guard identity.hasPrivateKeys else {
            logger.warning("Cannot respond to LINKREQUEST: destination \(hexPrefix, privacy: .public)... identity has no private keys")
            return
        }

        // Create responder link
        let link = Link(
            incomingRequest: incomingRequest,
            destination: destination,
            identity: identity
        )

        // Set up send callback for the link
        await link.setSendCallback { [weak self] (data: Data) async throws -> Void in
            guard let self = self else { return }
            try await self.sendRawBytes(data)
        }

        // Set link established callback
        await link.setLinkEstablishedCallback { [weak self] (establishedLink: Link) async -> Void in
            guard let self = self else { return }
            let linkIdHex = await establishedLink.linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
            print("[LINK_RESPONDER] Link \(linkIdHex) established (responder)")

            // Notify destination's link callback
            if let callback = await self.getDestinationLinkCallback(for: packet.destination) {
                await callback(establishedLink)
            }
        }

        // Create and send PROOF
        do {
            let proofPacket = try await link.createProofPacket()
            let proofData = proofPacket.encode()

            print("[LINK_RESPONDER] Sending PROOF (\(proofData.count) bytes) for link \(linkIdHex)")

            // Send PROOF via the interface that received the request
            if let interface = interfaces[interfaceId] {
                // For TCP, we need to use framed transport
                if let tcpInterface = interface as? TCPInterface {
                    try await tcpInterface.send(proofData)
                } else {
                    try await interface.send(proofData)
                }
            } else {
                // Broadcast to all interfaces as fallback
                try await sendRawBytes(proofData)
            }

            // Derive keys for decrypting LRRTT
            try await link.deriveResponderKeys()

            // Store link as pending (waiting for LRRTT to complete establishment)
            activeLinks[incomingRequest.linkId] = link
            print("[LINK_RESPONDER] Link \(linkIdHex) stored in activeLinks, awaiting LRRTT")

            logger.info("LINKREQUEST accepted for \(hexPrefix, privacy: .public)..., PROOF sent, awaiting LRRTT")

        } catch {
            logger.warning("Failed to create/send PROOF for \(hexPrefix, privacy: .public)...: \(error.localizedDescription, privacy: .public)")
            await link.close(reason: TeardownReason.timeout)
        }
    }

    /// Get the link callback for a destination (if registered).
    private func getDestinationLinkCallback(for destHash: Data) async -> ((Link) async -> Void)? {
        // TODO: Add link callback registration to Destination
        return nil
    }

    /// Handle PROOF for a pending link.
    ///
    /// Validates the proof and moves the link from pending to active.
    ///
    /// - Parameters:
    ///   - packet: PROOF packet
    ///   - link: The pending link that this proof is for
    private func handleLinkProof(_ packet: Packet, link: Link) async {
        let proofDestHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[PROOF_PROC] Processing PROOF for dest=\(proofDestHex)")
        print("[PROOF_PROC] PROOF data length: \(packet.data.count) bytes")
        let proofDataHex = packet.data.prefix(20).map { String(format: "%02x", $0) }.joined()
        print("[PROOF_PROC] PROOF data: \(proofDataHex)...")

        do {
            print("[PROOF_PROC] Calling link.processProof...")
            try await link.processProof(packet.data)
            print("[PROOF_PROC] link.processProof succeeded!")

            // Move from pending to active
            let linkId = await link.linkId
            pendingLinks.removeValue(forKey: linkId)
            activeLinks[linkId] = link

            let hexPrefix = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
            print("[PROOF_PROC] Link \(hexPrefix) moved to activeLinks, total=\(activeLinks.count)")
            logger.info("Link \(hexPrefix, privacy: .public)... established and active")

        } catch {
            // PROOF validation failed - close link
            print("[PROOF_PROC] PROOF processing FAILED: \(error)")
            await link.close(reason: .proofInvalid)
            pendingLinks.removeValue(forKey: packet.destination)

            let hexPrefix = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
            logger.warning("Link \(hexPrefix, privacy: .public)... PROOF validation failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Handle announce PROOF (path request response).
    ///
    /// - Parameters:
    ///   - packet: PROOF packet
    ///   - interfaceId: ID of interface that received the packet
    private func handleAnnounceProof(_ packet: Packet, from interfaceId: String) async {
        // Announce PROOF handling - may be needed for path request responses
        // For now, just log
        let hexPrefix = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
        logger.debug("Received announce PROOF for \(hexPrefix, privacy: .public)...")
    }

    /// Handle link DATA packet.
    ///
    /// Decrypts the packet and processes it (keep-alive, resource, identify, or user data).
    /// Routing priority:
    /// 1. Check wire-format context (packet.context) for LINKIDENTIFY (0xFB)
    /// 2. Check decrypted payload for keep-alive (1 byte)
    /// 3. Check decrypted payload for resource packets (context 0x01-0x07 with valid structure)
    /// 4. Otherwise treat as LXMF user data
    ///
    /// - Parameter packet: Link DATA packet
    private func handleLinkData(_ packet: Packet) async {
        let linkHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
        let activeKeysList = activeLinks.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
        print("[LINK_DATA] handleLinkData called for dest=\(linkHex), context=0x\(String(format: "%02x", packet.context)), activeLinks=\(activeKeysList)")

        guard let link = activeLinks[packet.destination] else {
            // Unknown link - ignore
            print("[LINK_DATA] No active link found for \(linkHex), ignoring packet")
            return
        }

        // FIRST: Check wire-format context for special link packets
        // These are handled BEFORE decryption check because the context is in the wire format

        // LINKIDENTIFY (0xFB) - peer revealing identity
        if packet.context == LinkConstants.CONTEXT_LINKIDENTIFY {
            print("[LINK_DATA] LINKIDENTIFY packet detected (wire-format context=0xFB)")
            do {
                let plaintext = try await link.decrypt(packet.data)
                print("[LINK_DATA] Decrypted LINKIDENTIFY payload: \(plaintext.count) bytes")
                // plaintext is: public_keys (64) + signature (64) = 128 bytes
                try await link.handleIdentifyPacket(plaintext)
            } catch {
                print("[LINK_DATA] Failed to decrypt/handle LINKIDENTIFY: \(error)")
            }
            return
        }

        // LINKCLOSE (0xFC) - peer closing the link
        if packet.context == LinkConstants.CONTEXT_LINKCLOSE {
            print("[LINK_DATA] LINKCLOSE packet detected (wire-format context=0xFC)")
            // Remote peer is closing the link - close our side too
            await link.close(reason: .destinationClosed)
            activeLinks.removeValue(forKey: packet.destination)
            let hexPrefix = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
            print("[LINK_DATA] Link \(hexPrefix) closed by remote peer")
            return
        }

        // LRRTT (0xFE) - RTT measurement packet (completes link establishment for responder)
        if packet.context == LinkConstants.CONTEXT_LRRTT {
            print("[LINK_DATA] LRRTT packet detected (wire-format context=0xFE)")
            // Only process if we're the responder and link is in handshake state
            let linkState = await link.state
            let isInitiator = await link.initiator

            if !isInitiator && linkState == .handshake {
                print("[LINK_DATA] Processing LRRTT for responder link")
                do {
                    let plaintext = try await link.decrypt(packet.data)
                    print("[LINK_DATA] Decrypted LRRTT: \(plaintext.count) bytes")
                    try await link.processLRRTT(plaintext)
                    let hexPrefix = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
                    print("[LINK_DATA] Link \(hexPrefix) establishment complete (responder)")
                } catch {
                    print("[LINK_DATA] Failed to process LRRTT: \(error)")
                    await link.close(reason: .timeout)
                    activeLinks.removeValue(forKey: packet.destination)
                }
            } else {
                print("[LINK_DATA] Ignoring LRRTT (initiator=\(isInitiator), state=\(linkState))")
            }
            return
        }

        // Decrypt and process
        do {
            let plaintext = try await link.decrypt(packet.data)
            let firstByteHex = plaintext.isEmpty ? "empty" : String(format: "0x%02x", plaintext[plaintext.startIndex])
            let hexDump = plaintext.prefix(32).map { String(format: "%02x", $0) }.joined()
            print("[LINK_DATA] Decrypted \(plaintext.count) bytes, firstByte=\(firstByteHex), data=\(hexDump)")

            // Check for keep-alive (1 byte)
            if plaintext.count == 1 {
                print("[LINK_DATA] Routing to keepalive handler")
                await link.processKeepalive(plaintext)
                return
            }

            // Check for resource packet (context byte 0x01-0x07 in payload)
            // Resource packets have specific structure: [context:1][...resource data...]
            // IMPORTANT: Only route to resource handler if the packet structure is valid
            // to avoid misrouting LXMF messages whose destination hash starts with 0x01-0x07
            if plaintext.count >= 1 {
                let firstByte = plaintext[plaintext.startIndex]
                if ResourcePacketContext.isResourceContext(firstByte) {
                    // Additional validation: resource packets have specific minimum sizes
                    // - Advertisement (0x01): >50 bytes (msgpack structure)
                    // - Request (0x02): >20 bytes
                    // - Data (0x03): >10 bytes
                    // LXMF messages are always >= 96 bytes (16+16+64 minimum)
                    //
                    // Key insight: Resource advertisements have a msgpack structure that
                    // differs from LXMF's [dest_hash:16][source_hash:16][signature:64]
                    // We can validate by checking if bytes 1-16 look like a resource structure
                    // rather than a random hash byte sequence.
                    //
                    // For now, use a heuristic: if packet is EXACTLY the expected resource
                    // packet size range, treat as resource. Otherwise, treat as LXMF.
                    // Resource packets are typically smaller and have msgpack encoding.
                    //
                    // SAFER: Check if byte 17 (would be source_hash[0] in LXMF) also looks
                    // like it could continue a msgpack structure or if the whole packet
                    // has the LXMF signature at bytes 32-95.
                    let isLikelyLXMF = plaintext.count >= 96 && isValidLXMFStructure(plaintext)

                    if !isLikelyLXMF {
                        // Resource packet - route to link resource handler
                        print("[LINK_DATA] Routing to resource handler (context=\(firstByteHex))")
                        await link.handleResourcePacket(plaintext)
                        return
                    } else {
                        print("[LINK_DATA] First byte matches resource context but structure looks like LXMF, treating as LXMF")
                    }
                }
            }

            // Regular data packet - deliver via callback
            // For LXMF direct delivery, the plaintext is a complete LXMF message:
            // [dest_hash:16][source_hash:16][signature:64][msgpack_payload]
            // Extract destination hash from first 16 bytes and deliver to that callback
            guard plaintext.count >= 16 else {
                let hexPrefix = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
                logger.warning("Link data too short for LXMF on link \(hexPrefix, privacy: .public)...")
                return
            }

            let lxmfDestHash = Data(plaintext.prefix(16))
            let lxmfDestHex = lxmfDestHash.prefix(4).map { String(format: "%02x", $0) }.joined()
            let linkHex = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
            logger.info("Delivering \(plaintext.count, privacy: .public) bytes from link \(linkHex, privacy: .public)... to LXMF dest \(lxmfDestHex, privacy: .public)...")

            // Deliver to the LXMF destination's callback
            // Create a synthetic packet for the callback (preserving link context)
            let syntheticPacket = Packet(
                header: packet.header,
                destination: lxmfDestHash,
                transportAddress: nil,
                context: packet.context,
                data: plaintext
            )
            await callbackManager.deliver(
                data: plaintext,
                packet: syntheticPacket,
                to: lxmfDestHash
            )
        } catch {
            let hexPrefix = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
            logger.warning("Failed to decrypt link data for \(hexPrefix, privacy: .public)...: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Check if data has valid LXMF message structure.
    ///
    /// LXMF messages have format: [dest_hash:16][source_hash:16][signature:64][msgpack]
    /// This function validates the structure to distinguish from resource packets.
    ///
    /// - Parameter data: Decrypted payload data
    /// - Returns: true if the data appears to be an LXMF message
    private func isValidLXMFStructure(_ data: Data) -> Bool {
        // LXMF minimum: 16 (dest) + 16 (source) + 64 (sig) + 1 (msgpack) = 97 bytes
        guard data.count >= 97 else { return false }

        // The signature starts at byte 32 and is 64 bytes
        // Ed25519 signatures have specific properties we could check,
        // but for simplicity, just verify the structure looks right:
        // - Bytes 0-15: destination hash (random bytes)
        // - Bytes 16-31: source hash (random bytes)
        // - Bytes 32-95: Ed25519 signature
        // - Bytes 96+: msgpack data

        // Check if byte 96 looks like valid msgpack start
        // Common msgpack prefixes:
        // - 0x80-0x8f: fixmap
        // - 0x90-0x9f: fixarray
        // - 0xa0-0xbf: fixstr
        // - 0xc0-0xdf: various types
        // - 0xe0-0xff: negative fixint
        let msgpackStart = data[data.startIndex.advanced(by: 96)]

        // Msgpack data typically starts with a map or array for LXMF
        // Maps: 0x80-0x8f (fixmap) or 0xde-0xdf (map16/32)
        // Arrays: 0x90-0x9f (fixarray) or 0xdc-0xdd (array16/32)
        let looksLikeMsgpack = (msgpackStart >= 0x80 && msgpackStart <= 0x9f) ||
                               (msgpackStart >= 0xdc && msgpackStart <= 0xdf)

        return looksLikeMsgpack
    }

    /// Handle regular (non-link) DATA packet.
    ///
    /// For SINGLE destination packets, decrypts the data using the destination's
    /// identity before delivering to the callback. This is required for OPPORTUNISTIC
    /// LXMF delivery which sends encrypted single-packet messages.
    ///
    /// - Parameters:
    ///   - packet: DATA packet
    ///   - interfaceId: ID of interface that received the packet
    private func handleRegularData(_ packet: Packet, from interfaceId: String) async {
        let destHash = packet.destination
        let hexPrefix = destHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        let hexFull = destHash.map { String(format: "%02x", $0) }.joined()

        // Debug: list all registered destinations
        let registeredDests = destinations.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
        print("[LXMF_INBOUND] handleRegularData: destHash=\(hexPrefix), registeredDests=\(registeredDests), destType=\(packet.header.destinationType)")

        // Check if destination is local
        guard let destination = destinations[destHash] else {
            // Destination not local - could forward in gateway mode
            print("[LXMF_INBOUND] Destination \(hexPrefix) NOT registered locally, dropping packet")
            logger.debug("Received packet for non-local destination \(hexPrefix, privacy: .public)...")
            return
        }

        print("[LXMF_INBOUND] Destination \(hexPrefix) IS local, proceeding to decrypt")
        logger.info("Delivering packet to local destination \(hexPrefix, privacy: .public)...")

        // Determine data to deliver - decrypt if needed
        var deliveryData = packet.data

        // SINGLE destination packets are encrypted to the destination's identity
        // They must be decrypted using Identity.decrypt() with the identity hash as HKDF salt
        if packet.header.destinationType == .single {
            guard let identity = destination.identity else {
                logger.warning("Cannot decrypt SINGLE packet: destination \(hexPrefix, privacy: .public)... has no identity")
                return
            }

            guard identity.hasPrivateKeys else {
                logger.warning("Cannot decrypt SINGLE packet: destination \(hexPrefix, privacy: .public)... identity has no private keys")
                return
            }

            do {
                // IMPORTANT: HKDF salt is the IDENTITY hash (SHA256(publicKeys)[:16]),
                // NOT the destination hash. This matches Python RNS Identity.get_salt().
                let identityHash = identity.hash
                print("[LXMF_INBOUND] Attempting decrypt, identityHash=\(identityHash.prefix(8).map { String(format: "%02x", $0) }.joined()), ciphertext len=\(packet.data.count)")
                deliveryData = try identity.decrypt(packet.data, identityHash: identityHash)
                let dataHex = deliveryData.prefix(16).map { String(format: "%02x", $0) }.joined()
                print("[LXMF_INBOUND] Decrypted SINGLE packet: \(deliveryData.count) bytes, data[0:16]=\(dataHex)")
            } catch {
                print("[LXMF_INBOUND] Decryption FAILED: \(error)")
                logger.warning("Failed to decrypt SINGLE packet for \(hexPrefix, privacy: .public)...: \(error.localizedDescription, privacy: .public)")
                return
            }
        }

        // Deliver decrypted data via callback manager
        print("[LXMF_INBOUND] Calling callbackManager.deliver() for destHash=\(hexPrefix)")
        await callbackManager.deliver(
            data: deliveryData,
            packet: packet,
            to: destHash
        )
        print("[LXMF_INBOUND] callbackManager.deliver() returned")
    }

    /// Process an announce packet via the announce handler.
    ///
    /// Implements Python Transport.py announce processing with:
    /// - Local rebroadcast detection via AnnounceTable
    /// - AnnounceFilter for per-interface mode filtering
    /// - Queued retransmission instead of immediate rebroadcast
    /// - Rate limiting via interface config
    /// - Transport enabled check before rebroadcast
    ///
    /// - Parameters:
    ///   - packet: Announce packet to process
    ///   - interfaceId: ID of interface that received the announce
    private func processAnnounce(packet: Packet, from interfaceId: String) async {
        // Get interface mode
        let mode = getInterfaceMode(for: interfaceId)

        // Local rebroadcast detection (Transport.py:1581-1597)
        // For HEADER_2 announces, check if this is our own rebroadcast heard back
        if packet.header.headerType == .header2, packet.transportAddress != nil {
            let destHash = packet.destination
            let detected = await announceTable.recordLocalRebroadcast(
                destinationHash: destHash,
                incomingHops: packet.header.hopCount
            )
            if detected {
                let hexPrefix = destHash.prefix(4).map { String(format: "%02x", $0) }.joined()
                logger.debug("Local rebroadcast detected for \(hexPrefix, privacy: .public)...")
            }
        }

        // Process via announce handler
        let result = await announceHandler.process(
            packet: packet,
            from: interfaceId,
            interfaceMode: mode
        )

        // Handle result
        switch result {
        case .ignored(let reason):
            let hexPrefix = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
            logger.debug("Announce ignored (\(String(describing: reason), privacy: .public)) for \(hexPrefix, privacy: .public)...")

        case .recorded(let destHash):
            let hexPrefix = destHash.prefix(4).map { String(format: "%02x", $0) }.joined()
            logger.info("Path recorded for destination \(hexPrefix, privacy: .public)...")
            await processPendingPackets(for: destHash)

        case .recordedAndRebroadcast(let destHash, let rebroadcastPacket):
            let hexPrefix = destHash.prefix(4).map { String(format: "%02x", $0) }.joined()
            let isLocal = isLocalDestination(destHash)

            // Transport.py:1741: Only rebroadcast if transport_enabled or local destination
            if transportEnabled || isLocal {
                // Rate limiting check (Transport.py:1691-1720)
                let sourceInterface = interfaces[interfaceId]
                if let rateTarget = sourceInterface?.config.announceRateTarget {
                    let blocked = await announceTable.isRateBlocked(
                        destinationHash: destHash,
                        rateTarget: rateTarget,
                        rateGrace: sourceInterface?.config.announceRateGrace ?? 0,
                        ratePenalty: sourceInterface?.config.announceRatePenalty ?? 0
                    )
                    if blocked {
                        logger.info("Announce for \(hexPrefix, privacy: .public)... rate-blocked")
                        await processPendingPackets(for: destHash)
                        return
                    }
                }

                // Queue for retransmission via AnnounceTable instead of immediate send
                let receivedFrom: Data
                if let transportId = rebroadcastPacket.transportAddress {
                    receivedFrom = transportId
                } else {
                    receivedFrom = destHash
                }

                await announceTable.insert(
                    destinationHash: destHash,
                    packet: rebroadcastPacket,
                    hops: rebroadcastPacket.header.hopCount,
                    receivedFrom: receivedFrom
                )
                logger.info("Announce for \(hexPrefix, privacy: .public)... queued for retransmission")
            } else {
                logger.debug("Transport disabled, not rebroadcasting \(hexPrefix, privacy: .public)...")
            }

            await processPendingPackets(for: destHash)
        }
    }

    /// Retransmit announces from the announce table as HEADER_2 packets.
    ///
    /// Called periodically (~1s) to process queued announce retransmissions.
    /// Packets are rebroadcast as HEADER_2 with the local transport identity hash.
    /// Per-interface AnnounceFilter is applied before sending.
    ///
    /// Reference: Python Transport.py:518-579
    private func processAnnounceRetransmissions() async {
        let actions = await announceTable.processRetransmissions()
        guard !actions.isEmpty else { return }

        for action in actions {
            // Build HEADER_2 retransmission packet
            let transportId = transportIdentityHash ?? Data(repeating: 0, count: 16)

            let newHeader = PacketHeader(
                headerType: .header2,
                hasContext: action.blockRebroadcasts,
                hasIFAC: false,
                transportType: .transport,
                destinationType: action.packet.header.destinationType,
                packetType: .announce,
                hopCount: action.hops
            )

            let retransmitPacket = Packet(
                header: newHeader,
                destination: action.packet.destination,
                transportAddress: transportId,
                context: action.blockRebroadcasts ? 0x01 : 0x00, // PATH_RESPONSE context
                data: action.packet.data
            )

            let encoded = retransmitPacket.encode()
            let destHex = action.destinationHash.prefix(4).map { String(format: "%02x", $0) }.joined()

            // Determine source interface mode for filtering
            // Use the interface the announce was originally received on
            let sourceMode: InterfaceMode? = nil // Source mode not tracked in current entry

            for (id, interface) in interfaces {
                // Skip disconnected interfaces
                guard interface.state == .connected else { continue }

                // Skip specific interface override
                if let attachedId = action.attachedInterfaceId, id != attachedId { continue }

                // Apply AnnounceFilter per-outgoing-interface
                let outgoingMode = interface.config.mode
                let isLocal = isLocalDestination(action.destinationHash)
                guard AnnounceFilter.shouldForward(
                    outgoingMode: outgoingMode,
                    sourceMode: sourceMode,
                    isLocalDestination: isLocal
                ) else {
                    continue
                }

                do {
                    try await interface.send(encoded)
                    logger.debug("Retransmitted announce for \(destHex, privacy: .public)... via \(id, privacy: .public)")
                } catch {
                    logger.warning("Failed to retransmit announce to \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
                }
            }
        }
    }

    /// Start the periodic announce retransmission task.
    ///
    /// Called when transport is set up. Runs every ~1 second.
    public func startRetransmissionLoop() {
        guard retransmissionTask == nil else { return }
        retransmissionTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self = self else { break }
                await self.processAnnounceRetransmissions()
            }
        }
    }

    /// Stop the periodic announce retransmission task.
    public func stopRetransmissionLoop() {
        retransmissionTask?.cancel()
        retransmissionTask = nil
    }

    /// Get the interface mode for a given interface ID.
    ///
    /// - Parameter interfaceId: Interface ID
    /// - Returns: Interface mode, defaults to .full if interface not found
    private func getInterfaceMode(for interfaceId: String) -> InterfaceMode {
        guard let interface = interfaces[interfaceId] else {
            return .full // Default to full mode
        }
        return interface.config.mode
    }

    // MARK: - Path Table Access

    /// Get the path table for direct access.
    ///
    /// Used for testing and advanced routing operations.
    public func getPathTable() -> PathTable {
        return pathTable
    }

    /// Get the callback manager for registering packet callbacks.
    ///
    /// Used by LXMRouter to register callbacks for LXMF delivery destinations.
    ///
    /// - Returns: DefaultCallbackManager instance
    public func getCallbackManager() -> DefaultCallbackManager {
        return callbackManager
    }

    /// Get the announce handler for direct access.
    ///
    /// Used for testing and advanced operations.
    public func getAnnounceHandler() -> AnnounceHandler {
        return announceHandler
    }

    /// Record a path entry in the path table.
    ///
    /// Convenience method for recording paths from validated announces.
    ///
    /// - Parameter entry: Path entry to record
    /// - Returns: true if path was recorded, false if ignored
    @discardableResult
    public func recordPath(entry: PathEntry) async -> Bool {
        let recorded = await pathTable.record(entry: entry)

        // If path was recorded, check for pending packets
        if recorded {
            await processPendingPackets(for: entry.destinationHash)
        }

        return recorded
    }

    // MARK: - Path Request Mechanism

    /// Request a path to a destination.
    ///
    /// This broadcasts a path request packet to all connected interfaces.
    /// The request is throttled to avoid flooding the network.
    ///
    /// When nodes receive the path request, they will respond with an announce
    /// if they have path information for the destination.
    ///
    /// Path requests are sent to the PLAIN destination "Transport.path.request"
    /// with payload: destination_hash (16 bytes) + request_tag (16 bytes)
    ///
    /// Reference: Python RNS Transport.request_path() lines 2541-2588
    ///
    /// - Parameter destinationHash: 16-byte destination hash to request path for
    public func requestPath(for destinationHash: Data) async {
        // Check throttling
        if let lastRequest = pathRequestTimestamps[destinationHash],
           Date().timeIntervalSince(lastRequest) < pathRequestCooldown {
            logger.debug("Path request throttled for destination (recent request)")
            return
        }

        // Update timestamp
        pathRequestTimestamps[destinationHash] = Date()

        // Clean up old timestamps (older than 10x cooldown)
        let staleThreshold = Date().addingTimeInterval(-pathRequestCooldown * 10)
        pathRequestTimestamps = pathRequestTimestamps.filter { $0.value > staleThreshold }

        let destHex = destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[TRANSPORT] Requesting path to \(destHex)...")

        // Generate random request tag (16 bytes)
        var requestTag = Data(count: 16)
        _ = requestTag.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }

        // Path request data: destination_hash (16 bytes) + request_tag (16 bytes)
        var requestData = destinationHash
        requestData.append(requestTag)

        // Compute destination hash for "Transport.path.request" (PLAIN destination)
        let pathRequestDestHash = Destination.plainHash(appName: "Transport", aspects: ["path", "request"])

        // Build path request packet (DATA packet, BROADCAST transport, HEADER_1)
        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            hasIFAC: false,
            transportType: .broadcast,
            destinationType: .plain,
            packetType: .data,
            hopCount: 0
        )

        let packet = Packet(
            header: header,
            destination: pathRequestDestHash,
            transportAddress: nil,
            context: 0x00,
            data: requestData
        )

        // Broadcast to all interfaces
        let encoded = packet.encode()
        var sentCount = 0

        for (id, interface) in interfaces {
            guard interface.state == .connected else { continue }

            do {
                try await interface.send(encoded)
                sentCount += 1
                logger.debug("Path request sent via interface: \(id, privacy: .public)")
            } catch {
                logger.warning("Failed to send path request via \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }

        print("[TRANSPORT] Path request sent for \(destHex) to \(sentCount) interface(s)")
    }

    /// Queue a packet waiting for path discovery.
    ///
    /// Queued packets are automatically sent when a path is learned via announce.
    ///
    /// - Parameters:
    ///   - packet: Packet to queue
    ///   - destinationHash: Destination hash the packet is waiting on
    private func queuePendingPacket(_ packet: Packet, for destinationHash: Data) {
        var queue = pendingPackets[destinationHash] ?? []

        // Limit queue size per destination
        if queue.count >= maxPendingPacketsPerDestination {
            logger.warning("Pending packet queue full for destination, dropping oldest")
            queue.removeFirst()
        }

        queue.append(packet)
        pendingPackets[destinationHash] = queue

        let hexPrefix = destinationHash.prefix(4).map { String(format: "%02x", $0) }.joined()
        logger.debug("Packet queued for \(hexPrefix, privacy: .public)... (queue size: \(queue.count, privacy: .public))")
    }

    /// Process pending packets for a destination that now has a path.
    ///
    /// Called when a path is recorded (announce received).
    ///
    /// - Parameter destinationHash: Destination that now has a path
    private func processPendingPackets(for destinationHash: Data) async {
        guard let packets = pendingPackets.removeValue(forKey: destinationHash) else {
            return
        }

        let hexPrefix = destinationHash.prefix(4).map { String(format: "%02x", $0) }.joined()
        logger.info("Processing \(packets.count, privacy: .public) pending packet(s) for \(hexPrefix, privacy: .public)...")

        for packet in packets {
            do {
                try await sendViaPath(packet)
                logger.debug("Pending packet sent successfully")
            } catch {
                logger.warning("Failed to send pending packet: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// Number of pending packets (for testing).
    public var pendingPacketCount: Int {
        pendingPackets.values.reduce(0) { $0 + $1.count }
    }

    /// Get pending packets for a destination (for testing).
    ///
    /// - Parameter destinationHash: Destination hash
    /// - Returns: Array of queued packets, or nil if none
    public func getPendingPackets(for destinationHash: Data) -> [Packet]? {
        return pendingPackets[destinationHash]
    }
}

// MARK: - Internal Handlers

extension ReticuLumTransport {
    /// Internal handler for state changes (actor-isolated).
    func handleInterfaceStateChange(id: String, state: InterfaceState) {
        logger.info("Interface \(id, privacy: .public) state: \(String(describing: state), privacy: .public)")
    }

    /// Internal handler for received data (actor-isolated).
    func handleReceivedData(data: Data, from interfaceId: String) {
        let hexDump = data.prefix(30).map { String(format: "%02x", $0) }.joined()
        print("[PACKET_RECV] ===== PACKET RECEIVED =====")
        print("[PACKET_RECV] \(data.count) bytes from interface \(interfaceId)")
        print("[PACKET_RECV] Raw hex: \(hexDump)...")

        // Parse the data into a packet
        do {
            let packet = try Packet(from: data)
            let destHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
            let destFullHex = packet.destination.map { String(format: "%02x", $0) }.joined()
            let contextStr = packet.header.hasContext ? String(format: "0x%02x", packet.context) : "none"
            print("[PACKET_RECV] Parsed: type=\(packet.header.packetType), destType=\(packet.header.destinationType)")
            print("[PACKET_RECV] dest=\(destHex), context=\(contextStr), dataLen=\(packet.data.count)")

            // Log pending links status for every packet
            let pendingKeysHex = pendingLinks.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
            let pendingFullKeysHex = pendingLinks.keys.map { $0.map { String(format: "%02x", $0) }.joined() }
            print("[PACKET_RECV] Current pendingLinks: \(pendingLinks.count), keys=\(pendingKeysHex)")

            Task {
                await self.receive(packet: packet, from: interfaceId)
            }
        } catch {
            print("[PACKET_RECV] ERROR parsing packet: \(error)")
            logger.error("Failed to parse packet from interface \(interfaceId, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Internal handler for interface errors (actor-isolated).
    func handleInterfaceError(id: String, error: Error) {
        logger.warning("Interface \(id, privacy: .public) error: \(error.localizedDescription, privacy: .public)")
        // Interface handles reconnection internally
    }
}

// MARK: - Delegate Wrapper

/// Wrapper class that bridges InterfaceDelegate protocol to ReticuLumTransport actor.
///
/// Since actors cannot directly conform to @MainActor protocols, this wrapper
/// receives delegate callbacks and forwards them to the actor asynchronously.
public final class TransportDelegateWrapper: InterfaceDelegate, @unchecked Sendable {
    private weak var transport: ReticuLumTransport?

    public init(transport: ReticuLumTransport) {
        self.transport = transport
    }

    @MainActor
    public func interface(id: String, didChangeState state: InterfaceState) {
        guard let transport = transport else { return }
        Task {
            await transport.handleInterfaceStateChange(id: id, state: state)
        }
    }

    @MainActor
    public func interface(id: String, didReceivePacket data: Data) {
        guard let transport = transport else { return }
        Task {
            await transport.handleReceivedData(data: data, from: id)
        }
    }

    @MainActor
    public func interface(id: String, didFailWithError error: Error) {
        guard let transport = transport else { return }
        Task {
            await transport.handleInterfaceError(id: id, error: error)
        }
    }
}
