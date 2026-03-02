//
//  ReticulumTransport.swift
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
/// This protocol abstracts the interface layer so ReticulumTransport
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

    /// Hardware MTU for this interface (default 500).
    /// Used during link MTU discovery to negotiate larger payloads.
    var hwMtu: Int { get }

    /// Connect to the interface
    func connect() async throws

    /// Disconnect from the interface
    func disconnect() async

    /// Send data through the interface
    func send(_ data: Data) async throws

    /// Set the delegate for receiving events
    func setDelegate(_ delegate: InterfaceDelegate) async
}

/// Default hwMtu for interfaces that don't override it.
extension NetworkInterface {
    public var hwMtu: Int { 500 }

    /// E16: Radio signal strength (RSSI) for the most recent reception.
    /// Override in radio interfaces (e.g., RNodeInterface). Default: nil (not a radio).
    public var radioRssi: Double? { nil }

    /// E16: Radio signal-to-noise ratio for the most recent reception.
    /// Override in radio interfaces. Default: nil.
    public var radioSnr: Double? { nil }

    /// E16: Radio link quality metric for the most recent reception.
    /// Override in radio interfaces. Default: nil.
    public var radioQuality: Double? { nil }
}

// MARK: - ReticulumTransport Actor

/// Central transport actor for Reticulum packet routing.
///
/// ReticulumTransport is the core routing engine that:
/// - Dispatches outbound broadcast packets (HEADER_1) to all interfaces
/// - Dispatches outbound routed packets (HEADER_2) via path table lookup
/// - Routes inbound packets to registered local destinations
/// - Manages interface lifecycle (add/remove)
/// - Registers destinations for packet delivery
///
/// Example usage:
/// ```swift
/// let transport = ReticulumTransport()
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
/// Entry in the per-interface announce bandwidth queue.
/// Matches Python's announce_queue entry format (Interface.py:~246).
/// Supports destination dedup (update-only-if-newer) and min-hop-first drain priority.
struct AnnounceQueueEntry {
    let destination: Data       // 16-byte destination hash
    let time: Date              // Arrival time
    let hops: UInt8             // Hop count at time of queuing
    let emitted: UInt64         // Emission timestamp from random blob bytes[5:10]
    let encoded: Data           // Full encoded packet bytes

    /// Extract emission timestamp from an announce packet's data payload.
    /// Python: Transport.announce_emitted(packet) reads random_blob at
    /// data[KEYSIZE//8 + NAME_HASH_LENGTH//8 : +10], then extracts bytes[5:10]
    /// as a big-endian timestamp.
    static func announceEmitted(from packetData: Data) -> UInt64 {
        // random_blob is at offset 80 (64 pubkeys + 16 name hash), length 10
        let blobOffset = 80
        guard packetData.count >= blobOffset + 10 else { return 0 }
        let blob = packetData.subdata(in: blobOffset..<(blobOffset + 10))
        return PathEntry.emissionTimestamp(from: blob)
    }
}

public actor ReticulumTransport {

    // MARK: - Properties

    /// Path table for routing lookups
    let pathTable: PathTable

    /// Callback manager for packet delivery
    private let callbackManager: DefaultCallbackManager

    /// Announce handler for processing received announces
    private let announceHandler: AnnounceHandler

    /// Announce table for scheduled retransmissions (Python Transport.announce_table)
    private let announceTable = AnnounceTable()

    /// Whether this node acts as a transport node.
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

    /// Destination link callbacks: destHash -> callback when link is established
    /// Used by LXMF to set up resource handling on inbound links
    private var destinationLinkCallbacks: [Data: @Sendable (Link) async -> Void] = [:]

    // MARK: - Packet Proof Properties

    /// Pending packet proof callbacks (key = full 32-byte packet hash).
    /// When a link DATA packet proof arrives, the continuation is resumed with `true`.
    /// On timeout, resumed with `false`.
    private var pendingPacketProofs: [Data: CheckedContinuation<Bool, Never>] = [:]

    /// Proof callbacks for sent packets (key = truncated packet hash, 16 bytes).
    /// When a PROOF arrives matching a registered hash, the callback is invoked
    /// to notify the sender (e.g., LXMF delivery proof → message state = delivered).
    /// Entries expire after 5 minutes.
    private var pendingProofCallbacks: [Data: (callback: @Sendable () async -> Void, registeredAt: Date)] = [:]

    // MARK: - Path Request Properties

    /// Timestamps of recent path requests for throttling
    var pathRequestTimestamps: [Data: Date] = [:]

    /// Cooldown period between path requests for same destination (seconds)
    /// E2: Changed from 5s to match Python Transport.PATH_REQUEST_MI = 20s
    private let pathRequestCooldown: TimeInterval = TransportConstants.PATH_REQUEST_MI

    /// Packets waiting for path discovery
    private var pendingPackets: [Data: [Packet]] = [:]

    /// Maximum packets to queue per destination
    private let maxPendingPacketsPerDestination: Int = 10

    /// PLAIN destination for receiving path requests from other nodes
    private var pathRequestDestination: Destination?

    /// C14: Per-interface earliest time the next announce can be sent (bandwidth cap)
    private var announceAllowedAt: [String: Date] = [:]

    /// C16: Held announces — announces deferred for path request responses (stub)
    /// Key = destination hash, Value = announce packet held until next retransmission cycle.
    /// Low priority for iOS single-interface client.
    private var heldAnnounces: [Data: Packet] = [:]

    /// E5: Per-interface announce queues for when bandwidth cap blocks immediate send.
    /// Python (Interface.py:246) drains min-hop first, deduplicates by destination
    /// (updating only if newer emission timestamp).
    private var announceQueues: [String: [AnnounceQueueEntry]] = [:]

    /// E11: Per-interface announce ingress timestamps for storm detection
    private var announceIngressTimestamps: [String: [Date]] = [:]
    private let ingressDequeSize = 6

    /// E12: Pending local path requests (dest hash → receiving interface ID)
    private var pendingLocalPathRequests: [Data: String] = [:]

    /// E13: Receipt-based proof validation
    private var receipts: [(hash: Data, callback: @Sendable () async -> Void, timeout: Date)] = []
    private let maxReceipts = 1024

    /// E16: Radio stats caching
    private var radioRssiCache: [(packetHash: Data, value: Double)] = []
    private var radioSnrCache: [(packetHash: Data, value: Double)] = []
    private var radioQualityCache: [(packetHash: Data, value: Double)] = []
    private let maxRadioCacheSize = 512

    /// Dedup cache for path request tags (matching Python max_pr_tags=32000)
    private var discoveryPrTags: [Data] = []
    private let maxPrTags = 32000

    /// Pending discovery path requests (for forwarding, keyed by dest hash)
    private var discoveryPathRequests: [Data: (timeout: Date, requestingInterfaceId: String?)] = [:]

    /// Path request constants matching Python Transport.py
    private static let PATH_REQUEST_GRACE: TimeInterval = 0.4
    private static let PATH_REQUEST_TIMEOUT: TimeInterval = 15.0

    /// Interface ID that last delivered an inbound packet (set before dispatch).
    /// Used by handlePathRequest to know which interface to avoid when forwarding.
    /// Safe because this actor processes packets sequentially.
    private var lastReceivedInterfaceId: String?

    // MARK: - Transport Table Properties

    /// Link transport table: link_id → entry.
    /// Populated when forwarding LINKREQUESTs; used for PROOF routing and DATA forwarding.
    /// Python reference: Transport.py ~line 1482
    var linkTable: [Data: LinkTableEntry] = [:]

    /// Reverse transport table: truncated_packet_hash → entry.
    /// Populated when forwarding non-link DATA; used for PROOF routing back.
    /// Python reference: Transport.py ~line 1551
    var reverseTable: [Data: ReverseTableEntry] = [:]

    /// Packet dedup hashlist: rotating sets of seen packet hashes.
    /// Python reference: Transport.py ~line 1230
    let packetHashlist = PacketHashlist()

    /// E8: Cached IFAC signing seeds per interface.
    /// Key = interface ID, Value = 32-byte Ed25519 signing seed (bytes 32-63 of ifac_key).
    /// Uses Ed25519Pure (deterministic RFC 8032) for IFAC interop with Python.
    private var ifacSigningSeeds: [String: Data] = [:]

    /// Called when a new sub-interface is added (e.g., BLE peer connects).
    /// The app layer hooks this to trigger a full announce (with display name, ratchet, etc.).
    private var onInterfaceAdded: (@Sendable (String) async -> Void)?

    /// Set the callback for when a new sub-interface is added.
    public func setOnInterfaceAdded(_ callback: (@Sendable (String) async -> Void)?) {
        self.onInterfaceAdded = callback
    }

    /// Diagnostic callback for packet receive events (set by app layer).
    public var onDiagnostic: (@Sendable (String) -> Void)?

    /// Set the diagnostic callback (actor-isolated setter for cross-actor access).
    public func setOnDiagnostic(_ callback: @escaping @Sendable (String) -> Void) {
        self.onDiagnostic = callback
    }

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
        self.logger = Logger(subsystem: "net.reticulum", category: "Transport")
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

        // E8: Cache IFAC Ed25519 signing seed if interface has IFAC configured
        // Python: ifac_identity = Identity.from_bytes(ifac_key) → signing key = bytes[32:64]
        if let ifacKey = interface.config.ifacKey, interface.config.ifacSize > 0, ifacKey.count == 64 {
            let signingSeed = ifacKey[32..<64]
            ifacSigningSeeds[id] = Data(signingSeed)
            logger.info("IFAC signing seed cached for interface \(id, privacy: .public), ifacSize=\(interface.config.ifacSize, privacy: .public)")
        }

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
                    await self.onInterfaceAdded?(peer.id)
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
                    await self.onInterfaceAdded?(peer.id)
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
    /// Check if a destination hash is registered.
    public func isDestinationRegistered(_ hash: Data) -> Bool {
        destinations[hash] != nil
    }

    /// Return hex hashes of all registered destinations (for diagnostics).
    public func registeredDestinationHashes() -> [String] {
        destinations.keys.map { $0.map { String(format: "%02x", $0) }.joined() }
    }

    /// Return hex hashes of all registered link callbacks (for diagnostics).
    public func registeredLinkCallbackHashes() -> [String] {
        destinationLinkCallbacks.keys.map { $0.map { String(format: "%02x", $0) }.joined() }
    }

    public func registerDestination(_ destination: Destination) {
        let hash = destination.hash
        destinations[hash] = destination
        destination.setCallbackManager(callbackManager)

        let hexFull = hash.map { String(format: "%02x", $0) }.joined()
        logger.info("registerDestination: hash=\(hexFull), destinations count=\(self.destinations.count)")
    }

    /// Register a callback for when a link is established to a destination.
    ///
    /// This is used by LXMF to set up resource handling (strategy + callbacks)
    /// on inbound links to delivery destinations.
    ///
    /// Reference: Python Transport.register_destination_link_callback()
    ///
    /// - Parameters:
    ///   - destHash: Destination hash to register callback for
    ///   - callback: Callback invoked when a link is established to this destination
    public func registerDestinationLinkCallback(for destHash: Data, callback: @escaping @Sendable (Link) async -> Void) {
        destinationLinkCallbacks[destHash] = callback
        let hex = destHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        logger.info("Registered link callback for destination \(hex)")
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

    /// Look up the HW_MTU of the next-hop interface for a destination.
    /// Matches Python Transport.next_hop_interface_hw_mtu().
    public func nextHopInterfaceHwMtu(for destinationHash: Data) async -> Int? {
        guard let pathEntry = await pathTable.lookup(destinationHash: destinationHash) else {
            return nil
        }
        guard let iface = interfaces[pathEntry.interfaceId] else {
            return nil
        }
        return await iface.hwMtu
    }

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

        // Query next-hop interface HW_MTU for link MTU discovery
        let hwMtu = await nextHopInterfaceHwMtu(for: destination.hash)
        let destHex = destination.hash.prefix(8).map { String(format: "%02x", $0) }.joined()
        logger.info("[MTU_DISCOVERY] dest=\(destHex, privacy: .public), hwMtu=\(String(describing: hwMtu), privacy: .public)")
        if hwMtu == nil {
            // Debug: log why lookup failed
            if let pathEntry = await pathTable.lookup(destinationHash: destination.hash) {
                let ifaceId = pathEntry.interfaceId
                let registered = Array(interfaces.keys)
                logger.info("[MTU_DISCOVERY] pathEntry.interfaceId='\(ifaceId, privacy: .public)', registered=\(registered.joined(separator: ","), privacy: .public)")
            } else {
                logger.info("[MTU_DISCOVERY] No path entry found (despite hasPath check)")
            }
        }

        // Create link with interface HW_MTU for MTU negotiation
        let link = Link(destination: destination, identity: identity, hwMtu: hwMtu)

        // Set send callback - routes via attached interface when known
        // The Link builds complete packets (with header, context, etc.)
        await link.setSendCallback { [weak self, weak link] packetBytes in
            guard let self = self else { throw TransportError.notConnected }
            let ifaceId = await link?.attachedInterfaceId
            try await self.sendRawBytes(packetBytes, interfaceId: ifaceId)
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

        logger.debug("LINKREQUEST raw len=\(packetRaw.count): \(packetRawHex)")
        logger.debug("LINKREQUEST hashable pre=\(hashablePreTrim), post=\(hashablePostTrim): \(hashableHex)")
        logger.debug("LINKREQUEST dest=\(packetDestHex), actualLinkId=\(actualHex), cachedLinkId=\(cachedHex)")

        // Use the ACTUAL link_id computed from the packet that will be sent
        let linkId = actualLinkId
        let actualFullHex = actualLinkId.map { String(format: "%02x", $0) }.joined()
        logger.debug("Registering pending link: linkId=\(actualHex) (full: \(actualFullHex)), pendingLinks before: \(self.pendingLinks.count)")
        pendingLinks[linkId] = link
        let afterKeys = pendingLinks.keys.map { $0.map { String(format: "%02x", $0) }.joined() }
        logger.debug("pendingLinks after: \(self.pendingLinks.count), keys=\(afterKeys)")

        await link.markRequestSent()
        let linkState = await link.state
        logger.debug("Link marked as sent, state=\(String(describing: linkState)). Sending LINKREQUEST packet...")
        try await send(packet: packet)
        logger.info("LINKREQUEST sent successfully, waiting for PROOF")

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

    /// Register a callback to be invoked when a delivery proof arrives for a sent packet.
    ///
    /// Used by LXMF to receive delivery confirmations for opportunistic messages.
    /// The callback is invoked once when a matching proof arrives, then removed.
    /// Callbacks expire after 5 minutes if no proof arrives.
    ///
    /// - Parameters:
    ///   - truncatedHash: Truncated packet hash (16 bytes) used as proof destination
    ///   - callback: Closure to invoke when proof arrives
    public func registerProofCallback(truncatedHash: Data, callback: @Sendable @escaping () async -> Void) {
        let hex = truncatedHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        logger.debug("Registered proof callback for \(hex), total=\(self.pendingProofCallbacks.count + 1)")
        pendingProofCallbacks[truncatedHash] = (callback: callback, registeredAt: Date())
    }

    /// Remove a pending proof callback (e.g., on send failure).
    public func removeProofCallback(truncatedHash: Data) {
        pendingProofCallbacks.removeValue(forKey: truncatedHash)
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
            logger.warning("Proof payload too short: \(proofData.count) bytes")
            return
        }

        let proofHash = Data(proofData.prefix(32))
        let proofHex = proofHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        logger.debug("Received DATA proof, packetHash=\(proofHex)..., totalLen=\(proofData.count)")

        // Check against pending packet proofs
        if let continuation = pendingPacketProofs.removeValue(forKey: proofHash) {
            logger.info("Proof confirmed delivery for packetHash=\(proofHex)")
            continuation.resume(returning: true)
        } else {
            let pendingHashes = pendingPacketProofs.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
            logger.debug("No pending proof match for \(proofHex). Pending hashes: \(pendingHashes)")
        }
    }

    /// Send raw packet bytes, optionally to a specific interface.
    ///
    /// Used by Link callbacks to send pre-built packets (LRRTT, keepalive, etc.)
    /// The bytes are sent directly without additional wrapping.
    /// When interfaceId is provided, sends only on that interface (matching Python's
    /// behavior of routing link traffic via the attached interface).
    ///
    /// - Parameters:
    ///   - bytes: Encoded packet bytes to send
    ///   - interfaceId: Optional specific interface to send on (nil = all)
    /// - Throws: TransportError if send fails
    private func sendRawBytes(_ bytes: Data, interfaceId: String? = nil) async throws {
        let bytesHex = bytes.prefix(20).map { String(format: "%02x", $0) }.joined()
        logger.debug("sendRawBytes called with \(bytes.count) bytes: \(bytesHex)... interfaceId=\(interfaceId ?? "all")")

        // If a specific interface is requested, send only on that one
        if let targetId = interfaceId {
            guard let interface = interfaces[targetId], interface.state == .connected else {
                // Fall back to broadcast if the specified interface is unavailable
                logger.warning("Specified interface \(targetId, privacy: .public) unavailable, falling back to broadcast")
                try await sendRawBytes(bytes, interfaceId: nil)
                return
            }
            // E8: Apply IFAC before transmitting
            let transmitData = applyIFAC(raw: bytes, interfaceId: targetId)
            try await interface.send(transmitData)
            logger.debug("Sent \(transmitData.count) bytes via attached interface '\(targetId)'")
            return
        }

        var successCount = 0
        var lastError: Error?

        for (id, interface) in interfaces {
            guard interface.state == .connected else {
                logger.debug("Skipping disconnected interface '\(id)'")
                continue
            }

            do {
                // E8: Apply IFAC per-interface before transmitting
                let transmitData = applyIFAC(raw: bytes, interfaceId: id)
                try await interface.send(transmitData)
                successCount += 1
                logger.debug("Sent \(transmitData.count) bytes via interface '\(id)'")
            } catch {
                lastError = error
                logger.warning("Failed to send raw bytes on interface '\(id)': \(error.localizedDescription)")
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
        logger.debug("Packet send: dest=\(destHex), packetType=\(String(describing: packet.header.packetType)), transportType=\(String(describing: packet.header.transportType))")

        // Determine dispatch strategy based on header type
        switch packet.header.transportType {
        case .broadcast:
            // ANNOUNCE packets must ALWAYS be sent as HEADER_1/BROADCAST by the originator.
            // Only transport nodes convert announces to HEADER_2 when re-broadcasting.
            // Converting our own announce to HEADER_2 causes the transport node to mishandle it.
            if packet.header.packetType == .announce {
                logger.debug("ANNOUNCE: sending as HEADER_1 with per-interface filtering")
                try await sendAnnounceFiltered(packet)
            } else {
                // HEADER_1: Check if we need to convert to HEADER_2 for multi-hop routing
                // This applies to LINKREQUEST and other packets going to remote destinations
                let pathEntry = await pathTable.lookup(destinationHash: packet.destination)
                if let entry = pathEntry {
                    let nextHopStatus = entry.nextHop != nil ? entry.nextHop!.prefix(8).map { String(format: "%02x", $0) }.joined() : "nil"
                    logger.debug("PathEntry found: hopCount=\(entry.hopCount), nextHop=\(nextHopStatus), interfaceId='\(entry.interfaceId)'")
                } else {
                    logger.debug("PathEntry NOT found for dest=\(destHex)")
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
                    logger.debug("Converting to HEADER_2: dest=\(destHex), nextHop=\(nextHopHex), hops=\(entry.hopCount)")
                    // M1: Send on specific interface when path is known
                    let outboundId = entry.interfaceId.isEmpty ? nil : entry.interfaceId
                    if let outboundId {
                        try await sendToInterface(routedPacket.encode(), interfaceId: outboundId)
                    } else {
                        try await sendToAllInterfaces(routedPacket)
                    }
                } else {
                    // Direct delivery (single hop or no path) - send as HEADER_1
                    if let entry = pathEntry {
                        if entry.hopCount > 1 && entry.nextHop == nil {
                            logger.warning("hopCount=\(entry.hopCount) but nextHop is nil! Sending as HEADER_1 (transport will route)")
                        } else if entry.hopCount == 1 {
                            logger.debug("Single hop (hops=1): sending as HEADER_1")
                        }
                        // M1: Send on specific interface when path is known
                        let outboundId = entry.interfaceId.isEmpty ? nil : entry.interfaceId
                        if let outboundId {
                            logger.debug("Sending as HEADER_1 via specific interface '\(outboundId)'")
                            try await sendToInterface(packet.encode(), interfaceId: outboundId)
                        } else {
                            logger.debug("Sending as HEADER_1 (direct broadcast)")
                            try await sendToAllInterfaces(packet)
                        }
                    } else {
                        // M2: Record outbound hash for broadcast (prevents self-reception on shared medium)
                        let packetHash = packet.getFullHash()
                        await packetHashlist.record(packetHash)
                        logger.debug("Sending as HEADER_1 (broadcast, no path)")
                        try await sendToAllInterfaces(packet)
                    }
                }
            }

        case .transport:
            // HEADER_2: Route via path table
            try await sendViaPath(packet)
        }
    }

    /// Send a packet and auto-register a receipt for proof-of-delivery.
    ///
    /// Matches Python Packet.send() which creates a PacketReceipt for non-PLAIN
    /// destination types. When a PROOF matching the packet hash arrives, the
    /// callback is invoked.
    ///
    /// - Parameters:
    ///   - packet: Packet to send
    ///   - receiptCallback: Callback invoked when delivery proof is received
    ///   - receiptTimeout: Receipt expiry in seconds (default 300)
    /// - Throws: TransportError if send fails
    public func send(
        packet: Packet,
        receiptCallback: @escaping @Sendable () async -> Void,
        receiptTimeout: TimeInterval = 300
    ) async throws {
        try await send(packet: packet)

        // Register receipt for proof-based delivery confirmation.
        // Python (Transport.py:947-958) only creates receipts when ALL conditions hold:
        //   1. packet_type == DATA
        //   2. destination.type != PLAIN
        //   3. context NOT in KEEPALIVE..LRPROOF (link-control range)
        //   4. context NOT in RESOURCE..RESOURCE_RCL (resource range)
        if packet.header.packetType == .data,
           packet.header.destinationType != .plain,
           !PacketContext.isLinkContext(packet.context),
           !PacketContext.isResourceContext(packet.context) {
            let packetHash = packet.getTruncatedHash()
            registerReceipt(hash: packetHash, timeout: receiptTimeout, callback: receiptCallback)
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

        // M3: Check if the link has an attached interface for targeted send
        let linkId = packet.destination
        let attachedId = await activeLinks[linkId]?.attachedInterfaceId

        // Look up path using the DESTINATION hash (not the linkId)
        // M4: Convert to HEADER_2 only when hops > 1 (Python Transport.py:~500)
        if let pathEntry = await pathTable.lookup(destinationHash: destinationHash),
           pathEntry.hopCount > 1,
           let nextHop = pathEntry.nextHop {
            // Convert to HEADER_2 for routed delivery
            let routedPacket = convertToHeader2(packet: packet, nextHop: nextHop)
            let destHex = destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined()
            let linkIdHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
            let nextHopHex = nextHop.prefix(8).map { String(format: "%02x", $0) }.joined()
            logger.debug("Link DATA: converting to HEADER_2, linkId=\(linkIdHex), destHash=\(destHex), nextHop=\(nextHopHex), hops=\(pathEntry.hopCount)")
            // M1/M3: Send on specific interface
            let outboundId = attachedId ?? (pathEntry.interfaceId.isEmpty ? nil : pathEntry.interfaceId)
            if let outboundId {
                try await sendToInterface(routedPacket.encode(), interfaceId: outboundId)
            } else {
                try await sendToAllInterfaces(routedPacket)
            }
        } else {
            // Direct delivery (no multi-hop) - send as HEADER_1
            let linkIdHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
            logger.debug("Link DATA: sending as HEADER_1, linkId=\(linkIdHex)")
            // M3: Use attached interface if known
            if let attachedId {
                try await sendToInterface(packet.encode(), interfaceId: attachedId)
            } else {
                try await sendToAllInterfaces(packet)
            }
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
        logger.debug("HEADER_2 packet encoded: \(encodedHex)...")

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

        logger.debug("Sending \(encoded.count) bytes: header=\(headerHex), dest=\(destHex), context=\(contextStr), headerType=\(String(describing: packet.header.headerType)), transportType=\(String(describing: packet.header.transportType)), destType=\(String(describing: packet.header.destinationType)), packetType=\(String(describing: packet.header.packetType)), interfaces=\(self.interfaces.count)")
        logger.debug("First 40 bytes: \(fullHex)")
        var successCount = 0
        var lastError: Error?

        for (id, interface) in interfaces {
            // Skip disconnected interfaces
            guard interface.state == .connected else {
                logger.debug("Skipping disconnected interface: \(id)")
                continue
            }

            do {
                // E8: Apply IFAC per-interface before transmitting
                let transmitData = applyIFAC(raw: encoded, interfaceId: id)
                try await interface.send(transmitData)
                successCount += 1
                logger.debug("Broadcast sent \(transmitData.count) bytes via '\(id)'")
            } catch {
                lastError = error
                logger.warning("Broadcast failed on '\(id)': \(error.localizedDescription)")
            }
        }

        // If no interfaces succeeded, throw error
        if successCount == 0 {
            logger.error("sendToAllInterfaces failed: no interfaces succeeded")
            if let error = lastError {
                throw TransportError.sendFailed(interfaceId: "all", underlying: error.localizedDescription)
            } else {
                throw TransportError.noInterfacesAvailable
            }
        }

        logger.info("Broadcast complete: \(successCount) interface(s)")
    }

    /// Send an announce with per-interface mode filtering and bandwidth cap.
    ///
    /// Matches Python Transport.outbound() behavior for announces:
    /// - Per-interface AnnounceFilter based on outgoing mode
    /// - Per-interface announce bandwidth cap (announce_allowed_at)
    /// - Queue announces that exceed bandwidth cap
    ///
    /// For outbound (originator) announces, sourceMode is nil (we are the source).
    ///
    /// - Parameter packet: Announce packet to send
    /// - Throws: TransportError if all sends fail
    private func sendAnnounceFiltered(_ packet: Packet) async throws {
        let encoded = packet.encode()
        let destHex = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
        let isLocal = isLocalDestination(packet.destination)
        let now = Date()

        var successCount = 0
        var lastError: Error?

        for (id, interface) in interfaces {
            guard interface.state == .connected else { continue }

            // Apply AnnounceFilter: for originator announces, sourceMode is nil
            guard AnnounceFilter.shouldForward(
                outgoingMode: interface.config.mode,
                sourceMode: nil,
                isLocalDestination: isLocal
            ) else {
                logger.debug("Filtered out announce for \(destHex) on interface '\(id)' (mode=\(String(describing: interface.config.mode)))")
                continue
            }

            // Per-interface announce bandwidth cap (C14)
            if let allowedAt = announceAllowedAt[id], now < allowedAt {
                // Queue announce for later delivery (E5) with dedup by destination
                var queue = announceQueues[id] ?? []
                let emitted = AnnounceQueueEntry.announceEmitted(from: packet.data)
                if let existingIdx = queue.firstIndex(where: { $0.destination == packet.destination }) {
                    // Python: only update if newer emission timestamp
                    if emitted > queue[existingIdx].emitted {
                        queue[existingIdx] = AnnounceQueueEntry(
                            destination: packet.destination, time: now,
                            hops: packet.header.hopCount, emitted: emitted, encoded: encoded
                        )
                    }
                } else if queue.count < TransportConstants.MAX_QUEUED_ANNOUNCES {
                    queue.append(AnnounceQueueEntry(
                        destination: packet.destination, time: now,
                        hops: packet.header.hopCount, emitted: emitted, encoded: encoded
                    ))
                }
                announceQueues[id] = queue
                continue
            }

            do {
                // E8: Apply IFAC per-interface before transmitting
                let transmitData = applyIFAC(raw: encoded, interfaceId: id)
                try await interface.send(transmitData)
                successCount += 1

                // Update bandwidth tracking
                let bitrate = interface.config.bitrate
                if bitrate > 0 {
                    let txTime = Double(encoded.count * 8) / Double(bitrate)
                    let waitTime = txTime / TransportConstants.ANNOUNCE_CAP
                    announceAllowedAt[id] = now.addingTimeInterval(waitTime)
                }

                logger.debug("Sent announce for \(destHex) via '\(id)'")
            } catch {
                lastError = error
                logger.warning("Failed to send announce on \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }

        if successCount == 0 {
            if let error = lastError {
                throw TransportError.sendFailed(interfaceId: "all", underlying: error.localizedDescription)
            } else {
                // All interfaces were filtered — not necessarily an error for announces
                logger.debug("Announce for \(destHex, privacy: .public) filtered on all interfaces")
            }
        }
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
            logger.info("No path to \(destHex)..., queuing packet")
            queuePendingPacket(packet, for: destHash)
            try? await requestPath(for: destHash)
            return  // Don't throw - packet is queued for later delivery
        }

        let interfaceId = pathEntry.interfaceId
        logger.debug("Found path to \(destHex)... via interface '\(interfaceId)'")

        // Get the interface
        guard let interface = interfaces[interfaceId] else {
            logger.error("Interface '\(interfaceId)' not found in interfaces dict (have: \(Array(self.interfaces.keys)))")
            throw TransportError.interfaceNotFound(id: interfaceId)
        }

        // Check interface is connected
        guard interface.state == .connected else {
            logger.error("Interface '\(interfaceId)' not connected (state=\(String(describing: interface.state)))")
            throw TransportError.interfaceNotFound(id: interfaceId)
        }

        // Send the packet
        let encoded = packet.encode()
        logger.debug("Sending \(encoded.count) bytes via '\(interfaceId)' (type=\(String(describing: packet.header.packetType)))")
        do {
            try await interface.send(encoded)
            logger.debug("Routed packet sent via interface '\(interfaceId)'")
        } catch {
            logger.error("Send failed via '\(interfaceId)': \(error.localizedDescription)")
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

        // E8: Apply IFAC before transmitting
        let transmitData = applyIFAC(raw: data, interfaceId: interfaceId)

        do {
            try await interface.send(transmitData)
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
        let destHex = destHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        onDiagnostic?("[RECV] type=\(packet.header.packetType) dest=\(destHex) from=\(interfaceId) len=\(packet.data.count)")

        // C1+C2+C5: packet_filter() equivalent — runs UNCONDITIONALLY (not gated on transportEnabled)
        // Python reference: Transport.py packet_filter()

        // C5: Transport ID pre-filter: HEADER_2 non-announce packets addressed to a
        // transport address that isn't ours should be dropped before dedup.
        if packet.header.headerType == .header2,
           packet.header.packetType != .announce,
           let transportAddr = packet.transportAddress,
           transportAddr != transportIdentityHash {
            onDiagnostic?("[FILTER] HEADER_2 non-announce not addressed to us, dropping dest=\(destHex)")
            return
        }

        // C1: PLAIN/GROUP hop limit filter
        // Python: drop all plain/group announces; drop non-announce with hops > 0
        if packet.header.destinationType == .plain || packet.header.destinationType == .group {
            if packet.header.packetType == .announce {
                onDiagnostic?("[FILTER] Dropping plain/group announce dest=\(destHex)")
                return
            }
            if packet.header.hopCount > 0 {
                onDiagnostic?("[FILTER] Dropping plain/group non-announce with hops>0 dest=\(destHex)")
                return
            }
        }

        // C2: Context bypass — skip dedup for these contexts
        let skipDedup = (
            packet.context == PacketContext.KEEPALIVE ||
            packet.context == PacketContext.RESOURCE ||
            packet.context == PacketContext.RESOURCE_REQ ||
            packet.context == PacketContext.RESOURCE_PRF ||
            packet.context == PacketContext.CACHE_REQUEST ||
            packet.context == PacketContext.CHANNEL
        )

        // Packet dedup: unconditional (not gated on transportEnabled), announces bypass
        // Python reference: Transport.py ~line 1230
        if !skipDedup && packet.header.packetType != .announce {
            let packetHash = packet.getFullHash()
            let isNew = await packetHashlist.shouldAccept(packetHash)
            if !isNew {
                onDiagnostic?("[DEDUP] Duplicate packet dropped dest=\(destHex)")
                return
            }

            // D5: Defer hash recording for link_table packets and LRPROOF.
            // On shared-medium interfaces, a packet might arrive at a transport node
            // before it reaches the actual link endpoint. If the hash were recorded
            // immediately, the endpoint would reject it as duplicate.
            // Python reference: Transport.py lines 1362-1369
            let isLinkTablePacket = linkTable[destHash] != nil
            let isLRProof = (packet.header.packetType == .proof && packet.context == PacketContext.LRPROOF)
            let deferRecording = isLinkTablePacket || isLRProof

            if !deferRecording {
                await packetHashlist.record(packetHash)
            }
        }

        // E16: Cache radio stats from interface (if available)
        if let iface = interfaces[interfaceId] {
            let ph = packet.getFullHash()
            if let v = iface.radioRssi {
                radioRssiCache.append((ph, v))
                if radioRssiCache.count > maxRadioCacheSize { radioRssiCache.removeFirst() }
            }
            if let v = iface.radioSnr {
                radioSnrCache.append((ph, v))
                if radioSnrCache.count > maxRadioCacheSize { radioSnrCache.removeFirst() }
            }
            if let v = iface.radioQuality {
                radioQualityCache.append((ph, v))
                if radioQualityCache.count > maxRadioCacheSize { radioQualityCache.removeFirst() }
            }
        }

        // Route based on packet type
        switch packet.header.packetType {
        case .announce:
            // Log full dest hash for announce to help debug telephony announce reception
            let fullDestHex = destHash.map { String(format: "%02x", $0) }.joined()
            onDiagnostic?("[RECV_ANNOUNCE] fullDest=\(fullDestHex) from=\(interfaceId)")
            logger.info("Processing ANNOUNCE packet from interface \(interfaceId)")
            await processAnnounce(packet: packet, from: interfaceId)

        case .linkRequest:
            // LINKREQUEST goes to registered destination (if we're the target)
            onDiagnostic?("[RECV] LINKREQUEST for dest=\(destHex)")
            await handleLinkRequest(packet, from: interfaceId)

        case .proof:
            // C9+C10: Restructured proof dispatch matching Python priority order.
            // Python checks: link_table → pending_links → active_links → reverse_table → local callbacks
            let proofDestHex = destHash.prefix(8).map { String(format: "%02x", $0) }.joined()
            let proofFullHex = destHash.map { String(format: "%02x", $0) }.joined()
            logger.debug("PROOF received: dest=\(proofDestHex), full=\(proofFullHex), context=0x\(String(format: "%02x", packet.context)), dataLen=\(packet.data.count)")

            // C9: Transport link proof forwarding — check linkTable FIRST (before pendingLinks)
            // This matches Python priority: transport forwarding takes precedence over local delivery
            if transportEnabled, let linkEntry = linkTable[destHash] {
                if packet.context == PacketContext.LRPROOF {
                    // E1: LRPROOF uses validated forwarding (signature check)
                    logger.debug("Forward LRPROOF for link=\(proofDestHex)")
                    await forwardLinkProof(packet, linkEntry: linkEntry, from: interfaceId)
                } else {
                    // E1: Non-LRPROOF proofs use simple bidirectional forwarding (no signature validation)
                    logger.debug("Forward non-LRPROOF for link=\(proofDestHex)")
                    await forwardLinkData(packet, linkEntry: linkEntry, from: interfaceId)
                }
            } else if let link = pendingLinks[destHash] {
                logger.info("Found pending link for PROOF dest=\(proofDestHex), processing...")
                await handleLinkProof(packet, link: link, from: interfaceId)
            } else if let link = activeLinks[destHash] {
                // PROOF on active link: could be data proof or resource proof
                if packet.context == ResourcePacketContext.resourceProof {
                    logger.debug("RESOURCE proof on active link \(proofDestHex), data=\(packet.data.count) bytes")
                    await link.handleResourcePacket(context: packet.context, data: packet.data)
                } else {
                    logger.debug("DATA proof on active link \(proofDestHex)")
                    await handleDataProof(packet, link: link)
                }
            } else {
                // C10: Sequential proof routing — forward via reverse table AND check local callbacks.
                // Python checks reverse_table AND receipts non-exclusively (both can match).
                var handled = false

                // Forward via reverse table (C11: works even without transportEnabled)
                if let reverseEntry = reverseTable.removeValue(forKey: destHash) {
                    logger.debug("Forward DATA PROOF for \(proofDestHex)")
                    await forwardDataProof(packet, reverseEntry: reverseEntry, from: interfaceId)
                    handled = true
                }

                // ALSO check local proof callbacks (not exclusive with reverse table)
                if let entry = pendingProofCallbacks.removeValue(forKey: destHash) {
                    logger.info("Matched delivery proof callback for \(proofDestHex), invoking callback")
                    Task { await entry.callback() }
                    handled = true
                }

                // E13: Check receipts — Python checks ALL receipts regardless of reverse table match
                if let idx = receipts.firstIndex(where: { $0.hash == destHash }) {
                    let receipt = receipts.remove(at: idx)
                    Task { await receipt.callback() }
                    handled = true
                }

                if !handled {
                    let cbCount = pendingProofCallbacks.count
                    logger.debug("No match for PROOF \(proofDestHex), pendingCallbacks=\(cbCount)")
                    await handleAnnounceProof(packet, from: interfaceId)
                }
            }

            // Clean up expired proof callbacks (older than 5 minutes)
            let now = Date()
            pendingProofCallbacks = pendingProofCallbacks.filter { now.timeIntervalSince($0.value.registeredAt) < 300 }

        case .data:
            // C24: CACHE_REQUEST stub — log and drop (no cache infrastructure on iOS)
            if packet.context == PacketContext.CACHE_REQUEST {
                onDiagnostic?("[RECV] CACHE_REQUEST received, dropping (not supported)")
                return
            }

            lastReceivedInterfaceId = interfaceId  // Track for path request handler
            let dataDestHex = destHash.prefix(8).map { String(format: "%02x", $0) }.joined()
            logger.debug("DATA packet received: destType=\(String(describing: packet.header.destinationType)), dest=\(dataDestHex), ctx=0x\(String(format: "%02x", packet.context)), dataLen=\(packet.data.count)")
            if packet.header.destinationType == .link {
                // Link DATA packet - route to link
                logger.debug("Routing to handleLinkData()")
                await handleLinkData(packet, from: interfaceId)
            } else {
                // Regular data - deliver to local destination
                logger.debug("Routing to handleRegularData()")
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
            // Not a local destination — try forwarding if transport is enabled
            if transportEnabled {
                await forwardLinkRequest(packet, from: interfaceId)
            } else {
                onDiagnostic?("[LINKREQUEST] dest \(hexPrefix) NOT registered, ignoring")
            }
            return
        }
        onDiagnostic?("[LINKREQUEST] dest \(hexPrefix) found, processing")

        // Parse the incoming LINKREQUEST
        let incomingRequest: IncomingLinkRequest
        do {
            incomingRequest = try IncomingLinkRequest(data: packet.data, packet: packet)
        } catch {
            logger.warning("Failed to parse LINKREQUEST for \(hexPrefix, privacy: .public)...: \(error.localizedDescription, privacy: .public)")
            return
        }

        let linkIdHex = incomingRequest.linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        logger.info("Received LINKREQUEST for dest=\(hexPrefix), linkId=\(linkIdHex)")

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

        // Set up send callback for the link - routes via attached interface when known
        await link.setSendCallback { [weak self, weak link] (data: Data) async throws -> Void in
            guard let self = self else { return }
            let ifaceId = await link?.attachedInterfaceId
            try await self.sendRawBytes(data, interfaceId: ifaceId)
        }

        // Configure link with destination callbacks IMMEDIATELY (before LRRTT).
        // This prevents a race condition where a resource advertisement arrives
        // and is processed before the LRRTT completes. Without this, the resource
        // strategy is still .acceptNone when the advertisement is checked, causing
        // the resource to be rejected and the link to close prematurely.
        // NOTE: Callbacks should only CONFIGURE the link here (set strategy,
        // handlers). Do NOT send data — encryption keys aren't derived yet.
        if let destCallback = destinationLinkCallbacks[packet.destination] {
            await destCallback(link)
            logger.debug("Pre-configured link \(linkIdHex) with destination callbacks")
        }

        // Chain any established callback set by destCallback with transport logging.
        let existingEstablishedCallback = await link.linkEstablishedCallback
        let diagCallback = self.onDiagnostic
        let capturedLogger = self.logger
        await link.setLinkEstablishedCallback { [weak self] (establishedLink: Link) async -> Void in
            let linkIdHex = await establishedLink.linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
            diagCallback?("[LINK] \(linkIdHex) established (responder)")
            capturedLogger.info("Link \(linkIdHex) established (responder)")
            // Invoke any callback set by the destination (e.g., LXST telephony)
            if existingEstablishedCallback != nil {
                diagCallback?("[LINK] invoking dest established callback for \(linkIdHex)")
                await existingEstablishedCallback?(establishedLink)
                diagCallback?("[LINK] dest established callback done for \(linkIdHex)")
            } else {
                diagCallback?("[LINK] no dest established callback for \(linkIdHex)")
            }
            _ = self // prevent unused warning
        }

        // Create and send PROOF
        do {
            let proofPacket = try await link.createProofPacket()
            let proofData = proofPacket.encode()

            logger.info("Sending PROOF (\(proofData.count) bytes) for link \(linkIdHex)")

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
            // H2: Track which interface the link was established on
            await link.setAttachedInterface(interfaceId)
            logger.debug("Link \(linkIdHex) stored in activeLinks, awaiting LRRTT")

            logger.info("LINKREQUEST accepted for \(hexPrefix, privacy: .public)..., PROOF sent, awaiting LRRTT")

        } catch {
            logger.warning("Failed to create/send PROOF for \(hexPrefix, privacy: .public)...: \(error.localizedDescription, privacy: .public)")
            await link.close(reason: TeardownReason.timeout)
        }
    }

    /// Get the link callback for a destination (if registered).
    private func getDestinationLinkCallback(for destHash: Data) async -> (@Sendable (Link) async -> Void)? {
        return destinationLinkCallbacks[destHash]
    }

    /// Handle PROOF for a pending link.
    ///
    /// Validates the proof and moves the link from pending to active.
    ///
    /// - Parameters:
    ///   - packet: PROOF packet
    ///   - link: The pending link that this proof is for
    ///   - interfaceId: ID of interface that received the PROOF (H2)
    private func handleLinkProof(_ packet: Packet, link: Link, from interfaceId: String) async {
        let proofDestHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
        let proofDataHex = packet.data.prefix(20).map { String(format: "%02x", $0) }.joined()
        logger.debug("Processing PROOF for dest=\(proofDestHex), data length=\(packet.data.count) bytes, data: \(proofDataHex)...")

        // C12: LRPROOF hop count check on local delivery
        // Python checks post-incremented hops against expected_hops from path table.
        // We don't currently track expected_hops on Link, so this is a no-op when
        // expectedHops defaults to PATHFINDER_M (always accepted). Implement when
        // Link gains an expectedHops property.

        do {
            logger.debug("Calling link.processProof...")
            try await link.processProof(packet.data)
            logger.debug("link.processProof succeeded!")

            // Move from pending to active
            let linkId = await link.linkId
            pendingLinks.removeValue(forKey: linkId)
            activeLinks[linkId] = link

            // H2: Track which interface the link was established on
            await link.setAttachedInterface(interfaceId)

            // M10: Mark path as responsive after successful link establishment
            let destHash = await link.destinationHash
            await pathTable.markPathResponsive(destHash)

            // L5: Record LRPROOF hash to prevent re-processing on shared-medium interfaces
            await packetHashlist.record(packet.getFullHash())

            let hexPrefix = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
            logger.info("Link \(hexPrefix) moved to activeLinks, total=\(self.activeLinks.count)")

        } catch {
            // PROOF validation failed - close link
            logger.error("PROOF processing failed: \(error.localizedDescription)")
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
    private func handleLinkData(_ packet: Packet, from interfaceId: String) async {
        let linkHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
        let activeKeysList = activeLinks.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
        logger.debug("handleLinkData: dest=\(linkHex), context=0x\(String(format: "%02x", packet.context)), activeLinks=\(activeKeysList), dataLen=\(packet.data.count)")

        guard let link = activeLinks[packet.destination] else {
            // Not a local link — try forwarding if transport is enabled
            if transportEnabled, let linkEntry = linkTable[packet.destination] {
                await forwardLinkData(packet, linkEntry: linkEntry, from: interfaceId)
            } else {
                logger.warning("No active link found for \(linkHex), ignoring packet")
            }
            return
        }

        // H2: Validate that link DATA arrives on the same interface it was established on.
        // Python (Transport.py:1993-1994): On interface mismatch, REMOVE the packet hash
        // from the hashlist so it can be re-accepted when it arrives on the correct interface.
        let attachedId = await link.attachedInterfaceId
        if let attachedId, attachedId != interfaceId {
            logger.warning("Dropping packet for \(linkHex): wrong interface (expected=\(attachedId), got=\(interfaceId))")
            await packetHashlist.remove(packet.getFullHash())
            return
        }

        // FIRST: Check wire-format context for special link packets
        // These are handled BEFORE decryption because the context is in the wire format

        // KEEPALIVE (0xFA) - NOT encrypted per Python RNS Packet.pack()
        // Python sends raw 0xFF (initiator) or 0xFE (responder) without encryption
        if packet.context == LinkConstants.CONTEXT_KEEPALIVE {
            logger.debug("KEEPALIVE packet detected (context=0xFA), data=\(packet.data.count) bytes")
            // Pass raw data directly - NOT encrypted
            await link.processKeepalive(packet.data)
            return
        }

        // RESOURCE packets (0x01-0x07) - handle based on type
        // Python RNS Packet.pack(): context RESOURCE (0x01) is NOT link-encrypted
        // Other resource contexts (0x02-0x07) ARE link-encrypted
        if ResourcePacketContext.isResourceContext(packet.context) {
            let ctxHex = String(format: "0x%02x", packet.context)
            logger.debug("Resource packet detected (context=\(ctxHex)), data=\(packet.data.count) bytes")

            if packet.context == ResourcePacketContext.resource {
                // Data parts (0x01): NOT link-encrypted, pass through directly
                await link.handleResourcePacket(context: packet.context, data: packet.data)
            } else {
                // Control packets (0x02-0x07): link-encrypted, decrypt first
                do {
                    let plaintext = try await link.decrypt(packet.data)
                    logger.debug("Decrypted resource control packet: \(plaintext.count) bytes")
                    await link.handleResourcePacket(context: packet.context, data: plaintext)
                } catch {
                    logger.error("Failed to decrypt resource packet: \(error.localizedDescription)")
                }
            }
            return
        }

        // LINKIDENTIFY (0xFB) - peer revealing identity (encrypted)
        if packet.context == LinkConstants.CONTEXT_LINKIDENTIFY {
            logger.debug("LINKIDENTIFY packet detected (context=0xFB)")
            do {
                let plaintext = try await link.decrypt(packet.data)
                logger.debug("Decrypted LINKIDENTIFY payload: \(plaintext.count) bytes")
                // plaintext is: public_keys (64) + signature (64) = 128 bytes
                try await link.handleIdentifyPacket(plaintext)
            } catch {
                logger.error("Failed to decrypt/handle LINKIDENTIFY: \(error.localizedDescription)")
            }
            return
        }

        // LINKCLOSE (0xFC) - peer closing the link (encrypted)
        // Python sends encrypted(link_id) and validates plaintext == link_id on receive
        if packet.context == LinkConstants.CONTEXT_LINKCLOSE {
            logger.debug("LINKCLOSE packet detected (context=0xFC)")
            do {
                let plaintext = try await link.decrypt(packet.data)
                let expectedLinkId = await link.linkId
                if plaintext == expectedLinkId {
                    await link.close(reason: .destinationClosed)
                    activeLinks.removeValue(forKey: packet.destination)
                    let hexPrefix = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
                    logger.info("Link \(hexPrefix) closed by remote peer (verified)")
                } else {
                    logger.warning("LINKCLOSE payload mismatch, ignoring")
                }
            } catch {
                logger.error("Failed to decrypt LINKCLOSE: \(error.localizedDescription)")
            }
            return
        }

        // LRRTT (0xFE) - RTT measurement packet (completes link establishment for responder)
        if packet.context == LinkConstants.CONTEXT_LRRTT {
            logger.debug("LRRTT packet detected (context=0xFE)")
            // Only process if we're the responder and link is in handshake state
            let linkState = await link.state
            let isInitiator = await link.initiator

            if !isInitiator && linkState == .handshake {
                logger.debug("Processing LRRTT for responder link")
                do {
                    let plaintext = try await link.decrypt(packet.data)
                    logger.debug("Decrypted LRRTT: \(plaintext.count) bytes")
                    try await link.processLRRTT(plaintext)
                    let hexPrefix = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
                    logger.info("Link \(hexPrefix) establishment complete (responder)")
                } catch {
                    logger.error("Failed to process LRRTT: \(error.localizedDescription)")
                    await link.close(reason: .timeout)
                    activeLinks.removeValue(forKey: packet.destination)
                }
            } else {
                logger.debug("Ignoring LRRTT (initiator=\(isInitiator), state=\(String(describing: linkState)))")
            }
            return
        }

        // CHANNEL (0x0E) - typed message channel data (encrypted)
        if packet.context == PacketContext.CHANNEL {
            do {
                let plaintext = try await link.decrypt(packet.data)
                await link.handleChannelData(plaintext)
            } catch {
                logger.error("Failed to decrypt CHANNEL data: \(error.localizedDescription)")
            }
            return
        }

        // REQUEST (0x09) - incoming request from peer (encrypted)
        // Python: link.decrypt(packet.data), unpack msgpack([timestamp, pathHash, data])
        if packet.context == RequestPacketContext.request {
            logger.debug("REQUEST packet detected (context=0x09), dataLen=\(packet.data.count)")
            do {
                let plaintext = try await link.decrypt(packet.data)
                logger.debug("Decrypted REQUEST: \(plaintext.count) bytes")
                // TODO: Route to request handler when we implement server-side request handling
                // For now, log and ignore (we're typically the client, not the server)
            } catch {
                logger.error("Failed to decrypt REQUEST: \(error.localizedDescription)")
            }
            return
        }

        // RESPONSE (0x0A) - response to our request (encrypted)
        // Python: link.decrypt(packet.data), unpack msgpack([requestId, responseData])
        if packet.context == RequestPacketContext.response {
            logger.debug("RESPONSE packet detected (context=0x0A), dataLen=\(packet.data.count)")
            do {
                let plaintext = try await link.decrypt(packet.data)
                logger.debug("Decrypted RESPONSE: \(plaintext.count) bytes")

                // Unpack msgpack([requestId, responseData])
                // responseData can be ANY msgpack type (array, binary, map, etc.)
                // Re-pack elements[1] back to bytes for the receipt handler
                if let value = try? unpackMsgPack(plaintext),
                   case .array(let elements) = value,
                   elements.count >= 2,
                   case .binary(let requestId) = elements[0] {
                    let responseData = packMsgPack(elements[1])
                    logger.debug("RESPONSE for request \(requestId.prefix(8).map { String(format: "%02x", $0) }.joined()), data=\(responseData.count) bytes")
                    await link.handleRequestResponse(requestId: requestId, data: responseData)
                } else {
                    logger.warning("Failed to parse RESPONSE msgpack from plaintext \(plaintext.count) bytes")
                }
            } catch {
                logger.error("Failed to decrypt RESPONSE: \(error.localizedDescription)")
            }
            return
        }

        // Decrypt and process (encrypted link data)
        // Resource packets (0x01-0x07) are already handled above by wire context.
        // Everything here is regular encrypted link data (context 0x00 = NONE).
        do {
            let plaintext = try await link.decrypt(packet.data)
            let first4 = plaintext.prefix(4).map { String(format: "%02x", $0) }.joined()
            let hasCB = await link.hasPacketCallback
            logger.debug("Decrypted \(plaintext.count) bytes, data=\(first4), hasCB=\(hasCB)")

            // Try generic packet callback first (Python: link.set_packet_callback)
            // LXST and other protocols use this for raw per-link data delivery
            let delivered = await link.deliverToPacketCallback(data: plaintext, packet: packet)
            if delivered {
                logger.debug("Delivered to packet callback, dataLen=\(plaintext.count)")
                return
            }
            logger.debug("No packetCallback — fell through to LXMF routing, dataLen=\(plaintext.count)")

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

        // Debug: list all registered destinations
        let registeredDests = destinations.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
        logger.debug("handleRegularData: destHash=\(hexPrefix), registeredDests=\(registeredDests), destType=\(String(describing: packet.header.destinationType))")

        // Check if destination is local
        guard let destination = destinations[destHash] else {
            // Not local — try forwarding if transport is enabled and this is a HEADER_2 addressed to us
            if transportEnabled,
               packet.header.headerType == .header2,
               let transportAddr = packet.transportAddress,
               transportAddr == transportIdentityHash {
                await forwardDataPacket(packet, from: interfaceId)
            } else {
                logger.debug("Destination \(hexPrefix) NOT registered locally, dropping packet")
            }
            return
        }

        logger.info("Destination \(hexPrefix) IS local, proceeding to decrypt")

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
                logger.debug("Attempting decrypt, identityHash=\(identityHash.prefix(8).map { String(format: "%02x", $0) }.joined()), ciphertext len=\(packet.data.count)")

                // Use ratchet fallback chain if destination has ratchets enabled
                let ratchetKeys: [Data]
                let enforce: Bool
                if let ratchetMgr = destination.ratchetManager {
                    ratchetKeys = await ratchetMgr.allRatchetPrivateKeys()
                    enforce = destination.ratchetsEnforced
                } else {
                    ratchetKeys = []
                    enforce = false
                }

                if !ratchetKeys.isEmpty {
                    deliveryData = try identity.decrypt(
                        packet.data,
                        identityHash: identityHash,
                        ratchets: ratchetKeys,
                        enforceRatchets: enforce
                    )
                } else {
                    deliveryData = try identity.decrypt(packet.data, identityHash: identityHash)
                }

                let dataHex = deliveryData.prefix(16).map { String(format: "%02x", $0) }.joined()
                logger.debug("Decrypted SINGLE packet: \(deliveryData.count) bytes, data[0:16]=\(dataHex)")
            } catch {
                logger.error("Decryption failed: \(error.localizedDescription)")
                logger.warning("Failed to decrypt SINGLE packet for \(hexPrefix, privacy: .public)...: \(error.localizedDescription, privacy: .public)")
                return
            }
        }

        // Attach resolved interface name to packet before delivery
        var deliveryPacket = packet
        if let name = await getInterfaceName(for: interfaceId) {
            deliveryPacket.receivingInterface = name
        } else {
            deliveryPacket.receivingInterface = interfaceId
        }

        // Deliver decrypted data via callback manager
        logger.debug("Calling callbackManager.deliver() for destHash=\(hexPrefix)")
        await callbackManager.deliver(
            data: deliveryData,
            packet: deliveryPacket,
            to: destHash
        )
        logger.debug("callbackManager.deliver() returned for destHash=\(hexPrefix)")

        // Send proof back for SINGLE destination opportunistic packets.
        // Python Transport calls packet.prove() after local delivery for SINGLE destinations.
        // Proof format: HEADER_1 / PROOF / BROADCAST / PLAIN
        //   destination = packet.getTruncatedHash() (16 bytes)
        //   data        = identity.sign(packet.getFullHash()) (64 bytes)
        if packet.header.destinationType == .single,
           let identity = destination.identity,
           identity.hasPrivateKeys {
            do {
                let signature = try identity.sign(packet.getFullHash())
                let proofHeader = PacketHeader(
                    headerType: .header1,
                    hasContext: false,
                    hasIFAC: false,
                    transportType: .broadcast,
                    destinationType: .plain,
                    packetType: .proof,
                    hopCount: 0
                )
                let proofPacket = Packet(
                    header: proofHeader,
                    destination: packet.getTruncatedHash(),
                    transportAddress: nil,
                    context: 0x00,
                    data: signature
                )
                let encoded = proofPacket.encode()
                if let iface = interfaces[interfaceId] {
                    try await iface.send(encoded)
                    logger.debug("Proof sent for packet \(hexPrefix), sig=\(signature.prefix(8).map { String(format: "%02x", $0) }.joined())...")
                }
            } catch {
                logger.error("Failed to send proof: \(error.localizedDescription)")
            }
        }
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
        // L6: Apply ingress storm detection only for unknown destinations
        // Known destinations are legitimate updates and should not be rate-limited
        let hasPath = await pathTable.hasPath(for: packet.destination)
        if !hasPath {
            recordAnnounceIngress(interfaceId: interfaceId)
            if shouldIngressLimit(interfaceId: interfaceId) {
                onDiagnostic?("[ANNOUNCE] Ingress limit reached for interface \(interfaceId)")
                return
            }
        }

        // C3: Drop announces for our own destinations to prevent path table corruption
        // Python reference: Transport.py received_announce() checks destination in local_client_interfaces
        if isLocalDestination(packet.destination) {
            onDiagnostic?("[ANNOUNCE] Ignoring announce for own destination")
            return
        }

        // Get interface mode
        let mode = getInterfaceMode(for: interfaceId)

        // L2: Rebroadcast detection moved to after validation (inside .recordedAndRebroadcast case)

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
            // C17: Check pending discovery path requests on announce arrival
            if transportEnabled, let prEntry = discoveryPathRequests.removeValue(forKey: destHash) {
                if let prInterfaceId = prEntry.requestingInterfaceId {
                    let transportId = transportIdentityHash ?? Data(repeating: 0, count: 16)
                    let pathResponsePacket = Packet(
                        header: PacketHeader(
                            headerType: .header2,
                            hasContext: packet.header.hasContext,
                            hasIFAC: false,
                            transportType: .transport,
                            destinationType: packet.header.destinationType,
                            packetType: .announce,
                            hopCount: packet.header.hopCount
                        ),
                        destination: packet.destination,
                        transportAddress: transportId,
                        context: PacketContext.PATH_RESPONSE,
                        data: packet.data
                    )
                    let encoded = pathResponsePacket.encode()
                    do {
                        try await sendToInterface(encoded, interfaceId: prInterfaceId)
                        onDiagnostic?("[TRANSPORT] Sent PATH_RESPONSE for \(destHash.prefix(4).map { String(format: "%02x", $0) }.joined()) to \(prInterfaceId)")
                    } catch {
                        onDiagnostic?("[TRANSPORT] Failed to send PATH_RESPONSE: \(error)")
                    }
                }
            }
            let hexPrefix = destHash.prefix(4).map { String(format: "%02x", $0) }.joined()
            logger.info("Path recorded for destination \(hexPrefix, privacy: .public)...")
            await processPendingPackets(for: destHash)

        case .recordedAndRebroadcast(let destHash, let rebroadcastPacket):
            let hexPrefix = destHash.prefix(4).map { String(format: "%02x", $0) }.joined()
            let isLocal = isLocalDestination(destHash)

            // L2: Local rebroadcast detection (moved here, after validation)
            // For HEADER_2 announces, check if this is our own rebroadcast heard back
            if packet.header.headerType == .header2, packet.transportAddress != nil {
                let detected = await announceTable.recordLocalRebroadcast(
                    destinationHash: destHash,
                    incomingHops: packet.header.hopCount
                )
                if detected {
                    logger.debug("Local rebroadcast detected for \(hexPrefix, privacy: .public)...")
                }
            }

            // C17: Check pending discovery path requests on announce arrival
            if transportEnabled, let prEntry = discoveryPathRequests.removeValue(forKey: destHash) {
                if let prInterfaceId = prEntry.requestingInterfaceId {
                    let transportId = transportIdentityHash ?? Data(repeating: 0, count: 16)
                    let pathResponsePacket = Packet(
                        header: PacketHeader(
                            headerType: .header2,
                            hasContext: rebroadcastPacket.header.hasContext,
                            hasIFAC: false,
                            transportType: .transport,
                            destinationType: rebroadcastPacket.header.destinationType,
                            packetType: .announce,
                            hopCount: rebroadcastPacket.header.hopCount
                        ),
                        destination: rebroadcastPacket.destination,
                        transportAddress: transportId,
                        context: PacketContext.PATH_RESPONSE,
                        data: rebroadcastPacket.data
                    )
                    let encoded = pathResponsePacket.encode()
                    do {
                        try await sendToInterface(encoded, interfaceId: prInterfaceId)
                        onDiagnostic?("[TRANSPORT] Sent PATH_RESPONSE for \(hexPrefix) to \(prInterfaceId)")
                    } catch {
                        onDiagnostic?("[TRANSPORT] Failed to send PATH_RESPONSE: \(error)")
                    }
                }
            }

            // Transport.py:1741: Only rebroadcast if transport_enabled or local destination
            if transportEnabled || isLocal {
                // C18: PATH_RESPONSE bypasses rate limiting (Python Transport.py)
                // Rate limiting check (Transport.py:1691-1720)
                let sourceInterface = interfaces[interfaceId]
                if packet.context != PacketContext.PATH_RESPONSE,
                   let rateTarget = sourceInterface?.config.announceRateTarget {
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

                // M5: PATH_RESPONSE bypasses announce table — send immediately
                if packet.context == PacketContext.PATH_RESPONSE {
                    let transportId = transportIdentityHash ?? Data(repeating: 0, count: 16)
                    let prHeader = PacketHeader(
                        headerType: .header2,
                        hasContext: rebroadcastPacket.header.hasContext,
                        hasIFAC: false,
                        transportType: .transport,
                        destinationType: rebroadcastPacket.header.destinationType,
                        packetType: .announce,
                        hopCount: rebroadcastPacket.header.hopCount
                    )
                    let prPacket = Packet(
                        header: prHeader,
                        destination: rebroadcastPacket.destination,
                        transportAddress: transportId,
                        context: PacketContext.PATH_RESPONSE,
                        data: rebroadcastPacket.data
                    )
                    try? await sendToAllInterfaces(prPacket)
                    logger.info("PATH_RESPONSE for \(hexPrefix, privacy: .public)... sent immediately")
                } else {
                    // Queue for retransmission via AnnounceTable
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
                        receivedFrom: receivedFrom,
                        receivingInterfaceId: interfaceId
                    )
                    logger.info("Announce for \(hexPrefix, privacy: .public)... queued for retransmission")
                }
            } else if let _ = pendingLocalPathRequests.removeValue(forKey: destHash) {
                // E12: Retransmit for pending local path request
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
                    receivedFrom: receivedFrom,
                    isLocalClient: true,
                    receivingInterfaceId: interfaceId
                )
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
                hasContext: action.packet.header.hasContext,  // Preserve original (ratchet flag)
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
                context: action.blockRebroadcasts ? PacketContext.PATH_RESPONSE : PacketContext.NONE,
                data: action.packet.data
            )

            let encoded = retransmitPacket.encode()
            let destHex = action.destinationHash.prefix(4).map { String(format: "%02x", $0) }.joined()

            // C13: Determine source interface mode from the receiving interface
            let sourceMode: InterfaceMode?
            if let recvIfId = action.receivingInterfaceId {
                sourceMode = getInterfaceMode(for: recvIfId)
            } else {
                sourceMode = nil
            }

            for (id, interface) in interfaces {
                // Skip disconnected interfaces
                guard interface.state == .connected else { continue }

                // C13: Skip the interface the announce was received from (Python behavior)
                if let recvIfId = action.receivingInterfaceId, id == recvIfId { continue }

                // Skip specific interface override
                if let attachedId = action.attachedInterfaceId, id != attachedId { continue }

                // C14: Per-interface announce bandwidth cap
                if let allowedAt = announceAllowedAt[id], Date() < allowedAt {
                    // E5: Queue announce with dedup by destination
                    var queue = announceQueues[id] ?? []
                    let emitted = AnnounceQueueEntry.announceEmitted(from: action.packet.data)
                    if let existingIdx = queue.firstIndex(where: { $0.destination == action.destinationHash }) {
                        if emitted > queue[existingIdx].emitted {
                            queue[existingIdx] = AnnounceQueueEntry(
                                destination: action.destinationHash, time: Date(),
                                hops: action.hops, emitted: emitted, encoded: encoded
                            )
                        }
                    } else if queue.count < TransportConstants.MAX_QUEUED_ANNOUNCES {
                        queue.append(AnnounceQueueEntry(
                            destination: action.destinationHash, time: Date(),
                            hops: action.hops, emitted: emitted, encoded: encoded
                        ))
                    }
                    announceQueues[id] = queue
                    continue
                }

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
                    // E8: Apply IFAC per-interface before transmitting
                    let transmitData = applyIFAC(raw: encoded, interfaceId: id)
                    try await interface.send(transmitData)

                    // C14: Update announce bandwidth tracking
                    let bitrate = interface.config.bitrate
                    if bitrate > 0 {
                        let txTime = Double(encoded.count * 8) / Double(bitrate)
                        let waitTime = txTime / TransportConstants.ANNOUNCE_CAP
                        announceAllowedAt[id] = Date().addingTimeInterval(waitTime)
                    }

                    logger.debug("Retransmitted announce for \(destHex, privacy: .public)... via \(id, privacy: .public)")
                } catch {
                    logger.warning("Failed to retransmit announce to \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
                }
            }
        }

        // E3: Reinsert held announces after retransmission cycle
        for (destHash, heldPacket) in heldAnnounces {
            await announceTable.insert(
                destinationHash: destHash,
                packet: heldPacket,
                hops: heldPacket.header.hopCount,
                receivedFrom: destHash,
                blockRebroadcasts: true
            )
        }
        heldAnnounces.removeAll()

        // E5: Process announce queues (one per interface per cycle).
        // Python (Interface.py:246): drain min-hop first, then oldest arrival.
        let now = Date()
        for (id, _) in interfaces {
            guard var queue = announceQueues[id], !queue.isEmpty else { continue }
            guard interfaces[id]?.state == .connected else { continue }
            // Remove expired
            queue.removeAll { now.timeIntervalSince($0.time) > TransportConstants.QUEUED_ANNOUNCE_LIFE }
            // Check bandwidth cap
            if let allowedAt = announceAllowedAt[id], now < allowedAt {
                announceQueues[id] = queue
                continue
            }
            // Select min-hop entry; among equal hops, pick oldest (earliest arrival)
            if !queue.isEmpty {
                let minHops = queue.min(by: { $0.hops < $1.hops })!.hops
                let candidates = queue.enumerated().filter { $0.element.hops == minHops }
                let oldest = candidates.min(by: { $0.element.time < $1.element.time })!
                let entry = oldest.element
                queue.remove(at: oldest.offset)
                do {
                    try await interfaces[id]?.send(entry.encoded)
                    let bitrate = interfaces[id]?.config.bitrate ?? 0
                    if bitrate > 0 {
                        let txTime = Double(entry.encoded.count * 8) / Double(bitrate)
                        announceAllowedAt[id] = now.addingTimeInterval(txTime / TransportConstants.ANNOUNCE_CAP)
                    }
                } catch {
                    logger.warning("Failed to send queued announce via \(id, privacy: .public)")
                }
            }
            announceQueues[id] = queue.isEmpty ? nil : queue
        }
    }

    /// H3: Clean up closed links from pendingLinks and activeLinks dictionaries.
    /// Prevents unbounded memory growth from accumulated dead links.
    private func cleanupLinks() async {
        for (linkId, link) in pendingLinks {
            let linkState = await link.state
            if linkState.isTerminal {
                pendingLinks.removeValue(forKey: linkId)
                // Non-transport: expire path for rediscovery (Python Transport.py:699)
                if !transportEnabled {
                    let destHash = await link.destinationHash
                    await pathTable.expirePath(destinationHash: destHash)
                }
            }
        }
        for (linkId, link) in activeLinks {
            let linkState = await link.state
            if linkState.isTerminal {
                activeLinks.removeValue(forKey: linkId)
            }
        }
    }

    /// Throttle counter for periodic cleanup in retransmission loop (H4/H3).
    private var tableCullCounter: Int = 0

    /// H3/H4: Periodic cleanup of links and paths, throttled to every ~5 seconds.
    private func periodicTableCleanup() async {
        tableCullCounter += 1
        guard tableCullCounter % 5 == 0 else { return }
        let activeIds = Set(interfaces.keys)
        await pathTable.cleanup(activeInterfaceIds: activeIds)
        await cleanupLinks()
    }

    /// Clean up expired discovery path requests and periodic maintenance.
    private func cleanupDiscoveryPathRequests() {
        // E12: Cull pending local path requests for removed interfaces
        pendingLocalPathRequests = pendingLocalPathRequests.filter { interfaces[$0.value] != nil || $0.value.isEmpty }
        // E13: Cull expired receipts
        receipts.removeAll { Date() > $0.timeout }
        let now = Date()
        discoveryPathRequests = discoveryPathRequests.filter { $0.value.timeout > now }
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
                await self.cleanupDiscoveryPathRequests()
                await self.cullTransportTables()
                await self.periodicTableCleanup()
            }
        }
    }

    /// Stop the periodic announce retransmission task.
    public func stopRetransmissionLoop() {
        retransmissionTask?.cancel()
        retransmissionTask = nil
    }

    /// Enable or disable transport mode at runtime.
    ///
    /// When enabled, this node rebroadcasts announces and forwards path requests
    /// for other devices on the network.
    ///
    /// - Parameters:
    ///   - enabled: Whether transport mode should be active.
    ///   - identity: Identity whose hash is used as transport_id in HEADER_2 packets.
    ///               Required when enabling; ignored when disabling.
    public func setTransportEnabled(_ enabled: Bool, identity: Identity? = nil) {
        transportEnabled = enabled
        if enabled {
            transportIdentityHash = identity?.hash
            startRetransmissionLoop()
            Task { await packetHashlist.load() }
        } else {
            transportIdentityHash = nil
            stopRetransmissionLoop()
            Task { await packetHashlist.save() }
            linkTable.removeAll()
            reverseTable.removeAll()
        }
    }

    /// Get the interface mode for a given interface ID.
    ///
    /// - Parameter interfaceId: Interface ID
    /// - Returns: Interface mode, defaults to .full if interface not found
    func getInterfaceMode(for interfaceId: String) -> InterfaceMode {
        guard let interface = interfaces[interfaceId] else {
            return .full // Default to full mode
        }
        return interface.config.mode
    }

    // MARK: - E8: IFAC Validation

    /// E8: Validate IFAC on raw wire bytes.
    ///
    /// Matches Python Transport.py inbound() IFAC validation:
    /// 1. If interface has no IFAC, reject packets with IFAC flag set
    /// 2. If interface has IFAC, require IFAC flag set
    /// 3. Extract IFAC, generate HKDF mask, unmask packet
    /// 4. Reconstruct original packet (strip IFAC, clear flag)
    /// 5. Re-sign and verify IFAC matches
    ///
    /// - Parameters:
    ///   - raw: Raw wire bytes
    ///   - interfaceId: ID of the receiving interface
    /// - Returns: Validated packet data (IFAC stripped), or nil if validation failed
    public func validateIFAC(raw: Data, interfaceId: String) -> Data? {
        guard let interface = interfaces[interfaceId] else { return raw }
        let config = interface.config

        guard let ifacKey = config.ifacKey, config.ifacSize > 0 else {
            // No IFAC on this interface — reject if packet has IFAC flag set
            if raw.count >= 1, raw[0] & 0x80 == 0x80 { return nil }
            return raw
        }

        guard let signingSeed = ifacSigningSeeds[interfaceId] else {
            // No cached signing seed — shouldn't happen if addInterface worked
            logger.error("IFAC signing seed not cached for \(interfaceId, privacy: .public)")
            return nil
        }

        let ifacSize = config.ifacSize

        // Require IFAC flag set
        guard raw.count >= 1, raw[0] & 0x80 == 0x80 else {
            // Interface requires IFAC but packet doesn't have it — drop
            return nil
        }

        // Ensure packet is long enough: 2 header + ifacSize + at least 1 byte payload
        guard raw.count > 2 + ifacSize else { return nil }

        // Extract IFAC (not masked, readable directly)
        let ifac = raw[2 ..< 2 + ifacSize]

        // Generate mask: HKDF(derive_from=ifac, salt=ifac_key, length=raw.count)
        let mask = KeyDerivation.deriveKey(
            length: raw.count,
            inputKeyMaterial: Data(ifac),
            salt: ifacKey
        )

        // Unmask: XOR bytes 0-1 and bytes after 2+ifacSize; leave IFAC untouched
        var unmasked = Data(count: raw.count)
        for i in 0 ..< raw.count {
            if i <= 1 || i > ifacSize + 1 {
                // Unmask header and payload
                unmasked[i] = raw[i] ^ mask[i]
            } else {
                // Don't unmask the IFAC itself
                unmasked[i] = raw[i]
            }
        }

        // Clear IFAC flag and reconstruct original packet (strip IFAC)
        let newHeader = Data([unmasked[0] & 0x7F, unmasked[1]])
        let newRaw = newHeader + unmasked[(2 + ifacSize)...]

        // Compute expected IFAC using deterministic Ed25519: sign(original_packet)[-ifacSize:]
        guard let signature = Ed25519Pure.sign(message: newRaw, seed: signingSeed) else {
            logger.error("Ed25519Pure sign failed on \(interfaceId, privacy: .public)")
            return nil
        }
        let expectedIfac = signature.suffix(ifacSize)

        guard Data(ifac) == expectedIfac else {
            logger.debug("IFAC validation failed on \(interfaceId, privacy: .public)")
            return nil
        }

        return newRaw
    }

    /// E8: Apply IFAC to outbound packet bytes.
    ///
    /// Matches Python Transport.transmit() IFAC application:
    /// 1. Sign the raw packet, take last ifacSize bytes as IFAC
    /// 2. Generate HKDF mask from IFAC
    /// 3. Set IFAC flag, insert IFAC between header and payload
    /// 4. Mask everything except the IFAC itself
    ///
    /// - Parameters:
    ///   - raw: Raw packet bytes to transmit
    ///   - interfaceId: ID of the outgoing interface
    /// - Returns: IFAC-protected bytes, or original bytes if no IFAC configured
    public func applyIFAC(raw: Data, interfaceId: String) -> Data {
        guard let config = interfaces[interfaceId]?.config,
              let ifacKey = config.ifacKey,
              config.ifacSize > 0,
              let signingSeed = ifacSigningSeeds[interfaceId] else {
            return raw
        }

        let ifacSize = config.ifacSize

        // Sign the original packet with deterministic Ed25519, take last ifacSize bytes
        guard let signature = Ed25519Pure.sign(message: raw, seed: signingSeed) else { return raw }
        let ifac = signature.suffix(ifacSize)

        // Generate mask: HKDF(derive_from=ifac, salt=ifac_key, length=raw.count+ifacSize)
        let mask = KeyDerivation.deriveKey(
            length: raw.count + ifacSize,
            inputKeyMaterial: Data(ifac),
            salt: ifacKey
        )

        // Set IFAC flag and assemble: header(2) + ifac + payload
        let newHeader = Data([raw[0] | 0x80, raw[1]])
        let newRaw = newHeader + ifac + raw[2...]

        // Mask: XOR everything except the IFAC bytes
        var masked = Data(count: newRaw.count)
        for i in 0 ..< newRaw.count {
            if i == 0 {
                // Mask first byte, but force IFAC flag on
                masked[i] = (newRaw[i] ^ mask[i]) | 0x80
            } else if i == 1 || i > ifacSize + 1 {
                // Mask second header byte and payload
                masked[i] = newRaw[i] ^ mask[i]
            } else {
                // Don't mask the IFAC itself
                masked[i] = newRaw[i]
            }
        }

        return masked
    }

    /// Backward-compatible IFAC validation using InterfaceConfig directly.
    /// Delegates to the interfaceId-based method by looking up the interface.
    public func validateIFAC(raw: Data, interfaceConfig: InterfaceConfig) -> Data? {
        return validateIFAC(raw: raw, interfaceId: interfaceConfig.id)
    }

    // MARK: - E11: Announce Ingress Tracking

    /// E11: Check if announce ingress rate exceeds threshold (storm detection).
    private func shouldIngressLimit(interfaceId: String) -> Bool {
        guard let ts = announceIngressTimestamps[interfaceId], ts.count >= ingressDequeSize else { return false }
        return ts.last!.timeIntervalSince(ts.first!) < 1.0  // 6 announces in <1s = storm
    }

    /// E11: Record an announce ingress event.
    private func recordAnnounceIngress(interfaceId: String) {
        var ts = announceIngressTimestamps[interfaceId] ?? []
        ts.append(Date())
        while ts.count > ingressDequeSize { ts.removeFirst() }
        announceIngressTimestamps[interfaceId] = ts
    }

    // MARK: - E13: Receipt Registration

    /// E13: Register a receipt for proof-based delivery confirmation.
    ///
    /// When a PROOF arrives matching the registered hash, the callback is invoked.
    /// Receipts expire after `timeout` seconds.
    ///
    /// - Parameters:
    ///   - hash: 16-byte truncated packet hash to match
    ///   - timeout: Expiry time in seconds (default 300)
    ///   - callback: Async callback to invoke when proof matches
    public func registerReceipt(hash: Data, timeout: TimeInterval = 300, callback: @escaping @Sendable () async -> Void) {
        if receipts.count >= maxReceipts { receipts.removeFirst() }
        receipts.append((hash: hash, callback: callback, timeout: Date().addingTimeInterval(timeout)))
    }

    // MARK: - Path Table Access

    /// Get the path table for direct access.
    ///
    /// Used for testing and advanced routing operations.
    public func getPathTable() -> PathTable {
        return pathTable
    }

    /// List all registered interface IDs (for debugging).
    public func listInterfaceIds() -> [String] {
        return Array(interfaces.keys)
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
        logger.info("Requesting path to \(destHex)...")

        // Generate random request tag (16 bytes)
        var requestTag = Data(count: 16)
        _ = requestTag.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }

        // Path request data: destination_hash (16) [+ transport_id (16)] + request_tag (16)
        var requestData = destinationHash
        if transportEnabled, let txHash = transportIdentityHash {
            requestData.append(txHash)
        }
        requestData.append(requestTag)

        // Compute destination hash for "Transport.path.request" (PLAIN destination)
        let pathRequestDestHash = Destination.plainHash(appName: "rnstransport", aspects: ["path", "request"])

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

        logger.info("Path request sent for \(destHex) to \(sentCount) interface(s)")
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

    // MARK: - Path Request Handler

    /// Register the PLAIN destination for receiving path requests from other nodes.
    ///
    /// Must be called once during transport setup. After registration, incoming
    /// path request packets are automatically routed to `handlePathRequest()`.
    ///
    /// Reference: Python Transport.py:2646 (path_request_handler registration)
    public func registerPathRequestHandler() async {
        let pathReqDest = Destination(
            plainAppName: "rnstransport",
            aspects: ["path", "request"]
        )
        pathRequestDestination = pathReqDest
        registerDestination(pathReqDest)

        // Register callback for incoming path requests
        await callbackManager.registerAsync(destinationHash: pathReqDest.hash) { [weak self] data, packet in
            guard let self = self else { return }
            Task {
                await self.handlePathRequest(data: data)
            }
        }

        let destHex = pathReqDest.hash.prefix(8).map { String(format: "%02x", $0) }.joined()
        logger.info("Path request handler registered (dest: \(destHex, privacy: .public))")
    }

    /// Handle incoming path request from another node.
    ///
    /// Format: dest_hash(16) [+ transport_id(16)] + tag(16)
    ///
    /// Decision tree (matching Python Transport.py:2698-2820):
    /// 1. Local destination → respond with announce (PATH_RESPONSE)
    /// 2. Known path in path_table → insert cached announce into announce table
    ///    with blockRebroadcasts=true and GRACE delay
    /// 3. Transport enabled → forward request on all other interfaces (discovery)
    ///
    /// Reference: Python Transport.py:2646-2820
    private func handlePathRequest(data: Data) async {
        guard data.count >= TRUNCATED_HASH_LENGTH else { return }

        let destinationHash = Data(data.prefix(TRUNCATED_HASH_LENGTH))

        // Extract requesting_transport_instance and tag based on data length
        let requestingTransportId: Data?
        let tagBytes: Data?
        if data.count > TRUNCATED_HASH_LENGTH * 2 {
            // Has transport_id: dest_hash(16) + transport_id(16) + tag(16)
            requestingTransportId = Data(data[TRUNCATED_HASH_LENGTH..<(TRUNCATED_HASH_LENGTH * 2)])
            let rawTag = Data(data[(TRUNCATED_HASH_LENGTH * 2)...])
            tagBytes = Data(rawTag.prefix(TRUNCATED_HASH_LENGTH))
        } else if data.count > TRUNCATED_HASH_LENGTH {
            // No transport_id: dest_hash(16) + tag(16)
            requestingTransportId = nil
            let rawTag = Data(data[TRUNCATED_HASH_LENGTH...])
            tagBytes = Data(rawTag.prefix(TRUNCATED_HASH_LENGTH))
        } else {
            requestingTransportId = nil
            tagBytes = nil
        }

        // Dedup via unique_tag
        guard let tag = tagBytes else { return }
        let uniqueTag = destinationHash + tag
        if discoveryPrTags.contains(uniqueTag) { return }
        discoveryPrTags.append(uniqueTag)
        if discoveryPrTags.count > maxPrTags {
            discoveryPrTags.removeFirst(discoveryPrTags.count - maxPrTags)
        }

        let destHex = destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        let receivingInterfaceId = lastReceivedInterfaceId
        onDiagnostic?("[PATH_REQ] for \(destHex) from interface \(receivingInterfaceId ?? "unknown")")

        // E12: Track local path requests (no transport_id = local origin)
        if requestingTransportId == nil {
            pendingLocalPathRequests[destinationHash] = receivingInterfaceId ?? ""
        }

        // 1. Check local destinations
        if let localDest = destinations[destinationHash] {
            onDiagnostic?("[PATH_REQ] \(destHex) is LOCAL, responding with announce")
            logger.info("Answering path request for \(destHex, privacy: .public): destination is local")
            respondWithAnnounce(destination: localDest, pathResponse: true, attachedInterfaceId: receivingInterfaceId)
            return
        }
        onDiagnostic?("[PATH_REQ] \(destHex) NOT local (registered: \(destinations.keys.count) dests)")

        // 2. Check path table for known path
        if transportEnabled, let pathEntry = await pathTable.lookup(destinationHash: destinationHash) {
            // Don't answer if next hop is the requestor
            if let reqTxId = requestingTransportId, pathEntry.nextHop == reqTxId {
                logger.debug("Not answering path request for \(destHex, privacy: .public): next hop is requestor")
                return
            }

            logger.info("Answering path request for \(destHex, privacy: .public): path is known")
            respondWithCachedPath(
                destinationHash: destinationHash,
                pathEntry: pathEntry,
                attachedInterfaceId: receivingInterfaceId
            )
            return
        }

        // 3. Forward path request to other interfaces (discovery mode)
        if transportEnabled {
            // E7: Only forward discovery on eligible interface modes
            let receivingMode = receivingInterfaceId.flatMap { getInterfaceMode(for: $0) } ?? .full
            guard TransportConstants.DISCOVER_PATHS_FOR.contains(receivingMode) else {
                logger.debug("Not forwarding path request for \(destHex, privacy: .public): mode \(String(describing: receivingMode)) not eligible")
                return
            }

            if discoveryPathRequests[destinationHash] != nil {
                logger.debug("Already forwarding path request for \(destHex, privacy: .public)")
                return
            }

            logger.info("Forwarding path request for \(destHex, privacy: .public) to other interfaces")
            discoveryPathRequests[destinationHash] = (
                timeout: Date().addingTimeInterval(Self.PATH_REQUEST_TIMEOUT),
                requestingInterfaceId: receivingInterfaceId
            )

            // Forward on all interfaces except the one we received from
            for (id, interface) in interfaces {
                guard id != receivingInterfaceId else { continue }
                guard interface.state == .connected else { continue }
                await sendPathRequest(for: destinationHash, onInterface: id, tag: tag)
            }
        }
    }

    /// Respond to a path request with a fresh announce for a local destination.
    ///
    /// Builds an Announce with `pathResponse: true` (context=0x0B) and sends it
    /// on the specified interface (or all if nil).
    ///
    /// Reference: Python Transport.py:2751-2759
    private func respondWithAnnounce(
        destination: Destination,
        pathResponse: Bool,
        attachedInterfaceId: String?
    ) {
        let announce = Announce(destination: destination, pathResponse: pathResponse)
        guard let packet = try? announce.buildPacket() else {
            logger.warning("Failed to build path response announce")
            return
        }
        let encoded = packet.encode()

        Task { [weak self] in
            guard let self = self else { return }
            if let attachedId = attachedInterfaceId,
               let interface = await self.getInterface(id: attachedId) {
                try? await interface.send(encoded)
            } else {
                for (_, interface) in await self.allInterfaces() {
                    guard interface.state == .connected else { continue }
                    try? await interface.send(encoded)
                }
            }
        }
    }

    /// Respond to a path request with a cached path from the path table.
    ///
    /// Inserts the cached announce into the announce table with
    /// `blockRebroadcasts=true` and `PATH_REQUEST_GRACE` delay, so the
    /// retransmission loop sends it as a PATH_RESPONSE (context=0x0B).
    ///
    /// Reference: Python Transport.py:2786-2820
    private func respondWithCachedPath(
        destinationHash: Data,
        pathEntry: PathEntry,
        attachedInterfaceId: String?
    ) {
        // L3: Don't answer if next hop is on the same roaming-mode interface
        if let attachedId = attachedInterfaceId,
           getInterfaceMode(for: attachedId) == .roaming,
           pathEntry.interfaceId == attachedId {
            return
        }

        guard let cachedData = pathEntry.announceData, !cachedData.isEmpty else {
            let destHex = destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined()
            logger.warning("Cannot respond to path request for \(destHex, privacy: .public): no cached announce data")
            return
        }

        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            hasIFAC: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .announce,
            hopCount: pathEntry.hopCount
        )

        let cachedPacket = Packet(
            header: header,
            destination: destinationHash,
            transportAddress: nil,
            context: PacketContext.NONE,
            data: cachedData
        )

        // E6: Capture interface mode before Task (actor-isolated)
        let isRoaming = attachedInterfaceId.flatMap { getInterfaceMode(for: $0) } == .roaming
        let extraDelay = Self.PATH_REQUEST_GRACE + (isRoaming ? TransportConstants.PATH_REQUEST_RG : 0)

        Task { [weak self] in
            guard let self = self else { return }
            // E3: Hold existing announce while path response is sent
            if let heldPacket = await self.announceTable.removeAndReturn(destinationHash) {
                await self.setHeldAnnounce(destinationHash: destinationHash, packet: heldPacket)
            }
            await self.announceTable.insert(
                destinationHash: destinationHash,
                packet: cachedPacket,
                hops: pathEntry.hopCount,
                receivedFrom: destinationHash,
                blockRebroadcasts: true,
                attachedInterfaceId: attachedInterfaceId,
                extraDelay: extraDelay
            )
        }
    }

    /// E3: Store a held announce (called from Task context).
    private func setHeldAnnounce(destinationHash: Data, packet: Packet) {
        heldAnnounces[destinationHash] = packet
    }

    /// Send a path request on a specific interface (for forwarding).
    ///
    /// Reference: Python Transport.py:2541-2588
    private func sendPathRequest(for destinationHash: Data, onInterface interfaceId: String, tag: Data) async {
        var requestData = destinationHash
        if transportEnabled, let txHash = transportIdentityHash {
            requestData.append(txHash)
        }
        requestData.append(tag)

        let pathRequestDestHash = Destination.plainHash(appName: "rnstransport", aspects: ["path", "request"])
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
            context: PacketContext.NONE,
            data: requestData
        )
        let encoded = packet.encode()

        guard let interface = interfaces[interfaceId] else { return }
        do {
            try await interface.send(encoded)
        } catch {
            logger.warning("Failed to forward path request via \(interfaceId, privacy: .public)")
        }
    }

    /// Request a path and wait until it's found or timeout.
    ///
    /// Matching Python Transport.await_path():
    /// 1. If path already known, return true
    /// 2. Send path request
    /// 3. Poll pathTable every 50ms until found or timeout
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash
    ///   - timeout: Max wait time (default 15s)
    /// - Returns: true if path was found
    public func awaitPath(for destinationHash: Data, timeout: TimeInterval = 15.0) async -> Bool {
        if await pathTable.hasPath(for: destinationHash) { return true }

        await requestPath(for: destinationHash)

        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await pathTable.hasPath(for: destinationHash) { return true }
            try? await Task.sleep(for: .milliseconds(50))
        }

        return await pathTable.hasPath(for: destinationHash)
    }

    /// Get all interfaces (for internal use).
    private func allInterfaces() -> [String: any NetworkInterface] {
        return interfaces
    }
}

// MARK: - Internal Handlers

extension ReticulumTransport {
    /// Internal handler for state changes (actor-isolated).
    func handleInterfaceStateChange(id: String, state: InterfaceState) {
        logger.info("Interface \(id, privacy: .public) state: \(String(describing: state), privacy: .public)")
        onDiagnostic?("[IFACE] \(id) → \(state)")

        // When any interface transitions to connected, fire onInterfaceAdded
        // so the app layer can send announces over the newly-available link.
        // AutoInterface/BLE peers fire this via their onPeerAdded callbacks,
        // but TCP interfaces only reach .connected asynchronously via this
        // delegate method — without this, TCP connections never trigger announces.
        if case .connected = state {
            Task {
                await self.onInterfaceAdded?(id)
            }
        }
    }

    /// Internal handler for received data (actor-isolated).
    public func handleReceivedData(data: Data, from interfaceId: String) {
        let hexDump = data.prefix(30).map { String(format: "%02x", $0) }.joined()
        logger.debug("Packet received: \(data.count) bytes from interface \(interfaceId), raw: \(hexDump)...")

        // E8: IFAC validation — must happen before packet parsing
        guard let validatedData = validateIFAC(raw: data, interfaceId: interfaceId) else {
            logger.warning("IFAC validation failed, dropping packet from \(interfaceId)")
            return
        }

        // Parse the data into a packet
        do {
            let packet = try Packet(from: validatedData)
            let destHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()
            let contextStr = packet.header.hasContext ? String(format: "0x%02x", packet.context) : "none"
            logger.debug("Parsed: type=\(String(describing: packet.header.packetType)), destType=\(String(describing: packet.header.destinationType)), dest=\(destHex), context=\(contextStr), dataLen=\(packet.data.count)")

            // Log pending links status for every packet
            let pendingKeysHex = pendingLinks.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
            logger.debug("Current pendingLinks: \(self.pendingLinks.count), keys=\(pendingKeysHex)")

            Task {
                await self.receive(packet: packet, from: interfaceId)
            }
        } catch {
            logger.error("Failed to parse packet from interface \(interfaceId): \(error.localizedDescription)")
        }
    }

    /// Internal handler for interface errors (actor-isolated).
    func handleInterfaceError(id: String, error: Error) {
        logger.warning("Interface \(id, privacy: .public) error: \(error.localizedDescription, privacy: .public)")
        // Interface handles reconnection internally
    }
}

// MARK: - Delegate Wrapper

/// Wrapper class that bridges InterfaceDelegate protocol to ReticulumTransport actor.
///
/// Since actors cannot directly conform to @MainActor protocols, this wrapper
/// receives delegate callbacks and forwards them to the actor asynchronously.
public final class TransportDelegateWrapper: InterfaceDelegate, @unchecked Sendable {
    private weak var transport: ReticulumTransport?

    public init(transport: ReticulumTransport) {
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
