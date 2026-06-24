// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

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

/// Bytes of a received PROOF packet surfaced to a delivery-receipt callback.
///
/// Mirrors RNS `PacketReceipt.proof_packet` (RNS/Packet.py:498-537): when a PROOF
/// matching a tracked packet hash arrives, RNS stashes the proof packet so a caller
/// can read its `data` (the proof payload — a 64-byte IMPLICIT signature, or a
/// 96-byte EXPLICIT `packet_hash || signature`) and its `raw` (the full encoded
/// proof packet bytes). The swift delivery-receipt callback is `() async -> Void`
/// and discards these bytes; the proof-carrying overloads
/// (`send(packet:proofReceiptCallback:)` / `registerReceipt(hash:proofCallback:)`)
/// surface them additively without changing the existing call sites.
public struct ReceivedProofPacket: Sendable {
    /// Proof payload bytes (`Packet.data` of the received PROOF packet).
    public let data: Data
    /// Full encoded PROOF packet bytes (`Packet.raw` — `Packet.encode()`).
    public let raw: Data
    public init(data: Data, raw: Data) {
        self.data = data
        self.raw = raw
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

    /// Externally-registered announce handlers (RNS `Transport.announce_handlers`,
    /// Transport.py:2465-2477). Populated via `registerAnnounceHandler`; the inbound
    /// dispatch loop (`dispatchAnnounceToHandlers`) iterates this list for EVERY
    /// accepted announce — including on leaf nodes with transport disabled — so apps
    /// like LXMF (lxmf.delivery / lxmf.propagation handlers) are notified.
    private var announceHandlers: [AnnounceHandlerProtocol] = []

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

    /// Whether an interface error should crash the instance (panic) versus be
    /// logged and survived. Defaults false, matching RNS
    /// (`Reticulum.panic_on_interface_error`, Reticulum.py:280). reticulum-swift
    /// keeps this as instance-level posture state only — it does NOT actually
    /// abort the process on a real interface error (see port-deviations.md); it
    /// is surfaced for config round-trip parity with the bridge's
    /// `wire_instance_posture`.
    public var panicOnInterfaceError: Bool = false

    /// Probe-responder destination (`rnstransport.probe`), or nil when
    /// `respond_to_probes` is off. Mirrors `Transport.probe_destination`
    /// (Transport.py:396-403). Registered via `registerProbeDestination`.
    public private(set) var probeDestination: Destination?

    /// Remote-management destination (`rnstransport.remote.management`), or nil
    /// when remote management is off. Mirrors
    /// `Transport.remote_management_destination` (Transport.py:252-258).
    public private(set) var remoteManagementDestination: Destination?

    /// Management destinations registered under the transport identity.
    /// Mirrors `Transport.mgmt_destinations` (Transport.py:254/:401).
    public private(set) var mgmtDestinations: [Destination] = []

    /// Hashes of management destinations gated for ACL/handler lookups.
    /// Mirrors `Transport.mgmt_hashes` (Transport.py:255). Only the
    /// remote-management destination is added to `mgmt_hashes` in RNS (the
    /// probe destination is appended to `mgmt_destinations` only).
    public private(set) var mgmtHashes: [Data] = []

    /// Whether this instance responds to probe requests
    /// (`Reticulum.respond_to_probes`, Reticulum.py:543-558). Default false.
    public private(set) var respondToProbes: Bool = false

    /// Whether remote management is enabled
    /// (`Reticulum.remote_management_enabled`, Reticulum.py:528-541). Default false.
    public private(set) var remoteManagementEnabled: Bool = false

    /// ACL of identity hashes (each exactly 16 bytes) permitted to use the
    /// remote-management destination (`Transport.remote_management_allowed`).
    public private(set) var remoteManagementAllowed: [Data] = []

    /// Task handle for periodic announce retransmission
    private var retransmissionTask: Task<Void, Never>?

    /// Last time the announce-table retransmit branch ran. The jobs() loop ticks
    /// every `job_interval` (0.25s) but the announce-retransmit branch is gated to
    /// `ANNOUNCES_CHECK_INTERVAL` (1.0s) so a heard announce rebroadcasts at most
    /// once per second. `.distantPast` makes the very first jobs() pass run it.
    /// Reference: Python Transport.announces_last_checked (Transport.py:181/574/636).
    private var announcesLastChecked: Date = .distantPast

    /// Registered interfaces by ID
    private var interfaces: [String: any NetworkInterface] = [:]

    /// Delegate wrappers for each interface (needed to prevent deallocation)
    private var delegateWrappers: [String: TransportDelegateWrapper] = [:]

    /// Registered local destinations by hash
    private var destinations: [Data: Destination] = [:]

    /// Interface IDs that are local-client interfaces (shared-instance clients).
    /// Mirrors Python `Transport.local_client_interfaces` (Transport.py:164).
    /// A path request arriving on a local-client interface is answered
    /// immediately (retransmit_timeout = now, no PATH_REQUEST_GRACE) per
    /// Transport.py:2973-2974 / from_local_client().
    private var localClientInterfaceIds: Set<String> = []

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

    /// RNS `Transport.blackholed_identities` (Transport.py:123): the set of
    /// announcing-identity hashes whose inbound announces are invalidated and
    /// dropped in `Identity.validate_announce` (Identity.py:567-569) BEFORE any
    /// path is learned. Populated via `blackholeIdentity` / cleared via
    /// `unblackholeIdentity`; consulted in `processAnnounce`.
    private var blackholedIdentities: Set<Data> = []

    /// Add an identity hash to the blackhole set (RNS Transport.blackhole_identity,
    /// Transport.py:3399-3413). Subsequent announces from this identity are dropped.
    public func blackholeIdentity(_ identityHash: Data) {
        blackholedIdentities.insert(identityHash)
    }

    /// Remove an identity hash from the blackhole set (RNS Transport.unblackhole_identity,
    /// Transport.py:3415-3428).
    public func unblackholeIdentity(_ identityHash: Data) {
        blackholedIdentities.remove(identityHash)
    }

    /// Whether an identity hash is currently blackholed.
    public func isIdentityBlackholed(_ identityHash: Data) -> Bool {
        blackholedIdentities.contains(identityHash)
    }

    /// E13: Receipt-based proof validation.
    ///
    /// The stored callback carries the received PROOF packet's bytes
    /// (`ReceivedProofPacket?`) so the proof-carrying overloads can surface
    /// `proof_data`/`proof_raw`. The legacy `() async -> Void` registrations are
    /// wrapped to ignore the argument, keeping existing call sites
    /// (Columba/LXMFSwift delivery receipts) byte-for-byte unchanged.
    private var receipts: [(hash: Data, callback: @Sendable (ReceivedProofPacket?) async -> Void, timeout: Date)] = []
    private let maxReceipts = 1024

    /// Whether single-packet PROOFs emitted by this transport use the IMPLICIT
    /// (signature-only, 64 B) or EXPLICIT (`packet_hash || signature`, 96 B) form.
    ///
    /// Mirrors RNS `Reticulum.should_use_implicit_proof()` (RNS/Reticulum.py:1699-1705,
    /// default True at :256). RNS stores this as a process-global class attribute
    /// (`Reticulum.__use_implicit_proof`); the swift port scopes it PER-TRANSPORT so
    /// concurrent in-process peers (e.g. the conformance bridge hosting multiple wire
    /// peers in one process) cannot cross-contaminate each other's proof policy. See
    /// port-deviations.md. Read via `shouldUseImplicitProof()`, set via
    /// `setUseImplicitProof(_:)`.
    private var _useImplicitProof: Bool = true

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

    // (Removed `lastReceivedInterfaceId` global — the path-request handler
    // now receives the inbound interface id directly through the callback
    // chain via `packet.receivingInterface`. The old global raced when any
    // other packet arrived between handler dispatch and the async
    // handler's read, which let the hub leak path-response announces to
    // peers other than the asker.)

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

    /// Called when a peer-spawning interface (AutoInterface / BLEInterface /
    /// MPCInterface) accepts a new peer. Distinct from `onInterfaceConnected`:
    /// `onInterfacePeerSpawned` fires on the *parent's* peer-add hook the
    /// moment a peer is registered, before the peer's own transport
    /// necessarily reaches `.connected`. App-side this is the right hook for
    /// "fire an announce when a new peer joins" so the new peer learns us
    /// even if their TCP/UDP child handshake races our state-change observer.
    private var onInterfacePeerSpawned: (@Sendable (String) async -> Void)?

    /// Called when any registered interface (or peer-child interface)
    /// transitions to `.connected`. This includes TCP reconnects, RNode
    /// reconnects, and the `.connected` transition of peer-children spawned
    /// by AutoInterface / BLEInterface. App-side this is the hook for
    /// "fire an announce on every (re)connect of a stable interface" — for
    /// peer-spawn semantics use `onInterfacePeerSpawned` instead.
    private var onInterfaceConnected: (@Sendable (String) async -> Void)?

    /// Set the callback for when a peer is spawned on AutoInterface /
    /// BLEInterface / MPCInterface. See `onInterfacePeerSpawned`.
    public func setOnInterfacePeerSpawned(_ callback: (@Sendable (String) async -> Void)?) {
        self.onInterfacePeerSpawned = callback
    }

    /// Set the callback for when any interface transitions to `.connected`.
    /// See `onInterfaceConnected`.
    public func setOnInterfaceConnected(_ callback: (@Sendable (String) async -> Void)?) {
        self.onInterfaceConnected = callback
    }

    /// Compatibility shim: the legacy `setOnInterfaceAdded` registered a
    /// single callback that was invoked from BOTH the peer-spawn paths and
    /// the state-change-to-connected path. Existing callers that haven't
    /// been migrated to the split callbacks above get the same behavior by
    /// having this setter wire the same closure to both new hooks.
    @available(*, deprecated, message: "Use setOnInterfacePeerSpawned and/or setOnInterfaceConnected for granular control")
    public func setOnInterfaceAdded(_ callback: (@Sendable (String) async -> Void)?) {
        self.onInterfacePeerSpawned = callback
        self.onInterfaceConnected = callback
    }

    /// Diagnostic callback for packet receive events (set by app layer).
    public var onDiagnostic: (@Sendable (String) -> Void)?

    /// Set the diagnostic callback (actor-isolated setter for cross-actor access).
    public func setOnDiagnostic(_ callback: @escaping @Sendable (String) -> Void) {
        self.onDiagnostic = callback
    }

    /// Whether single-packet PROOFs emitted by this transport use the IMPLICIT
    /// (signature-only, 64 B) form. Mirrors RNS `Reticulum.should_use_implicit_proof()`
    /// (RNS/Reticulum.py:1699-1705). Defaults True (RNS/Reticulum.py:256).
    public func shouldUseImplicitProof() -> Bool {
        return _useImplicitProof
    }

    /// Set the implicit/explicit single-packet PROOF policy for THIS transport.
    /// When `false`, the SINGLE-destination opportunistic prove path emits the
    /// EXPLICIT form `packet.getFullHash() || identity.sign(getFullHash())` (96 B);
    /// when `true` (default) it emits the IMPLICIT signature-only form (64 B).
    /// Mirrors flipping `Reticulum.__use_implicit_proof` (RNS/Reticulum.py:555-558),
    /// but scoped per-transport (see port-deviations.md).
    public func setUseImplicitProof(_ value: Bool) {
        self._useImplicitProof = value
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
        localClientInterfaceIds.remove(id)
    }

    /// Register an interface as a local-client interface (shared-instance
    /// client connection). Mirrors appending to Python
    /// `Transport.local_client_interfaces` (Transport.py:164, populated by
    /// LocalInterface accept). Path requests arriving on such an interface
    /// are answered immediately (see respondWithCachedPath).
    public func markLocalClientInterface(id: String) {
        localClientInterfaceIds.insert(id)
    }

    /// Whether `id` is a registered local-client interface.
    /// Mirrors `packet.receiving_interface in Transport.local_client_interfaces`
    /// (Transport.from_local_client, Transport.py:1479-1510).
    func isLocalClientInterface(_ id: String) -> Bool {
        localClientInterfaceIds.contains(id)
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
                    await self.onInterfacePeerSpawned?(peer.id)
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
                    await self.onInterfacePeerSpawned?(peer.id)
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

    #if canImport(MultipeerConnectivity)
    /// Add an MPCInterface with peer lifecycle management.
    ///
    /// MPCInterface spawns sub-interfaces for each connected Multipeer Connectivity peer.
    /// This method registers the parent for state tracking and wires up
    /// callbacks to add/remove child interfaces as peers connect/disconnect.
    public func addMPCInterface(_ mpcInterface: MPCInterface) async throws {
        let parentId = mpcInterface.id
        logger.info("Adding MPCInterface: \(parentId, privacy: .public)")

        // Register parent for state tracking
        interfaces[parentId] = mpcInterface
        let wrapper = TransportDelegateWrapper(transport: self)
        delegateWrappers[parentId] = wrapper
        await mpcInterface.setDelegate(wrapper)

        // Wire peer lifecycle callbacks
        await mpcInterface.setPeerCallbacks(
            onPeerAdded: { [weak self] peer in
                guard let self = self else { return }
                Task {
                    try? await self.addInterface(peer)
                    await self.onInterfacePeerSpawned?(peer.id)
                }
            },
            onPeerRemoved: { [weak self] peerId in
                guard let self = self else { return }
                Task {
                    await self.removeInterface(id: peerId)
                }
            }
        )

        // Start the interface (advertising + browsing begins)
        try await mpcInterface.connect()
        logger.info("MPCInterface \(parentId, privacy: .public) connected")
    }
    #endif

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
                let addr = peer.peerAddress
                return "AutoInterface [\(addr)]"
            }
            if let blePeer = iface as? BLEPeerInterface {
                let identityHex = blePeer.peerIdentityHex
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
        if interfaceId.hasPrefix("tcp") {
            return "TCP"
        }
        if interfaceId.hasPrefix("rnode") {
            return "RNode"
        }
        return nil
    }

    /// Get a snapshot of all registered interfaces and their states.
    public func getInterfaceSnapshots() async -> [InterfaceSnapshot] {
        var snapshots: [InterfaceSnapshot] = []
        for (_, iface) in interfaces {
            let state = iface.state
            let config = iface.config
            // Get error description from TCP / RNode interfaces if available, so the NE
            // snapshot carries an actionable reason (e.g. "firmware too old", "Invalid
            // configuration — TX power…") instead of a bare offline flag.
            let errorDesc: String?
            if let tcp = iface as? TCPInterface {
                errorDesc = await tcp.lastErrorDescription
            } else if let rnode = iface as? RNodeInterface {
                errorDesc = await rnode.lastErrorDescription
            } else {
                errorDesc = nil
            }
            if let peer = iface as? AutoInterfacePeer {
                let addr = peer.peerAddress
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
                let identityHex = blePeer.peerIdentityHex
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

    // MARK: - Probe / Remote-management destinations (Transport.py:252-258, :396-403)

    /// Register the transport probe-responder destination, mirroring
    /// `Transport.probe_destination` (Transport.py:396-403): an `IN`/`SINGLE`
    /// destination `rnstransport.probe` under the transport identity with proof
    /// strategy `PROVE_ALL` (0x23) and `accepts_links(False)`, tracked in
    /// `mgmt_destinations` (the probe destination is NOT added to `mgmt_hashes`).
    /// Idempotent. Triggered by the `respond_to_probes` knob; default off leaves
    /// `probeDestination == nil`.
    ///
    /// The resulting destination hash is
    /// `full_hash(full_hash("rnstransport.probe")[:10] + identity.hash)[:16]`
    /// (matches `Destination.hash(identity:appName:aspects:)`).
    ///
    /// - Parameter identity: The transport identity the destination is owned by.
    public func registerProbeDestination(identity: Identity) {
        respondToProbes = true
        guard probeDestination == nil else { return }

        let dest = Destination(
            identity: identity,
            appName: "rnstransport",
            aspects: ["probe"],
            type: .single,
            direction: .in
        )
        // Transport.py:399 — probe destination always responds with proofs.
        try? dest.setProofStrategy(Destination.PROVE_ALL)
        // RNS appends only to mgmt_destinations here (Transport.py:400).
        probeDestination = dest
        mgmtDestinations.append(dest)
        // Make it routable so real probe requests reach it (Transport.py registers
        // it as a live Destination under the transport identity).
        registerDestination(dest)

        let hex = dest.hash.map { String(format: "%02x", $0) }.joined()
        logger.info("Registered transport probe destination \(hex, privacy: .public)")
    }

    /// Register the transport remote-management destination, mirroring
    /// `Transport.remote_management_destination` (Transport.py:252-258): an
    /// `IN`/`SINGLE` destination `rnstransport.remote.management` under the
    /// transport identity, with `/status` and `/path` request handlers each
    /// `ALLOW_LIST` (0x02) bound to the `remote_management_allowed` ACL,
    /// tracked in both `mgmt_destinations` and `mgmt_hashes`. Idempotent.
    /// Triggered by the `enable_remote_management` knob; default off registers
    /// nothing.
    ///
    /// - Parameters:
    ///   - identity: The transport identity the destination is owned by.
    ///   - allowed: ACL of identity hashes (each exactly 16 bytes) permitted to
    ///     issue requests. RNS truncated-hash length is `TRUNCATED_HASHLENGTH//8`.
    /// - Throws: `TransportError.invalidConfiguration` if any ACL entry is not
    ///   exactly 16 bytes.
    public func registerRemoteManagementDestination(identity: Identity, allowed: [Data]) throws {
        // Validate ACL entries are 16-byte (TRUNCATED_HASHLENGTH//8) hashes.
        for entry in allowed where entry.count != TRUNCATED_HASH_LENGTH {
            throw TransportError.invalidConfiguration(
                reason: "remote_management_allowed hash must be \(TRUNCATED_HASH_LENGTH) bytes, got \(entry.count)"
            )
        }

        remoteManagementEnabled = true
        remoteManagementAllowed = allowed
        guard remoteManagementDestination == nil else { return }

        let dest = Destination(
            identity: identity,
            appName: "rnstransport",
            aspects: ["remote", "management"],
            type: .single,
            direction: .in
        )
        // Stub response generators: remote status/path responses are not modeled
        // (out of scope — only registration + ACL binding round-trips). RNS:
        // remote_status_handler / remote_path_handler (Transport.py:253-254).
        let noResponse: ResponseGenerator = { _, _, _, _, _, _ in .none }
        try dest.registerRequestHandler(
            path: "/status",
            responseGenerator: noResponse,
            allow: Destination.ALLOW_LIST,
            allowedList: allowed
        )
        try dest.registerRequestHandler(
            path: "/path",
            responseGenerator: noResponse,
            allow: Destination.ALLOW_LIST,
            allowedList: allowed
        )
        remoteManagementDestination = dest
        mgmtDestinations.append(dest)
        mgmtHashes.append(dest.hash)
        registerDestination(dest)

        let hex = dest.hash.map { String(format: "%02x", $0) }.joined()
        logger.info("Enabled remote management on \(hex, privacy: .public)")
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
        return iface.hwMtu
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
        // Wire the Channel delivery-proof hooks so the link's Channel TX ring can
        // observe when a CHANNEL packet's PROOF returns (drives window growth /
        // retransmission). Mirrors RNS registering a PacketReceipt with Transport.
        await link.setChannelProofHooks(
            register: { [weak self] truncatedHash, cb in
                await self?.registerProofCallback(truncatedHash: truncatedHash, callback: cb)
            },
            deregister: { [weak self] truncatedHash in
                await self?.removeProofCallback(truncatedHash: truncatedHash)
            }
        )

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

    /// Inbound (responder) Links accepted for a destination.
    ///
    /// Mirrors RNS `Destination.links` (Destination.py:172), which is populated by
    /// `incoming_link_request` (Destination.py:420-424) — the same append we perform in
    /// `handleLinkRequest`. The conformance bridge's `wire_listener_link_status` uses this to
    /// find the receiver-side link by destination hash and report its status, count and
    /// teardown reason.
    ///
    /// Preferred source is the registered `Destination.links`. As a safety net (e.g. a link
    /// whose destination is not in the `destinations` map), we filter the active responder
    /// links by destination hash. `link.initiator` and `link.destination` are immutable
    /// `Sendable` lets, so this stays a synchronous, non-isolated read.
    ///
    /// - Parameter destinationHash: The destination hash to look up.
    /// - Returns: The responder Links for that destination, or `[]` if none.
    public func linksForDestination(_ destinationHash: Data) -> [Link] {
        if let destination = destinations[destinationHash] {
            return destination.links
        }
        return activeLinks.values.filter { !$0.initiator && $0.destination.hash == destinationHash }
    }

    /// Number of active links.
    public var activeLinkCount: Int {
        activeLinks.count
    }

    /// Enumerate every currently-active link.
    ///
    /// RNS tracks established links in `Transport.active_links`; the swift port keeps
    /// them in the private `activeLinks` map. This accessor exposes the values so a
    /// graceful-shutdown / process-exit path can tear every active link down with a
    /// flushed LINKCLOSE (`Link.closeAndFlush`) — mirroring RNS's exit handler closing
    /// links so peers observe DESTINATION_CLOSED instead of only a watchdog TIMEOUT.
    /// Category (a) accessor over otherwise-private state.
    public func activeLinkList() -> [Link] {
        Array(activeLinks.values)
    }

    /// Graceful-shutdown teardown mirroring RNS `Transport.detach_interfaces`
    /// (RNS/Transport.py:3076-3088): tear every active AND pending link down with a
    /// flushed LINKCLOSE (`Link.closeAndFlush`, role-derived reason), then hold a
    /// 150ms drain window so those teardown packets actually leave local transport
    /// before the interfaces / process go away.
    ///
    /// Without the drain, `NWConnection.send` reports `.contentProcessed` (bytes
    /// accepted into the framework's send buffer) but the process can exit before
    /// they are flushed to the kernel/wire, so the peer never receives the LINKCLOSE
    /// and falls back to a watchdog TIMEOUT instead of DESTINATION_CLOSED. RNS avoids
    /// this with `if closed_links: time.sleep(0.15)` (Transport.py:3088); we mirror it.
    public func detachInterfaces() async {
        // Active links first, then pending links (RNS/Transport.py:3078-3084).
        let links = Array(activeLinks.values) + Array(pendingLinks.values)
        for link in links {
            await link.closeAndFlush()
        }
        // "Provide a 150ms window to allow link teardown packets to leave local
        // transport" (RNS/Transport.py:3086-3088).
        if !links.isEmpty {
            try? await Task.sleep(for: .milliseconds(150))
        }
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

        // Check against pending packet proofs (continuation-style API)
        if let continuation = pendingPacketProofs.removeValue(forKey: proofHash) {
            logger.info("Proof confirmed delivery for packetHash=\(proofHex)")
            continuation.resume(returning: true)
        } else {
            // Don't say "no match" here — the callback-style API
            // (`pendingProofCallbacks`, used by LXMF DIRECT) is
            // checked next and is the common path for link-context
            // proofs. A bare "no pending proof match" log on a
            // successful callback dispatch misleads anyone triaging
            // a delivery problem into thinking nothing handled the
            // proof.
            let pendingHashes = pendingPacketProofs.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
            logger.debug("No continuation-style proof match for \(proofHex). Checking callback API. Pending continuations: \(pendingHashes)")
        }

        // ALSO check the callback-style API. LXMF DIRECT-small uses
        // `registerProofCallback(truncatedHash:)` to learn when its
        // link-data packet has been proven; without this branch the
        // callback dict would be checked only for non-link proofs and
        // a DIRECT delivery proof would silently never advance the
        // outbound message state to `.delivered`. Mirrors the symmetric
        // check at the non-link proof path (callback + receipt are
        // both fired non-exclusively).
        let truncatedHash = Data(proofHash.prefix(TRUNCATED_HASH_LENGTH))
        if let entry = pendingProofCallbacks.removeValue(forKey: truncatedHash) {
            logger.info("Matched delivery proof callback (link) for \(proofHex), invoking callback")
            Task { await entry.callback() }
        }

        // Sweep expired callbacks here too. The non-link proof path
        // already does this around line 1693, but if a Swift LXMF
        // DIRECT proof is dropped on the wire, the registered
        // callback would otherwise sit in the dict until an
        // unrelated non-link PROOF arrived to trigger cleanup —
        // a subtle leak under intermittent loss. 5-minute TTL
        // matches the non-link sweep.
        let now = Date()
        pendingProofCallbacks = pendingProofCallbacks.filter {
            now.timeIntervalSince($0.value.registeredAt) < 300
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
            // RNS Transport.outbound is best-effort and NEVER raises: it iterates
            // every OUT interface, calls Transport.transmit (which wraps
            // process_outgoing in try/except and only logs on error,
            // RNS/Transport.py:1050-1087), and returns a `sent` bool — sent=False
            // when no interface accepted the frame (RNS/Transport.py:1090-1326).
            // Mirror that: surface a genuine per-interface send error so callers
            // are not silently blind to it, but do NOT throw merely because no
            // interface is connected/eligible yet (e.g. a registered TCP peer that
            // has not finished connecting). Throwing noInterfacesAvailable here was
            // a production divergence — an announce/send before a peer connects must
            // not fail.
            if let error = lastError {
                throw TransportError.sendFailed(interfaceId: "all", underlying: error.localizedDescription)
            } else {
                logger.debug("sendRawBytes: no eligible interface accepted the frame — best-effort no-op (RNS outbound returns sent=False)")
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
        // RNS Transport.outbound is best-effort: with no eligible interface it
        // simply returns sent=False and NEVER raises (RNS/Transport.py:1090-1326,
        // tail `return sent`). Mirror that here — do NOT throw merely because no
        // interface is registered/connected yet. This is production-relevant:
        // a TCP server (or any interface) with no peer connected at send time
        // must not make announce/transmit fail. The previous
        // `throw noInterfacesAvailable` here diverged from RNS and surfaced as
        // spurious failures on the conformance bridge's server side (where the
        // listening parent's interface map can be momentarily empty/racing).
        guard !interfaces.isEmpty else {
            logger.debug("send(packet:): no interfaces registered — best-effort no-op (RNS outbound returns sent=False)")
            return
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

                // If the path entry references an interface we no longer have
                // (e.g. stale path from a previous app run), invalidate it and
                // request a fresh path. We queue the packet in that case so
                // processPendingPackets can re-send it once a new path arrives,
                // instead of falling through to a broadcast.
                let resolvedEntry: PathEntry? = {
                    guard let entry = pathEntry else { return nil }
                    let outboundId = entry.interfaceId
                    if !outboundId.isEmpty, interfaces[outboundId] == nil {
                        logger.warning("Path entry references missing interface '\(outboundId)' — invalidating stale path to \(destHex)...")
                        return nil
                    }
                    return entry
                }()
                let hadStalePath = resolvedEntry == nil && pathEntry != nil
                if hadStalePath, let staleInterfaceId = pathEntry?.interfaceId {
                    // Queue FIRST — before any await that releases the actor. Both
                    // pathTable.remove and requestPath have real suspension points;
                    // an announce arriving during either would trigger
                    // processPendingPackets on an empty queue, stranding this
                    // packet until the next unsolicited announce.
                    //
                    // Use the conditional remove so that if an announce did arrive
                    // during the suspension and replaced the entry with a fresh
                    // interface id, we don't erase the just-learned path.
                    queuePendingPacket(packet, for: packet.destination)
                    await pathTable.remove(destinationHash: packet.destination, ifInterface: staleInterfaceId)
                    await requestPath(for: packet.destination)
                    logger.info("Queuing packet to \(destHex)... after invalidating stale path; broadcasting skipped")
                    return
                }

                // Python converts to HEADER_2 only if hops > 1 (Transport.py line ~500)
                // hops == 1 means destination is one hop away, send HEADER_1 directly
                // hops > 1 means destination needs multi-hop routing via transport node
                if let entry = resolvedEntry,
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
                    if let entry = resolvedEntry {
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

    /// Send a packet and auto-register a PROOF-CARRYING receipt for proof-of-delivery.
    ///
    /// Additive overload of `send(packet:receiptCallback:)` whose callback receives
    /// the matched PROOF packet's bytes (`ReceivedProofPacket`) so the caller can
    /// read `proof_data`/`proof_raw` and classify IMPLICIT (64 B) vs EXPLICIT (96 B).
    /// Same receipt-creation gate as the no-arg overload (Transport.py:947-958).
    ///
    /// - Parameters:
    ///   - packet: Packet to send
    ///   - proofReceiptCallback: Callback invoked with the received PROOF bytes
    ///   - receiptTimeout: Receipt expiry in seconds (default 300)
    /// - Throws: TransportError if send fails
    public func send(
        packet: Packet,
        proofReceiptCallback: @escaping @Sendable (ReceivedProofPacket?) async -> Void,
        receiptTimeout: TimeInterval = 300
    ) async throws {
        try await send(packet: packet)

        if packet.header.packetType == .data,
           packet.header.destinationType != .plain,
           !PacketContext.isLinkContext(packet.context),
           !PacketContext.isResourceContext(packet.context) {
            let packetHash = packet.getTruncatedHash()
            registerReceipt(hash: packetHash, timeout: receiptTimeout, proofCallback: proofReceiptCallback)
        }
    }

    /// Send link data packet on the link's attached interface.
    ///
    /// Link DATA packets are ALWAYS sent as HEADER_1 to the link's
    /// `attached_interface`, never converted to HEADER_2. This mirrors
    /// python `Transport.outbound` (RNS/Transport.py:1063, 1122-1130):
    /// the path-table lookup at :1063 keys on `packet.destination_hash`
    /// which for link packets equals the link_id — and link_ids are
    /// never inserted into the path_table. So python falls through to
    /// the broadcast loop at :1122 where the LINK destination guard at
    /// :1128-1130 forces transmission on `attached_interface` only.
    ///
    /// The transport node (e.g. rnsd between iPhone and the echo bot)
    /// matches the inbound HEADER_1 packet's destination_hash against
    /// its own `Transport.active_links` registry and forwards on the
    /// peer's leg. Sending a HEADER_2 packet here breaks that path:
    /// rnsd interprets HEADER_2 as a transport-routed packet, but the
    /// destination_hash is a link_id (not a routable destination), and
    /// the packet is silently dropped. This was the root cause of
    /// `direct_echo` failing on the iOS smoke pipeline (state=SENT but
    /// echo bot never received the message).
    ///
    /// - Parameter packet: Link DATA packet (destination = linkId)
    /// - Throws: TransportError if no interfaces available or send fails
    public func sendLinkData(packet: Packet) async throws {
        guard !interfaces.isEmpty else {
            throw TransportError.noInterfacesAvailable
        }

        let linkId = packet.destination
        let linkIdHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()
        let attachedId = await activeLinks[linkId]?.attachedInterfaceId

        if let attachedId {
            logger.debug("Link DATA: HEADER_1 to attached interface, linkId=\(linkIdHex), iface=\(attachedId)")
            try await sendToInterface(packet.encode(), interfaceId: attachedId)
        } else {
            // Mirrors python `RNS/Transport.py:1124-1130`: every interface
            // fails the `interface != packet.destination.attached_interface`
            // guard when `attached_interface` is `None`, so the packet is
            // not transmitted at all. Silent drop is correct — broadcasting
            // here would spray link DATA across LoRa / BLE / other
            // physical media a stale-or-unestablished link should not be
            // touching. Logged as a warning so the case is debuggable, but
            // wire behavior matches python.
            logger.warning("Link DATA: linkId=\(linkIdHex) has no attached interface; dropping (matches python)")
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

        // RNS Transport.outbound's broadcast loop is best-effort: it calls
        // Transport.transmit on every eligible interface and returns sent=False
        // if none accepted the frame — it NEVER raises (RNS/Transport.py:1118-1326,
        // transmit try/except at :1050-1087). Mirror that: surface a genuine
        // per-interface send error, but do NOT throw merely because no interface
        // is connected/eligible (which previously produced a spurious
        // noInterfacesAvailable for sends issued before a peer connected).
        if successCount == 0 {
            if let error = lastError {
                logger.error("sendToAllInterfaces failed: no interfaces succeeded")
                throw TransportError.sendFailed(interfaceId: "all", underlying: error.localizedDescription)
            } else {
                logger.debug("sendToAllInterfaces: no eligible/connected interface — best-effort no-op (RNS outbound returns sent=False)")
            }
            return
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
                    let waitTime = txTime / interface.config.announceCap
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
            await requestPath(for: destHash)
            return  // Don't throw - packet is queued for later delivery
        }

        let interfaceId = pathEntry.interfaceId
        logger.debug("Found path to \(destHex)... via interface '\(interfaceId)'")

        // Get the interface. If it's missing (e.g. stored path references an
        // interface from a previous app run), invalidate the stale path and
        // re-request so a fresh path can be learned.
        guard let interface = interfaces[interfaceId] else {
            logger.warning("Interface '\(interfaceId)' not found (have: \(Array(self.interfaces.keys))) — invalidating stale path to \(destHex)...")
            // Queue before any await to avoid the actor-reentrancy race where
            // an announce arriving during pathTable.remove or requestPath
            // triggers processPendingPackets on an empty queue. Use the
            // conditional remove so a fresh announce that landed during our
            // suspension isn't overwritten by our invalidation.
            queuePendingPacket(packet, for: destHash)
            await pathTable.remove(destinationHash: destHash, ifInterface: interfaceId)
            await requestPath(for: destHash)
            return
        }

        // Check interface is connected. If not, treat as transient — queue
        // the packet but don't invalidate the path (interface may reconnect).
        // Also kick off a path re-request: if topology changed and the
        // destination is now reachable via a different interface, the new
        // announce will arrive and flush the queue. Without this, a queued
        // packet can sit indefinitely if the interface never reconnects and
        // the remote node doesn't happen to re-announce on its own.
        guard interface.state == .connected else {
            logger.warning("Interface '\(interfaceId)' not connected (state=\(String(describing: interface.state))) — queuing packet and re-requesting path")
            queuePendingPacket(packet, for: destHash)
            await requestPath(for: destHash)
            return
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

        // RNS Transport.py:1516-1530 — PLAIN-broadcast shared-instance fanout.
        // A PLAIN BROADCAST packet is never injected into transport; instead, if it
        // came from a local client it is repeated on every OTHER interface, and if it
        // came from a normal interface it is pushed to the local-client interfaces
        // only. Control destinations (e.g. the path-request PLAIN destination) are
        // excluded (`if not packet.destination_hash in Transport.control_hashes`).
        if packet.header.destinationType == .plain,
           packet.header.transportType == .broadcast,
           !controlHashes.contains(destHash) {
            await fanoutPlainBroadcast(packet: packet, from: interfaceId)
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
                    // Surface the received PROOF packet's bytes (RNS receipt.proof_packet,
                    // RNS/Packet.py:498-537): `data` is the proof payload (64 B implicit
                    // signature or 96 B explicit packet_hash||signature), `raw` is the full
                    // encoded proof packet. Legacy `() async -> Void` receipts wrap to
                    // ignore the argument, so this is non-breaking.
                    let proofPacket = ReceivedProofPacket(data: packet.data, raw: packet.encode())
                    Task { await receipt.callback(proofPacket) }
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
        // Wire the Channel delivery-proof hooks (responder side) — see the matching
        // block on the initiator path. A responder's Channel can also send, so it
        // needs the same receipt-resolution wiring.
        await link.setChannelProofHooks(
            register: { [weak self] truncatedHash, cb in
                await self?.registerProofCallback(truncatedHash: truncatedHash, callback: cb)
            },
            deregister: { [weak self] truncatedHash in
                await self?.removeProofCallback(truncatedHash: truncatedHash)
            }
        )

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

            // Send PROOF via the interface that received the request.
            // Route through sendToInterface (NOT interface.send directly)
            // so applyIFAC runs on the outbound bytes. Calling
            // interface.send directly skipped IFAC, producing a raw
            // LINKPROOF that every IFAC-configured peer rejected with
            // "IFAC validation failed" — specifically breaking 3-peer
            // IFAC link establishment, since in that topology the
            // LINKPROOF has to traverse a middle transport which drops
            // the packet for missing IFAC before it reaches the sender.
            if interfaces[interfaceId] != nil {
                try await sendToInterface(proofData, interfaceId: interfaceId)
            } else {
                // Broadcast to all interfaces as fallback
                try await sendRawBytes(proofData)
            }

            // Derive keys for decrypting LRRTT
            try await link.deriveResponderKeys()

            // Store link as pending (waiting for LRRTT to complete establishment)
            activeLinks[incomingRequest.linkId] = link
            // Mirror RNS Destination.incoming_link_request (Destination.py:420-424):
            // self.links.append(link). This makes the inbound responder link visible through
            // Destination.links / Transport.linksForDestination, which the conformance bridge's
            // wire_listener_link_status uses to report the receiver-side link, its count and
            // teardown reason (e.g. observing INITIATOR_CLOSED on the non-initiating side).
            destination.appendLink(link)
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
            // Only tear the link down if it is NOT already established. A duplicate or
            // late LRPROOF — the SAME proof arriving via two interfaces on a shared
            // medium / BLE mesh, which is exactly why LRPROOF dedup exists but is only
            // recorded AFTER processProof succeeds (above) — makes processProof throw an
            // invalid-STATE error, because the first copy already promoted the link to
            // .active. That is not a bad proof: closing here would flap a just-
            // established link and emit a spurious LINKCLOSE to the peer. RNS gates proof
            // validation on `status == PENDING` and silently ignores a proof otherwise.
            if await link.state.isEstablished {
                let hexPrefix = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
                logger.warning("Ignoring duplicate/late LRPROOF on already-established link \(hexPrefix, privacy: .public)...: \(error.localizedDescription, privacy: .public)")
            } else {
                logger.error("PROOF processing failed: \(error.localizedDescription)")
                await link.close(reason: .proofInvalid)
                pendingLinks.removeValue(forKey: packet.destination)

                let hexPrefix = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
                logger.warning("Link \(hexPrefix, privacy: .public)... PROOF validation failed: \(error.localizedDescription, privacy: .public)")
            }
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
        // Python sends encrypted(link_id) and validates plaintext == link_id on receive.
        // Delegate to Link.handleClose, which mirrors RNS teardown_packet (Link.py:710-722):
        //   - re-validates plaintext == link_id,
        //   - sets teardown_reason = initiator ? DESTINATION_CLOSED : INITIATOR_CLOSED
        //     (role-correct; the old close(reason:.destinationClosed) HARDCODED the reason,
        //      mislabeling a responder's received close as DESTINATION_CLOSED),
        //   - runs link_closed cleanup but emits NO LINKCLOSE packet (the old close() path
        //     re-emitted a redundant LINKCLOSE on every received close; RNS teardown_packet
        //     sends nothing — only the locally-initiated teardown() emits a packet).
        if packet.context == LinkConstants.CONTEXT_LINKCLOSE {
            logger.debug("LINKCLOSE packet detected (context=0xFC)")
            do {
                let plaintext = try await link.decrypt(packet.data)
                let expectedLinkId = await link.linkId
                if plaintext == expectedLinkId {
                    await link.handleClose(plaintext)
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
            let isInitiator = link.initiator

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
        // Mirrors RNS Link.receive CHANNEL branch (Link.py:1165-1173):
        //   elif packet.context == RNS.Packet.CHANNEL:
        //       if not self._channel:
        //           RNS.log("Channel data received without open channel", ...)
        //       else:
        //           packet.prove()
        //           plaintext = self.decrypt(packet.data)
        //           if plaintext != None:
        //               self.__update_phy_stats(packet)
        //               self._channel._receive(plaintext)
        // The packet is only processed — and crucially PROVED — when the link
        // has an open channel; with no channel it is dropped WITHOUT a proof
        // (Link.py:1166-1167). RNS proves CHANNEL packets UNCONDITIONALLY when a
        // channel is open (Link.py:1172) — unlike the DATA branch below, it does
        // NOT consult the destination's proof_strategy. Proving lets the sender's
        // PacketReceipt resolve, so it stops retransmitting (otherwise 5 retries
        // → link teardown). provePacket guards initiator-side proving internally
        // (an initiator would sign with the wrong key), hence `try?` as in the
        // DATA branch. Prove is done before decrypt to match RNS ordering;
        // provePacket signs the wire packet's full hash, independent of decrypt.
        if packet.context == PacketContext.CHANNEL {
            guard await link.hasOpenChannel else {
                logger.debug("Channel data received without open channel")
                return
            }
            try? await link.provePacket(packet)
            do {
                let plaintext = try await link.decrypt(packet.data)
                await link.handleChannelData(plaintext)
            } catch {
                logger.error("Failed to decrypt CHANNEL data: \(error.localizedDescription)")
            }
            return
        }

        // REQUEST (0x09) - incoming request from peer (encrypted)
        // Mirrors RNS Link.receive REQUEST branch (Link.py:1030-1040):
        //   request_id      = packet.getTruncatedHash()   # computed on the WIRE packet, pre-decrypt
        //   packed_request  = self.decrypt(packet.data)
        //   unpacked_request= umsgpack.unpackb(packed_request)
        //   handle_request(request_id, unpacked_request)
        // The umsgpack unpack + ALLOW gating + generator fork live in Link.handleRequestPacket
        // -> Link.handleRequest (Link.py:853-904) to keep the wire/RPC logic on the Link, exactly
        // as RNS does. We compute request_id from the inbound packet's truncated hash before
        // decrypting, then hand the plaintext to the Link.
        if packet.context == RequestPacketContext.request {
            logger.debug("REQUEST packet detected (context=0x09), dataLen=\(packet.data.count)")
            // request_id is derived from the wire packet (RNS reads getTruncatedHash on the
            // received packet, NOT on the plaintext), so capture it before decrypt.
            let requestId = packet.getTruncatedHash()
            do {
                let plaintext = try await link.decrypt(packet.data)
                logger.debug("Decrypted REQUEST: \(plaintext.count) bytes, requestId=\(requestId.prefix(8).map { String(format: "%02x", $0) }.joined())")
                await link.handleRequestPacket(plaintext, requestId: requestId)
            } catch {
                logger.error("Failed to decrypt REQUEST: \(error.localizedDescription)")
            }
            return
        }

        // RESPONSE (0x0A) - response to our request (encrypted)
        // Mirrors RNS Link.receive RESPONSE branch (Link.py:1042-1054):
        //   packed_response   = self.decrypt(packet.data)
        //   unpacked_response = umsgpack.unpackb(packed_response)   # [request_id, response_data]
        //   handle_response(request_id, response_data, ...)
        // The umsgpack unpack + RAW-payload extraction now live in Link.handleResponsePacket
        // (Link.py:906-925). This is the double-frame fix: the previous inline path here
        // re-packed the already-decoded response value (`packMsgPack(elements[1])`), which
        // re-added an msgpack bin frame so the receipt held [0xc4,len,...] instead of the raw
        // payload. Delegating to the Link keeps the sub-MDU packet path and the >MDU
        // response-Resource conclude path agreeing on the exact wire-observable bytes.
        if packet.context == RequestPacketContext.response {
            logger.debug("RESPONSE packet detected (context=0x0A), dataLen=\(packet.data.count)")
            do {
                let plaintext = try await link.decrypt(packet.data)
                logger.debug("Decrypted RESPONSE: \(plaintext.count) bytes")
                await link.handleResponsePacket(plaintext)
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

            // DATA auto-prove. Mirrors RNS Link.receive context==NONE branch (Link.py:998-1008):
            // after delivering the plaintext to the packet callback, consult the destination's
            // proof_strategy and prove the inbound packet accordingly.
            //   PROVE_ALL -> always prove
            //   PROVE_APP -> prove iff destination.proof_requested(packet) returns true
            //   PROVE_NONE (default) -> do nothing
            // This is purely ADDITIVE: every existing Columba/LXMF destination leaves
            // proof_strategy at the PROVE_NONE default, so the regular link-DATA path is
            // unchanged. RNS passes the still-encrypted wire packet to the proof_requested
            // callback (the app decrypts it itself), so we pass `packet` here too. provePacket()
            // guards against initiator-side proving internally, hence `try?`. Runs whether or not
            // the packet callback consumed the data, matching RNS (proof is outside the
            // callback branch). Note this is the LINK-DATA path; the opportunistic SINGLE-
            // destination prove (handleRegularData, proof after local delivery) is a separate
            // code path and is not double-fired here.
            let proofStrategy = link.destination.proofStrategy
            if proofStrategy == Destination.PROVE_ALL {
                try? await link.provePacket(packet)
            } else if proofStrategy == Destination.PROVE_APP {
                if link.destination.proofRequestedCallback?(packet) ?? false {
                    try? await link.provePacket(packet)
                }
            }

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

            // Deliver to the LXMF destination's callback. Pass the
            // ORIGINAL link packet — its destination is the linkId,
            // and the LXMF delivery callback uses
            // `packet.getFullHash()` / `getTruncatedHash()` to compute
            // the proof reply. Rewriting `destination` to lxmfDestHash
            // would change those hashes, so the proof we send back
            // would not match the receipt the sender registered for
            // the original link-DATA packet — DIRECT delivery would
            // never advance to `delivered` for the sender even though
            // the message arrived correctly.
            await callbackManager.deliver(
                data: plaintext,
                packet: packet,
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
            // for_local_client (RNS Transport.py:1511/1545-1581): a non-announce
            // packet whose destination is held at hops==0 via a local-client
            // interface is routed back to that client. The hops==0 sentinel exists
            // only because the local-client decrement (Transport.py:1479-1480) made
            // the attached app look master-originated. RNS regenerates the
            // transport_id stripped on the previous hop (:1545-1546); the
            // remaining_hops==0 relay branch (:1575-1579) strips transport headers,
            // so the wire re-emission stays HEADER_1 with the hop count incremented —
            // which is exactly forwardDataPacket's hopCount==0 branch.
            if !localClientInterfaceIds.isEmpty,
               let pathEntry = await pathTable.lookup(destinationHash: destHash),
               pathEntry.hopCount == 0,
               isLocalClientInterface(pathEntry.interfaceId) {
                await forwardDataPacket(packet, from: interfaceId)
                return
            }
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

        // Attach the receiving interface ID (NOT the human-readable name)
        // to the packet before delivery. Callbacks (notably the path-request
        // handler) need the stable id to look up the interface in the
        // `interfaces` map and decide where to send a targeted response.
        // Earlier code stored the name when available, which made
        // `packet.receivingInterface` ambiguous (sometimes name, sometimes
        // id) and forced handlers to fall back to the racy
        // `lastReceivedInterfaceId` global instead — which let path-response
        // routing leak to peers that just happened to be the most-recent
        // sender of any packet at handler-dispatch time. If a caller wants
        // a display name they can call `getInterfaceName(for:)`.
        var deliveryPacket = packet
        deliveryPacket.receivingInterface = interfaceId

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
        // Proof format: HEADER_1 / PROOF / BROADCAST / SINGLE
        //   destination = packet.getTruncatedHash() (16 bytes)
        //   data        = proof_data (see implicit/explicit branch below)
        //
        // Reference: Python RNS/Packet.py ProofDestination.type = RNS.Destination.SINGLE.
        // The destinationType MUST be .single (not .plain) — the wire-format flag is set
        // from the proof destination's type, and using .plain produces a malformed proof
        // that Python/Android receivers cannot validate against the original packet.
        if packet.header.destinationType == .single,
           let identity = destination.identity,
           identity.hasPrivateKeys {
            // RNS Transport.py:2156-2165: after local delivery, emit a proof for an
            // opportunistic SINGLE packet ONLY as the destination's proof_strategy
            // dictates — the default PROVE_NONE proves nothing, PROVE_ALL always
            // proves, and PROVE_APP consults the proof_requested callback. This mirrors
            // the link-DATA prove gate above (RNS Link.receive context==NONE branch).
            //
            // Previously this path proved unconditionally whenever the destination held
            // private keys. That diverged from RNS (which never proves opportunistic
            // SINGLE packets at PROVE_NONE) and double-proved LXMF opportunistic
            // delivery: LXMF-swift's deliveryPacket callback already emits the delivery
            // proof, exactly as python LXMF keeps its delivery destination at the
            // PROVE_NONE default and calls packet.prove() inside delivery_packet
            // (LXMF/LXMRouter.py:1823). Gating here restores RNS fidelity without
            // dropping Columba/LXMF delivery proofs (those come from the callback).
            let proofStrategy = destination.proofStrategy
            let shouldProve: Bool
            switch proofStrategy {
            case Destination.PROVE_ALL:
                shouldProve = true
            case Destination.PROVE_APP:
                shouldProve = destination.proofRequestedCallback?(packet) ?? false
            default:                       // PROVE_NONE (default) — no opportunistic proof
                shouldProve = false
            }
            guard shouldProve else { return }
            do {
                // RNS Identity.prove (RNS/Identity.py:959-970): sign the FULL packet hash,
                // then select the proof payload by the implicit-proof policy:
                //   implicit (default) -> proof_data = signature                  (64 B)
                //   explicit           -> proof_data = packet_hash || signature    (96 B)
                // `packet.getFullHash()` is RNS `packet.packet_hash`; the explicit form
                // concatenates the full (NOT truncated) hash before the signature so the
                // sender's PacketReceipt.validate_proof accepts it.
                let fullHash = packet.getFullHash()
                let signature = try identity.sign(fullHash)
                let proofData: Data = _useImplicitProof ? signature : (fullHash + signature)
                let proofHeader = PacketHeader(
                    headerType: .header1,
                    hasContext: false,
                    hasIFAC: false,
                    transportType: .broadcast,
                    destinationType: .single,
                    packetType: .proof,
                    hopCount: 0
                )
                let proofPacket = Packet(
                    header: proofHeader,
                    destination: packet.getTruncatedHash(),
                    transportAddress: nil,
                    context: 0x00,
                    data: proofData
                )
                let encoded = proofPacket.encode()
                // Route through sendToInterface (NOT interface.send directly) so applyIFAC
                // runs on the outbound bytes. Calling iface.send directly skips IFAC and
                // produces a raw proof that IFAC-configured peers reject as "IFAC validation
                // failed" — the same anti-pattern previously fixed for LINKPROOF send.
                if interfaces[interfaceId] != nil {
                    try await sendToInterface(encoded, interfaceId: interfaceId)
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

        // Blackhole gate (RNS Identity.validate_announce, Identity.py:567-569): if
        // the announcing identity's hash is in Transport.blackholed_identities
        // (Transport.py:123), the announce is invalidated and dropped before any
        // path is learned. The announced identity hash is truncated_hash(public_key),
        // where public_key is the leading 64 (KEYSIZE//8) bytes of the announce
        // payload — the same slice validate_announce takes (Identity.py:535). Only
        // typed (non-PLAIN) destinations carry identity key material.
        if !blackholedIdentities.isEmpty,
           packet.header.destinationType != .plain,
           packet.data.count >= 64 {
            let publicKey = Data(packet.data.prefix(64))
            let announcedIdentityHash = Hashing.truncatedHash(publicKey)
            if blackholedIdentities.contains(announcedIdentityHash) {
                let hexPrefix = announcedIdentityHash.prefix(4).map { String(format: "%02x", $0) }.joined()
                logger.debug("Dropped announce from blackholed identity \(hexPrefix, privacy: .public)...")
                onDiagnostic?("[ANNOUNCE] Dropped announce from blackholed identity")
                return
            }
        }

        // Get interface mode
        let mode = getInterfaceMode(for: interfaceId)

        // RNS local-client hop decrement (Transport.py:1455/1479-1480): an announce
        // heard from a shared-instance local client is stored at its wire hop count
        // (net-zero +1/-1), making the destination look master-originated.
        let isFromLocalClient = isLocalClientInterface(interfaceId)

        // Process via announce handler
        let result = await announceHandler.process(
            packet: packet,
            from: interfaceId,
            interfaceMode: mode,
            hopDecrement: isFromLocalClient
        )

        // L2: Local-rebroadcast / passed-on detection (RNS Transport.py:1719-1736).
        // Runs for ANY VALIDATED HEADER_2 announce carrying a transport_id whose
        // destination is already in our announce_table — INDEPENDENT of whether the
        // announce updates the path table. In the reference this detection sits
        // BEFORE the should_add logic, so a heard rebroadcast that is older / more
        // hops (and therefore not re-admitted) still counts toward the local
        // rebroadcast limit and can cancel a pending retry. `.recorded` /
        // `.recordedAndRebroadcast` / `.ignored(.alreadySeen)` all imply the
        // signature validated; `.invalidSignature` / `.invalidFormat` /
        // `.hopLimitExceeded` do not.
        let announceValidated: Bool
        switch result {
        case .recorded, .recordedAndRebroadcast:
            announceValidated = true
        case .ignored(let reason):
            announceValidated = (reason == .alreadySeen)
        }
        if transportEnabled, announceValidated,
           packet.header.headerType == .header2,
           packet.transportAddress != nil {
            // RNS increments packet.hops on receive (so its detection compares the
            // RECEIVED hop count); this port keeps packet.header.hopCount at the
            // wire value and applies the +1 at each use site (the path record does
            // the same, AnnounceHandler.swift:295), so add 1 here to get the
            // received hop count the comparison expects.
            let detected = await announceTable.recordLocalRebroadcast(
                destinationHash: packet.destination,
                incomingHops: packet.header.hopCount + 1
            )
            if detected {
                let hexPrefix = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
                logger.debug("Local rebroadcast detected for \(hexPrefix, privacy: .public)...")
            }
        }

        // Handle result
        switch result {
        case .ignored(let reason):
            let hexPrefix = packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()
            logger.debug("Announce ignored (\(String(describing: reason), privacy: .public)) for \(hexPrefix, privacy: .public)...")

        case .recorded(let destHash):
            // RNS Transport.py:2034-2086 — dispatch every accepted announce
            // (should_add==True) to externally-registered announce handlers. This
            // runs for EVERY accepted announce regardless of transport_enabled (it
            // is NOT gated on the rebroadcast block below), so leaf nodes still
            // deliver to app handlers (e.g. LXMF lxmf.delivery / lxmf.propagation).
            // The ORIGINAL packet is passed so announce_packet_hash == packet hash.
            await dispatchAnnounceToHandlers(packet: packet, destinationHash: destHash)

            // RNS Transport.py:1931-1976 — re-emit every accepted announce to our
            // attached local clients immediately, rewritten to HEADER_2/TRANSPORT
            // with our own identity as transport_id so they see the destination as
            // 1-hop reachable via this shared instance.
            await reEmitAnnounceToLocalClients(packet: packet, receivingInterfaceId: interfaceId, isFromLocalClient: isFromLocalClient)

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

            // RNS Transport.py:2034-2086 — dispatch every accepted announce to
            // externally-registered handlers. MUST run here, OUTSIDE/BEFORE the
            // `if transportEnabled || isLocal` rebroadcast block below, so it fires
            // for every should_add==True announce regardless of transport_enabled.
            // The ORIGINAL packet is passed so announce_packet_hash == packet hash.
            await dispatchAnnounceToHandlers(packet: packet, destinationHash: destHash)

            // RNS Transport.py:1931-1976 — re-emit every accepted announce to our
            // attached local clients immediately (HEADER_2/TRANSPORT, our identity as
            // transport_id). Independent of transport_enabled and of the normal
            // announce-table rebroadcast below.
            await reEmitAnnounceToLocalClients(packet: packet, receivingInterfaceId: interfaceId, isFromLocalClient: isFromLocalClient)

            // L2: Local-rebroadcast detection now runs before this switch (hoisted
            // to fire for any validated HEADER_2 announce, RNS Transport.py:1719-1736).

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

                    // Transport.py:1889-1893: a heard announce arriving on a
                    // local-client interface (is_from_local_client) is scheduled to
                    // rebroadcast immediately (retransmit_timeout==now) exactly once
                    // (retries preset to PATHFINDER_R); an ordinary forwarded announce
                    // gets the random PATHFINDER_RW window with retries=0.
                    await announceTable.insert(
                        destinationHash: destHash,
                        packet: rebroadcastPacket,
                        hops: rebroadcastPacket.header.hopCount,
                        receivedFrom: receivedFrom,
                        isLocalClient: isLocalClientInterface(interfaceId),
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

    /// Destination hashes of control-plane destinations that are exempt from the
    /// PLAIN-broadcast shared-instance fanout and the general relay (RNS
    /// `Transport.control_hashes`, populated from `control_destinations` at
    /// Transport.start()). RNS registers the path-request and tunnel-synthesize
    /// PLAIN destinations as control destinations, so both are carved out here —
    /// independent of whether this port has a handler bound for each.
    private lazy var controlHashes: Set<Data> = {
        var hashes: Set<Data> = []
        hashes.insert(Destination(plainAppName: "rnstransport", aspects: ["path", "request"]).hash)
        hashes.insert(Destination(plainAppName: "rnstransport", aspects: ["tunnel", "synthesize"]).hash)
        return hashes
    }()

    /// Fan out a PLAIN BROADCAST packet across the shared-instance boundary.
    ///
    /// Mirrors RNS Transport.py:1516-1530. PLAIN broadcasts are never injected into
    /// transport: a broadcast that arrived FROM a local client is repeated on every
    /// other attached interface; one that arrived on a normal interface is pushed to
    /// the local-client interfaces only. The original bytes are forwarded verbatim.
    private func fanoutPlainBroadcast(packet: Packet, from interfaceId: String) async {
        let raw = packet.encode()
        if isLocalClientInterface(interfaceId) {
            // From a local client: send on all interfaces except the originator.
            for (otherId, iface) in interfaces {
                guard otherId != interfaceId, iface.state == .connected else { continue }
                try? await sendToInterface(raw, interfaceId: otherId)
            }
        } else {
            // From a normal interface: push to the local clients only.
            for localId in localClientInterfaceIds {
                guard let iface = interfaces[localId], iface.state == .connected else { continue }
                try? await sendToInterface(raw, interfaceId: localId)
            }
        }
    }

    /// Re-emit an accepted announce to every attached local client immediately.
    ///
    /// Mirrors RNS Transport.py:1931-1976 (the `if len(local_client_interfaces)`
    /// block inside the should_add announce path). Each local client receives a
    /// fresh announce rewritten to HEADER_2 / TRANSPORT carrying THIS instance's
    /// identity as the transport_id, so a client behind the shared instance learns
    /// the destination as 1-hop reachable via its LocalClientInterface. The packet
    /// is never re-emitted to the interface it arrived on. The hop count is the
    /// post-increment value RNS carries at this point: +1 for the receive, minus 1
    /// again if the source was itself a local client (Transport.py:1455/1479-1480).
    private func reEmitAnnounceToLocalClients(packet: Packet, receivingInterfaceId: String, isFromLocalClient: Bool) async {
        guard !localClientInterfaceIds.isEmpty else { return }
        guard let transportId = transportIdentityHash else { return }

        // packet.hops after the inbound +1 / local-client -1 net (Transport.py:1957/1975).
        let reEmitHops = packet.header.hopCount &+ (isFromLocalClient ? 0 : 1)

        for localInterfaceId in localClientInterfaceIds {
            // RNS: `if packet.receiving_interface != local_interface`
            guard localInterfaceId != receivingInterfaceId else { continue }
            guard let iface = interfaces[localInterfaceId], iface.state == .connected else { continue }

            let header = PacketHeader(
                headerType: .header2,
                hasContext: packet.header.hasContext,
                hasIFAC: false,
                transportType: .transport,
                destinationType: packet.header.destinationType,
                packetType: .announce,
                hopCount: reEmitHops
            )
            let reEmit = Packet(
                header: header,
                destination: packet.destination,
                transportAddress: transportId,
                context: packet.context,
                data: packet.data
            )
            do {
                try await sendToInterface(reEmit.encode(), interfaceId: localInterfaceId)
                onDiagnostic?("[TRANSPORT] Re-emitted announce for \(packet.destination.prefix(4).map { String(format: "%02x", $0) }.joined()) to local client \(localInterfaceId)")
            } catch {
                onDiagnostic?("[TRANSPORT] Failed to re-emit announce to local client \(localInterfaceId): \(error)")
            }
        }
    }

    /// Retransmit announces from the announce table as HEADER_2 packets.
    ///
    /// Called periodically (~1s) to process queued announce retransmissions.
    /// Packets are rebroadcast as HEADER_2 with the local transport identity hash.
    /// Per-interface AnnounceFilter is applied before sending.
    ///
    /// Reference: Python Transport.py:518-579
    private func processAnnounceRetransmissions(force: Bool = false) async {
        // Transport.py:574/636: the announce-retransmit branch only runs when
        // `now > announces_last_checked + announces_check_interval` (1.0s), even
        // though jobs() itself ticks every job_interval (0.25s). `force` mirrors the
        // behavioral force-cull, which zeroes announces_last_checked to drive one
        // deterministic pass regardless of the gate (behavioral_transport.py force_cull).
        let now = Date()
        if !force && now.timeIntervalSince(announcesLastChecked) < TransportConstants.ANNOUNCES_CHECK_INTERVAL {
            return
        }
        announcesLastChecked = now

        // Transport.py:1004-1047: jobs() collects every due announce into `outgoing`,
        // then handle_outgoing_announces emits them `sorted(outgoing, key=p.hops)` —
        // lowest hop-count first. Mirror that ascending-hops ordering so batched
        // rebroadcasts egress (and hit the per-interface announce cap) in hop order.
        let actions = await announceTable.processRetransmissions()
            .sorted { $0.hops < $1.hops }
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
                // Python Transport.py:1041: announce filter only runs when
                // attached_interface is None (broadcast). When attached_interface
                // is set, it's a targeted response (e.g. path request reply)
                // that bypasses filtering.
                if action.attachedInterfaceId == nil {
                    let outgoingMode = interface.config.mode
                    let isLocal = isLocalDestination(action.destinationHash)
                    guard AnnounceFilter.shouldForward(
                        outgoingMode: outgoingMode,
                        sourceMode: sourceMode,
                        isLocalDestination: isLocal
                    ) else {
                        continue
                    }
                }

                do {
                    // E8: Apply IFAC per-interface before transmitting
                    let transmitData = applyIFAC(raw: encoded, interfaceId: id)
                    try await interface.send(transmitData)

                    // C14: Update announce bandwidth tracking
                    let bitrate = interface.config.bitrate
                    if bitrate > 0 {
                        let txTime = Double(encoded.count * 8) / Double(bitrate)
                        let waitTime = txTime / interface.config.announceCap
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

    }

    /// E5: Drain each interface's deferred announce queue, one entry per
    /// per-interface cap interval.
    ///
    /// This mirrors RNS `Interface.process_announce_queue` (Interface.py:323-358),
    /// which is a SEPARATE, Timer-driven mechanism from the announce-table
    /// retransmit job (Transport.jobs()): a forwarded announce that hits the
    /// per-interface `announce_cap` is parked in `announce_queue` and drained one
    /// at a time, min-hop first then oldest arrival, each drain re-arming the
    /// `announce_allowed_at` spacing. The swift jobloop calls this every
    /// `job_interval` (0.25s) so the queue makes progress even on passes with no
    /// newly-due announce-table entries — the earlier coupling (draining only
    /// inside `processAnnounceRetransmissions`, behind its no-due-actions early
    /// return) left queued announces stuck until the next due retransmit.
    func processAnnounceQueues() async {
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
                    let transmitData = applyIFAC(raw: entry.encoded, interfaceId: id)
                    try await interfaces[id]?.send(transmitData)
                    let bitrate = interfaces[id]?.config.bitrate ?? 0
                    if bitrate > 0 {
                        let txTime = Double(entry.encoded.count * 8) / Double(bitrate)
                        let cap = interfaces[id]?.config.announceCap ?? TransportConstants.ANNOUNCE_CAP
                        announceAllowedAt[id] = now.addingTimeInterval(txTime / cap)
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
    /// The retransmission loop runs every 0.25s (RNS job_interval), so gate this
    /// heavier sweep on every 20th pass (20 * 0.25s = 5s).
    private func periodicTableCleanup() async {
        tableCullCounter += 1
        guard tableCullCounter % 20 == 0 else { return }
        // Mirror python Transport.jobs() (Transport.py:778-785): cull paths that have
        // expired OR whose attached interface is no longer present. Keeping the
        // interface-absent cull is correct — the BLE boot/transient path-loss is fixed
        // at the right layer (per-peer interface lifecycle: grace-period detach + reuse,
        // matching ble-reticulum), not by weakening this sweep.
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
    /// Ticks every `job_interval` (0.25s), matching RNS `Transport.jobloop()`
    /// (Transport.py:500-503, `sleep(Transport.job_interval)` with
    /// `job_interval = 0.250`). The fast tick drives the announce-queue cap drain
    /// and table culls; the announce-table retransmit branch itself is rate-limited
    /// internally to `ANNOUNCES_CHECK_INTERVAL` (1.0s). The heavier table-cull is
    /// kept on its ~5s budget via `periodicTableCleanup`'s internal counter.
    public func startRetransmissionLoop() {
        guard retransmissionTask == nil else { return }
        // Anchor the announces_check_interval phase deterministically at loop start.
        //
        // PORT DEVIATION (documented in port-deviations.md): RNS keeps
        // `announces_last_checked` process-global on the singleton Transport
        // (Transport.py:181), so a long-lived process phases the once-per-second
        // announce sweep arbitrarily relative to any given heard announce. The swift
        // bridge instead builds a FRESH Transport per behavioral handle, so the phase
        // would otherwise re-anchor every test and race the sweep against a test's
        // sub-second drain. We back-date the anchor by FIRST so the first sweep lands
        // ~0.75s after start — comfortably inside a forwarded announce's [0,0.5]s due
        // window-plus-margin yet before a 1.0s rebroadcast-drain, and after the
        // sub-0.5s windows of the last-hop/forwarding tests. Steady-state cadence is
        // unchanged at exactly ANNOUNCES_CHECK_INTERVAL thereafter.
        let firstSweepDelay: TimeInterval = 0.75
        announcesLastChecked = Date().addingTimeInterval(firstSweepDelay - TransportConstants.ANNOUNCES_CHECK_INTERVAL)
        retransmissionTask = Task { [weak self] in
            // Mirror RNS `jobloop()` (Transport.py:500-503): run jobs() FIRST, then
            // sleep job_interval, so the cull/queue maintenance starts promptly
            // rather than after one idle interval.
            var firstPass = true
            while !Task.isCancelled {
                if !firstPass {
                    try? await Task.sleep(for: .milliseconds(250))
                }
                firstPass = false
                guard let self = self else { break }
                await self.processAnnounceRetransmissions()
                await self.processAnnounceQueues()
                await self.cleanupDiscoveryPathRequests()
                await self.cullTransportTables()
                await self.periodicTableCleanup()
            }
        }
    }

    /// Run a single announce-retransmission pass synchronously.
    ///
    /// Exposes the otherwise-private `processAnnounceRetransmissions()` (the
    /// announce branch of RNS jobs(), Transport.py:573-636) so a deterministic
    /// jobs() pass can be driven without the 1-second timer. Paired with
    /// `cullTransportTables()` this mirrors a full forced jobs() run.
    public func runAnnounceRetransmissions() async {
        // force == true bypasses the announces_check_interval gate, mirroring the
        // reference force-cull which zeroes announces_last_checked before jobs().
        await processAnnounceRetransmissions(force: true)
        // Drain any announces the forced pass parked behind the per-interface cap,
        // so a single force-cull makes progress on the queue without waiting for
        // the next jobloop tick.
        await processAnnounceQueues()
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
        // Wrap the legacy no-arg callback into the proof-carrying storage form,
        // discarding the proof bytes. Keeps existing call sites unchanged.
        registerReceipt(hash: hash, timeout: timeout) { _ in await callback() }
    }

    /// E13 (proof-carrying): register a receipt whose callback receives the matched
    /// PROOF packet's bytes (`ReceivedProofPacket`), or `nil` if unavailable.
    ///
    /// Additive overload of `registerReceipt(hash:timeout:callback:)` that surfaces
    /// `proof_data`/`proof_raw` (RNS `receipt.proof_packet`, RNS/Packet.py:498-537)
    /// for callers that need to classify the proof as IMPLICIT (64 B) vs EXPLICIT
    /// (96 B). The no-arg overload above wraps onto this same storage.
    ///
    /// - Parameters:
    ///   - hash: 16-byte truncated packet hash to match
    ///   - timeout: Expiry time in seconds (default 300)
    ///   - proofCallback: Async callback invoked with the received PROOF bytes
    public func registerReceipt(hash: Data, timeout: TimeInterval = 300, proofCallback: @escaping @Sendable (ReceivedProofPacket?) async -> Void) {
        if receipts.count >= maxReceipts { receipts.removeFirst() }
        receipts.append((hash: hash, callback: proofCallback, timeout: Date().addingTimeInterval(timeout)))
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

    // MARK: - External Announce Handlers (RNS register_announce_handler)

    /// `Transport.register_announce_handler(handler)` (Transport.py:2465-2477).
    ///
    /// RNS only registers a handler that HAS an `aspect_filter` attribute
    /// (`if hasattr(handler, "aspect_filter")`); the swift port models that guard
    /// via `handler.hasAspectFilter`. A handler without an aspect filter is NOT
    /// registered and the call returns `false` (no observer is wired). The handler
    /// is retained for the dispatch loop until `deregisterAnnounceHandler`.
    ///
    /// - Returns: `true` if the handler was registered (had an aspect filter).
    @discardableResult
    public func registerAnnounceHandler(_ handler: AnnounceHandlerProtocol) -> Bool {
        // RNS Transport.py:2476-2477 — guard on hasattr(handler, "aspect_filter").
        guard handler.hasAspectFilter else { return false }
        announceHandlers.append(handler)
        return true
    }

    /// `Transport.deregister_announce_handler(handler)` (Transport.py:2481-2489):
    /// remove every registration of `handler` by identity.
    public func deregisterAnnounceHandler(_ handler: AnnounceHandlerProtocol) {
        announceHandlers.removeAll { $0 === handler }
    }

    /// Number of currently-registered external announce handlers (observability).
    public var announceHandlerCount: Int {
        announceHandlers.count
    }

    /// Dispatch an accepted announce to every externally-registered handler,
    /// faithfully porting the RNS inbound dispatch loop (Transport.py:2034-2086).
    ///
    /// For each handler:
    ///   1. recall the announced identity / app_data from the process-global
    ///      `known_destinations` populated by `AnnounceHandler.process`'s
    ///      unconditional `Identity.remember` (Transport.py:2037,2058);
    ///   2. evaluate the aspect filter — `aspectFilter == nil` matches all,
    ///      otherwise `Destination.hash_from_name_and_identity(aspectFilter,
    ///      announcedIdentity) == destinationHash` (Transport.py:2040-2047);
    ///   3. apply the PATH_RESPONSE delivery gate — a PATH_RESPONSE-context
    ///      announce is delivered only to handlers with `receivePathResponses`
    ///      (Transport.py:2049-2053);
    ///   4. select the callback arity (3/4/5) — 4+ additionally receive
    ///      `announce_packet_hash = packet.packet_hash`, 5 additionally receive
    ///      `is_path_response` (Transport.py:2055-2069);
    ///   5. isolate exceptions per-handler so a raising handler cannot block a
    ///      later one (Transport.py:2083-2086).
    ///
    /// RNS spawns a daemon thread per delivery; the swift port runs the recording
    /// synchronously inside the actor (observably equivalent and race-free for the
    /// poll-based conformance tests — see port-deviations.md).
    private func dispatchAnnounceToHandlers(packet: Packet, destinationHash: Data) async {
        guard !announceHandlers.isEmpty else { return }

        // RNS Transport.py:2037 — announce_identity = Identity.recall(dest, _no_use=True)
        let announcedIdentity = Identity.recall(destinationHash)
        // RNS Transport.py:2058 — app_data = Identity.recall_app_data(dest, _no_use=True)
        let appData = Identity.recallAppData(destinationHash)
        // RNS Transport.py:2061 — announce_packet_hash = packet.packet_hash
        let announcePacketHash = packet.getFullHash()
        // RNS Transport.py:2050 — packet.context == RNS.Packet.PATH_RESPONSE
        let isPathResponse = packet.context == PacketContext.PATH_RESPONSE

        for handler in announceHandlers {
            do {
                // RNS Transport.py:2040-2047 — aspect_filter match.
                var executeCallback = false
                if handler.aspectFilter == nil {
                    executeCallback = true
                } else if let filter = handler.aspectFilter,
                          let expectedHash = announceHandlerExpectedHash(
                              aspectFilter: filter, identity: announcedIdentity
                          ),
                          expectedHash == destinationHash {
                    executeCallback = true
                }

                // RNS Transport.py:2049-2053 — PATH_RESPONSE delivery gate.
                if isPathResponse && !handler.receivePathResponses {
                    executeCallback = false
                }

                guard executeCallback else { continue }

                // RNS Transport.py:2055-2069 — arity-selected delivery.
                switch handler.callbackParameterCount {
                case 3:
                    try handler.receivedAnnounce(
                        destinationHash: destinationHash,
                        announcedIdentity: announcedIdentity,
                        appData: appData,
                        announcePacketHash: nil,
                        isPathResponse: nil
                    )
                case 4:
                    try handler.receivedAnnounce(
                        destinationHash: destinationHash,
                        announcedIdentity: announcedIdentity,
                        appData: appData,
                        announcePacketHash: announcePacketHash,
                        isPathResponse: nil
                    )
                case 5:
                    try handler.receivedAnnounce(
                        destinationHash: destinationHash,
                        announcedIdentity: announcedIdentity,
                        appData: appData,
                        announcePacketHash: announcePacketHash,
                        isPathResponse: isPathResponse
                    )
                default:
                    // RNS Transport.py:2071 — raise TypeError("Invalid signature ...")
                    logger.error("Announce handler has invalid callback arity \(handler.callbackParameterCount)")
                }
            } catch {
                // RNS Transport.py:2083-2086 — per-handler exception isolation.
                logger.error("Error while processing external announce callback: \(error.localizedDescription)")
            }
        }
    }

    /// `Destination.hash_from_name_and_identity(full_name, identity)`
    /// (Destination.py:139-148): split the dotted aspect filter into
    /// `app_and_aspects_from_name` (`components[0]`, `components[1:]`) then
    /// `Destination.hash(identity, app_name, *aspects)`. Returns nil only when
    /// the announced identity is nil AND the filter targets an identity-bearing
    /// destination (no plausible match), matching RNS where a SINGLE destination
    /// hash never equals the identity-less plain hash.
    private func announceHandlerExpectedHash(aspectFilter: String, identity: Identity?) -> Data? {
        // RNS Destination.app_and_aspects_from_name (Destination.py:133-138):
        // full_name.split(".") — first component is the app name, rest are aspects.
        let components = aspectFilter
            .split(separator: ".", omittingEmptySubsequences: false)
            .map(String.init)
        guard let appName = components.first else { return nil }
        let aspects = Array(components.dropFirst())
        if let identity = identity {
            return Destination.hash(identity: identity, appName: appName, aspects: aspects)
        }
        // RNS hash_from_name_and_identity with identity==None yields the plain
        // (identity-less) hash; it cannot match an identity-bearing destination,
        // so an unrecalled identity simply won't satisfy a non-nil aspect filter.
        return Destination.plainHash(appName: appName, aspects: aspects)
    }

    // MARK: - Packet hashlist observability (RNS Transport.packet_hashlist)

    /// Number of packet hashes currently retained in the dedup hashlist.
    ///
    /// RNS exposes `Transport.packet_hashlist` as a plain attribute; the swift
    /// `PacketHashlist` is an actor held privately here, so this is a category-(a)
    /// observability accessor (the bridge reads the count delta to prove a frame
    /// was accepted and recorded). RNS ref: Transport.py:1469-1480 add_packet_hash.
    public func packetHashlistCount() async -> Int {
        await packetHashlist.count
    }

    /// Whether a given full packet hash is already recorded in the dedup hashlist.
    /// (`PacketHashlist.shouldAccept` returns true for a NEW hash, so membership is
    /// its negation.) RNS ref: Transport.py:1469-1480 packet_hashlist membership.
    public func packetHashlistContains(_ hash: Data) async -> Bool {
        await !packetHashlist.shouldAccept(hash)
    }

    /// Get the announce table for direct access.
    ///
    /// Exposed primarily for conformance bridge observables —
    /// path-response answering logic enqueues cached announces here
    /// for re-transmission. Absence after a path-request is how tests
    /// distinguish "refused to answer" from "normal quiescence".
    public func getAnnounceTable() -> AnnounceTable {
        return announceTable
    }

    // MARK: - Observability for conformance bridge

    /// True if the path table has a route to `destinationHash`.
    public func hasPath(for destinationHash: Data) async -> Bool {
        return await pathTable.hasPath(for: destinationHash)
    }

    /// Hop count to `destinationHash`, or nil if no path is known.
    public func hopsTo(_ destinationHash: Data) async -> UInt8? {
        return await pathTable.lookup(destinationHash: destinationHash)?.hopCount
    }

    /// Full path entry for `destinationHash`, or nil if no path is known.
    public func pathEntry(for destinationHash: Data) async -> PathEntry? {
        return await pathTable.lookup(destinationHash: destinationHash)
    }

    /// True if a pending discovery path request exists for `destinationHash`.
    ///
    /// Exposed for path-discovery conformance tests that assert mode-gated
    /// recursive forwarding fired (or didn't) by observing the
    /// discoveryPathRequests map.
    public func hasDiscoveryPathRequest(for destinationHash: Data) -> Bool {
        return discoveryPathRequests[destinationHash] != nil
    }

    /// Send an unconditional path-request packet, bypassing the throttle
    /// and recent-request guards in `requestPath(for:)`.
    ///
    /// Matches Python `RNS.Transport.request_path` semantics: always emit
    /// a packet on the wire. Tests for the "fresh PR for already-known
    /// destination" path use this to avoid the early-skip guard.
    public func sendPathRequestUnconditional(for destinationHash: Data) async {
        // Force a re-request by clearing the cooldown entry first, but
        // remember the previous timestamp so we can put it back if
        // `requestPath(for:)` returns without writing a fresh one.
        // Otherwise an early-return path inside `requestPath` would
        // permanently strip this destination's throttle slot, letting
        // every subsequent regular path-request bypass the cooldown
        // until something else re-populates it.
        let previous = pathRequestTimestamps.removeValue(forKey: destinationHash)
        await requestPath(for: destinationHash)
        if pathRequestTimestamps[destinationHash] == nil, let previous {
            pathRequestTimestamps[destinationHash] = previous
        }
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

        // Re-route through send(packet:) rather than sendViaPath directly so
        // HEADER_1 packets get the proper convertToHeader2 treatment when the
        // freshly-learned path has hopCount > 1. Calling sendViaPath on a
        // HEADER_1 packet would transmit the wrong header type to the next
        // transport node.
        for packet in packets {
            do {
                try await send(packet: packet)
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

    /// Test hook: synchronously process queued packets for a destination.
    /// Production code flushes the queue as a side effect of recording a new
    /// path (see `recordPath` call sites) — this entry point lets unit tests
    /// exercise the flush behavior without reconstructing the full announce
    /// pipeline.
    internal func testFlushPendingPackets(for destinationHash: Data) async {
        await processPendingPackets(for: destinationHash)
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

        // Register callback for incoming path requests. Capture the
        // receiving interface id from the packet at callback time so the
        // async handler doesn't have to read a racy global — `packet`
        // arrives with `receivingInterface` set to the interface id by
        // `deliverToLocalDestination`, which is stable across concurrent
        // arrivals on different interfaces.
        await callbackManager.registerAsync(destinationHash: pathReqDest.hash) { [weak self] data, packet in
            guard let self = self else { return }
            let recvIface = packet.receivingInterface
            Task {
                await self.handlePathRequest(data: data, receivingInterfaceId: recvIface)
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
    private func handlePathRequest(data: Data, receivingInterfaceId: String? = nil) async {
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
        // Use the per-packet receivingInterfaceId captured by the caller
        // (the registerPathRequestHandler closure reads
        // `packet.receivingInterface` at callback time and passes it
        // through). The previous implementation read a `lastReceivedInterfaceId`
        // global, which races whenever any other packet arrives between
        // the path-request landing and the async handler running — and the
        // hub-routing-isolation test catches exactly that race by bouncing
        // keepalive traffic through a witness peer between asker→hub PR
        // delivery and hub→asker response dispatch.
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

        // E6: Capture interface mode before Task (actor-isolated).
        //
        // The retransmit grace mirrors Python Transport.py:2973-2987 exactly:
        //   - local-client requestor          -> now            (delay 0)
        //   - FULL/other arrival              -> now + GRACE     (0.4s)
        //   - ROAMING arrival                 -> now + GRACE+RG  (1.9s)
        // and crucially NO PATHFINDER_RW random window is added — a path-request
        // answer uses a *fixed* delay, unlike a heard-announce reinsert
        // (Transport.py:1871). The `pathRequestAnswer` flag selects that fixed
        // path in AnnounceTable.insert and sets retries = PATHFINDER_R (2968).
        let isLocalClientRequest = attachedInterfaceId.map { isLocalClientInterface($0) } ?? false
        let isRoaming = attachedInterfaceId.flatMap { getInterfaceMode(for: $0) } == .roaming
        let extraDelay: TimeInterval = isLocalClientRequest
            ? 0
            : Self.PATH_REQUEST_GRACE + (isRoaming ? TransportConstants.PATH_REQUEST_RG : 0)

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
                pathRequestAnswer: true,
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

        // When any interface transitions to connected, fire onInterfaceConnected
        // so the app layer can send announces over the newly-available link.
        // AutoInterface/BLE peers fire `onInterfacePeerSpawned` separately via
        // their onPeerAdded hooks; both fire here too once the peer's child
        // transport reaches .connected. App-side gating decides which trigger
        // is meaningful.
        if case .connected = state {
            Task {
                await self.onInterfaceConnected?(id)
            }
        }
    }

    /// Synchronous public inbound entry, mirroring RNS `Transport.inbound(raw, interface)`.
    ///
    /// `handleReceivedData` (the delegate sink) runs the same IFAC pre-unpack
    /// guards and parse, but dispatches `receive` on a detached `Task` — making
    /// it fire-and-forget, which forces observers (e.g. the conformance bridge's
    /// raw-frame injector) to sleep-and-poll for a deterministic result. This
    /// entry instead `await`s `receive` to completion before returning, so the
    /// caller can immediately observe learned state (`hasPath`, path/announce
    /// tables) without a timing race.
    ///
    /// The IFAC pre-unpack drop guards live in `validateIFAC`
    /// (RNS/Transport.py:1398-1447): on an IFAC-less interface a frame carrying
    /// the IFAC flag is dropped; on an IFAC interface a frame missing the flag,
    /// or shorter than `2 + ifac_size + 1`, is dropped; and a frame that fails
    /// the recomputed-IFAC check is dropped.
    ///
    /// - Parameters:
    ///   - frame: Raw wire bytes as received off the interface (IFAC-masked or not).
    ///   - interfaceId: ID of the receiving interface.
    /// - Returns: `true` if the frame passed IFAC validation, parsed into a
    ///   packet, and was handed to the inbound pipeline; `false` if it was
    ///   dropped by an IFAC pre-unpack guard or failed to parse.
    /// - Python reference: RNS/Transport.py:1387-1447 (inbound IFAC pre-unpack guards).
    @discardableResult
    public func inbound(frame: Data, interface interfaceId: String) async -> Bool {
        // Short-packet pre-unpack guard. RNS gates the whole IFAC/parse block on
        // `if len(raw) > 2: ... else: return` (RNS/Transport.py:1397), dropping any
        // frame too short to carry a 2-byte header + payload before it ever reaches
        // validateIFAC (which only enforces the >2+ifac_size min-length on the
        // IFAC-configured path).
        guard frame.count > 2 else {
            logger.debug("inbound: short-packet guard dropped \(frame.count) bytes from \(interfaceId)")
            return false
        }

        // IFAC pre-unpack drop guards (flag-on-open, flag-missing, min-length,
        // IFAC-mismatch). validateIFAC returns nil for any dropped frame and the
        // IFAC-stripped, unmasked bytes otherwise.
        guard let validated = validateIFAC(raw: frame, interfaceId: interfaceId) else {
            logger.debug("inbound: IFAC pre-unpack guard dropped \(frame.count) bytes from \(interfaceId)")
            return false
        }

        let packet: Packet
        do {
            packet = try Packet(from: validated)
        } catch {
            logger.debug("inbound: failed to parse \(validated.count) bytes from \(interfaceId): \(error.localizedDescription)")
            return false
        }

        // Run the full inbound pipeline to completion (announce learning,
        // transport relay, local delivery) before returning — unlike
        // handleReceivedData which spawns a detached Task.
        await receive(packet: packet, from: interfaceId)
        return true
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

    public func interface(id: String, didChangeState state: InterfaceState) {
        guard let transport = transport else { return }
        Task {
            await transport.handleInterfaceStateChange(id: id, state: state)
        }
    }

    public func interface(id: String, didReceivePacket data: Data) {
        guard let transport = transport else { return }
        Task {
            await transport.handleReceivedData(data: data, from: id)
        }
    }

    public func interface(id: String, didFailWithError error: Error) {
        guard let transport = transport else { return }
        Task {
            await transport.handleInterfaceError(id: id, error: error)
        }
    }
}
