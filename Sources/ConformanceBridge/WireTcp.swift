// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  WireTcp.swift
//  ConformanceBridge
//
//  Implements the wire_* bridge commands used by
//  reticulum-conformance/tests/wire/*. Unlike the behavioral_* commands
//  (MockInterface, zero-wire), wire_* spins up real Network.framework
//  NWListener/NWConnection pairs so cross-impl tests exercise the full
//  transmit/receive pipeline end-to-end with IFAC applied on the wire.
//
//  Protocol reference: reticulum-conformance/reference/wire_tcp.py and
//  reticulum-kt/conformance-bridge/src/main/kotlin/WireTcp.kt
//
//  Process model: at most ONE wire instance per bridge process (server
//  OR client). The wire_peers pytest fixture spawns two bridges to pair
//  roles. resetWireState() is called at the top of every wire_start_*
//  to guarantee a clean slate.
//

import CryptoKit
import Foundation
import ReticulumSwift

// ACCEPT_APP boundary: an inbound Resource is accepted iff its advertised
// uncompressed data size is <= this many bytes (reference/wire_tcp.py:1212
// _RESOURCE_APP_ACCEPT_MAX_SIZE). Test payloads sit on either side of it.
let wireResourceAppAcceptMaxSize = 4096

// MARK: - Per-wire-handle state

/// State for a wire instance.
///
/// `role` is "server" or "client". Held by strong ref so the Transport
/// and interface stay alive for the duration of the test.
final class WireInstance: @unchecked Sendable {
    let transport: ReticulumTransport
    let identity: Identity
    let role: String
    let port: UInt16
    let serverInterface: TCPServerInterface?
    let clientInterface: TCPInterface?

    // Keep strong references to created destinations so they aren't GC'd
    // between wire_announce/wire_listen and downstream wire_poll_path.
    var destinations: [(Identity, Destination)] = []

    // Per-listener state, keyed by IN destination hash hex.
    var listeners: [String: WireListener] = [:]

    // Outbound links opened by wire_link_open, keyed by link_id hex.
    var outLinks: [String: Link] = [:]

    // Outbound Resources started by wire_resource_send, keyed by a generated
    // resource_id hex. Populated for both wait=True and wait=False sends so
    // wire_resource_cancel can abort a non-blocking transfer mid-flight
    // (RESOURCE_ICL). Mirrors python's inst["out_resources"] registry
    // (reference/wire_tcp.py cmd_wire_resource_send / cmd_wire_resource_cancel).
    var outResources: [String: Resource] = [:]

    // GROUP symmetric Token keys created/loaded by wire_group_create, keyed by
    // the GROUP destination hash hex. Mirrors python wire_tcp.py inst["group_dests"]
    // (cmd_wire_group_create :5286), but stores the raw 64-byte AES-256-CBC Token
    // key rather than a Destination object (reticulum-swift Destination has no
    // GROUP symmetric key slot — the GROUP path is RNS's Token directly, exactly
    // as Ext+Destination.swift destination_group_encrypt does). Backs the sibling
    // wire_group_encrypt / wire_group_decrypt commands.
    var groupKeys: [String: Data] = [:]

    // MARK: Captured reticulum_config posture knobs
    //
    // RNS resolves these once at Reticulum.__init__ / __apply_config time and
    // the wire posture commands (wire_instance_posture / wire_transport_enabled
    // / wire_rpc_authkey) read them straight back off the live RNS objects.
    // reticulum-swift models no `Reticulum` config object, so wire_start_tcp_*
    // captures the config values here for the round-trip. The probe /
    // remote-management DESTINATIONS, by contrast, are genuine library state
    // (registered on the Transport) — these fields only carry the
    // standalone-instance posture flags. See port-deviations.md (Transport
    // probe / remote-management destinations — registration + posture only).

    /// Resolved `enable_transport` posture (RNS.Reticulum.transport_enabled()).
    /// Tri-state at the config layer: omitted -> True (server default), explicit
    /// null -> False (option-ABSENT default-off, Reticulum.py:253/:497-499),
    /// explicit bool -> that value. Reported by wire_instance_posture /
    /// wire_transport_enabled. Decoupled from the INTERNAL routing-enable
    /// (`transport.transportEnabled`), which is kept on so directly-connected
    /// wire peers still answer path requests regardless of posture — RNS keeps
    /// endpoint behaviour irrespective of transport_enabled.
    var enableTransport: Bool = true
    /// `panic_on_interface_error` (Reticulum.py:280 default False, :551-553 knob).
    var panicOnInterfaceError: Bool = false
    /// `use_implicit_proof` -> should_use_implicit_proof() (Reticulum.py:256 default True).
    var useImplicitProof: Bool = true
    /// `respond_to_probes` (Reticulum.py:257 default False); also drives the
    /// real Transport.probe_destination registration.
    var respondToProbes: Bool = false
    /// `enable_remote_management` (Reticulum.py:255 default False); also drives
    /// the real Transport.remote_management_destination registration.
    var remoteManagementEnabled: Bool = false
    /// `remote_management_allowed` ACL, normalised lowercase-hex (32-hex each).
    var remoteManagementAllowed: [String] = []
    /// `blackhole_sources`, validated (16-byte/hex) + deduplicated, lowercase-hex.
    var blackholeSources: [String] = []
    /// `interface_discovery_sources`, validated + deduplicated, lowercase-hex.
    var interfaceDiscoverySources: [String] = []
    /// A VALID custom `rpc_key` (verbatim bytes). nil => no custom key OR a
    /// malformed one => fall back to SHA-256(transport private key)
    /// (Reticulum.py:489-495, :347-348).
    var rpcKey: Data? = nil

    init(
        transport: ReticulumTransport,
        identity: Identity,
        role: String,
        port: UInt16,
        serverInterface: TCPServerInterface? = nil,
        clientInterface: TCPInterface? = nil
    ) {
        self.transport = transport
        self.identity = identity
        self.role = role
        self.port = port
        self.serverInterface = serverInterface
        self.clientInterface = clientInterface
    }
}

/// Per-destination receive buffer for incoming link data + completed resources.
final class WireListener: @unchecked Sendable {
    let destination: Destination
    let identity: Identity
    private let lock = NSLock()
    private var _recvBuffer: [Data] = []
    // Opportunistic SINGLE-DATA addressed directly to this destination (NOT
    // routed through a Link), buffered SEPARATELY from link recv data so
    // wire_opportunistic_poll and wire_link_poll drain distinct surfaces.
    // Mirrors python's per-listener opportunistic_buffer vs recv_buffer split
    // (reference/wire_tcp.py:1312-1313).
    private var _opportunisticBuffer: [Data] = []
    private var _resourceBuffer: [Data] = []
    // Per-link resource hash dedup, matching Kotlin's fix for the
    // double-fire of resourceConcluded. Swift doesn't currently exhibit
    // the same double-fire, but dedup is cheap and keeps behaviour
    // consistent should the upstream pattern change.
    private var _seenResourceHashes: Set<Data> = []

    init(destination: Destination, identity: Identity) {
        self.destination = destination
        self.identity = identity
    }

    func append(packetData: Data) {
        lock.lock(); defer { lock.unlock() }
        _recvBuffer.append(packetData)
    }

    /// Buffer a decrypted opportunistic SINGLE-DATA payload, surfaced by the
    /// destination's packet callback (DATA not routed through a Link).
    /// Mirrors python on_opportunistic_packet (reference/wire_tcp.py:1331-1334).
    func append(opportunisticData: Data) {
        lock.lock(); defer { lock.unlock() }
        _opportunisticBuffer.append(opportunisticData)
    }

    func append(resource: Data, hash: Data?) {
        lock.lock(); defer { lock.unlock() }
        if let h = hash {
            if _seenResourceHashes.contains(h) { return }
            _seenResourceHashes.insert(h)
        }
        _resourceBuffer.append(resource)
    }

    func drainPackets() -> [Data] {
        lock.lock(); defer { lock.unlock() }
        let out = _recvBuffer
        _recvBuffer.removeAll()
        return out
    }

    func drainResources() -> [Data] {
        lock.lock(); defer { lock.unlock() }
        let out = _resourceBuffer
        _resourceBuffer.removeAll()
        return out
    }

    func hasAnyPackets() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !_recvBuffer.isEmpty
    }

    func drainOpportunistic() -> [Data] {
        lock.lock(); defer { lock.unlock() }
        let out = _opportunisticBuffer
        _opportunisticBuffer.removeAll()
        return out
    }

    func hasAnyOpportunistic() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !_opportunisticBuffer.isEmpty
    }

    func hasAnyResources() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !_resourceBuffer.isEmpty
    }
}

// MARK: - Instance registry

// NOTE: visibility is `internal` (no `private`) so the per-cluster wire
// sub-handlers in WireTcp+*.swift can share this single instance registry +
// lock. The dispatch chain in handleWireCommand's default case routes any
// unmatched wire_* command into those sub-handlers (see Ext+Dispatch.swift).
let wireLock = NSLock()
nonisolated(unsafe) var wireInstances: [String: WireInstance] = [:]

/// Generate a fresh, unique handle for `wire_start_*`.
func newHandle() -> String {
    Data((0..<8).map { _ in UInt8.random(in: 0...255) })
        .map { String(format: "%02x", $0) }.joined()
}

/// Tear down all wire state: detach interfaces, stop retransmission,
/// clear handle map. Called at the top of wire_start_* to guarantee
/// each test starts with a clean slate.
func resetWireState() {
    wireLock.lock()
    let stale = Array(wireInstances.values)
    wireInstances.removeAll()
    wireLock.unlock()

    for inst in stale {
        inst.serverInterface?.stop()
        let clientIface = inst.clientInterface
        try? blockingAsync {
            if let c = clientIface { await c.disconnect() }
            await inst.transport.stopRetransmissionLoop()
        }
    }
}

// MARK: - IFAC key derivation

/// Fixed salt constant shared across all Reticulum implementations.
/// Python: RNS.Reticulum.IFAC_SALT (Reticulum.py:152).
///
/// `hexToBytes` is failable now (returns nil on malformed input). The
/// nil-coalesce to empty Data is purely a belt-and-braces against a typo
/// in this literal: a 32-byte mismatch surfaces as IFAC validation
/// failures in the conformance suite rather than a crash on bridge
/// startup. The literal is the canonical Reticulum salt and is verified
/// by the cross-impl IFAC interop tests, so empty data is unreachable
/// in practice.
private let ifacSalt: Data = hexToBytes(
    "adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8"
) ?? Data()

/// Derive the 64-byte IFAC key from a network name and passphrase.
///
/// Matches Python RNS.Reticulum._add_interface (Reticulum.py:810-825):
/// ```
/// ifac_origin = b""
/// if netname: ifac_origin += full_hash(netname)
/// if passphrase: ifac_origin += full_hash(passphrase)
/// ifac_origin_hash = full_hash(ifac_origin)
/// ifac_key = HKDF(length=64, derive_from=ifac_origin_hash,
///                 salt=Reticulum.IFAC_SALT)
/// ```
///
/// Returns nil if both netname and passphrase are empty (no IFAC configured).
func deriveIfacKey(networkName: String, passphrase: String) -> Data? {
    if networkName.isEmpty && passphrase.isEmpty { return nil }
    var ifacOrigin = Data()
    if !networkName.isEmpty {
        ifacOrigin.append(Data(SHA256.hash(data: Data(networkName.utf8))))
    }
    if !passphrase.isEmpty {
        ifacOrigin.append(Data(SHA256.hash(data: Data(passphrase.utf8))))
    }
    let ifacOriginHash = Data(SHA256.hash(data: ifacOrigin))
    return KeyDerivation.deriveKey(
        length: 64,
        inputKeyMaterial: ifacOriginHash,
        salt: ifacSalt
    )
}


// MARK: - enable_transport tri-state parsing

/// Resolve the `enable_transport` knob from raw JSON, mirroring RNS's
/// option-presence semantics (Reticulum.py:253 default False; :497-499 only
/// flips True on an explicit Yes):
///   - key ABSENT entirely -> the conftest's server default (True) — most wire
///     tests never pass the knob and rely on transport being on;
///   - key present as JSON null -> the option-ABSENT-from-config posture: False;
///   - key present as a bool -> that value.
func parseEnableTransport(_ p: [String: JSONValue]) -> Bool {
    guard let v = p["enable_transport"] else { return true }   // omitted -> default on
    switch v {
    case .null: return false                                   // explicit None -> option absent -> off
    case .bool(let b): return b
    default: return true
    }
}

// MARK: - Identity-hash ACL/source-list validation

/// Validate a list of identity-hash hex strings the way RNS's `__apply_config`
/// does at startup (Reticulum.py:575-591): each entry must be exactly
/// TRUNCATED_HASHLENGTH//8 == 16 bytes (32 hex) AND valid hexadecimal, else the
/// start aborts (here: a thrown BridgeError, which the pytest `BridgeError`
/// path expects). Valid entries are DEDUPLICATED preserving first-occurrence
/// order and returned as canonical lowercase hex.
func validateIdentityHashList(_ raw: [String], label: String) throws -> [String] {
    var out: [String] = []
    var seen = Set<Data>()
    for entry in raw {
        guard let bytes = hexToBytes(entry), bytes.count == 16 else {
            throw BridgeError.invalidData(
                "\(label) entry must be a 16-byte (32-hex) identity hash, got '\(entry)'"
            )
        }
        if seen.insert(bytes).inserted {
            out.append(bytesToHex(bytes))
        }
    }
    return out
}

// MARK: - Interface mode parsing

func parseWireInterfaceMode(_ raw: String?) throws -> InterfaceMode {
    guard let raw, !raw.isEmpty else { return .full }
    switch raw.lowercased() {
    case "full": return .full
    case "gateway", "gw": return .gateway
    case "ap", "access_point", "accesspoint": return .accessPoint
    case "roaming": return .roaming
    case "boundary": return .boundary
    case "point_to_point", "pointtopoint", "p2p", "ptp": return .pointToPoint
    default:
        throw BridgeError.invalidData("Unknown interface mode: \(raw)")
    }
}

// MARK: - Free port allocation

/// Pre-allocate a free loopback port by binding then closing.
/// Tiny race window; acceptable for localhost conformance use.
func allocateFreePort() -> UInt16 {
    let sock = socket(AF_INET, SOCK_STREAM, 0)
    guard sock >= 0 else { return 0 }
    defer { close(sock) }

    var reuse: Int32 = 1
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    addr.sin_port = 0
    let size = socklen_t(MemoryLayout<sockaddr_in>.size)

    let bindResult = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(sock, $0, size)
        }
    }
    guard bindResult == 0 else { return 0 }

    var boundAddr = sockaddr_in()
    var boundSize = size
    let nameResult = withUnsafeMutablePointer(to: &boundAddr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            getsockname(sock, $0, &boundSize)
        }
    }
    guard nameResult == 0 else { return 0 }

    return UInt16(bigEndian: boundAddr.sin_port)
}

// MARK: - Command dispatch

func handleWireCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result {
    switch command {

    // MARK: wire_start_tcp_server

    case "wire_start_tcp_server":
        resetWireState()

        let networkName = getStringOptional(p, "network_name") ?? ""
        let passphrase = getStringOptional(p, "passphrase") ?? ""
        let requestedPortInt = getIntOptional(p, "bind_port") ?? 0
        let requestedPort = UInt16(clamping: requestedPortInt)
        let bindPort = requestedPort == 0 ? allocateFreePort() : requestedPort
        guard bindPort != 0 else {
            throw BridgeError.invalidData("Failed to allocate free port")
        }
        let mode = try parseWireInterfaceMode(getStringOptional(p, "mode"))

        // --- reticulum_config knobs (all optional) ---
        // enable_transport tri-state (see parseEnableTransport): the POSTURE
        // value reported back by wire_instance_posture / wire_transport_enabled.
        // The internal routing-enable is kept ON unconditionally below so two
        // directly-connected wire peers still answer path requests regardless of
        // posture (RNS keeps endpoint behaviour irrespective of transport_enabled,
        // Reticulum.py; the internal flag couples Swift's PR/forwarding logic).
        let enableTransport = parseEnableTransport(p)
        let panicOnInterfaceError = getBoolOptional(p, "panic_on_interface_error") ?? false
        let respondToProbes = getBoolOptional(p, "respond_to_probes") ?? false
        // should_use_implicit_proof defaults True (Reticulum.py:256).
        let useImplicitProof = getBoolOptional(p, "use_implicit_proof") ?? true
        let enableRemoteManagement = getBoolOptional(p, "enable_remote_management") ?? false
        // Validate ACL / source lists up front so a malformed entry aborts the
        // start with a BridgeError BEFORE any interface/Transport is built —
        // matching RNS's startup ValueError (Reticulum.py:532-536/:575-591).
        let remoteManagementAllowed = try validateIdentityHashList(
            getStringArray(p, "remote_management_allowed"), label: "remote_management_allowed"
        )
        let blackholeSources = try validateIdentityHashList(
            getStringArray(p, "blackhole_sources"), label: "blackhole_sources"
        )
        let interfaceDiscoverySources = try validateIdentityHashList(
            getStringArray(p, "interface_discovery_sources"), label: "interface_discovery_sources"
        )
        // rpc_key: a VALID hex key is honoured verbatim; a malformed one falls
        // back to the SHA-256(private key) default (Reticulum.py:489-495). Capture
        // the parsed bytes (nil => fall back) for wire_rpc_authkey.
        let capturedRpcKey: Data? = getStringOptional(p, "rpc_key").flatMap { hexToBytes($0) }
        // fixed_mtu (must be >= Reticulum.MTU, the TCP*Interface init enforces it)
        // and bitrate (effective-bitrate floor applied at read-back) feed the
        // InterfaceConfig so the live interface's derived hwMtu / bitrate round-trip.
        let fixedMtu = getIntOptional(p, "fixed_mtu")
        let bitrate = getIntOptional(p, "bitrate") ?? 0

        let ifacKey = deriveIfacKey(networkName: networkName, passphrase: passphrase)
        // IFAC size: no IFAC configured -> 0 (no validation on the wire); IFAC
        // configured -> resolve the BITS knob via Interface.resolveIfacSize
        // (>=8 -> //8, sub-minimum/absent -> DEFAULT_IFAC_SIZE 16), matching
        // Reticulum.py:719-723 + the DEFAULT_IFAC_SIZE fallback.
        let ifacSize = ifacKey != nil ? Interface.resolveIfacSize(bits: getIntOptional(p, "ifac_size")) : 0

        let identity = Identity()
        let transport = ReticulumTransport(pathTable: PathTable())

        try blockingAsync {
            // Internal routing-enable kept ON regardless of the reported posture
            // (see enableTransport note above) so PR answering keeps working.
            await transport.setTransportEnabled(true, identity: identity)
            await transport.startRetransmissionLoop()
            // Register the RNS `rnstransport.path.request` callback so
            // this peer answers incoming path requests with cached
            // announces and forwards unknown-destination PRs to other
            // interfaces. Without this, every wire test that asserts on
            // PR behaviour (test_roaming_loop_prevention_positive_companion,
            // test_discover_paths_for_mode_gating) fails because Swift's
            // `handlePathRequest` is never invoked. PipePeer already
            // does this at startup for the same reason.
            await transport.registerPathRequestHandler()
            // respond_to_probes / enable_remote_management register REAL IN/SINGLE
            // management destinations under the transport identity (probe ->
            // PROVE_ALL/accepts_links(false); remote.management -> /status + /path
            // ALLOW_LIST handlers bound to the ACL), tracked in mgmt_destinations
            // (+ mgmt_hashes for remote mgmt). Transport.py:396-403 / :252-258.
            if respondToProbes {
                await transport.registerProbeDestination(identity: identity)
            }
            if enableRemoteManagement {
                // ACL already validated above (16-byte) — won't throw here.
                try await transport.registerRemoteManagementDestination(
                    identity: identity,
                    allowed: remoteManagementAllowed.compactMap { hexToBytes($0) }
                )
            }
        }

        // Build the server's InterfaceConfig.
        let ifaceId = "wire-server-\(newHandle())"
        let config = InterfaceConfig(
            id: ifaceId,
            name: "Wire TCP Server",
            type: .tcp,
            enabled: true,
            mode: mode,
            host: "127.0.0.1",
            port: bindPort,
            bitrate: bitrate,
            ifacSize: ifacSize,
            ifacKey: ifacKey,
            fixedMtu: fixedMtu
        )

        let server: TCPServerInterface
        do {
            server = try TCPServerInterface(config: config)
        } catch {
            throw BridgeError.invalidData("TCPServerInterface init failed: \(error)")
        }

        // onClientConnected registers the spawned peer with the Transport
        // so path responses attached to that interface aren't silently
        // dropped. Mirrors Kotlin's WireTcp.kt:198-210.
        //
        // Register synchronously (via blockingAsync) rather than in a
        // fire-and-forget Task: the spawned peer's receive loop starts
        // inside addInterface (via interface.connect()), and any packet
        // arriving before the Transport knows about this interface would
        // be dropped at validateIFAC (interfaceId not in `interfaces` →
        // passthrough of still-masked IFAC bytes → packet parser chokes
        // on the header flag/offset). addInterface handles both
        // `setDelegate(TransportDelegateWrapper)` and `connect()`, so the
        // bridge has nothing else to do here.
        server.onClientConnected = { [weak transport] spawned in
            guard let transport else { return }
            do {
                try blockingAsync {
                    try await transport.addInterface(spawned)
                }
            } catch {
                FileHandle.standardError.write(
                    Data("[WireTcp] Failed to register spawned peer \(spawned.id): \(error)\n".utf8)
                )
            }
        }

        // Start the listener. We deliberately do NOT register the server
        // parent with the Transport — spawned peers are the actual
        // interfaces the Transport broadcasts over. Registering both
        // would double-deliver every HEADER_1 outbound (once via the
        // server's fan-out to peers, once per peer iterated by Transport)
        // and also double-apply IFAC using two different signing seeds,
        // which guarantees the receiving side rejects one of them.
        // Python and Kotlin take the same approach (spawned children are
        // the interfaces of record).
        do {
            try server.start()
        } catch {
            throw BridgeError.invalidData("TCPServerInterface.start failed: \(error)")
        }

        let handle = newHandle()
        let inst = WireInstance(
            transport: transport,
            identity: identity,
            role: "server",
            port: bindPort,
            serverInterface: server
        )
        // Stash the captured reticulum_config posture knobs for the read-back
        // commands (wire_instance_posture / wire_transport_enabled /
        // wire_rpc_authkey). The probe / remote-management DESTINATIONS are
        // already live on the Transport (registered above); these flags carry
        // the standalone-instance posture.
        inst.enableTransport = enableTransport
        inst.panicOnInterfaceError = panicOnInterfaceError
        inst.useImplicitProof = useImplicitProof
        // Propagate the implicit-proof policy to THIS instance's prover transport
        // so the single-packet prove path emits the configured form (implicit
        // signature-only vs explicit packet_hash||signature). Per-instance scoped —
        // see wire_set_proof_implicit (WireTcp+Iface.swift). Defaults true on both.
        try blockingAsync { await inst.transport.setUseImplicitProof(useImplicitProof) }
        inst.respondToProbes = respondToProbes
        inst.remoteManagementEnabled = enableRemoteManagement
        inst.remoteManagementAllowed = remoteManagementAllowed
        inst.blackholeSources = blackholeSources
        inst.interfaceDiscoverySources = interfaceDiscoverySources
        inst.rpcKey = capturedRpcKey
        wireLock.lock()
        wireInstances[handle] = inst
        wireLock.unlock()

        return [
            "handle": .string(handle),
            "port": .int(Int(bindPort)),
            "identity_hash": hex(identity.hash),
            // Echo the resolved transport posture (python parity, wire_tcp.py:714);
            // the conftest records it as `configured_transport_enabled`.
            "transport_enabled": boolean(enableTransport)
        ]

    // MARK: wire_start_tcp_client

    case "wire_start_tcp_client":
        resetWireState()

        let networkName = getStringOptional(p, "network_name") ?? ""
        let passphrase = getStringOptional(p, "passphrase") ?? ""
        let targetHost = try getString(p, "target_host")
        let targetPortInt = try getInt(p, "target_port")
        let targetPort = UInt16(clamping: targetPortInt)
        let mode = try parseWireInterfaceMode(getStringOptional(p, "mode"))
        // fixed_mtu mirrors the server side: both ends of a link must pin the
        // same fixed MTU for the small link SDU to survive negotiation
        // (TCPInterface.py:110-116). Absent -> autoconfigured (8192 for 10 Mbps).
        let fixedMtu = getIntOptional(p, "fixed_mtu")

        let ifacKey = deriveIfacKey(networkName: networkName, passphrase: passphrase)
        let ifacSize = ifacKey != nil ? Interface.resolveIfacSize(bits: getIntOptional(p, "ifac_size")) : 0

        let identity = Identity()
        let transport = ReticulumTransport(pathTable: PathTable())

        try blockingAsync {
            await transport.setTransportEnabled(true, identity: identity)
            await transport.startRetransmissionLoop()
            // Register the RNS `rnstransport.path.request` callback so
            // this peer answers incoming path requests with cached
            // announces and forwards unknown-destination PRs to other
            // interfaces. Without this, every wire test that asserts on
            // PR behaviour (test_roaming_loop_prevention_positive_companion,
            // test_discover_paths_for_mode_gating) fails because Swift's
            // `handlePathRequest` is never invoked. PipePeer already
            // does this at startup for the same reason.
            await transport.registerPathRequestHandler()
        }

        let ifaceId = "wire-client-\(newHandle())"
        let config = InterfaceConfig(
            id: ifaceId,
            name: "Wire TCP Client",
            type: .tcp,
            enabled: true,
            mode: mode,
            host: targetHost,
            port: targetPort,
            ifacSize: ifacSize,
            ifacKey: ifacKey,
            fixedMtu: fixedMtu
        )

        let client: TCPInterface
        do {
            client = try TCPInterface(config: config)
        } catch {
            throw BridgeError.invalidData("TCPInterface init failed: \(error)")
        }

        // addInterface attaches a TransportDelegateWrapper (which forwards
        // inbound packets into handleReceivedData) and calls connect() in
        // one shot — no separate setDelegate / connect wiring needed.
        try blockingAsync {
            try await transport.addInterface(client)
        }

        // Wait for the NWConnection to actually finish its handshake before
        // we return. TCPInterface.connect() kicks off the connection
        // asynchronously and returns immediately, so without a wait the
        // very next wire_announce might send before the wire is up and
        // the bytes would be silently dropped. Poll on TCPInterface.state
        // with a capped deadline rather than sleeping a fixed interval:
        // fast hosts return quickly, slow/loaded CI hosts get the time
        // they need, and the cap prevents a stalled NWConnection from
        // hanging the bridge command loop.
        //
        // If the deadline passes without reaching .connected, throw a
        // clear connect-timeout error rather than returning a handle
        // that points at a broken interface — otherwise every downstream
        // `wire_announce` / `wire_poll_path` would fail opaquely with
        // "path not found" instead of surfacing the real cause.
        let connectDeadline = Date().addingTimeInterval(5.0)
        var clientConnected = false
        while Date() < connectDeadline {
            let ready: Bool = try blockingAsync { await client.state == .connected }
            if ready { clientConnected = true; break }
            Thread.sleep(forTimeInterval: 0.02)
        }
        guard clientConnected else {
            // Best-effort teardown so we don't leak a half-open interface.
            try? blockingAsync {
                let cid = await client.id
                await transport.removeInterface(id: cid)
                await client.disconnect()
            }
            throw BridgeError.invalidData(
                "TCPInterface did not connect to \(targetHost):\(targetPort) within 5s"
            )
        }

        let handle = newHandle()
        let inst = WireInstance(
            transport: transport,
            identity: identity,
            role: "client",
            port: targetPort,
            clientInterface: client
        )
        wireLock.lock()
        wireInstances[handle] = inst
        wireLock.unlock()

        return [
            "handle": .string(handle),
            "identity_hash": hex(identity.hash)
        ]

    // MARK: wire_stop

    case "wire_stop":
        let handle = try getString(p, "handle")
        wireLock.lock()
        let inst = wireInstances.removeValue(forKey: handle)
        wireLock.unlock()
        guard let inst else {
            return ["stopped": boolean(false)]
        }
        inst.serverInterface?.stop()
        let clientIface = inst.clientInterface
        try blockingAsync {
            if let c = clientIface { await c.disconnect() }
            await inst.transport.stopRetransmissionLoop()
        }
        return ["stopped": boolean(true)]

    // MARK: wire_announce

    case "wire_announce":
        let handle = try getString(p, "handle")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let appData = getHexOptional(p, "app_data")
        // enable_ratchets (RNS cmd_wire_announce): grow a per-destination ratchet
        // store BEFORE announcing so the announce carries the current ratchet
        // public key and the destination exposes ratchet observables.
        let enableRatchets = getBoolOptional(p, "enable_ratchets") ?? false

        let inst = try requireInstance(handle)

        let identity = Identity()
        let destination = Destination(
            identity: identity,
            appName: appName,
            aspects: aspects,
            type: .single,
            direction: .in
        )
        if let ad = appData, !ad.isEmpty {
            destination.appData = ad
        }
        try blockingAsync {
            await inst.transport.registerDestination(destination)
        }

        // Destination.enable_ratchets (Destination.py:466-489): leaves count >= 1
        // with a valid current ratchet id. Unique temp store per destination to
        // avoid cross-test contamination / signed-store reload mismatch.
        var ratchetPub: Data? = nil
        if enableRatchets {
            let ratchetStore = FileManager.default.temporaryDirectory
                .appendingPathComponent("rns-swift-dest-ratchets-\(UUID().uuidString)", isDirectory: true).path
            try blockingAsync {
                try await destination.enableRatchets(storagePath: ratchetStore)
            }
            ratchetPub = try blockingAsync { await destination.ratchetManager?.currentRatchetPublicBytes() }
        }

        let announce = Announce(destination: destination, appData: appData, ratchet: ratchetPub)
        let packet: Packet
        do {
            packet = try announce.buildPacket()
        } catch {
            throw BridgeError.invalidData("buildPacket failed: \(error)")
        }

        try blockingAsync {
            try await inst.transport.send(packet: packet)
        }

        inst.destinations.append((identity, destination))

        var announceResult: [String: JSONValue] = [
            "destination_hash": hex(destination.hash),
            "identity_hash": hex(identity.hash)
        ]
        if enableRatchets {
            let ratchetCount = try blockingAsync { await destination.ratchetManager?.count() ?? 0 }
            announceResult["ratchets_enabled"] = boolean(destination.ratchetsEnabled)
            announceResult["ratchet_count"] = .int(ratchetCount)
        }
        return announceResult

    // MARK: wire_poll_path

    case "wire_poll_path":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 5000

        let inst = try requireInstance(handle)

        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while Date() < deadline {
            let found: Bool = try blockingAsync {
                await inst.transport.hasPath(for: destHash)
            }
            if found {
                let hops: Int = try blockingAsync {
                    Int(await inst.transport.hopsTo(destHash) ?? 0)
                }
                return ["found": boolean(true), "hops": .int(hops)]
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return ["found": boolean(false), "hops": .null]

    // MARK: wire_read_path_entry

    case "wire_read_path_entry":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")

        let inst = try requireInstance(handle)

        let entry: PathEntry? = try blockingAsync {
            await inst.transport.pathEntry(for: destHash)
        }
        guard let entry else {
            return ["found": boolean(false)]
        }

        // Map interfaceId back to the human-readable name the test asserts
        // on (e.g., "Wire TCP Server" / "Wire TCP Client"). TCPInterface is
        // an actor, so read its identity via blockingAsync.
        //
        // Server-role instances only register spawned peers with the
        // Transport (see wire_start_tcp_server above) — the parent
        // TCPServerInterface itself is never an interface of record, so
        // entry.interfaceId can only ever match a spawned peer here.
        let ifaceName: JSONValue
        if let server = inst.serverInterface {
            if let peer = server.spawnedPeers.first(where: { $0.id == entry.interfaceId }) {
                ifaceName = .string(peer.config.name)
            } else {
                ifaceName = .null
            }
        } else if let client = inst.clientInterface {
            let clientId: String = try blockingAsync { await client.id }
            let clientName: String = try blockingAsync { await client.config.name }
            ifaceName = (entry.interfaceId == clientId) ? .string(clientName) : .null
        } else {
            ifaceName = .null
        }

        return [
            "found": boolean(true),
            // Python reference bridge normalizes to ms-since-epoch; Kotlin does
            // the same. Match that so cross-impl expires - timestamp arithmetic
            // lines up in the tests.
            "timestamp": .int(Int(entry.timestamp.timeIntervalSince1970 * 1000)),
            "expires": .int(Int(entry.expires.timeIntervalSince1970 * 1000)),
            "hops": .int(Int(entry.hopCount)),
            "next_hop": hex(entry.nextHop ?? Data()),
            "receiving_interface_name": ifaceName
        ]

    // MARK: wire_has_discovery_path_request

    case "wire_has_discovery_path_request":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)
        let found: Bool = try blockingAsync {
            await inst.transport.hasDiscoveryPathRequest(for: destHash)
        }
        return ["found": boolean(found)]

    // MARK: wire_has_announce_table_entry

    case "wire_has_announce_table_entry":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)
        let found: Bool = try blockingAsync {
            await inst.transport.getAnnounceTable().contains(destHash)
        }
        return ["found": boolean(found)]

    // MARK: wire_read_announce_table_timestamp

    case "wire_read_announce_table_timestamp":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)
        let ts: Date? = try blockingAsync {
            await inst.transport.getAnnounceTable().entryTimestamp(destHash)
        }
        guard let ts else {
            return ["found": boolean(false)]
        }
        return [
            "found": boolean(true),
            "timestamp": .int(Int(ts.timeIntervalSince1970 * 1000))
        ]

    // MARK: wire_tx_bytes

    case "wire_tx_bytes":
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)
        var total: UInt64 = 0
        if let server = inst.serverInterface {
            total += server.totalBytesSent
        }
        if let client = inst.clientInterface {
            // TCPInterface.bytesSent is actor-isolated.
            total += try blockingAsync { await client.bytesSent }
        }
        // `Int(clamping:)` saturates at Int.max instead of trapping if a
        // 32-bit consumer ever sees a counter past 2³¹-1. macOS bridge
        // builds are always 64-bit so the saturation branch is
        // unreachable today, but the explicit clamp documents the
        // truncation semantics if `JSONValue.int` ever moves to a
        // narrower platform — and is the standard way to silence the
        // implicit-narrowing concern Greptile flagged.
        return ["tx_bytes": .int(Int(clamping: total))]

    // MARK: wire_read_path_random_hash

    case "wire_read_path_random_hash":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)

        let entry: PathEntry? = try blockingAsync {
            await inst.transport.pathEntry(for: destHash)
        }
        guard let entry else {
            return ["found": boolean(false)]
        }
        // Prefer the most recent random blob seen for this destination —
        // PathEntry stores a history bounded by MAX_RANDOM_BLOBS, and the
        // cached announce layout matches Python's (public_key[0:64] +
        // name_hash[64:74] + random_hash[74:84]).
        let blob = entry.randomBlob
        guard blob.count == 10 else {
            return ["found": boolean(false)]
        }
        return [
            "found": boolean(true),
            "random_hash": hex(blob)
        ]

    // MARK: wire_request_path

    case "wire_request_path":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)
        try blockingAsync {
            await inst.transport.sendPathRequestUnconditional(for: destHash)
        }
        return ["sent": boolean(true)]

    // MARK: wire_set_interface_mode

    case "wire_set_interface_mode":
        let handle = try getString(p, "handle")
        let modeStr = try getString(p, "mode")
        let newMode = try parseWireInterfaceMode(modeStr)

        let inst = try requireInstance(handle)

        if let server = inst.serverInterface {
            server.modeOverride = newMode
            // Kotlin also propagates to spawned children so packets
            // arriving on existing connections observe the new mode
            // immediately, not just on future connections.
            for peer in server.spawnedPeers {
                peer.modeOverride = newMode
            }
        } else if inst.clientInterface != nil {
            // TCPInterface exposes mode via InterfaceConfig and the config
            // is let-bound (immutable). There's currently no runtime
            // override hook — the only way to change a client-side mode
            // is to reconnect with a new config. Surface this so a test
            // that expects runtime mutation fails loudly instead of
            // silently reading the old value.
            throw BridgeError.invalidData(
                "wire_set_interface_mode: TCPInterface mode is immutable; "
                + "the conformance suite only exercises this on server-side "
                + "interfaces. If a test needs client-side runtime mutation, "
                + "add a modeOverride hook to TCPInterface."
            )
        }
        return ["mode": .string(modeStr.lowercased())]

    // MARK: wire_listen

    case "wire_listen":
        let handle = try getString(p, "handle")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        // resource_strategy ('all'|'none'|'app', default 'all'): how an inbound
        // Link accepts incoming Resource advertisements (RNS Link.set_resource_strategy,
        // RNS/Link.py:1087-1098). python cmd_wire_listen validates the same three
        // values and raises on anything else (reference/wire_tcp.py:1261-1265).
        let strategyStr = (getStringOptional(p, "resource_strategy") ?? "all").lowercased()
        let resourceStrategy: ResourceStrategy
        switch strategyStr {
        case "all": resourceStrategy = .acceptAll
        case "none": resourceStrategy = .acceptNone
        case "app": resourceStrategy = .acceptApp
        default:
            throw BridgeError.invalidData(
                "resource_strategy must be 'all', 'none' or 'app' (got \(strategyStr))"
            )
        }
        // enable_ratchets (RNS cmd_wire_listen): same precondition as wire_announce
        // — the IN destination grows a ratchet store before its immediate announce.
        let enableRatchets = getBoolOptional(p, "enable_ratchets") ?? false
        // proof_strategy ('none' default | 'all'): the IN destination's packet-proof
        // strategy (RNS cmd_wire_listen, reference/wire_tcp.py:1267,1292-1298 calls
        // destination.set_proof_strategy). handleRegularData GATES opportunistic
        // SINGLE-DATA auto-proof on destination.proofStrategy
        // (ReticulumTransport.swift:2705-2710), so a receiver must be set to PROVE_ALL
        // to auto-prove (tests/wire/test_opportunistic_proof.py). Default PROVE_NONE
        // is left untouched so the LXMF/Columba opportunistic path is not double-proofed.
        let proofStrategyStr = (getStringOptional(p, "proof_strategy") ?? "none").lowercased()
        // open_channel (default True): whether the link-established hook opens a
        // Channel on each inbound link. Mirrors python cmd_wire_listen
        // (reference/wire_tcp.py:1268-1272): an open channel makes the receiver
        // PROVE inbound CHANNEL-context packets (Link.py:1172), which resolves the
        // sender's PacketReceipt so it stops retransmitting; open_channel=False
        // reproduces a peer with NO channel, where an inbound CHANNEL packet is
        // dropped WITHOUT a proof (Link.py:1166-1167).
        let openChannel = getBoolOptional(p, "open_channel") ?? true

        let inst = try requireInstance(handle)

        let identity = Identity()
        let destination = Destination(
            identity: identity,
            appName: appName,
            aspects: aspects,
            type: .single,
            direction: .in
        )

        // Mirror python's set_proof_strategy mapping exactly: 'all' -> PROVE_ALL,
        // 'none' -> default PROVE_NONE (no-op), anything else raises
        // (reference/wire_tcp.py:1292-1298).
        switch proofStrategyStr {
        case "all":
            try destination.setProofStrategy(Destination.PROVE_ALL)
        case "none":
            break
        default:
            throw BridgeError.invalidData(
                "Unsupported proof_strategy=\(proofStrategyStr); expected 'none' or 'all'"
            )
        }

        let listener = WireListener(destination: destination, identity: identity)

        // Register destination so inbound packets/link requests get routed
        // to it, and attach a link-established callback that wires up the
        // packet + resource callbacks onto each newly-accepted Link.
        try blockingAsync {
            await inst.transport.registerDestination(destination)
            // Opportunistic-DATA callback on the SINGLE destination itself
            // (DATA addressed directly to the destination hash, NOT routed
            // through a Link). Mirrors python's
            // destination.set_packet_callback(on_opportunistic_packet)
            // (reference/wire_tcp.py:1331-1334): the decrypted SINGLE-DATA
            // payload surfaced by handleRegularData's callbackManager.deliver
            // (ReticulumTransport.swift:2678) is buffered in the SEPARATE
            // opportunistic buffer so wire_opportunistic_poll and
            // wire_link_poll drain distinct surfaces
            // (reference/wire_tcp.py:1312-1313,10317-10320). registerDestination
            // above already installed the callback manager, so this never
            // throws callbackManagerNotSet.
            try destination.registerCallback { data, _packet in
                listener.append(opportunisticData: data)
            }
            await inst.transport.registerDestinationLinkCallback(for: destination.hash) { link in
                await link.setPacketCallback { data, _packet in
                    listener.append(packetData: data)
                }
                // Honor the requested resource strategy (RNS/Link.py:1087-1098):
                // .acceptAll accepts every advertisement, .acceptNone drops them
                // silently (no parts flow), .acceptApp consults the callback's
                // resourceAdvertised predicate and sends a RESOURCE_RCL reject on
                // decline. Mirrors python's link.set_resource_strategy(strategy_const)
                // + the app_accept callback (reference/wire_tcp.py:1442-1451).
                await link.setResourceStrategy(resourceStrategy)
                // Resource lifecycle callbacks: the ACCEPT_APP predicate, the
                // bz2-bomb decompression-bound lowering (resourceStarted), and the
                // completed-resource buffering (resourceConcluded).
                let callbacks = WireResourceCallbacks(
                    listener: listener, strategy: resourceStrategy
                )
                await link.setResourceCallbacks(callbacks)
                // Open a Channel on the inbound link when requested (default), so
                // the receiver PROVES inbound CHANNEL-context packets
                // (ReticulumTransport CHANNEL branch / Link.py:1172). Without an
                // open channel the prove is (correctly) skipped (Link.py:1166-1167)
                // and a reference sender retransmits to teardown. Mirrors python
                // cmd_wire_listen's link.get_channel() on link-established
                // (reference/wire_tcp.py:1268-1272).
                if openChannel {
                    let channel = await link.getOrCreateChannel()
                    // Attach a recording handler so the receiver can surface the
                    // channel payloads it delivered (server-role channel_received).
                    // Mirrors python cmd_wire_listen's recorder (wire_tcp.py:1268-1289).
                    let lid = await link.linkId
                    await wireAttachInboundChannelRecorder(
                        handle: handle, linkId: lid, channel: channel
                    )
                }
            }
        }

        // Destination.enable_ratchets (Destination.py:466-489) before the announce,
        // so the announce carries the current ratchet public key.
        var ratchetPub: Data? = nil
        if enableRatchets {
            let ratchetStore = FileManager.default.temporaryDirectory
                .appendingPathComponent("rns-swift-dest-ratchets-\(UUID().uuidString)", isDirectory: true).path
            try blockingAsync {
                try await destination.enableRatchets(storagePath: ratchetStore)
            }
            ratchetPub = try blockingAsync { await destination.ratchetManager?.currentRatchetPublicBytes() }
        }

        // Announce so the sender peer can learn a path to this destination.
        let announce = Announce(destination: destination, ratchet: ratchetPub)
        let packet: Packet
        do {
            packet = try announce.buildPacket()
        } catch {
            throw BridgeError.invalidData("buildPacket for wire_listen announce failed: \(error)")
        }
        try blockingAsync {
            try await inst.transport.send(packet: packet)
        }

        inst.destinations.append((identity, destination))
        inst.listeners[destination.hash.map { String(format: "%02x", $0) }.joined()] = listener

        var listenResult: [String: JSONValue] = [
            "destination_hash": hex(destination.hash),
            "identity_hash": hex(identity.hash),
            "resource_strategy": .string(strategyStr),
            // public_key surfaced for the recall byte-identity asserts (conftest
            // listening_identity); additive, tolerated by older consumers.
            "public_key": hex(identity.publicKeys)
        ]
        if enableRatchets {
            let ratchetCount = try blockingAsync { await destination.ratchetManager?.count() ?? 0 }
            listenResult["ratchets_enabled"] = boolean(destination.ratchetsEnabled)
            listenResult["ratchet_count"] = .int(ratchetCount)
        }
        return listenResult

    // MARK: wire_link_open

    case "wire_link_open":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 10000

        let inst = try requireInstance(handle)

        // Identity comes from the previously-received announce, stashed in
        // the path entry's publicKeys. Swift has no Identity.recall global,
        // so we reconstruct public-key-only from the path table.
        let entry: PathEntry? = try blockingAsync {
            await inst.transport.pathEntry(for: destHash)
        }
        guard let entry, entry.publicKeys.count == 64 else {
            throw BridgeError.invalidData(
                "No path entry for \(destHash.map { String(format: "%02x", $0) }.joined()) "
                + "— ensure wire_listen (on the remote) and wire_poll_path "
                + "(here) completed before wire_link_open"
            )
        }
        let outIdentity: Identity
        do {
            outIdentity = try Identity(publicKeyBytes: entry.publicKeys)
        } catch {
            throw BridgeError.invalidData("Identity from publicKeys failed: \(error)")
        }
        let outDest = Destination(
            identity: outIdentity,
            appName: appName,
            aspects: aspects,
            type: .single,
            direction: .out
        )

        let link: Link = try blockingAsync {
            try await inst.transport.initiateLink(to: outDest, identity: inst.identity)
        }

        // Poll link state until active, bounded by timeoutMs.
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        var linkActive = false
        while Date() < deadline {
            let state: LinkState = try blockingAsync { await link.state }
            if case .active = state {
                linkActive = true
                break
            }
            if case .closed = state {
                throw BridgeError.invalidData(
                    "Link to \(destHash.map { String(format: "%02x", $0) }.joined()) closed before becoming active"
                )
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        guard linkActive else {
            throw BridgeError.invalidData(
                "Link to \(destHash.map { String(format: "%02x", $0) }.joined()) did not become active within \(timeoutMs)ms"
            )
        }

        let linkId: Data = try blockingAsync { await link.linkId }
        let linkIdHex = linkId.map { String(format: "%02x", $0) }.joined()
        inst.outLinks[linkIdHex] = link

        return ["link_id": .string(linkIdHex)]

    // MARK: wire_link_send

    case "wire_link_send":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let payload = try getHex(p, "data")

        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // Link.send mirrors Python's link.send(): encrypts the plaintext
        // with the link's session key, frames a DATA packet addressed to
        // the linkId, and dispatches via the link's sendCallback.
        try blockingAsync {
            try await link.send(payload)
        }
        return ["sent": boolean(true)]

    // MARK: wire_link_poll

    case "wire_link_poll":
        let handle = try getString(p, "handle")
        let destHashHex = try getString(p, "destination_hash")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 5000

        let inst = try requireInstance(handle)
        guard let listener = inst.listeners[destHashHex] else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHashHex)")
        }

        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while Date() < deadline, !listener.hasAnyPackets() {
            Thread.sleep(forTimeInterval: 0.05)
        }
        let out = listener.drainPackets().map { JSONValue.string(bytesToHex($0)) }
        return ["packets": .array(out)]

    // MARK: wire_opportunistic_poll

    case "wire_opportunistic_poll":
        // python: cmd_wire_opportunistic_poll (reference/wire_tcp.py:10308-10349).
        // Receiver-side observable for opportunistic delivery: drains the
        // destination's opportunistic-DATA buffer (DATA addressed directly to
        // the SINGLE destination, NOT routed through a Link) populated by the
        // packet callback registered in wire_listen. Counterpart to the
        // sender-side wire_send_opportunistic. Kept separate from
        // wire_link_poll so a test that opens a Link AND receives opportunistic
        // DATA on the same destination drains each surface unambiguously
        // (reference/wire_tcp.py:10317-10320). Returns {packets:[hex,...]} of
        // the decrypted payloads and clears the buffer.
        let handle = try getString(p, "handle")
        let destHashHex = try getString(p, "destination_hash")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 5000

        let inst = try requireInstance(handle)
        guard let listener = inst.listeners[destHashHex] else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHashHex)")
        }

        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while Date() < deadline, !listener.hasAnyOpportunistic() {
            Thread.sleep(forTimeInterval: 0.05)
        }
        let out = listener.drainOpportunistic().map { JSONValue.string(bytesToHex($0)) }
        return ["packets": .array(out)]

    // MARK: wire_resource_send

    case "wire_resource_send":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let payload = try getHex(p, "data")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 30000
        // metadata (hex) -> packed into the Resource 'x' field + flag bit 5
        // (RNS/Resource.py:260-268); None omits it. python cmd_wire_resource_send
        // passes it straight to RNS.Resource (wire_tcp.py resource_send docstring).
        let metadata = getHexOptional(p, "metadata")
        // wait (default True): when False, start the transfer and return
        // immediately with {started, resource_id, ...} so the caller can abort it
        // mid-flight via wire_resource_cancel — the only way to drive RESOURCE_ICL
        // (reference/wire_tcp.py:1809-1828). A blocking send polls to a terminal
        // state instead.
        let wait = getBoolOptional(p, "wait") ?? true

        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }

        // sendResource returns once the advertisement is sent; we need to
        // wait until the transfer completes (or times out). Poll the
        // resource's state.
        let resource: Resource = try blockingAsync {
            try await link.sendResource(data: payload, metadata: metadata)
        }

        // Generate a resource_id (python secrets.token_hex(8) — 16 hex chars) and
        // retain the outbound Resource so wire_resource_cancel can abort it later.
        // Stored for BOTH wait paths, matching python's inst["out_resources"]
        // (reference/wire_tcp.py cmd_wire_resource_send).
        let resourceId = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
            .map { String(format: "%02x", $0) }.joined()
        inst.outResources[resourceId] = resource

        // Construction-time observables read off the REAL prepared outbound
        // Resource (sendResource has already run __init__ + prepare). These keys
        // mirror the python cmd_wire_resource_send response (total_segments /
        // has_metadata / compressed / original_hash, read off RNS.Resource — never
        // recomputed). total_segments and has_metadata are asserted by
        // test_resource_protocol.py (completeness + metadata_x_flag cases); their
        // prior absence surfaced as KeyError on the python side.
        let sendObservables: [String: WireSendObs] = try blockingAsync {
            let totalSegments = await resource.totalSegments
            let hasMetadata = await resource.metadataSize > 0
            let compressed = await resource.compressed
            let segHash = await resource.hash
            let originalHash = await resource.originalHash ?? segHash
            return [
                "total_segments": .i(totalSegments),
                "has_metadata": .b(hasMetadata),
                "compressed": .b(compressed),
                "original_hash": originalHash.map { WireSendObs.h($0) } ?? .null
            ]
        }

        // Non-blocking send (wait=False): the transfer is running on the link's
        // own tasks; return immediately so the caller can cancel it mid-flight.
        // Mirrors python's {started, resource_id, size, **info} early return
        // (reference/wire_tcp.py:1809-1828).
        if !wait {
            var startedResult: Result = [
                "started": boolean(true),
                "resource_id": .string(resourceId),
                "size": .int(payload.count)
            ]
            for (k, v) in sendObservables { startedResult[k] = wireSendObsToJSON(v) }
            return startedResult
        }

        // Track the most-recent observed state separately from the
        // terminal state. If the poll times out while the resource is
        // still .transferring / .advertised, returning 0 (.none) in
        // `status` would hide the actual stage the transfer got stuck
        // in — report `lastSeen` instead so tests can distinguish
        // "never started" from "stalled mid-transfer".
        //
        // Break on ANY terminal state (state.isTerminal), not just
        // .complete/.failed: an ACCEPT_APP/bomb RESOURCE_RCL lands the sender in
        // .rejected (status 0) and a cancel lands it in .failed/.cancelled — all
        // must conclude the poll promptly instead of spinning to the full
        // timeout (RNS REJECTED conclusion, RNS/Link.py handleResourceReject).
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        var lastSeen: ResourceState = .none
        var terminalState: ResourceState?
        while Date() < deadline {
            let state: ResourceState = try blockingAsync { await resource.state }
            lastSeen = state
            if state.isTerminal {
                terminalState = state
                break
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        let timedOut = terminalState == nil
        let reportedState = terminalState ?? lastSeen
        let success = reportedState == .complete
        var sendResult: Result = [
            "success": boolean(success),
            "status": .int(reportedState.rawValueForBridge),
            "size": .int(payload.count),
            "timed_out": boolean(timedOut),
            "resource_id": .string(resourceId)
        ]
        for (k, v) in sendObservables { sendResult[k] = wireSendObsToJSON(v) }
        return sendResult

    // MARK: wire_resource_poll

    case "wire_resource_poll":
        let handle = try getString(p, "handle")
        let destHashHex = try getString(p, "destination_hash")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 30000

        let inst = try requireInstance(handle)
        guard let listener = inst.listeners[destHashHex] else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHashHex)")
        }

        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while Date() < deadline, !listener.hasAnyResources() {
            Thread.sleep(forTimeInterval: 0.1)
        }
        let out = listener.drainResources().map { JSONValue.string(bytesToHex($0)) }
        return ["resources": .array(out)]

    default:
        // Route any wire_* command not matched above into the per-cluster
        // wire sub-handlers (WireTcp+Link/Resource/Channel/Inject/Send/
        // Identity/Iface.swift). Each returns nil for commands it doesn't own;
        // the chain is defined in handleWireExtensionCommand (Ext+Dispatch.swift).
        if let r = try handleWireExtensionCommand(command, p) { return r }
        throw BridgeError.unknownCommand(command)
    }
}

// MARK: - Helpers

func requireInstance(_ handle: String) throws -> WireInstance {
    wireLock.lock(); defer { wireLock.unlock() }
    guard let inst = wireInstances[handle] else {
        throw BridgeError.invalidData("Unknown handle: \(handle)")
    }
    return inst
}

/// Resource callbacks adapter for buffering completed resources into a
/// WireListener. Lives at module scope because ResourceCallbacks requires
/// AnyObject + Sendable conformance, which nested closures can't express
/// directly.
private final class WireResourceCallbacks: ResourceCallbacks, @unchecked Sendable {
    let listener: WireListener
    let strategy: ResourceStrategy
    init(listener: WireListener, strategy: ResourceStrategy = .acceptAll) {
        self.listener = listener
        self.strategy = strategy
    }

    /// ACCEPT_APP predicate (consulted only under `.acceptApp`, see
    /// Link.receiveResourceAdvertisement gate): accept iff the advertised
    /// uncompressed data size is <= 4096. Mirrors python's app_accept
    /// (reference/wire_tcp.py:1442-1451:
    /// `advertisement.get_data_size() <= _RESOURCE_APP_ACCEPT_MAX_SIZE`). The
    /// inbound `resource` here is built from the advertisement, so its
    /// `totalDataSize` equals `advertisement.dataSize`, which is exactly what
    /// RNS `ResourceAdvertisement.get_data_size()` returns (RNS/Resource.py:1312).
    /// On decline the Link emits a RESOURCE_RCL, landing the sender in REJECTED.
    func resourceAdvertised(_ resource: Resource) async -> Bool {
        let dataSize = await resource.totalDataSize
        return dataSize <= wireResourceAppAcceptMaxSize
    }

    /// Retain every inbound Resource the instant it starts, keyed by this
    /// listener's IN destination hash, so wire_resource_receiver_status can read
    /// its terminal state / receivedMetadata / assembledData / HMU counters after
    /// it concludes. Mirrors the python listener's resource_started hook that
    /// appends an incoming_resources record (wire_tcp.py:1368-1407). Resource is
    /// an actor; Resource.cleanup() keeps assembledData + receivedMetadata in RAM,
    /// so the retained reference stays readable post-conclusion. The observation
    /// registry + reader live in WireTcp+Resource.swift (the W-RESOURCE cluster).
    func resourceStarted(_ resource: Resource) async {
        // Lower the per-inbound-resource decompression bound so the bz2
        // decompression-bomb guard trips cheaply at assemble() time. resourceStarted
        // fires before any part is decompressed, so the bound is in effect when the
        // bounded bz2 decompressor runs (RNS/Resource.py:686-689). Mirrors python's
        // on_resource_started setting resource.max_decompressed_size =
        // _WIRE_RX_MAX_DECOMPRESSED (reference/wire_tcp.py:1368-1384).
        await resource.setMaxDecompressedSize(wireRxMaxDecompressed)
        let destHashHex = listener.destination.hash
            .map { String(format: "%02x", $0) }.joined()
        wireRegisterInboundResource(destinationHashHex: destHashHex, resource)
    }

    func resourceConcluded(_ resource: Resource) async {
        let state = await resource.state
        guard state == .complete else { return }
        guard let data = await resource.assembledData else {
            FileHandle.standardError.write(
                Data("[WireTcp] wire_listen: COMPLETE resource has nil assembledData, dropping\n".utf8)
            )
            return
        }
        let hash = await resource.hash
        listener.append(resource: data, hash: hash)
    }
}

/// Sendable scalar carrier for the construction observables wire_resource_send
/// reads off the prepared outbound Resource inside `blockingAsync` (a
/// `[String: WireSendObs]` is Sendable; the JSONValue helpers are not). Mapped to
/// JSONValue outside the actor hop.
private enum WireSendObs: Sendable {
    case i(Int)
    case b(Bool)
    case h(Data)
    case null
}

private func wireSendObsToJSON(_ v: WireSendObs) -> JSONValue {
    switch v {
    case .i(let x): return .int(x)
    case .b(let x): return .bool(x)
    case .h(let d): return hex(d)
    case .null: return .null
    }
}

// MARK: - State → int helper

private extension ResourceState {
    /// Numeric value for the bridge protocol. Kotlin/Python report an int;
    /// mirror that by mapping enum cases to stable ints matching Python's
    /// RNS.Resource status codes (Resource.py constants).
    var rawValueForBridge: Int {
        switch self {
        case .none: return 0
        case .queued: return 1
        case .advertised: return 2
        case .transferring: return 3
        case .awaitingProof: return 4
        case .assembling: return 5
        case .complete: return 6
        case .failed: return 7
        // RNS REJECTED == NONE == 0; swift `.cancelled` -> RNS FAILED (cancel() sets
        // FAILED); CORRUPT == 0x08 (RNS/Resource.py:143-152). Unified with the other
        // two status mappers.
        case .rejected: return 0
        case .corrupt: return 8
        case .cancelled: return 7
        }
    }
}
