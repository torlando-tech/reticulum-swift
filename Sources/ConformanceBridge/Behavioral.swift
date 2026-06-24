// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Behavioral.swift
//  ConformanceBridge
//
//  Implements the behavioral_* bridge commands used by
//  reticulum-conformance's tests/behavioral/* to drive ReticulumTransport
//  through mock interfaces, injecting raw bytes on the receive side and
//  draining raw bytes from the send side.
//
//  Protocol reference: reticulum-conformance/reference/behavioral_transport.py
//

import CryptoKit
import Foundation
import ReticulumSwift

// MARK: - Mock interface

/// NetworkInterface whose send() buffers packets and inject() fires the
/// delegate. No real I/O.
final class BehavioralMockInterface: NetworkInterface, @unchecked Sendable {
    let id: String
    let config: InterfaceConfig

    // Mode constrains AnnounceFilter decisions. Kept nonisolated(unsafe)
    // for the same reason other test mocks use it — bridge commands are
    // dispatched serially by the readLine loop.
    nonisolated(unsafe) var state: InterfaceState = .connected
    nonisolated(unsafe) private var _sent: [Data] = []
    nonisolated(unsafe) private var _delegate: InterfaceDelegate?
    private let lock = NSLock()

    init(id: String, name: String, mode: InterfaceMode, mtu: Int,
         bitrate: Int? = nil, announceCap: Double? = nil,
         ifacKey: Data? = nil, ifacSize: Int = 0,
         announceRateTarget: TimeInterval? = nil,
         announceRateGrace: Int = 0,
         announceRatePenalty: TimeInterval = 0) {
        self.id = id
        self.config = InterfaceConfig(
            id: id,
            name: name,
            type: .tcp,
            enabled: true,
            mode: mode,
            host: "mock",
            port: 0,
            // Per-interface announce-rate knobs (RNS Interface.announce_rate_*)
            // so the production inbound rate limiter (isRateBlocked) runs and the
            // announce_rate_table becomes observable via read_announce_rate.
            announceRateTarget: announceRateTarget,
            announceRateGrace: announceRateGrace,
            announceRatePenalty: announceRatePenalty,
            // Mirror the reference mock (behavioral_transport.py:173 `self.bitrate =
            // 10_000_000 if bitrate is None else int(bitrate)`): a default 10 Mbit/s
            // link so the announce_cap egress spacing `(len*8/bitrate)/announce_cap`
            // is negligible unless a test deliberately lowers bitrate / announce_cap.
            // (The previous mtu*8 default made the cap ~15s and silently swallowed
            // every forwarded announce after the first within a test's drain window.)
            bitrate: bitrate ?? 10_000_000,
            announceCap: announceCap ?? TransportConstants.ANNOUNCE_CAP,
            // IFAC (Interface Access Codes): when ifac_netname/ifac_netkey were
            // supplied to behavioral_attach_mock_interface the 64-byte HKDF key
            // and access-code size ride on the config so transport.addInterface
            // caches the IFAC signing seed (ReticulumTransport.swift:467-469) and
            // the inbound IFAC gate / applyIFAC become live for this mock.
            ifacSize: ifacSize,
            ifacKey: ifacKey
        )
    }

    // NetworkInterface

    func connect() async throws {}
    func disconnect() async {}

    func send(_ data: Data) async throws {
        lock.lock(); defer { lock.unlock() }
        _sent.append(data)
    }

    func setDelegate(_ delegate: InterfaceDelegate) async {
        lock.lock(); defer { lock.unlock() }
        _delegate = delegate
    }

    // Test harness hooks

    /// Fire the delegate's `didReceivePacket` as if `raw` arrived on the wire.
    ///
    /// This is intentionally fire-and-forget: `TransportDelegateWrapper.interface`
    /// spawns a `Task { await transport.handleReceivedData(...) }` to cross back
    /// into the actor, so packet processing happens asynchronously even on return.
    /// Behavioral tests sleep between inject and drain_tx (see reference impl's
    /// `behavioral_transport.py` — PATHFINDER_RW + job-loop window) to let that
    /// Task run. A synchronous inject→drain barrier would either require
    /// awaiting on the actor (which negates the point of a synchronous bridge
    /// command) or reaching into Transport's internal job loop, which would
    /// couple the bridge to Transport-private scheduling.
    func inject(_ raw: Data) {
        let d: InterfaceDelegate?
        lock.lock()
        d = _delegate
        lock.unlock()
        d?.interface(id: id, didReceivePacket: raw)
    }

    func drainTx() -> [Data] {
        lock.lock(); defer { lock.unlock() }
        let out = _sent
        _sent = []
        return out
    }
}

// MARK: - Instance registry

/// State for a single behavioral_start handle.
///
/// `interfaces` is serialized by a dedicated lock rather than relying on the
/// main readLine-loop's dispatch ordering. Bridge commands happen on that
/// loop but `startRetransmissionLoop` spins a background Task on the actor
/// that can race here if future changes move interface reads off the I/O
/// thread.
final class BehavioralInstance: @unchecked Sendable {
    let transport: ReticulumTransport
    let identity: Identity
    private var _interfaces: [String: BehavioralMockInterface] = [:]
    private let interfacesLock = NSLock()

    init(transport: ReticulumTransport, identity: Identity) {
        self.transport = transport
        self.identity = identity
    }

    func setInterface(_ iface: BehavioralMockInterface, forId id: String) {
        interfacesLock.lock(); defer { interfacesLock.unlock() }
        _interfaces[id] = iface
    }

    func interface(forId id: String) -> BehavioralMockInterface? {
        interfacesLock.lock(); defer { interfacesLock.unlock() }
        return _interfaces[id]
    }

    func interfaceIds() -> [String] {
        interfacesLock.lock(); defer { interfacesLock.unlock() }
        return Array(_interfaces.keys)
    }
}

/// Serialized access to the instance map. Bridge commands arrive serially
/// but behavioral_start spawns a background retransmission Task on the
/// transport, so the dictionary itself still needs locking.
// internal (not private) so the per-cluster behavioral sub-handlers in
// Behavioral+*.swift can share this registry. The dispatch chain in
// handleBehavioralCommand's default case routes unmatched behavioral_*
// commands into those sub-handlers (see Ext+Dispatch.swift).
let behavioralLock = NSLock()
nonisolated(unsafe) var behavioralInstances: [String: BehavioralInstance] = [:]

/// Fetch a started behavioral instance by handle, or throw. Shared by the
/// per-cluster behavioral sub-handlers.
func requireBehavioralInstance(_ handle: String) throws -> BehavioralInstance {
    behavioralLock.lock(); defer { behavioralLock.unlock() }
    guard let inst = behavioralInstances[handle] else {
        throw BridgeError.invalidData("Unknown behavioral handle: \(handle)")
    }
    return inst
}

// MARK: - Helpers

private func parseInterfaceMode(_ raw: String) -> InterfaceMode {
    switch raw.uppercased() {
    case "FULL": return .full
    case "GATEWAY": return .gateway
    case "AP", "ACCESS_POINT", "ACCESSPOINT": return .accessPoint
    case "ROAMING": return .roaming
    case "BOUNDARY": return .boundary
    case "POINT_TO_POINT", "POINTTOPOINT", "P2P": return .pointToPoint
    default: return .full
    }
}

/// Maximum wall-clock wait for any blockingAsync operation. Bridge commands
/// should complete within a couple of seconds; anything longer indicates a
/// hung actor (e.g. startRetransmissionLoop deadlocking). Throw rather than
/// block indefinitely so a flaky Transport bug doesn't turn into a wedged
/// conformance runner that has to be SIGKILLed.
private let blockingAsyncTimeout: DispatchTimeInterval = .seconds(30)

/// Run an async operation to completion from a synchronous context.
/// Bridge commands are dispatched synchronously by main.swift's readLine
/// loop, but ReticulumTransport is an actor — this is the bridge between
/// the two worlds. Only used on the bridge's I/O thread.
func blockingAsync<T>(_ op: @Sendable @escaping () async throws -> T) throws -> T {
    let sem = DispatchSemaphore(value: 0)
    let box = ResultBox<T>()
    Task {
        do {
            let value = try await op()
            box.set(.success(value))
        } catch {
            box.set(.failure(error))
        }
        sem.signal()
    }
    switch sem.wait(timeout: .now() + blockingAsyncTimeout) {
    case .success:
        return try box.get()
    case .timedOut:
        throw BridgeError.invalidData("blockingAsync timed out after \(blockingAsyncTimeout) — bridge actor likely hung")
    }
}

private final class ResultBox<T>: @unchecked Sendable {
    private var value: Swift.Result<T, Error>?
    private let lock = NSLock()
    func set(_ v: Swift.Result<T, Error>) { lock.lock(); value = v; lock.unlock() }
    func get() throws -> T {
        lock.lock(); defer { lock.unlock() }
        guard let value else {
            throw BridgeError.invalidData("ResultBox.get called before set — async op did not signal")
        }
        return try value.get()
    }
}

// MARK: - Command dispatch

func handleBehavioralCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result {
    switch command {

    case "behavioral_start":
        // enable_transport defaults to true per the reference impl.
        let enableTransport = getBoolOptional(p, "enable_transport") ?? true
        let seedHex = getHexOptional(p, "identity_seed")

        let identity: Identity
        if let seed = seedHex {
            // seed is already hex-decoded bytes (getHexOptional decodes the
            // 128-char hex string). We check the decoded byte count (64 =
            // 32-byte encryption seed + 32-byte signing seed).
            //
            // This matches the Python reference (behavioral_transport.py
            // cmd_behavioral_start): `seed = bytes.fromhex(identity_seed_hex);
            // if len(seed) != 64: raise ValueError(...)`.
            guard seed.count == 64 else {
                throw BridgeError.invalidData(
                    "identity_seed must decode to 64 bytes (32 encryption + 32 signing) — got \(seed.count)-byte decoded value from hex input"
                )
            }
            identity = try Identity(privateKeyBytes: seed)
        } else {
            identity = Identity()
        }

        let pathTable = PathTable()  // in-memory, no sqlite file
        let transport = ReticulumTransport(pathTable: pathTable)

        try blockingAsync {
            await transport.setTransportEnabled(enableTransport, identity: identity)
            await transport.startRetransmissionLoop()
            // Register the RNS `rnstransport.path.request` callback so this
            // behavioral peer answers injected path-request packets with cached
            // announces (and forwards unknown-destination PRs). Without this the
            // PLAIN `rnstransport/path/request` destination is never registered,
            // so `deliverToLocalDestination` drops every injected PR packet and
            // tests asserting on PR behaviour (test_path_request_tag_dedup,
            // test_path_request_answer_grace_delays, ...) see {'found': False}.
            // Mirrors wire_start_tcp_server (WireTcp.swift:471) and PipePeer.
            await transport.registerPathRequestHandler()
            // Register the RNS `rnstransport.tunnel.synthesize` control destination
            // so injected tunnel-synthesize packets reach the validate/establish
            // handler (Transport.py:247-250 -> tunnel_synthesize_handler ->
            // handle_tunnel). Without this the PLAIN control destination is never
            // recognized and behavioral_read_tunnels stays empty after a valid
            // synthesize packet is injected (test_tunnels / exact-length-gate).
            await transport.registerTunnelSynthesizeHandler()
        }

        let handle = Data((0..<8).map { _ in UInt8.random(in: 0...255) }).map { String(format: "%02x", $0) }.joined()
        let inst = BehavioralInstance(transport: transport, identity: identity)

        behavioralLock.lock()
        behavioralInstances[handle] = inst
        behavioralLock.unlock()

        return [
            "handle": .string(handle),
            "identity_hash": hex(identity.hash)
        ]

    case "behavioral_stop":
        let handle = try getString(p, "handle")
        behavioralLock.lock()
        let inst = behavioralInstances.removeValue(forKey: handle)
        behavioralLock.unlock()
        guard let inst else { return ["stopped": boolean(false)] }

        let idsToRemove = inst.interfaceIds()
        try blockingAsync {
            for ifaceId in idsToRemove {
                await inst.transport.removeInterface(id: ifaceId)
            }
            await inst.transport.stopRetransmissionLoop()
        }
        return ["stopped": boolean(true)]

    case "behavioral_attach_mock_interface":
        let handle = try getString(p, "handle")
        let name = try getString(p, "name")
        let modeRaw = getStringOptional(p, "mode") ?? "FULL"
        let mtu = getIntOptional(p, "mtu") ?? 500

        behavioralLock.lock()
        let inst = behavioralInstances[handle]
        behavioralLock.unlock()
        guard let inst else {
            throw BridgeError.invalidData("Unknown handle: \(handle)")
        }

        // Optional IFAC (Interface Access Codes) configuration, mirroring
        // RNS._add_interface (Reticulum.py:1060-1078): when ifac_netname and/or
        // ifac_netkey are supplied, derive the 64-byte ifac_key from
        // full_hash(netname)+full_hash(netkey) via HKDF(salt=IFAC_SALT) and use a
        // byte-sized access code (ifac_size param as bytes, else DEFAULT_IFAC_SIZE=16,
        // matching behavioral_transport.py:541-562 `int(ifac_size) if ... else 16`).
        let ifacNetname = getStringOptional(p, "ifac_netname")
        let ifacNetkey = getStringOptional(p, "ifac_netkey")
        var ifacKey: Data? = nil
        var ifacSize = 0
        if ifacNetname != nil || ifacNetkey != nil {
            ifacKey = deriveIfacKey(
                networkName: ifacNetname ?? "",
                passphrase: ifacNetkey ?? ""
            )
            if ifacKey != nil {
                ifacSize = getIntOptional(p, "ifac_size") ?? TransportConstants.DEFAULT_IFAC_SIZE
            }
        }

        // Generate 6 random bytes, use them for both the hex id and the
        // 16-byte truncated-SHA256 interface hash. Hashing the raw bytes
        // keeps the hash stable across hex-decoding boundaries and avoids
        // the earlier bug where Data(ifaceId.utf8) hashed the ASCII form.
        // Per-interface announce-rate knobs (RNS Interface.announce_rate_target /
        // _grace / _penalty). When announce_rate_target is supplied, the
        // production inbound rate limiter runs and populates the announce_rate_table
        // that behavioral_read_announce_rate observes.
        let announceRateTarget = p["announce_rate_target"]?.doubleValue
        let announceRateGrace = getIntOptional(p, "announce_rate_grace") ?? 0
        let announceRatePenalty = p["announce_rate_penalty"]?.doubleValue ?? 0
        // Per-interface announce-egress knobs (RNS Interface.bitrate / announce_cap).
        // When absent the constructor falls back to the reference mock defaults
        // (bitrate 10 Mbit/s, announce_cap = ANNOUNCE_CAP). A test lowers these to
        // widen the announce_cap egress spacing (behavioral_transport.py:163,211-212).
        let bitrate = getIntOptional(p, "bitrate")
        let announceCap = p["announce_cap"]?.doubleValue

        let idBytes = Data((0..<6).map { _ in UInt8.random(in: 0...255) })
        let ifaceId = idBytes.map { String(format: "%02x", $0) }.joined()
        let iface = BehavioralMockInterface(
            id: ifaceId,
            name: name,
            mode: parseInterfaceMode(modeRaw),
            mtu: mtu,
            bitrate: bitrate,
            announceCap: announceCap,
            ifacKey: ifacKey,
            ifacSize: ifacSize,
            announceRateTarget: announceRateTarget,
            announceRateGrace: announceRateGrace,
            announceRatePenalty: announceRatePenalty
        )

        // local_client marks this as a shared-instance client interface
        // (Python Transport.local_client_interfaces). A path request arriving
        // on it is answered immediately (no PATH_REQUEST_GRACE). Mirrors
        // behavioral_transport.py attach_mock_interface(local_client=...).
        let isLocalClient = getBoolOptional(p, "local_client") ?? false

        try blockingAsync {
            // addInterface caches the IFAC signing seed (ifacKey[32..64]) when the
            // config carries a 64-byte ifacKey + non-zero ifacSize, arming the
            // inbound IFAC gate and applyIFAC for this interface.
            try await inst.transport.addInterface(iface)
            if isLocalClient {
                await inst.transport.markLocalClientInterface(id: ifaceId)
            }
        }
        inst.setInterface(iface, forId: ifaceId)

        return [
            "iface_id": .string(ifaceId),
            "interface_hash": hex(Data(SHA256.hash(data: idBytes)).prefix(16)),
            // Reported so attach_ifac_interface can size the access-code field
            // (behavioral_transport.py:570); 0 when no IFAC was configured.
            "ifac_size": num(ifacSize)
        ]

    case "behavioral_inject":
        let handle = try getString(p, "handle")
        let ifaceId = try getString(p, "iface_id")
        let raw = try getHex(p, "raw")

        behavioralLock.lock()
        let inst = behavioralInstances[handle]
        behavioralLock.unlock()
        guard let inst, inst.interface(forId: ifaceId) != nil else {
            throw BridgeError.invalidData("Unknown handle or iface_id")
        }

        // SYNCHRONOUS inject, matching the reference (behavioral_transport.py:589
        // MockInterface.inject -> RNS.Transport.inbound directly). The swift mock's
        // fire-and-forget delegate path (BehavioralMockInterface.inject -> spawned
        // Task) raced reads that follow inject with no sleep (random_blob cap,
        // missing-interface eviction, announce-handler dispatch). inbound(frame:)
        // runs the full pipeline — IFAC gate + parse + receive() to completion +
        // external announce-handler dispatch — before returning, so table/handler
        // state is observable on return. Rebroadcast egress still flows through the
        // async retransmission loop, so drain_tx-based tests are unaffected.
        try blockingAsync {
            _ = await inst.transport.inbound(frame: raw, interface: ifaceId)
        }
        return [:]

    case "behavioral_drain_tx":
        let handle = try getString(p, "handle")
        let ifaceId = try getString(p, "iface_id")

        behavioralLock.lock()
        let inst = behavioralInstances[handle]
        behavioralLock.unlock()
        guard let inst, let iface = inst.interface(forId: ifaceId) else {
            throw BridgeError.invalidData("Unknown handle or iface_id")
        }

        let packets = iface.drainTx()
        return ["packets": .array(packets.map { .string(bytesToHex($0)) })]

    default:
        // Route any behavioral_* command not matched above into the per-cluster
        // behavioral sub-handlers (Behavioral+Announce/Path/Blackhole/Tables.swift).
        // Each returns nil for commands it doesn't own; chain in Ext+Dispatch.swift.
        if let r = try handleBehavioralExtensionCommand(command, p) { return r }
        throw BridgeError.unknownCommand(command)
    }
}
