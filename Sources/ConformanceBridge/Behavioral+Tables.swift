// Behavioral+Tables.swift — conformance bridge behavioral sub-handler cluster: B-TABLES (link table, tunnels, detach_interface, force_cull, ifac_mask, inbound_remembered, packet_filter)
//
// Ports from reticulum-conformance reference/behavioral_transport.py. Shares the
// behavioralInstances registry + behavioralLock + requireBehavioralInstance()
// (internal in Behavioral.swift). Returns nil for commands it doesn't own
// (dispatch chain: handleBehavioralExtensionCommand in Ext+Dispatch.swift).
// Keeps python-faithful result keys/values; reconstructs logic inline against the
// real ReticulumTransport + primitives, reporting genuine subsystem gaps rather
// than bailing (see /tmp/bridge_behavioral_spec.md DO-NOT-BAIL rule).
import CryptoKit
import Foundation
import ReticulumSwift

/// Recompute the 16-byte interface hash a mock interface was attached with
/// (SHA256(idBytes).prefix(16), where idBytes == hex-decoded iface_id). Mirrors
/// behavioral_attach_mock_interface's `interface_hash` and the behavioralInterfaceHash
/// helper in Behavioral+Path.swift (kept file-local to avoid cross-file private coupling).
private func behavioralTablesInterfaceHash(forId ifaceId: String) -> Data? {
    guard let idBytes = hexToBytes(ifaceId) else { return nil }
    return Data(Data(SHA256.hash(data: idBytes)).prefix(16))
}

// MARK: - packet_filter reconstruction state
//
// ReticulumTransport's packet_filter gate and its packet_hashlist are
// module-internal (no public accessor), so cmd_behavioral_packet_filter's
// stateful accept-then-replay-drop behaviour is reconstructed here against a
// bridge-local per-handle hashlist. This mirrors RNS Transport.packet_filter +
// add_packet_hash (Transport.py:1334-1384 / :1374) byte-for-byte at the verdict
// level. Guarded by its own lock (never nested inside behavioralLock).
private let behavioralPacketFilterLock = NSLock()
nonisolated(unsafe) private var behavioralPacketFilterHashlists: [String: Set<Data>] = [:]

/// Reconstruction of RNS Transport.packet_filter (Transport.py:1334-1384).
/// `alreadySeen` reports membership in the bridge-local per-handle hashlist
/// (the stand-in for Transport.packet_hashlist / _prev). Returns the accept
/// verdict; the caller applies the add_packet_hash remember step.
private func behavioralPacketFilterVerdict(
    packet: Packet, identityHash: Data, alreadySeen: Bool
) -> Bool {
    // Transport.owner.is_connected_to_shared_instance is always False in the
    // behavioral harness (no shared-master LocalClientInterface), so the
    // "shared instance handles filtering" short-circuit is never taken.

    // Filter packets intended for other transport instances: a HEADER_2
    // (transport-relayed) non-announce packet whose transport_id is not THIS
    // instance's identity hash was relayed toward a different node.
    if let transportId = packet.transportAddress,
       packet.header.packetType != .announce,
       transportId != identityHash {
        return false
    }

    // Context-bypass exemptions accepted BEFORE the hashlist check, so they are
    // never subject to the replay/loop drop.
    switch packet.context {
    case PacketContext.KEEPALIVE, PacketContext.RESOURCE_REQ, PacketContext.RESOURCE_PRF,
         PacketContext.RESOURCE, PacketContext.CACHE_REQUEST, PacketContext.CHANNEL:
        return true
    default:
        break
    }

    // PLAIN / GROUP non-announce TTL ceiling: dropped once wire hops > 1; the
    // corresponding announce of these destination types is always invalid.
    if packet.header.destinationType == .plain || packet.header.destinationType == .group {
        if packet.header.packetType != .announce {
            return packet.header.hopCount <= 1
        }
        return false
    }

    // Hashlist replay/loop drop with the SINGLE-announce carve-out: a novel
    // packet is accepted; a re-seen one is dropped UNLESS it is a SINGLE announce
    // (those carry their own random_blob replay protection).
    if !alreadySeen {
        return true
    }
    if packet.header.packetType == .announce && packet.header.destinationType == .single {
        return true
    }
    return false
}

func handleBehavioralTablesCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    case "behavioral_packet_filter":
        // Run a raw packet through the duplicate/replay filter and report the
        // verdict (Transport.py:669-720 reference). accepted-then-dropped on
        // replay; remember records the hash so the next identical packet drops.
        let handle = try getString(p, "handle")
        let raw = try getHex(p, "raw")
        let remember = getBoolOptional(p, "remember") ?? true
        let inst = try requireBehavioralInstance(handle)

        let packet: Packet
        do {
            packet = try Packet(from: raw)
        } catch {
            // Mirrors python `if not packet.unpack(): raise ValueError(...)`.
            throw BridgeError.invalidData("packet failed to unpack")
        }
        let packetHash = packet.getFullHash()
        let identityHash = inst.identity.hash

        // FORCED DEVIATION: ReticulumTransport.packet_filter / packetHashlist are
        // module-internal — reconstruct the RNS gate inline over a bridge-local
        // per-handle hashlist (see behavioralPacketFilterVerdict above).
        behavioralPacketFilterLock.lock()
        var seen = behavioralPacketFilterHashlists[handle] ?? []
        let alreadySeen = seen.contains(packetHash)
        let accepted = behavioralPacketFilterVerdict(
            packet: packet, identityHash: identityHash, alreadySeen: alreadySeen
        )
        var remembered = false
        if accepted && remember {
            // Mirror inbound's add_packet_hash remember step so a subsequent
            // identical packet is filtered as a duplicate.
            seen.insert(packetHash)
            behavioralPacketFilterHashlists[handle] = seen
            remembered = true
        }
        behavioralPacketFilterLock.unlock()

        return [
            "accepted": boolean(accepted),
            "packet_hash": hex(packetHash),
            "remembered": boolean(remembered),
        ]

    case "behavioral_force_cull":
        // Run the time-gated cull branches once, synchronously, with no real
        // sleep (Transport.py:1020-1045 reference -> jobs() cull pass).
        let handle = try getString(p, "handle")
        let inst = try requireBehavioralInstance(handle)
        try blockingAsync {
            // Announce-retransmit branch FIRST (RNS jobs() runs :573-636 before the
            // table cull), so a due entry (retransmit_timeout aged into the past via
            // behavioral_set_announce_timestamp) advances retries / reschedules /
            // completes deterministically on this synchronous pass.
            await inst.transport.runAnnounceRetransmissions()
            // Link + reverse table cull (LINK_TIMEOUT / proof-timeout / REVERSE_
            // TIMEOUT arms + the dead-interface arm), Transport.py:670-692.
            await inst.transport.cullTransportTables()
            // Path-table cull: expired entries + paths whose receiving interface
            // is no longer attached (Transport.py:782-785 missing-interface
            // eviction). The active set is the transport's currently-registered
            // interfaces — a detached interface is already absent from it.
            let ids = await inst.transport.interfaceIds
            let activeIds = Set(ids)
            let pathTable = await inst.transport.getPathTable()
            _ = await pathTable.cleanup(activeInterfaceIds: activeIds)
        }
        return ["culled": boolean(true)]

    case "behavioral_detach_interface":
        // Detach one interface and remove it from the transport's interface set,
        // arming the path-table missing-interface eviction (Transport.py:1048-
        // 1079 reference). The instance keeps its bookkeeping so behavioral_stop
        // still tears it down cleanly (removeInterface is idempotent).
        let handle = try getString(p, "handle")
        let ifaceId = try getString(p, "iface_id")
        let inst = try requireBehavioralInstance(handle)
        guard inst.interface(forId: ifaceId) != nil else {
            throw BridgeError.invalidData("Unknown iface_id: \(ifaceId)")
        }
        try blockingAsync {
            // removeInterface disconnects + drops it from Transport.interfaces,
            // mirroring iface.detach() + Transport.interfaces.remove(iface).
            await inst.transport.removeInterface(id: ifaceId)
        }
        return ["detached": boolean(true)]

    case "behavioral_ifac_mask":
        // IFAC-mask a genuine packet for an interface and return the on-wire
        // (masked) bytes (Transport.py:1082-1125 reference). Delegates to the
        // real Transport.applyIFAC (== Transport.transmit's IFAC masking: sign
        // with the interface ifac_identity, HKDF mask, set flag, insert access
        // code, mask payload). No masking is reimplemented here.
        let handle = try getString(p, "handle")
        let ifaceId = try getString(p, "iface_id")
        let raw = try getHex(p, "raw")
        let inst = try requireBehavioralInstance(handle)
        guard let iface = inst.interface(forId: ifaceId) else {
            throw BridgeError.invalidData("Unknown iface_id: \(ifaceId)")
        }
        // python raises if iface.ifac_identity is None (behavioral_transport.py:
        // 1115-1116). behavioral_attach_mock_interface now derives ifac_key/ifac_size
        // from ifac_netname/ifac_netkey onto the mock's config, so an IFAC interface
        // carries a 64-byte key here and the guard only fires for a non-IFAC mock.
        guard let ifacKey = iface.config.ifacKey, iface.config.ifacSize > 0, !ifacKey.isEmpty else {
            throw BridgeError.invalidData("interface has no IFAC identity configured")
        }
        let masked = try blockingAsync {
            await inst.transport.applyIFAC(raw: raw, interfaceId: ifaceId)
        }
        return ["masked": hex(masked)]

    case "behavioral_inbound_remembered":
        // Run the FULL real inbound on a raw frame and report whether the packet
        // hash was recorded (Transport.py:1128-1197 reference). inject() fires the
        // mock delegate -> handleReceivedData -> receive(), i.e. the production
        // packet_filter gate + dedup record path.
        let handle = try getString(p, "handle")
        let ifaceId = try getString(p, "iface_id")
        let raw = try getHex(p, "raw")
        let inst = try requireBehavioralInstance(handle)
        guard let iface = inst.interface(forId: ifaceId) else {
            throw BridgeError.invalidData("Unknown iface_id: \(ifaceId)")
        }

        // Suppress the unused-binding warning: existence is validated above; the
        // real inbound is driven through the transport by iface_id below.
        _ = iface

        // Independently determine the packet hash (excludes the hops byte via
        // getHashablePart, so it equals the hash inbound stores even though
        // inbound bumps hops). Same parse inbound runs.
        let probe = try? Packet(from: raw)
        let unpackable = probe != nil
        let packetHash: Data? = probe?.getFullHash()

        // Drive the REAL inbound synchronously and observe the packet_hashlist
        // count delta around it (Transport.py:1184-1188 reference). inbound(frame:)
        // runs the IFAC gate (Transport.py:1399-1445) + the inbound deferrals
        // (link-table / LRPROOF, :1496-1504) + the dedup record, so a frame that
        // clears the gate grows the hashlist while a dropped frame does not.
        // packetHashlistCount/Contains surface the otherwise-internal
        // PacketHashlist (the library observability accessors).
        let (before, after, inHashlist): (Int, Int, Bool) = try blockingAsync {
            let before = await inst.transport.packetHashlistCount()
            _ = await inst.transport.inbound(frame: raw, interface: ifaceId)
            let after = await inst.transport.packetHashlistCount()
            var inList = false
            if let h = packetHash {
                inList = await inst.transport.packetHashlistContains(h)
            }
            return (before, after, inList)
        }

        return [
            "hashlist_before": num(before),
            "hashlist_after": num(after),
            "hashlist_grew": boolean(after > before),
            "unpackable": boolean(unpackable),
            "packet_hash": packetHash.map { hex($0) } ?? .null,
            "in_hashlist": boolean(inHashlist),
        ]

    case "behavioral_read_tunnels":
        // Read the REAL tunnel table (reference cmd_behavioral_read_tunnels,
        // behavioral_transport.py:886-920; RNS Transport.tunnels, Transport.py:119,
        // IDX_TT_* at :3581-3584). Each entry decomposes to the python shape
        // {tunnel_id, interface_hash, interface_id, expires, num_paths}. The table
        // is populated by the validated tunnel-synthesize handshake
        // (Transport.py:2306-2345) which inbound() drives synchronously, so a
        // tunnel established by a just-injected synthesize packet is observable here.
        let handle = try getString(p, "handle")
        let inst = try requireBehavioralInstance(handle)
        let entries = try blockingAsync { await inst.transport.tunnelsSnapshot() }
        let tunnels: [JSONValue] = entries.map { e in
            // interface_hash mirrors read_link_table's iface descriptor (the
            // 16-byte attach hash); RNS surfaces iface.get_hash() here. Not asserted
            // by the tunnel tests but provided for python shape parity.
            let ifaceHash = e.interfaceId.flatMap { behavioralTablesInterfaceHash(forId: $0) }
            return .dict([
                "tunnel_id": hex(e.tunnelId),
                "interface_hash": ifaceHash.map { hex($0) } ?? .null,
                "interface_id": e.interfaceId.map { str($0) } ?? .null,
                "expires": num(e.expires.timeIntervalSince1970),
                "num_paths": num(e.paths.count),
            ])
        }
        return ["tunnels": .array(tunnels)]

    case "behavioral_synthesize_tunnel":
        // Emit a tunnel-synthesize packet on an interface (Transport.py:923-954
        // reference -> RNS Transport.synthesize_tunnel, Transport.py:2282-2303).
        let handle = try getString(p, "handle")
        let ifaceId = try getString(p, "iface_id")
        let inst = try requireBehavioralInstance(handle)
        guard let iface = inst.interface(forId: ifaceId) else {
            throw BridgeError.invalidData("Unknown iface_id: \(ifaceId)")
        }

        // LIBRARY-GAP: ReticulumTransport has no synthesize_tunnel(); the tunnel
        // subsystem is absent. RECONSTRUCT the emit inline from real primitives
        // (Identity public key + Ed25519 sign, Hashing.full_hash, the
        // rnstransport/tunnel/synthesize PLAIN control destination) and send it on
        // the interface so drain_tx observes the on-wire bytes. The inbound
        // validate/establish side (read_tunnels) remains a gap.
        let publicKey = inst.identity.publicKeys                   // 64B: enc || sig
        let ifaceIdBytes = hexToBytes(iface.id) ?? Data(iface.id.utf8)
        let interfaceHash = Hashing.fullHash(ifaceIdBytes)         // 32B interface hash
        let randomHash = Data((0..<16).map { _ in UInt8.random(in: 0...255) })

        let tunnelIdData = publicKey + interfaceHash               // pubkey || iface_hash
        let tunnelId = Hashing.fullHash(tunnelIdData)              // full_hash(pubkey||iface_hash)
        let signedData = tunnelIdData + randomHash                 // pubkey || iface_hash || random
        let signature = try inst.identity.sign(signedData)         // 64B Ed25519 signature
        let payload = signedData + signature                       // 64+32+16+64 = 176B

        let dest = Destination.plainHash(appName: "rnstransport", aspects: ["tunnel", "synthesize"])
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
            destination: dest,
            transportAddress: nil,
            context: PacketContext.NONE,
            data: payload
        )
        let encoded = packet.encode()
        try blockingAsync {
            // Route through the real IFAC step (no-op for a non-IFAC mock), then
            // buffer on the interface's TX queue exactly as a sent packet would.
            let onWire = await inst.transport.applyIFAC(raw: encoded, interfaceId: ifaceId)
            try await iface.send(onWire)
        }

        return ["iface_id": str(ifaceId), "tunnel_id": hex(tunnelId)]

    case "behavioral_read_link_table":
        // Read the REAL link table decomposed into fields (RNS Transport.py:1298-1363
        // reference; IDX_LT_* at Transport.py:3569-3578). Reads the live
        // ReticulumTransport.linkTable via linkTableSnapshot() — the same table the
        // real LINKREQUEST relay populates and the inbound deferral / hop-count gate /
        // cull consult — so a relayed or seeded entry is observed faithfully. With
        // `link_id` return that single decomposed entry; without it return all entries.
        let handle = try getString(p, "handle")
        let inst = try requireBehavioralInstance(handle)
        let linkIdOpt = getHexOptional(p, "link_id")

        let table = try blockingAsync { await inst.transport.linkTableSnapshot() }

        func descriptor(_ ifaceId: String) -> (id: JSONValue, hash: JSONValue, name: JSONValue) {
            let h = behavioralTablesInterfaceHash(forId: ifaceId)
            let iface = inst.interface(forId: ifaceId)
            return (str(ifaceId),
                    h.map { hex($0) } ?? .null,
                    iface.map { str($0.config.name) } ?? .null)
        }
        func decompose(keyHex: String, _ e: LinkTableEntry) -> Result {
            // LinkTableEntry field → IDX_LT_* mapping: outboundInterfaceId == NH_IF,
            // receivingInterfaceId == RCVD_IF, takenHops == HOPS. An empty
            // nextHopTransportId is the python `None` (seeded entries store no next hop).
            let nh = descriptor(e.outboundInterfaceId)
            let rcvd = descriptor(e.receivingInterfaceId)
            return [
                "link_id": str(keyHex),
                "timestamp": num(e.timestamp.timeIntervalSince1970),
                "next_hop_transport_id": e.nextHopTransportId.isEmpty ? .null : hex(e.nextHopTransportId),
                "next_hop_if": nh.id,
                "next_hop_if_hash": nh.hash,
                "remaining_hops": num(Int(e.remainingHops)),
                "received_if": rcvd.id,
                "received_if_hash": rcvd.hash,
                "hops": num(Int(e.takenHops)),
                "destination_hash": hex(e.destinationHash),
                "validated": boolean(e.validated),
                "proof_timeout": num(e.proofTimeout.timeIntervalSince1970),
            ]
        }

        if let linkId = linkIdOpt {
            guard let e = table[linkId] else { return ["found": boolean(false)] }
            var d = decompose(keyHex: bytesToHex(linkId), e)
            d["found"] = boolean(true)
            return d
        }

        let entries = table.map { decompose(keyHex: bytesToHex($0.key), $0.value) }
        return ["entries": .array(entries.map { .dict($0) })]

    case "behavioral_seed_link_table":
        // Seed a correctly-shaped link_table entry directly into the REAL
        // ReticulumTransport.linkTable so the inbound link-table deferral
        // (Transport.py:1496-1498), the cross/same-interface hop-count gate
        // (Transport.py:1644-1679) and the link-table cull (Transport.py:685-692)
        // can be exercised on a single injected packet (link_entry layout at
        // Transport.py:1600-1620, IDX_LT_* at :3569-3578).
        let handle = try getString(p, "handle")
        let dest = try getHex(p, "dest")
        let inst = try requireBehavioralInstance(handle)
        let nhIfaceId = try getString(p, "nh_iface_id")
        let rcvdIfaceId = try getString(p, "rcvd_iface_id")
        // Faithful param validation: the next-hop / received interfaces must be
        // attached MockInterfaces (mirrors python's lookup + raise).
        guard inst.interface(forId: nhIfaceId) != nil,
              inst.interface(forId: rcvdIfaceId) != nil else {
            throw BridgeError.invalidData("nh_iface_id / rcvd_iface_id must reference attached interfaces")
        }
        // Aging / validation knobs drive the cull (Transport.py:685-692):
        //   timestamp_age_s    — backdate timestamp (validated LINK_TIMEOUT arm)
        //   validated          — False drives the unvalidated proof-timeout arm
        //   proof_timeout_in_s — proof_timeout relative to now (negative = expired)
        let remHops = getIntOptional(p, "rem_hops") ?? 99
        let takenHops = getIntOptional(p, "hops") ?? 99
        let validated = getBoolOptional(p, "validated") ?? true
        let ageS = (try? getDouble(p, "timestamp_age_s")) ?? 0
        let proofTimeoutInS = (try? getDouble(p, "proof_timeout_in_s")) ?? 60.0
        let now = Date()
        // link_entry next_hop (IDX_LT_NH_TRID) is None in the python seed; the empty
        // Data here is surfaced as null by read_link_table. Field mapping:
        // outboundInterfaceId == NH_IF (next hop), receivingInterfaceId == RCVD_IF.
        let entry = LinkTableEntry(
            timestamp: now.addingTimeInterval(-ageS),
            nextHopTransportId: Data(),
            outboundInterfaceId: nhIfaceId,
            remainingHops: UInt8(clamping: remHops),
            receivingInterfaceId: rcvdIfaceId,
            takenHops: UInt8(clamping: takenHops),
            destinationHash: dest,
            validated: validated,
            proofTimeout: now.addingTimeInterval(proofTimeoutInS)
        )
        try blockingAsync { await inst.transport.seedLinkTableEntry(key: dest, entry: entry) }
        return ["seeded": boolean(true), "dest": hex(dest)]

    default:
        return nil
    }
}
