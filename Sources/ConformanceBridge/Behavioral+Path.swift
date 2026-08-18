// Behavioral+Path.swift — conformance bridge behavioral sub-handler cluster: B-PATH (path/reverse table seed+read, request_path, register_destination, destination_deliveries)
//
// Ports from reticulum-conformance reference/behavioral_transport.py. Shares the
// behavioralInstances registry + behavioralLock + requireBehavioralInstance()
// (internal in Behavioral.swift). Returns nil for commands it doesn't own
// (dispatch chain: handleBehavioralExtensionCommand in Ext+Dispatch.swift).
// Keep python-faithful; report library gaps; reconstruct logic inline rather
// than bailing (see /tmp/bridge_behavioral_spec.md DO-NOT-BAIL rule).
import CryptoKit
import Foundation
import ReticulumSwift

// MARK: - B-PATH shared module state
//
// Bridge commands arrive serially on main.swift's readLine loop, but the
// destination recording callback fires on the ReticulumTransport actor's task
// (DefaultCallbackManager.deliver runs inside the actor), so every store below
// is guarded by a single lock.
private let behavioralPathLock = NSLock()

// Plaintexts delivered to a registered destination's recording packet callback,
// keyed by "<handle>:<dest_hex>" (mirrors python inst["dest_deliveries"][hash]).
nonisolated(unsafe) private var behavioralDestinationDeliveries: [String: [Data]] = [:]

// Keep registered Destination objects alive for the lifetime of the handle. The
// Transport retains them in its `destinations` map too, but holding our own
// reference makes the ownership explicit and survives any future Transport churn.
nonisolated(unsafe) private var behavioralRegisteredDestinations: [String: [Destination]] = [:]

// behavioral_seed_reverse_table / behavioral_read_reverse_table now operate on the
// REAL ReticulumTransport.reverseTable via seedReverseTableEntry / reverseTableSnapshot
// (RNS Transport.py:3554-3556 IDX_RT_*) — the same table the real DATA-forwarding path
// populates and the REVERSE_TIMEOUT cull (cullTransportTables) evicts from. No shadow.

private func deliveryStoreKey(_ handle: String, _ destHex: String) -> String { "\(handle):\(destHex)" }

private func recordBehavioralDelivery(handle: String, destHex: String, data: Data) {
    let key = deliveryStoreKey(handle, destHex)
    behavioralPathLock.lock(); defer { behavioralPathLock.unlock() }
    behavioralDestinationDeliveries[key, default: []].append(data)
}

private func readBehavioralDeliveries(handle: String, destHex: String) -> [Data] {
    let key = deliveryStoreKey(handle, destHex)
    behavioralPathLock.lock(); defer { behavioralPathLock.unlock() }
    return behavioralDestinationDeliveries[key] ?? []
}

/// Recompute the 16-byte interface hash a mock interface was attached with.
/// behavioral_attach_mock_interface hashes the raw 6 id bytes:
/// `SHA256(idBytes).prefix(16)`, where iface_id == hex(idBytes). Reproducing it
/// here matches the `interface_hash` attach returned (RNS iface.get_hash()).
private func behavioralInterfaceHash(forId ifaceId: String) -> Data? {
    guard let idBytes = hexToBytes(ifaceId) else { return nil }
    return Data(Data(SHA256.hash(data: idBytes)).prefix(16))
}

func handleBehavioralPathCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // Read this Transport's PATH TABLE entry for a destination, decomposed into the
    // RNS path_table fields (Transport.py:3545-3551 IDX_PT_*). Drives the real swift
    // PathTable via getPathTable(); allEntries() is used (not lookup()) so an entry
    // that is present-but-expired still reports found=true, matching python's raw
    // `dest in path_table` membership check.
    case "behavioral_read_path_table":
        let handle = try getString(p, "handle")
        let dest = try getHex(p, "dest")
        let inst = try requireBehavioralInstance(handle)

        let entryOpt: PathEntry? = try blockingAsync {
            let pt = await inst.transport.getPathTable()
            return await pt.allEntries().first { $0.destinationHash == dest }
        }
        guard let entry = entryOpt else { return ["found": boolean(false)] }

        let rxHash = behavioralInterfaceHash(forId: entry.interfaceId)
        return [
            "found": boolean(true),
            "hops": num(Int(entry.hopCount)),
            "next_hop": entry.nextHop.map { hex($0) } ?? .null,
            "timestamp": num(entry.timestamp.timeIntervalSince1970),
            "expires": num(entry.expires.timeIntervalSince1970),
            "random_blobs": .array(entry.randomBlobs.map { hex($0) }),
            "receiving_interface": str(entry.interfaceId),
            "receiving_interface_hash": rxHash.map { hex($0) } ?? .null,
            // LIBRARY-GAP: PathEntry stores no announce packet_hash (RNS
            // IDX_PT_PACKET). The swift path table keeps `announceData` (raw payload)
            // but never the announce packet's hash, so this surfaces as null rather
            // than being fabricated. Not asserted by any current B-PATH test.
            "packet_hash": .null,
        ]

    // Set path_table[dest][IDX_PT_TIMESTAMP] for deterministic, sleep-free expiry
    // eviction (Transport.py:771-785; pair with force_cull). PathEntry.timestamp is
    // immutable, so we read the existing entry, rebuild it with the new timestamp,
    // and remove+record it. record() on an absent key takes the unconditional
    // Path-1 insert (PathTable.record:260-268), preserving all other fields.
    case "behavioral_set_path_timestamp":
        let handle = try getString(p, "handle")
        let dest = try getHex(p, "dest")
        let ts = try getDouble(p, "timestamp")
        let inst = try requireBehavioralInstance(handle)

        let didSet: Bool = try blockingAsync {
            let pt = await inst.transport.getPathTable()
            guard let existing = await pt.allEntries().first(where: { $0.destinationHash == dest }) else {
                return false
            }
            let updated = PathEntry(
                destinationHash: existing.destinationHash,
                publicKeys: existing.publicKeys,
                interfaceId: existing.interfaceId,
                hopCount: existing.hopCount,
                timestamp: Date(timeIntervalSince1970: ts),
                expires: existing.expires,
                randomBlob: existing.randomBlob,
                randomBlobs: existing.randomBlobs,
                pathState: existing.pathState,
                ratchet: existing.ratchet,
                appData: existing.appData,
                nextHop: existing.nextHop,
                announceData: existing.announceData
            )
            await pt.remove(destinationHash: dest)
            _ = await pt.record(entry: updated)
            return true
        }
        return ["set": boolean(didSet)]

    // Set path_table[dest][IDX_PT_EXPIRES] for the larger-hop expired-path
    // replacement branch (Transport.py:1789). Same read/rebuild/remove+record dance
    // as set_path_timestamp, overriding EXPIRES only.
    case "behavioral_set_path_expires":
        let handle = try getString(p, "handle")
        let dest = try getHex(p, "dest")
        let expires = try getDouble(p, "expires")
        let inst = try requireBehavioralInstance(handle)

        let didSet: Bool = try blockingAsync {
            let pt = await inst.transport.getPathTable()
            guard let existing = await pt.allEntries().first(where: { $0.destinationHash == dest }) else {
                return false
            }
            let updated = PathEntry(
                destinationHash: existing.destinationHash,
                publicKeys: existing.publicKeys,
                interfaceId: existing.interfaceId,
                hopCount: existing.hopCount,
                timestamp: existing.timestamp,
                expires: Date(timeIntervalSince1970: expires),
                randomBlob: existing.randomBlob,
                randomBlobs: existing.randomBlobs,
                pathState: existing.pathState,
                ratchet: existing.ratchet,
                appData: existing.appData,
                nextHop: existing.nextHop,
                announceData: existing.announceData
            )
            await pt.remove(destinationHash: dest)
            _ = await pt.record(entry: updated)
            return true
        }
        return ["set": boolean(didSet)]

    // Mark a path unresponsive via the real PathTable.markPathUnresponsive
    // (the swift analogue of Transport.mark_path_unresponsive, Transport.py:2719-2724;
    // backs the equal-emission replacement branch Transport.py:1818-1823). The swift
    // call is a no-op + returns Void when no path exists, so we report `marked` from
    // the path's presence (python returns False when dest is not in path_table).
    case "behavioral_mark_path_unresponsive":
        let handle = try getString(p, "handle")
        let dest = try getHex(p, "dest")
        let inst = try requireBehavioralInstance(handle)

        let marked: Bool = try blockingAsync {
            let pt = await inst.transport.getPathTable()
            let present = await pt.allEntries().contains { $0.destinationHash == dest }
            if present { await pt.markPathUnresponsive(dest) }
            return present
        }
        return ["marked": boolean(marked)]

    // Drive a path-request emission and let the test drain the bytes
    // (Transport.py:2769-2812). ReticulumTransport.requestPath(for:) mints its own
    // random tag, returns nothing, and broadcasts to ALL interfaces, so it can't
    // satisfy the test's supplied-tag / single-interface / returned-tag contract.
    // We therefore reconstruct the exact packet the swift Transport builds
    // (ReticulumTransport.swift:3185-3215) from real primitives and send it on the
    // named mock interface: a PLAIN DATA HEADER_1 BROADCAST packet to the
    // rnstransport.path.request control destination carrying
    // dest(16) [|| transport_id(16)] || tag(16) (transport_id only when transport
    // is enabled).
    case "behavioral_request_path":
        let handle = try getString(p, "handle")
        let ifaceId = try getString(p, "iface_id")
        let dest = try getHex(p, "dest")
        let inst = try requireBehavioralInstance(handle)
        guard let iface = inst.interface(forId: ifaceId) else {
            throw BridgeError.invalidData("Unknown iface_id: \(ifaceId)")
        }

        // Supply a tag for deterministic payload-length assertions; otherwise mint a
        // 16-byte random tag (matches RNS.Identity.get_random_hash() length).
        let tag: Data = getHexOptional(p, "tag") ?? Data((0..<16).map { _ in UInt8.random(in: 0...255) })

        _ = try blockingAsync { () -> Bool in
            let enabled = await inst.transport.transportEnabled
            let txHash = await inst.transport.transportIdentityHash
            var payload = dest
            if enabled, let txHash { payload.append(txHash) }
            payload.append(tag)

            let prDest = Destination.plainHash(appName: "rnstransport", aspects: ["path", "request"])
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
                destination: prDest,
                transportAddress: nil,
                context: 0x00,
                data: payload
            )
            try await iface.send(packet.encode())
            return true
        }
        return ["tag": hex(tag)]

    // Register a real local IN destination on this Transport (Destination.py:196 ->
    // Transport.register_destination, Transport.py:2415-2426). A recording packet
    // callback is attached so inbound DELIVERY decisions (Transport.py:2155-2165) are
    // observable via behavioral_read_destination_deliveries. The destination_hash
    // equals the announce-built hash for the same identity+app+aspects, exercising the
    // local-destination announce carve-out.
    case "behavioral_register_destination":
        let handle = try getString(p, "handle")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let typeName = (getStringOptional(p, "type") ?? "single").lowercased()
        let proofStrategy = getStringOptional(p, "proof_strategy")
        let inst = try requireBehavioralInstance(handle)

        let destType: DestType
        switch typeName {
        case "single": destType = .single
        case "plain": destType = .plain
        case "group": destType = .group
        default:
            throw BridgeError.invalidData("unknown destination type: \(typeName)")
        }

        let destination: Destination
        if destType == .plain {
            destination = Destination(plainAppName: appName, aspects: aspects, direction: .in)
        } else {
            let seed = try getHex(p, "identity_seed")
            guard seed.count == 64 else {
                throw BridgeError.invalidData("identity_seed must be 64 bytes (32 enc + 32 sig)")
            }
            let identity = try Identity(privateKeyBytes: seed)
            destination = Destination(
                identity: identity, appName: appName, aspects: aspects,
                type: destType, direction: .in
            )
        }

        // LIBRARY-GAP: swift Destination has no set_proof_strategy / PROVE_ALL|NONE|APP
        // (RNS Destination.set_proof_strategy). ReticulumTransport hardcodes a SINGLE
        // proof-on-receive (ReticulumTransport.swift:2343-2353); the strategy knob is
        // accepted but cannot be applied. Not exercised by current B-PATH tests.
        _ = proofStrategy

        let destHash = destination.hash
        let destHex = bytesToHex(destHash)

        _ = try blockingAsync { () -> Bool in
            await inst.transport.registerDestination(destination)
            // registerDestination wires `destination` to the transport's internal
            // DefaultCallbackManager; register the recording callback on that same
            // manager (registerAsync guarantees it lands before we return).
            let mgr = await inst.transport.getCallbackManager()
            await mgr.registerAsync(destinationHash: destHash) { data, _ in
                recordBehavioralDelivery(handle: handle, destHex: destHex, data: data)
            }
            return true
        }

        behavioralPathLock.lock()
        behavioralRegisteredDestinations[handle, default: []].append(destination)
        behavioralPathLock.unlock()

        return ["destination_hash": hex(destHash)]

    // Read the plaintexts delivered to a registered destination's recording callback.
    // The callback fires only when the real Transport delivers (callbackManager.deliver,
    // after the type-match + decrypt gates), so this is the honest delivery observable.
    case "behavioral_read_destination_deliveries":
        let handle = try getString(p, "handle")
        let dest = try getHex(p, "dest")
        _ = try requireBehavioralInstance(handle)

        let deliveries = readBehavioralDeliveries(handle: handle, destHex: bytesToHex(dest))
        return [
            "count": num(deliveries.count),
            "deliveries": .array(deliveries.map { hex($0) }),
        ]

    // Seed a reverse_table[key] entry [received_if, outbound_if, timestamp] (RNS
    // IDX_RT_*, Transport.py:3554-3556) so the REVERSE_TIMEOUT cull can be driven
    // deterministically. The interfaces must be real attached mock interfaces (so the
    // interface-membership cull arms don't fire); timestamp_age_s backdates the entry.
    //
    // Seeds the REAL ReticulumTransport.reverseTable via seedReverseTableEntry, so a
    // force_cull-driven REVERSE_TIMEOUT eviction (cullTransportTables, Transport.py:670-677)
    // IS observed by read_reverse_table. The interfaces are real attached MockInterfaces,
    // so the interface-membership cull arms do not fire — isolating the timeout arm.
    case "behavioral_seed_reverse_table":
        let handle = try getString(p, "handle")
        let key = try getHex(p, "key")
        let rcvdIfaceId = try getString(p, "rcvd_iface_id")
        let outbIfaceId = try getString(p, "outb_iface_id")
        let ageS = (try? getDouble(p, "timestamp_age_s")) ?? 0
        let inst = try requireBehavioralInstance(handle)

        guard inst.interface(forId: rcvdIfaceId) != nil,
              inst.interface(forId: outbIfaceId) != nil else {
            throw BridgeError.invalidData("rcvd_iface_id / outb_iface_id must reference attached interfaces")
        }

        let entry = ReverseTableEntry(
            receivingInterfaceId: rcvdIfaceId,
            outboundInterfaceId: outbIfaceId,
            timestamp: Date().addingTimeInterval(-ageS)
        )
        try blockingAsync { await inst.transport.seedReverseTableEntry(key: key, entry: entry) }
        return ["seeded": boolean(true), "key": str(bytesToHex(key))]

    // Read the REAL reverse_table entries via reverseTableSnapshot() (RNS
    // Transport.py:3554-3556). With `dest` (a reverse-table key = the forwarded
    // packet's truncated hash) return that single decomposed entry; without it return
    // all entries. Reads the same table the real DATA-forwarding path populates and the
    // PROOF return-routing consumes, so a relayed entry is observed faithfully.
    case "behavioral_read_reverse_table":
        let handle = try getString(p, "handle")
        let inst = try requireBehavioralInstance(handle)
        let destOpt = getHexOptional(p, "dest")

        let table = try blockingAsync { await inst.transport.reverseTableSnapshot() }

        func descriptor(_ ifaceId: String) -> (id: String, hash: JSONValue, name: JSONValue) {
            let h = behavioralInterfaceHash(forId: ifaceId)
            let iface = inst.interface(forId: ifaceId)
            return (ifaceId,
                    h.map { hex($0) } ?? .null,
                    iface.map { str($0.config.name) } ?? .null)
        }
        func decompose(keyHex: String, _ e: ReverseTableEntry) -> Result {
            let rcvd = descriptor(e.receivingInterfaceId)
            let outb = descriptor(e.outboundInterfaceId)
            return [
                "key": str(keyHex),
                "received_if": str(rcvd.id),
                "outbound_if": str(outb.id),
                "received_if_hash": rcvd.hash,
                "outbound_if_hash": outb.hash,
                "received_if_name": rcvd.name,
                "outbound_if_name": outb.name,
                "timestamp": num(e.timestamp.timeIntervalSince1970),
            ]
        }

        if let dest = destOpt {
            guard let e = table[dest] else { return ["found": boolean(false)] }
            var d = decompose(keyHex: bytesToHex(dest), e)
            d["found"] = boolean(true)
            return d
        }

        let entries = table.map { decompose(keyHex: bytesToHex($0.key), $0.value) }
        return ["entries": .array(entries.map { .dict($0) })]

    default:
        return nil
    }
}
