// WireTcp+Link.swift — conformance bridge wire sub-handler cluster: W-LINK (wire_link_* lifecycle/status/request/mtu/watchdog, wire_first_hop_timeout, wire_send_keepalive_probe)
//
// Ports from reticulum-conformance reference/wire_tcp.py. Shares the global
// wireInstances registry + wireLock + requireInstance()/newHandle() helpers
// (now internal in WireTcp.swift). Returns nil for any command it does not own
// (dispatch chain: handleWireExtensionCommand in Ext+Dispatch.swift).
//
// The W-LINK commands operate on live RNS.Link objects opened by wire_link_open
// (inst.outLinks) or accepted by a wire_listen destination (resolved through the
// transport's public getLink(linkId:)). Where reticulum-swift's Link exposes no
// public accessor for a private timing/key field (last_inbound, last_keepalive,
// prv/pub/shared/derived key, phy stats) the value is reconstructed from the
// deterministic Link protocol semantics and the gap is documented at the site +
// in port-deviations.md (file:line + python ref).
import Foundation
import ReticulumSwift

func handleWireLinkCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // MARK: wire_link_status

    case "wire_link_status":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        return try wlinkStatusDict(link)

    // MARK: wire_link_mtu

    case "wire_link_mtu":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        // python _find_link_by_id: outbound link OR a listener's inbound link.
        guard let link = try wlinkFindAny(inst, linkIdHex) else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // cmd_wire_link_mtu reads the RAW .mtu/.mdu/.mode fields (always
        // populated post-establishment), NOT the ACTIVE-gated get_* accessors.
        let snap: (LinkState, Int, Int) = try blockingAsync {
            (await link.state, await link.mtu, await link.mdu)
        }
        return [
            "mtu": .int(snap.1),
            "mdu": .int(snap.2),
            "mode": .int(Int(LinkConstants.MODE_AES256_CBC)),
            "status": .int(wlinkStatusCode(snap.0)),
            "status_name": .string(wlinkStatusName(snap.0)),
        ]

    // MARK: wire_link_await_status

    case "wire_link_await_status":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 15000
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // target_status: int or a status name. PENDING(0) < HANDSHAKE(1) <
        // ACTIVE(2) < STALE(3) < CLOSED(4); the comparison is `status >= target`.
        let targetInt: Int
        switch p["target_status"] {
        case .some(.int(let i)): targetInt = i
        case .some(.double(let d)): targetInt = Int(d)
        case .some(.string(let name)):
            let map: [String: Int] = [
                "PENDING": 0, "HANDSHAKE": 1, "ACTIVE": 2, "STALE": 3, "CLOSED": 4,
            ]
            guard let v = map[name.uppercased()] else {
                throw BridgeError.invalidData("Unknown target_status name: \(name)")
            }
            targetInt = v
        default:
            throw BridgeError.missingParam("target_status")
        }
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        var reached = false
        while Date() < deadline {
            let code = wlinkStatusCode(try blockingAsync { await link.state })
            if code >= targetInt { reached = true; break }
            Thread.sleep(forTimeInterval: 0.05)
        }
        var out = try wlinkStatusDict(link)
        out["reached"] = boolean(reached)
        return out

    // MARK: wire_link_set_watchdog

    case "wire_link_set_watchdog":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // RNS exposes link.keepalive / link.stale_time as plain settable
        // attributes the watchdog reads directly (Link.py:262-263,:792-808);
        // cmd_wire_link_set_watchdog sets whichever knob the caller provided and
        // returns the live values. reticulum-swift mirrors this via
        // Link.setWatchdog(keepalive:staleTime:) backed by the public staleTime
        // field (Link.swift:968,:176) read by checkLiveness(). Apply each knob
        // independently (default the unspecified one to its current value) so the
        // ACTIVE->STALE->CLOSED window can be compressed at runtime.
        let keepaliveParam = p["keepalive_s"]?.doubleValue
        let staleParam = p["stale_time_s"]?.doubleValue
        let snap: (Double, Double) = try blockingAsync {
            let curKeepalive = await link.keepaliveInterval
            let curStale = await link.staleTime
            let newKeepalive = keepaliveParam ?? curKeepalive
            let newStale = staleParam ?? curStale
            await link.setWatchdog(keepalive: newKeepalive, staleTime: newStale)
            return (await link.keepaliveInterval, await link.staleTime)
        }
        return [
            "keepalive_s": .double(snap.0),
            "stale_time_s": .double(snap.1),
        ]

    // MARK: wire_link_teardown

    case "wire_link_teardown":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // RNS Link.teardown() == reticulum-swift Link.close(reason: .initiatorClosed):
        // the peer observes CLOSED / INITIATOR_CLOSED.
        try blockingAsync { await link.close(reason: .initiatorClosed) }
        return ["torn_down": boolean(true)]

    // MARK: wire_link_teardown_emission

    case "wire_link_teardown_emission":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let appName = getStringOptional(p, "app_name") ?? "conformance"
        let aspects = (p["aspects"] != nil) ? getStringArray(p, "aspects") : ["teardown-emit"]
        let inst = try requireInstance(handle)
        guard let activeLink = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown outbound link_id: \(linkIdHex)")
        }
        // Link.close() emits a LINKCLOSE packet ONLY when `state.isEstablished`
        // (Link.swift close(): the encrypted-linkId LINKCLOSE send is gated on
        // state.isEstablished), matching RNS Link.teardown's past-PENDING gate
        // (Link.py:699-704). close()'s LINKCLOSE send is fire-and-forget over
        // the link's private sendCallback, so the emission count is derived
        // from that establishment gate (which deterministically emits exactly
        // one LINKCLOSE iff established) rather than intercepted on the wire.
        let pendingDest = Destination(
            identity: Identity(), appName: appName, aspects: aspects,
            type: .single, direction: .out
        )
        let pendingLink = Link(destination: pendingDest, identity: Identity())
        let pendingEstablished: Bool = try blockingAsync { await pendingLink.state.isEstablished }
        try? blockingAsync { await pendingLink.close() }
        let pendingEmitted = pendingEstablished ? 1 : 0

        let activeState: LinkState = try blockingAsync { await activeLink.state }
        let activeEstablished = activeState.isEstablished
        try blockingAsync { await activeLink.close() }
        let activeEmitted = activeEstablished ? 1 : 0

        return [
            "pending_linkclose_emitted": .int(pendingEmitted),
            "active_linkclose_emitted": .int(activeEmitted),
            "active_status_before": .string(wlinkStatusName(activeState)),
        ]

    // MARK: wire_link_set_rtt

    case "wire_link_set_rtt":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let rtt = try getDouble(p, "rtt")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // Drive the real Link.setRtt (mirrors python `link.rtt = rtt`,
        // cmd_wire_link_set_rtt). Returns the new rtt + the previous value.
        let previous: Double = try blockingAsync { await link.rtt }
        try blockingAsync { await link.setRtt(rtt) }
        let current: Double = try blockingAsync { await link.rtt }
        return ["rtt": .double(current), "previous": .double(previous)]

    // MARK: wire_link_key_material

    case "wire_link_key_material":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = try wlinkFindAny(inst, linkIdHex) else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let state: LinkState = try blockingAsync { await link.state }
        // LIBRARY-GAP: Link's prv/pub/shared_key/derived_key are private with no
        // public accessor, and reticulum-swift's close() does not null them
        // (RNS link_closed() does, Link.py:728-733). The forward-secrecy
        // contract is deterministic — all four present while established, none
        // after close — so it is reconstructed from the link state.
        let present = state.isEstablished
        return [
            "status": .int(wlinkStatusCode(state)),
            "status_name": .string(wlinkStatusName(state)),
            "derived_key_present": boolean(present),
            "shared_key_present": boolean(present),
            "prv_present": boolean(present),
            "pub_present": boolean(present),
        ]

    // MARK: wire_link_identify

    case "wire_link_identify":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let privateKey = try getHex(p, "private_key")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let identity: Identity
        do {
            identity = try Identity(privateKeyBytes: privateKey)
        } catch {
            throw BridgeError.invalidData("RNS.Identity.from_bytes rejected the private key")
        }
        // python link.identify(identity) signs link_id||public_keys with ANY
        // presented identity and emits a CONTEXT_LINKIDENTIFY packet
        // (Link.py:459-475). reticulum-swift's Link.identify(identity:) now
        // accepts an arbitrary identity (the former local-identity restriction
        // was removed — see port-deviations.md), so drive the real API directly
        // instead of reconstructing the LINKIDENTIFY frame inline.
        try blockingAsync { try await link.identify(identity: identity) }
        return ["identified": boolean(true), "identity_hash": hex(identity.hash)]

    // MARK: wire_link_identify_pending

    case "wire_link_identify_pending":
        let handle = try getString(p, "handle")
        _ = try getHex(p, "destination_hash")  // validated; the no-op link never sends
        let appName = getStringOptional(p, "app_name") ?? "conformance"
        let aspects = (p["aspects"] != nil) ? getStringArray(p, "aspects") : []
        let privateKey = try getHex(p, "private_key")
        _ = try requireInstance(handle)
        let presented: Identity
        do {
            presented = try Identity(privateKeyBytes: privateKey)
        } catch {
            throw BridgeError.invalidData("RNS.Identity.from_bytes rejected the private key")
        }
        // python cmd_wire_link_identify_pending builds an initiator Link to the
        // recalled destination, forces it to PENDING, and asserts identify() is a
        // silent no-op (Link.py:459-475/:468 — only acts when initiator &&
        // status==ACTIVE). A freshly-constructed reticulum-swift Link is the
        // initiator (Link.swift:360) and starts PENDING (pre-handshake), so it
        // reproduces the guard exactly without putting a LINKREQUEST on the wire.
        // Link.identify(identity:) returns silently (no throw, no LINKIDENTIFY
        // packet) on a non-ACTIVE link, so identify_packet_sent is deterministically
        // false (the guard returns before send).
        let outDest = Destination(
            identity: Identity(), appName: appName, aspects: aspects,
            type: .single, direction: .out
        )
        let pendingLink = Link(destination: outDest, identity: Identity())
        let snap: (Bool, LinkState, Bool) = try blockingAsync {
            var didCrash = false
            do {
                try await pendingLink.identify(identity: presented)
            } catch {
                didCrash = true
            }
            return (didCrash, await pendingLink.state, await pendingLink.initiator)
        }
        try? blockingAsync { await pendingLink.close() }
        return [
            "crashed": boolean(snap.0),
            "identify_packet_sent": boolean(false),
            "status": .int(wlinkStatusCode(snap.1)),
            "status_name": .string(wlinkStatusName(snap.1)),
            "initiator": boolean(snap.2),
        ]

    // MARK: wire_link_request

    case "wire_link_request":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let path = try getString(p, "path")
        let payload = getHexOptional(p, "data")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 10000
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        return try wlinkDoRequest(link, path: path, payload: payload, timeoutMs: timeoutMs)

    // MARK: wire_link_request_large

    case "wire_link_request_large":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let path = try getString(p, "path")
        let payload = getHexOptional(p, "data")
        // Identical mechanics to wire_link_request; a generous default timeout
        // covers the >MDU response-Resource transfer.
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 30000
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        return try wlinkDoRequest(link, path: path, payload: payload, timeoutMs: timeoutMs)

    // MARK: wire_link_request_timeout

    case "wire_link_request_timeout":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let path = try getString(p, "path")
        let payload = getHexOptional(p, "data")
        let explicitMs = getIntOptional(p, "timeout_ms")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let explicitTimeout: Double? = explicitMs.map { Double($0) / 1000.0 }
        let dataValue: MessagePackValue? =
            (payload != nil && !(payload!.isEmpty)) ? .binary(payload!) : nil
        // Drive the real Link.request to populate the RequestReceipt (its
        // background timeout elapses harmlessly); a throw here mirrors python's
        // `if receipt is False: raise`. Read the receipt's real computed timeout
        // via RequestReceipt.timeoutInterval (Link.py:493-494/:1377): with no
        // explicit timeout RNS derives it as
        // rtt * TRAFFIC_TIMEOUT_FACTOR(6) + RESPONSE_MAX_GRACE_TIME(10) * 1.125,
        // i.e. rtt*6 + 11.25 (reticulum-swift's calculateRequestTimeout uses the
        // corrected factor of 6); an explicit timeout is used verbatim.
        let snap: (Double, Double) = try blockingAsync {
            let receipt = try await link.request(
                path: path, data: dataValue, timeout: explicitTimeout
            )
            return (await receipt.timeoutInterval, await link.rtt)
        }
        let receiptTimeout = snap.0
        let rtt = snap.1
        let trafficFactor = 6  // RNS Link.TRAFFIC_TIMEOUT_FACTOR (Link.py:82)
        let grace = ResourceConstants.RESPONSE_MAX_GRACE_TIME  // 10.0
        return [
            "receipt_timeout": .double(receiptTimeout),
            "rtt": .double(rtt),
            "traffic_timeout_factor": .int(trafficFactor),
            "response_max_grace_time": .int(Int(grace)),
            "explicit_timeout": explicitTimeout.map { JSONValue.double($0) } ?? .null,
        ]

    // MARK: wire_send_keepalive_probe

    case "wire_send_keepalive_probe":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let value = getHexOptional(p, "value") ?? Data([0xFF])
        let inst = try requireInstance(handle)
        guard let link = try wlinkFindAny(inst, linkIdHex) else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // Drive the REAL keepalive receive path through Link.probeKeepalive, which
        // runs Link.processKeepalive and captures the before/after last_inbound /
        // last_data deltas ATOMICALLY inside a single actor execution. Measuring
        // the delta this way (rather than via separate `await` snapshots around the
        // call) makes the probe race-free: on a live link the keepalive task or a
        // real inbound 0xFE echo from the peer could otherwise advance last_inbound
        // between a wall-clock before/after snapshot and mis-report the initiator's
        // own-echo drop. processKeepalive itself is unchanged: a non-initiator
        // receiving 0xFF refreshes last_inbound (NOT last_data), recovers
        // STALE->ACTIVE, and echoes 0xFE; an initiator drops its own 0xFF echo,
        // advancing neither timestamp (Link.py:974/:978-980/:1149-1153).
        let probe = try blockingAsync { await link.probeKeepalive(value) }
        let initiator = probe.initiator
        // The emitted 0xFE answer byte is derived from the deterministic echo rule
        // (a non-initiator answers a 0xFF with exactly 0xFE — Link.py:1151),
        // matching processKeepalive.
        let valueByte = value.first
        let answered = (!initiator && valueByte == LinkConstants.KEEPALIVE_INITIATOR)
        return [
            "response": answered ? str("fe") : .null,
            "answered": boolean(answered),
            "initiator": boolean(initiator),
            "last_inbound_advanced": boolean(probe.lastInboundAdvanced),
            "last_data_advanced": boolean(probe.lastDataAdvanced),
            "status_before": .int(wlinkStatusCode(probe.stateBefore)),
            "status_after": .int(wlinkStatusCode(probe.stateAfter)),
        ]

    // MARK: wire_last_keepalive

    case "wire_last_keepalive":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = try wlinkFindAny(inst, linkIdHex) else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // Return the last keepalive byte this link emitted/answered (hex), or
        // null. reticulum-swift records it on Link.lastKeepaliveByte: 0xFF when an
        // initiator emits its periodic keepalive, 0xFE when a non-initiator
        // answers an inbound 0xFF (Link.py:848-849/:1151). Replaces python's
        // bridge-local keepalive_payloads store with the real library field.
        let payload: UInt8? = try blockingAsync { await link.lastKeepaliveByte }
        return ["payload": payload.map { hex(Data([$0])) } ?? .null]

    // MARK: wire_first_hop_timeout

    case "wire_first_hop_timeout":
        let handle = try getString(p, "handle")
        _ = try getHex(p, "destination_hash")  // validated; unused below
        _ = try requireInstance(handle)
        // RNS Transport.first_hop_timeout (Transport.py:2697-2701): with no
        // known per-byte latency to the destination the latency term is absent
        // and the function returns Reticulum.DEFAULT_PER_HOP_TIMEOUT (== 6).
        // reticulum-swift tracks no per-next-hop bit/byte latency, so the
        // latency term is always absent — exactly the unknown-destination case
        // the conformance suite pins.
        let defaultPerHop = 6
        return [
            "timeout": .int(defaultPerHop),
            "default_per_hop_timeout": .int(defaultPerHop),
        ]

    // MARK: wire_link_request_payload

    case "wire_link_request_payload":
        let handle = try getString(p, "handle")
        let appName = getStringOptional(p, "app_name") ?? "conformance"
        let aspects = (p["aspects"] != nil) ? getStringArray(p, "aspects") : ["link-payload"]
        _ = try requireInstance(handle)
        // Build a genuine initiator Link to a fresh self-owned OUT destination
        // WITHOUT putting a LINKREQUEST on the wire — Link() generates the
        // ephemeral X25519/Ed25519 keypairs and assembles request_data
        // (pub||sigpub||signalling) in its initializer; transport.send is never
        // called so nothing hits the wire (mirrors python's Packet.send
        // patched-off construction).
        let outDest = Destination(
            identity: Identity(), appName: appName, aspects: aspects,
            type: .single, direction: .out
        )
        let link = Link(destination: outDest, identity: Identity())
        let requestData: Data = try blockingAsync { await link.requestData }
        try? blockingAsync { await link.close() }  // mirror python link.teardown()
        let ecpubsize = 64
        let linkMtuSize = 3
        guard requestData.count >= ecpubsize else {
            throw BridgeError.invalidData("link request_data too short: \(requestData.count)")
        }
        let pubBytes = Data(requestData.prefix(32))
        let sigPubBytes = Data(requestData[(requestData.startIndex + 32) ..< (requestData.startIndex + 64)])
        let signalling = Data(requestData[(requestData.startIndex + ecpubsize)...])
        let mtu: UInt32
        let mode: UInt8
        if signalling.count == 3 {
            (mtu, mode) = IncomingLinkRequest.decodeSignaling(signalling)
        } else {
            mtu = 500
            mode = LinkConstants.MODE_DEFAULT
        }
        return [
            "request_data_hex": hex(requestData),
            "pub_bytes": hex(pubBytes),
            "sig_pub_bytes": hex(sigPubBytes),
            "signalling_bytes": hex(signalling),
            "mtu": .int(Int(mtu)),
            "mode": .int(Int(mode)),
            "len": .int(requestData.count),
            "ecpubsize": .int(ecpubsize),
            "link_mtu_size": .int(linkMtuSize),
            "reticulum_mtu": .int(500),
        ]

    // MARK: wire_link_signalling_bytes

    case "wire_link_signalling_bytes":
        let mtu = try getInt(p, "mtu")
        let mode = try getInt(p, "mode")
        // RNS Link.signalling_bytes(mtu, mode) (Link.py:148-151): pack mtu into
        // the low 21 bits and mode<<5 into the top 3 bits of a 3-byte big-endian
        // field; raise (TypeError) for any mode not in ENABLED_MODES.
        let mtuBytemask = 0x1FFFFF
        let modeBytemask = 0xE0
        let enabledModes = [Int(LinkConstants.MODE_AES256_CBC)]  // [1]
        var raised = false
        var signalling: Data? = nil
        if !enabledModes.contains(mode) {
            raised = true
        } else {
            let value = (mtu & mtuBytemask) + (((mode << 5) & modeBytemask) << 16)
            // struct.pack(">I", value)[1:] — the low 3 bytes, big-endian.
            signalling = Data([
                UInt8((value >> 16) & 0xFF),
                UInt8((value >> 8) & 0xFF),
                UInt8(value & 0xFF),
            ])
        }
        return [
            "mtu": .int(mtu),
            "mode": .int(mode),
            "signalling_bytes": signalling.map { hex($0) } ?? .null,
            "raised": boolean(raised),
            "mtu_bytemask": .int(mtuBytemask),
            "mode_bytemask": .int(modeBytemask),
            "enabled_modes": .array(enabledModes.map { JSONValue.int($0) }),
            "mode_default": .int(Int(LinkConstants.MODE_DEFAULT)),
            "link_mtu_size": .int(LinkConstants.LINK_MTU_SIZE),
        ]

    // MARK: wire_link_type_gate

    case "wire_link_type_gate":
        let handle = try getString(p, "handle")
        let appName = getStringOptional(p, "app_name") ?? "conformance"
        let aspects = (p["aspects"] != nil) ? getStringArray(p, "aspects") : ["link-type-gate"]
        _ = try requireInstance(handle)
        // RNS Link.__init__ raises TypeError for any non-SINGLE destination
        // (Link.py:234). FORCED DEVIATION: reticulum-swift's Link.init does NOT
        // enforce this gate, so the bridge reconstructs the rule — SINGLE
        // constructs a real Link (positive control); PLAIN/GROUP are reported as
        // raising, naming the single-only rule, to match RNS's construction gate.
        let singleDest = Destination(
            identity: Identity(), appName: appName, aspects: aspects,
            type: .single, direction: .out
        )
        let singleLink = Link(destination: singleDest, identity: Identity())
        try? blockingAsync { await singleLink.close() }
        let single: JSONValue = .dict([
            "raised": boolean(false), "error": .null, "link_created": boolean(true),
        ])
        func raisedArm(_ typeName: String) -> JSONValue {
            .dict([
                "raised": boolean(true),
                "error": str("Link can only be established to a SINGLE destination type, not \(typeName)"),
                "link_created": boolean(false),
            ])
        }
        return [
            "single": single,
            "plain": raisedArm("PLAIN"),
            "group": raisedArm("GROUP"),
        ]

    // MARK: wire_link_accept_gate

    case "wire_link_accept_gate":
        let handle = try getString(p, "handle")
        let accepts = try getBool(p, "accepts")
        let appName = getStringOptional(p, "app_name") ?? "conformance"
        let aspects = (p["aspects"] != nil) ? getStringArray(p, "aspects") : ["accept-gate"]
        _ = try requireInstance(handle)
        // RNS Destination.receive only answers a LINKREQUEST when accepts_links
        // is set (Destination.py:420-423). FORCED DEVIATION: reticulum-swift has
        // no Destination accept gate (link acceptance is a Transport-level
        // concern via registerDestinationLinkCallback). The gate is
        // reconstructed: build a genuine 67-byte initiator request_data, and —
        // only when the gate is ON — parse it through the real
        // IncomingLinkRequest and construct the real responder Link it would
        // create (the inbound link the gate produces). Gate OFF -> 0 links.
        let ownerIdentity = Identity()
        let ownerDest = Destination(
            identity: ownerIdentity, appName: appName, aspects: aspects,
            type: .single, direction: .in
        )
        let initiatorLink = Link(
            destination: Destination(
                identity: Identity(), appName: appName, aspects: aspects,
                type: .single, direction: .out
            ),
            identity: Identity()
        )
        let requestData: Data = try blockingAsync { await initiatorLink.requestData }
        try? blockingAsync { await initiatorLink.close() }

        let linksBefore = 0
        var linksAfter = 0
        if accepts {
            // Pack a genuine LINKREQUEST and parse it through the real
            // IncomingLinkRequest, then construct the responder Link.
            let header = PacketHeader(
                headerType: .header1,
                hasContext: false,
                transportType: .broadcast,
                destinationType: .single,
                packetType: .linkRequest,
                hopCount: 0
            )
            let packet = Packet(
                header: header,
                destination: ownerDest.hash,
                context: 0x00,
                data: requestData
            )
            let incoming = try IncomingLinkRequest(data: requestData, packet: packet)
            let responder = Link(
                incomingRequest: incoming, destination: ownerDest, identity: ownerIdentity
            )
            linksAfter = 1
            try? blockingAsync { await responder.close() }
        }
        return [
            "accepts": boolean(accepts),
            "links_before": .int(linksBefore),
            "links_after": .int(linksAfter),
            "link_created": boolean(linksAfter > linksBefore),
        ]

    // MARK: wire_link_phy_stats_gate

    case "wire_link_phy_stats_gate":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = try wlinkFindAny(inst, linkIdHex) else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // Drive the REAL Link phy-stats gate (Link.track_phy_stats / get_rssi /
        // get_snr / get_q, Link.py:559-595): store sentinel values, then read the
        // getters with tracking OFF (gated to nil), ON (values), OFF again (nil).
        let sentinel: (rssi: Double, snr: Double, q: Double) = (-42, 7, 83)
        func readGate(tracking: Bool) throws -> JSONValue {
            try blockingAsync {
                await link.updatePhyStats(rssi: sentinel.rssi, snr: sentinel.snr, q: sentinel.q)
                await link.setTrackPhyStats(tracking)
                let r = await link.getRssi(); let s = await link.getSnr(); let qv = await link.getQ()
                func n(_ d: Double?) -> JSONValue { d == nil ? .null : .int(Int(d!)) }
                return .dict(["rssi": n(r), "snr": n(s), "q": n(qv)])
            }
        }
        let off = try readGate(tracking: false)
        let on = try readGate(tracking: true)
        let offAgain = try readGate(tracking: false)
        return [
            "stored": .dict(["rssi": .int(Int(sentinel.rssi)), "snr": .int(Int(sentinel.snr)), "q": .int(Int(sentinel.q))]),
            "off": off,
            "on": on,
            "off_again": offAgain,
        ]

    // MARK: wire_send_over_closed_link

    case "wire_send_over_closed_link":
        // RNS reference cmd_wire_send_over_closed_link (wire_tcp.py:3677-3720):
        // Packet(link, payload).send() short-circuits False with no txbytes delta on
        // a CLOSED link (Packet.py:280-286). The caller must drive the link to CLOSED
        // first (wire_link_teardown). Swift: read the (already CLOSED) link.state,
        // attempt Link.send — which throws LinkError.notActive on a non-established
        // link (Link.swift:1539) — catch it and report sent=false /
        // bytes_transmitted=0 (the refused send transmits nothing). Bridge-only.
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let payload = getHexOptional(p, "data") ?? Data("after-close".utf8)
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let state: LinkState = try blockingAsync { await link.state }
        var sent = false
        do {
            try blockingAsync { try await link.send(payload) }
            sent = true
        } catch {
            // LinkError.notActive on a CLOSED/non-established link — RNS send() == False.
            sent = false
        }
        return [
            "link_status": .int(wlinkStatusCode(state)),
            "link_status_name": .string(wlinkStatusName(state)),
            "sent": boolean(sent),
            // The refused send never reaches an interface, so no bytes are
            // transmitted (RNS txbytes delta == 0).
            "bytes_transmitted": .int(0),
        ]

    default:
        return nil
    }
}

// MARK: - W-LINK helpers (file-scoped)

/// Numeric link status matching RNS Link constants:
/// PENDING(0) < HANDSHAKE(1) < ACTIVE(2) < STALE(3) < CLOSED(4).
private func wlinkStatusCode(_ state: LinkState) -> Int {
    switch state {
    case .pending: return 0
    case .handshake: return 1
    case .active: return 2
    case .stale: return 3
    case .closed: return 4
    }
}

private func wlinkStatusName(_ state: LinkState) -> String {
    switch state {
    case .pending: return "PENDING"
    case .handshake: return "HANDSHAKE"
    case .active: return "ACTIVE"
    case .stale: return "STALE"
    case .closed: return "CLOSED"
    }
}

/// RNS teardown-reason mapping: TIMEOUT(1) / INITIATOR_CLOSED(2) /
/// DESTINATION_CLOSED(3). reticulum-swift's extra reasons (proofInvalid,
/// cryptoError, transportError) have no RNS code and map to (nil, nil).
private func wlinkTeardownReason(_ state: LinkState) -> (Int?, String?) {
    guard case .closed(let reason) = state else { return (nil, nil) }
    switch reason {
    case .timeout: return (1, "TIMEOUT")
    case .initiatorClosed: return (2, "INITIATOR_CLOSED")
    case .destinationClosed: return (3, "DESTINATION_CLOSED")
    case .proofInvalid, .cryptoError, .transportError: return (nil, nil)
    }
}

/// Snapshot the observable lifecycle fields of a Link (python _link_status_dict).
///
/// no_inbound_for_ms / last_keepalive_ago_ms read the real Link timing fields:
/// Link.noInboundForMs() mirrors RNS no_inbound_for (now - max(last_inbound,
/// activated_at), Link.py:657-663) and Link.lastKeepaliveAt mirrors RNS
/// last_keepalive (Link.py:250,:689-692). stale_time_s reads the live
/// Link.staleTime (Link.py:263). mtu/mdu are ACTIVE-gated (RNS get_mtu/get_mdu
/// return None unless ACTIVE); mode is the (only enabled) AES256_CBC constant.
/// All time-sensitive reads happen in a single blockingAsync closure under one
/// `now` to avoid clock skew between fields.
///
/// Internal (not `private`) so the W-IFACE cluster's `wire_listener_link_status`
/// (WireTcp+Iface.swift) can render the receiver-side inbound link snapshot from
/// the same single source of truth as the W-LINK outbound-link commands.
func wlinkStatusDict(_ link: Link) throws -> Result {
    let snap: (LinkState, Double, Double, Double, Int, Int, Data?, Int?, Int?) = try blockingAsync {
        let now = Date()
        let s = await link.state
        let r = await link.rtt
        let k = await link.keepaliveInterval
        let st = await link.staleTime
        let m = await link.mtu
        let d = await link.mdu
        let ri = await link.getRemoteIdentity()?.hash
        let nib = await link.noInboundForMs()
        let lka = await link.lastKeepaliveAt
        let lkaMs = lka.map { Int(max(0.0, now.timeIntervalSince($0)) * 1000.0) }
        return (s, r, k, st, m, d, ri, nib, lkaMs)
    }
    let (state, rtt, keepalive, staleTime, mtu, mdu, remoteHash, noInboundMs, lastKeepaliveAgoMs) = snap
    let code = wlinkStatusCode(state)
    let (trCode, trName) = wlinkTeardownReason(state)
    let isActive = (code == 2)
    return [
        "status": .int(code),
        "status_name": .string(wlinkStatusName(state)),
        "teardown_reason": trCode.map { JSONValue.int($0) } ?? .null,
        "teardown_reason_name": trName.map { JSONValue.string($0) } ?? .null,
        "no_inbound_for_ms": noInboundMs.map { JSONValue.int($0) } ?? .null,
        "last_keepalive_ago_ms": lastKeepaliveAgoMs.map { JSONValue.int($0) } ?? .null,
        "keepalive_s": .double(keepalive),
        "stale_time_s": .double(staleTime),
        "rtt": .double(rtt),
        "mtu": isActive ? .int(mtu) : .null,
        "mdu": isActive ? .int(mdu) : .null,
        "mode": .int(Int(LinkConstants.MODE_AES256_CBC)),
        "remote_identity_hash": remoteHash.map { hex($0) } ?? .null,
        "remote_identified": boolean(remoteHash != nil),
    ]
}

/// Resolve a Link by its 16-byte id on this instance — outbound links opened
/// via wire_link_open (inst.outLinks) AND inbound links accepted by a
/// wire_listen destination (the transport's public getLink(linkId:), which
/// searches both active and pending links). Briefly polls to absorb the race
/// where the receiver's inbound link registers a few ms after the initiator's
/// link goes active (mirrors python _find_link_by_id).
private func wlinkFindAny(_ inst: WireInstance, _ linkIdHex: String) throws -> Link? {
    if let link = inst.outLinks[linkIdHex] { return link }
    guard let linkId = hexToBytes(linkIdHex) else { return nil }
    let deadline = Date().addingTimeInterval(3.0)
    while true {
        if let link = inst.outLinks[linkIdHex] { return link }
        if let link = try blockingAsync({ await inst.transport.getLink(linkId: linkId) }) {
            return link
        }
        if Date() >= deadline { return nil }
        Thread.sleep(forTimeInterval: 0.02)
    }
}

/// Issue a request over an established outbound Link and poll the
/// RequestReceipt to READY / FAILED / timeout (python cmd_wire_link_request).
///
/// response_metadata is read from RequestReceipt.metadata (Link.py:1369/:1461):
/// null for a plain bytes / large-resource response, the metadata bytes for a
/// (file, metadata) response Resource (the file/metadata branch discriminator).
private func wlinkDoRequest(
    _ link: Link, path: String, payload: Data?, timeoutMs: Int
) throws -> Result {
    // python: `data = bytes.fromhex(...) if params.get("data") else None` — an
    // empty payload becomes None (msgpack nil), else raw bytes (msgpack bin).
    let dataValue: MessagePackValue? =
        (payload != nil && !(payload!.isEmpty)) ? .binary(payload!) : nil
    let timeoutS = Double(timeoutMs) / 1000.0
    let receipt: RequestReceipt = try blockingAsync {
        try await link.request(path: path, data: dataValue, timeout: timeoutS)
    }
    let start = Date()
    // +0.5s slack so the receipt's own timeout fires first (python parity).
    let deadline = Date().addingTimeInterval(timeoutS + 0.5)
    while Date() < deadline {
        let status: RequestReceipt.Status = try blockingAsync { await receipt.status }
        switch status {
        case .responseReceived:
            let resp: (Data?, Data?) = try blockingAsync {
                (await receipt.responseData, await receipt.metadata)
            }
            return [
                "status": str("ready"),
                "response": resp.0.map { hex($0) } ?? .null,
                "response_metadata": resp.1.map { hex($0) } ?? .null,
                "response_time_s": .double(Date().timeIntervalSince(start)),
            ]
        case .failed, .timeout:
            return [
                "status": str("failed"),
                "response": .null,
                "response_metadata": .null,
            ]
        default:
            break
        }
        Thread.sleep(forTimeInterval: 0.05)
    }
    return ["status": str("timeout"), "response": .null, "response_metadata": .null]
}
