//
//  ReticulumTransport+Transport.swift
//  ReticulumSwift
//
//  Transport node forwarding logic: link_table, reverse_table, packet_hashlist.
//  Matches Python RNS Transport.py link_table, reverse_table, and packet_hashlist.
//
//  When transport mode is enabled, this node can:
//  - Forward LINKREQUESTs to destinations via the path table
//  - Route LINKPROOFs back to the requester via the link table
//  - Forward link DATA bidirectionally between link endpoints
//  - Forward non-link DATA packets and route their PROOFs back
//
//  Python references:
//  - link_table: Transport.py ~line 1482
//  - reverse_table: Transport.py ~line 1551
//  - packet_hashlist: Transport.py ~line 1230
//

import Foundation
import OSLog

// MARK: - Transport Forwarding Methods

extension ReticulumTransport {

    // MARK: - Link Request Forwarding

    /// Forward a LINKREQUEST through this transport node.
    ///
    /// When a LINKREQUEST arrives addressed to our transport identity but
    /// the destination isn't local, look up the path and forward it.
    /// Populates the link_table for subsequent PROOF and DATA routing.
    ///
    /// Python reference: Transport.py ~line 1482
    ///
    /// - Parameters:
    ///   - packet: The LINKREQUEST packet
    ///   - interfaceId: Interface that received the packet
    public func forwardLinkRequest(_ packet: Packet, from interfaceId: String) async {
        let destHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()

        // Only forward HEADER_2 packets addressed to our transport identity
        guard packet.header.headerType == .header2,
              let transportAddr = packet.transportAddress,
              transportAddr == transportIdentityHash else {
            onDiagnostic?("[TRANSPORT] LINKREQUEST not addressed to us, ignoring dest=\(destHex)")
            return
        }

        // Look up path to the actual destination
        guard let pathEntry = await pathTable.lookup(destinationHash: packet.destination) else {
            onDiagnostic?("[TRANSPORT] No path to dest=\(destHex), dropping LINKREQUEST")
            return
        }

        // Compute link_id from the packet (same formula as IncomingLinkRequest.calculateLinkId)
        // The hashable part is hop-independent and transport-address-independent,
        // so the link_id is the same regardless of the transport chain.
        let linkId = computeLinkIdFromPacket(packet)
        let linkIdHex = linkId.prefix(8).map { String(format: "%02x", $0) }.joined()

        // Don't forward if we already have this link in the table
        guard linkTable[linkId] == nil else {
            onDiagnostic?("[TRANSPORT] Duplicate LINKREQUEST for link=\(linkIdHex), ignoring")
            return
        }

        // Determine next hop and build forwarded packet
        let outboundInterfaceId = pathEntry.interfaceId
        let incomingHops = packet.header.hopCount
        let newHops = incomingHops &+ 1  // Increment hop count (Python inbound() line 1319)

        // Guard max hops
        guard newHops <= TransportConstants.PATHFINDER_M else {
            onDiagnostic?("[TRANSPORT] LINKREQUEST exceeded max hops (\(newHops)), dropping")
            return
        }

        // D9+C7: Clamp MTU signaling considering both inbound and outbound interfaces.
        // Python reference: Transport.py lines 1458-1480
        var packetToForward = packet
        if packet.data.count > LinkConstants.ECPUBSIZE {
            let outboundIface = getInterface(id: outboundInterfaceId)
            let inboundIface = getInterface(id: interfaceId)
            let outMtu = outboundIface?.hwMtu ?? 0
            let inMtu = inboundIface?.hwMtu ?? 0

            let signalingStart = packet.data.count - IncomingLinkRequest.MTU_SIZE
            let signalingBytes = Data(packet.data[signalingStart...])
            let (requestedMtu, mode) = IncomingLinkRequest.decodeSignaling(signalingBytes)

            if outMtu == 0 {
                // C7: No HW_MTU on outbound: strip signaling entirely
                let newData = Data(packet.data.prefix(signalingStart))
                packetToForward = Packet(
                    header: packet.header,
                    destination: packet.destination,
                    transportAddress: packet.transportAddress,
                    context: packet.context,
                    data: newData
                )
                onDiagnostic?("[TRANSPORT] Stripped LINKREQUEST MTU signaling (outbound has no HW_MTU)")
            } else {
                // C7: Clamp to min of both interfaces
                let effectiveMtu = inMtu > 0 ? UInt32(min(outMtu, inMtu)) : UInt32(outMtu)
                if requestedMtu > effectiveMtu {
                    let clampedSignaling = IncomingLinkRequest.encodeSignaling(mtu: effectiveMtu, mode: mode)
                    var newData = Data(packet.data.prefix(signalingStart))
                    newData.append(clampedSignaling)
                    packetToForward = Packet(
                        header: packet.header,
                        destination: packet.destination,
                        transportAddress: packet.transportAddress,
                        context: packet.context,
                        data: newData
                    )
                    onDiagnostic?("[TRANSPORT] Clamped LINKREQUEST MTU from \(requestedMtu) to \(effectiveMtu) for interface \(outboundInterfaceId)")
                }
            }
        }

        // Compute remaining hops from this node to destination
        let remainingHops = pathEntry.hopCount

        // B3: Python has three branches (Transport.py lines 1433-1449):
        //   remaining_hops > 1: rewrite as HEADER_2 with next hop
        //   remaining_hops == 1: convert to HEADER_1 (last hop)
        //   remaining_hops == 0: keep header, just update hop count (destination is local to next interface)
        let forwardedRaw: Data
        if remainingHops > 1, let nextHop = pathEntry.nextHop {
            // Multi-hop to destination: rewrite as HEADER_2 with new next hop
            forwardedRaw = rewriteAsHeader2(
                packet: packetToForward,
                newTransportAddress: nextHop,
                newHopCount: newHops
            )
        } else if remainingHops == 1 {
            // Last hop to destination: convert to HEADER_1
            forwardedRaw = rewriteAsHeader1(packet: packetToForward, newHopCount: newHops)
        } else {
            // remaining_hops == 0: keep header unchanged, just update hop count
            forwardedRaw = rewriteHopCount(rawPacket: packetToForward.encode(), newHopCount: newHops)
        }

        // Store link table entry
        // B4: Python uses max(1, remaining_hops) not (remaining_hops + 1)
        // C8: Add extra_link_proof_timeout based on inbound interface bitrate
        let extraTimeout: TimeInterval
        if let inboundIface = getInterface(id: interfaceId), inboundIface.config.bitrate > 0 {
            extraTimeout = Double(500 * 8) / Double(inboundIface.config.bitrate)
        } else {
            extraTimeout = 0
        }
        let proofTimeout = Date().addingTimeInterval(
            extraTimeout + LinkConstants.ESTABLISHMENT_TIMEOUT_PER_HOP * Double(max(1, remainingHops))
        )
        let entry = LinkTableEntry(
            nextHopTransportId: pathEntry.nextHop ?? Data(),
            outboundInterfaceId: outboundInterfaceId,
            remainingHops: UInt8(clamping: remainingHops),
            receivingInterfaceId: interfaceId,
            takenHops: newHops,  // Post-increment value (Python increments hops globally before dispatch)
            destinationHash: packet.destination,
            proofTimeout: proofTimeout
        )
        linkTable[linkId] = entry

        // Send on outbound interface
        do {
            try await sendToInterface(forwardedRaw, interfaceId: outboundInterfaceId)
            // D12: Touch path table timestamp after successful forwarding
            await pathTable.touch(destinationHash: packet.destination)
            let nextHopHex = pathEntry.nextHop?.prefix(8).map { String(format: "%02x", $0) }.joined() ?? "direct"
            onDiagnostic?("[TRANSPORT] Forwarded LINKREQUEST link=\(linkIdHex) → \(outboundInterfaceId) nextHop=\(nextHopHex) hops=\(newHops)")
            print("[TRANSPORT] Forwarded LINKREQUEST link=\(linkIdHex) dest=\(destHex) via=\(outboundInterfaceId) hops=\(newHops)")
        } catch {
            // Failed to forward — remove link table entry
            linkTable.removeValue(forKey: linkId)
            onDiagnostic?("[TRANSPORT] Failed to forward LINKREQUEST: \(error)")
        }
    }

    // MARK: - Link Proof Forwarding

    /// Forward a LINKPROOF back to the link requester via the link table.
    ///
    /// The proof arrives from the destination side (outbound interface) and
    /// must be forwarded back on the receiving interface (toward requester).
    ///
    /// Python reference: Transport.py ~line 1514
    ///
    /// - Parameters:
    ///   - packet: The PROOF packet (destination = link_id)
    ///   - linkEntry: The link table entry for this link
    ///   - interfaceId: Interface that received the proof
    public func forwardLinkProof(_ packet: Packet, linkEntry: LinkTableEntry, from interfaceId: String) async {
        let linkIdHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()

        // Proof should arrive from the outbound side (destination direction)
        guard interfaceId == linkEntry.outboundInterfaceId else {
            onDiagnostic?("[TRANSPORT] LINKPROOF for link=\(linkIdHex) arrived on wrong interface (\(interfaceId) != \(linkEntry.outboundInterfaceId))")
            return
        }

        // D2/B2: Hop count must match remainingHops stored when LINKREQUEST was forwarded
        // Python reference: Transport.py line 2018
        // Python checks post-incremented packet.hops (line 1319: packet.hops += 1 before dispatch).
        // Swift doesn't do global increment, so we add 1 to the wire hop count for comparison.
        let proofHopsPostIncrement = packet.header.hopCount &+ 1
        guard proofHopsPostIncrement == linkEntry.remainingHops else {
            onDiagnostic?("[TRANSPORT] LINKPROOF for link=\(linkIdHex) hop count mismatch: hops=\(proofHopsPostIncrement) expected=\(linkEntry.remainingHops)")
            return
        }

        // D13: Validate proof data length
        // Python reference: Transport.py line 2021
        // Valid lengths: SIGLENGTH/8 + ECPUBSIZE/2 (= 64+32 = 96) or + LINK_MTU_SIZE (96+3 = 99)
        let proofMinLen = 96  // sig(64) + encPubkey(32)
        let proofMaxLen = 99  // sig(64) + encPubkey(32) + signaling(3)
        guard packet.data.count == proofMinLen || packet.data.count == proofMaxLen else {
            onDiagnostic?("[TRANSPORT] LINKPROOF for link=\(linkIdHex) invalid data length: \(packet.data.count) (expected \(proofMinLen) or \(proofMaxLen))")
            return
        }

        // D1: Validate LINKPROOF signature against recalled peer identity
        // Python reference: Transport.py lines 2013-2042
        // Look up the destination's signing key from the path table
        if let pathEntry = await pathTable.lookup(destinationHash: linkEntry.destinationHash),
           pathEntry.signingPublicKey.count == 32 {
            let linkId = packet.destination  // 16-byte link_id
            let peerEncPubBytes = Data(packet.data[64..<96])  // peer encryption public key
            let peerSigPubBytes = pathEntry.signingPublicKey   // destination's signing public key

            // Reconstruct signed_data: link_id + peer_pub_bytes + peer_sig_pub_bytes [+ signaling]
            var signedData = Data()
            signedData.append(linkId)
            signedData.append(peerEncPubBytes)
            signedData.append(peerSigPubBytes)
            if packet.data.count > proofMinLen {
                signedData.append(Data(packet.data[96...]))  // signaling bytes
            }

            let signature = Data(packet.data.prefix(64))
            do {
                let valid = try Identity.verify(signature: signature, for: signedData, publicKey: peerSigPubBytes)
                guard valid else {
                    onDiagnostic?("[TRANSPORT] LINKPROOF for link=\(linkIdHex) FAILED signature validation")
                    return
                }
                onDiagnostic?("[TRANSPORT] LINKPROOF for link=\(linkIdHex) signature validated")
            } catch {
                // Key format error — can't validate, treat like Python's recall() returning None
                onDiagnostic?("[TRANSPORT] LINKPROOF for link=\(linkIdHex) key error, skipping validation: \(error)")
            }
        } else {
            // No path entry or no valid signing key — can't validate
            // Python: Identity.recall() returning None skips validation but still forwards
            onDiagnostic?("[TRANSPORT] LINKPROOF for link=\(linkIdHex) cannot validate (no path/identity for destination)")
        }

        // D5: Record deferred packet hash now that we've decided to forward
        await packetHashlist.record(packet.getFullHash())

        // Increment hop count and forward on receiving interface (back toward requester)
        let newHops = packet.header.hopCount &+ 1
        let forwardedRaw = rewriteHopCount(rawPacket: packet.encode(), newHopCount: newHops)

        // C23: Set validated flag BEFORE send (matches Python which sets before transmit)
        linkTable[packet.destination]?.validated = true
        // C22: Do NOT update timestamp on LINKPROOF forwarding (Python only updates during DATA forwarding)

        do {
            try await sendToInterface(forwardedRaw, interfaceId: linkEntry.receivingInterfaceId)

            onDiagnostic?("[TRANSPORT] Forwarded LINKPROOF link=\(linkIdHex) → \(linkEntry.receivingInterfaceId) hops=\(newHops)")
            print("[TRANSPORT] Forwarded LINKPROOF link=\(linkIdHex) via=\(linkEntry.receivingInterfaceId) hops=\(newHops)")
        } catch {
            onDiagnostic?("[TRANSPORT] Failed to forward LINKPROOF: \(error)")
        }
    }

    // MARK: - Link Data Forwarding

    /// Forward link DATA bidirectionally through this transport node.
    ///
    /// Python routing logic (Transport.py ~lines 1514-1553):
    /// - If packet arrived on outbound interface → forward on receiving interface (toward initiator)
    /// - If packet arrived on receiving interface → forward on outbound interface (toward responder)
    ///
    /// - Parameters:
    ///   - packet: Link DATA packet (destination = link_id)
    ///   - linkEntry: The link table entry for this link
    ///   - interfaceId: Interface that received the packet
    public func forwardLinkData(_ packet: Packet, linkEntry: LinkTableEntry, from interfaceId: String) async {
        let linkIdHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()

        // B1: Python does `packet.hops += 1` globally (line 1319) BEFORE any checks.
        // All hop comparisons in Python use the post-incremented value.
        // Swift doesn't do global increment, so add 1 to wire hop count for comparisons.
        let hopsPostIncrement = packet.header.hopCount &+ 1

        // Determine direction and validate hop count
        // Python reference: Transport.py lines 1521-1537
        let targetInterfaceId: String
        if linkEntry.outboundInterfaceId == linkEntry.receivingInterfaceId {
            // D4: Same-interface case — both sides of the link on the same interface
            // Accept if hops match either direction
            guard hopsPostIncrement == linkEntry.remainingHops || hopsPostIncrement == linkEntry.takenHops else {
                onDiagnostic?("[TRANSPORT] Link DATA for link=\(linkIdHex) hop count mismatch (same-if): hops=\(hopsPostIncrement) taken=\(linkEntry.takenHops) remaining=\(linkEntry.remainingHops)")
                await packetHashlist.remove(packet.getFullHash())  // E17
                return
            }
            targetInterfaceId = linkEntry.outboundInterfaceId
        } else if interfaceId == linkEntry.outboundInterfaceId {
            // Data flowing from responder toward initiator
            // D3: Hop count must match remainingHops (outbound direction)
            guard hopsPostIncrement == linkEntry.remainingHops else {
                onDiagnostic?("[TRANSPORT] Link DATA for link=\(linkIdHex) hop count mismatch (outbound): hops=\(hopsPostIncrement) expected=\(linkEntry.remainingHops)")
                await packetHashlist.remove(packet.getFullHash())  // E17
                return
            }
            targetInterfaceId = linkEntry.receivingInterfaceId
        } else if interfaceId == linkEntry.receivingInterfaceId {
            // Data flowing from initiator toward responder
            // D3: Hop count must match takenHops (receiving direction)
            guard hopsPostIncrement == linkEntry.takenHops else {
                onDiagnostic?("[TRANSPORT] Link DATA for link=\(linkIdHex) hop count mismatch (receiving): hops=\(hopsPostIncrement) expected=\(linkEntry.takenHops)")
                await packetHashlist.remove(packet.getFullHash())  // E17
                return
            }
            targetInterfaceId = linkEntry.outboundInterfaceId
        } else {
            onDiagnostic?("[TRANSPORT] Link DATA for link=\(linkIdHex) arrived on unknown interface \(interfaceId)")
            await packetHashlist.remove(packet.getFullHash())  // E17
            return
        }

        // D5: Record deferred packet hash now that we've decided to forward
        await packetHashlist.record(packet.getFullHash())

        // Increment hop count (use the post-incremented value, matching Python's behavior)
        let forwardedRaw = rewriteHopCount(rawPacket: packet.encode(), newHopCount: hopsPostIncrement)

        // Touch timestamp for keepalive
        linkTable[packet.destination]?.timestamp = Date()

        do {
            try await sendToInterface(forwardedRaw, interfaceId: targetInterfaceId)
            onDiagnostic?("[TRANSPORT] Forwarded link DATA link=\(linkIdHex) → \(targetInterfaceId) hops=\(hopsPostIncrement)")
        } catch {
            onDiagnostic?("[TRANSPORT] Failed to forward link DATA: \(error)")
        }
    }

    // MARK: - Regular Data Forwarding

    /// Forward a non-link HEADER_2 DATA packet through this transport node.
    ///
    /// Populates the reverse_table so the corresponding PROOF can be
    /// routed back to the sender.
    ///
    /// Python reference: Transport.py ~line 1551
    ///
    /// - Parameters:
    ///   - packet: DATA packet (HEADER_2 addressed to our transport)
    ///   - interfaceId: Interface that received the packet
    public func forwardDataPacket(_ packet: Packet, from interfaceId: String) async {
        let destHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()

        // Look up path to the actual destination
        guard let pathEntry = await pathTable.lookup(destinationHash: packet.destination) else {
            onDiagnostic?("[TRANSPORT] No path to dest=\(destHex) for DATA forwarding, dropping")
            return
        }

        let outboundInterfaceId = pathEntry.interfaceId
        let newHops = packet.header.hopCount &+ 1

        guard newHops <= TransportConstants.PATHFINDER_M else {
            onDiagnostic?("[TRANSPORT] DATA forwarding exceeded max hops (\(newHops)), dropping")
            return
        }

        // B3: Three branches matching Python (Transport.py lines 1433-1449)
        let forwardedRaw: Data
        if pathEntry.hopCount > 1, let nextHop = pathEntry.nextHop {
            forwardedRaw = rewriteAsHeader2(
                packet: packet,
                newTransportAddress: nextHop,
                newHopCount: newHops
            )
        } else if pathEntry.hopCount == 1 {
            forwardedRaw = rewriteAsHeader1(packet: packet, newHopCount: newHops)
        } else {
            // remaining_hops == 0: keep header, just update hop count
            forwardedRaw = rewriteHopCount(rawPacket: packet.encode(), newHopCount: newHops)
        }

        // Store reverse table entry keyed by packet's truncated hash
        // so the proof can be routed back
        let packetHash = packet.getTruncatedHash()
        reverseTable[packetHash] = ReverseTableEntry(
            receivingInterfaceId: interfaceId,
            outboundInterfaceId: outboundInterfaceId
        )

        do {
            try await sendToInterface(forwardedRaw, interfaceId: outboundInterfaceId)
            // D12: Touch path table timestamp after successful forwarding
            await pathTable.touch(destinationHash: packet.destination)
            onDiagnostic?("[TRANSPORT] Forwarded DATA dest=\(destHex) → \(outboundInterfaceId) hops=\(newHops)")
            print("[TRANSPORT] Forwarded DATA dest=\(destHex) via=\(outboundInterfaceId) hops=\(newHops)")
        } catch {
            reverseTable.removeValue(forKey: packetHash)
            onDiagnostic?("[TRANSPORT] Failed to forward DATA: \(error)")
        }
    }

    // MARK: - Data Proof Forwarding

    /// Forward a data PROOF back via the reverse table.
    ///
    /// - Parameters:
    ///   - packet: PROOF packet
    ///   - reverseEntry: The reverse table entry for routing
    ///   - interfaceId: Interface that received the proof
    public func forwardDataProof(_ packet: Packet, reverseEntry: ReverseTableEntry, from interfaceId: String) async {
        let proofDestHex = packet.destination.prefix(8).map { String(format: "%02x", $0) }.joined()

        // D10: Proof must arrive on the outbound interface (the direction data was forwarded)
        // Python reference: Transport.py line 2093
        guard interfaceId == reverseEntry.outboundInterfaceId else {
            onDiagnostic?("[TRANSPORT] DATA PROOF for \(proofDestHex) arrived on wrong interface (\(interfaceId) != \(reverseEntry.outboundInterfaceId))")
            return
        }

        let newHops = packet.header.hopCount &+ 1
        let forwardedRaw = rewriteHopCount(rawPacket: packet.encode(), newHopCount: newHops)

        do {
            try await sendToInterface(forwardedRaw, interfaceId: reverseEntry.receivingInterfaceId)
            onDiagnostic?("[TRANSPORT] Forwarded DATA PROOF \(proofDestHex) → \(reverseEntry.receivingInterfaceId) hops=\(newHops)")
            print("[TRANSPORT] Forwarded DATA PROOF \(proofDestHex) via=\(reverseEntry.receivingInterfaceId) hops=\(newHops)")
        } catch {
            onDiagnostic?("[TRANSPORT] Failed to forward DATA PROOF: \(error)")
        }
    }

    // MARK: - Table Maintenance

    /// Remove stale entries from link_table and reverse_table.
    ///
    /// Called periodically from the retransmission loop.
    public func cullTransportTables() {
        let now = Date()

        // C21: Collect expired unvalidated entries before filtering (for path rediscovery)
        let expiredUnvalidated = linkTable.filter { (_, entry) in
            !entry.validated && now >= entry.proofTimeout
        }

        // Cull link table: remove unvalidated entries past proof timeout,
        // validated entries past the general link timeout,
        // C20: and entries referencing interfaces that no longer exist
        linkTable = linkTable.filter { (_, entry) in
            // C20: Check interfaces still exist
            guard getInterface(id: entry.outboundInterfaceId) != nil else { return false }
            guard getInterface(id: entry.receivingInterfaceId) != nil else { return false }

            if !entry.validated {
                return now < entry.proofTimeout
            } else {
                return now.timeIntervalSince(entry.timestamp) < TransportConstants.LINK_TIMEOUT
            }
        }

        // C21+E4: Trigger path rediscovery for expired unvalidated entries (4 conditions)
        // Python reference: Transport.py link_table cleanup, conditions 1-4
        for (_, entry) in expiredUnvalidated {
            let destHash = entry.destinationHash
            // Capture actor-isolated state before Task
            let lastReq = pathRequestTimestamps[destHash]
            let throttled = lastReq != nil && Date().timeIntervalSince(lastReq!) < TransportConstants.PATH_REQUEST_MI
            let recvMode = getInterfaceMode(for: entry.receivingInterfaceId)
            Task { [weak self] in
                guard let self = self else { return }
                let pathExists = await self.pathTable.lookup(destinationHash: destHash) != nil

                // Condition 1: Path missing
                if !pathExists {
                    await self.requestPath(for: destHash)
                    return
                }
                // Condition 2: Local client link (takenHops == 0)
                if entry.takenHops == 0 && !throttled {
                    await self.requestPath(for: destHash)
                    return
                }
                // Condition 3: Destination 1 hop away
                if entry.remainingHops == 1 && !throttled {
                    await self.requestPath(for: destHash)
                    if recvMode != .boundary {
                        await self.pathTable.markPathUnresponsive(destHash)
                    }
                    return
                }
                // Condition 4: Initiator 1 hop away (takenHops == 1)
                if entry.takenHops == 1 && !throttled {
                    await self.requestPath(for: destHash)
                    if recvMode != .boundary {
                        await self.pathTable.markPathUnresponsive(destHash)
                    }
                }
            }
        }

        // Cull reverse table: remove entries older than REVERSE_TIMEOUT
        // C20: and entries referencing interfaces that no longer exist
        reverseTable = reverseTable.filter { (_, entry) in
            guard getInterface(id: entry.outboundInterfaceId) != nil else { return false }
            guard getInterface(id: entry.receivingInterfaceId) != nil else { return false }
            return now.timeIntervalSince(entry.timestamp) < TransportConstants.REVERSE_TIMEOUT
        }
    }

    // MARK: - Raw Byte Rewrite Helpers

    /// Compute link_id from a LINKREQUEST packet.
    ///
    /// Uses the same formula as `IncomingLinkRequest.calculateLinkId()`:
    /// the hashable part (hop-independent, transport-address-independent)
    /// with signaling bytes trimmed.
    ///
    /// - Parameter packet: LINKREQUEST packet
    /// - Returns: 16-byte link ID
    func computeLinkIdFromPacket(_ packet: Packet) -> Data {
        // getHashablePart() already handles HEADER_1 vs HEADER_2
        // by skipping the transport address and hop byte
        var hashable = packet.getHashablePart()

        // Trim signaling bytes from end (same as Link.link_id_from_lr_packet)
        let ecPubSize = 64
        if packet.data.count > ecPubSize {
            let trimCount = packet.data.count - ecPubSize
            hashable = Data(hashable.dropLast(trimCount))
        }

        return Hashing.truncatedHash(hashable)
    }

    /// Rewrite a HEADER_2 packet with a new transport address and hop count.
    ///
    /// Used when forwarding through a multi-hop transport chain.
    ///
    /// - Parameters:
    ///   - packet: Original packet
    ///   - newTransportAddress: New 16-byte transport address
    ///   - newHopCount: New hop count
    /// - Returns: Raw packet bytes ready to send
    func rewriteAsHeader2(packet: Packet, newTransportAddress: Data, newHopCount: UInt8) -> Data {
        let newHeader = PacketHeader(
            headerType: .header2,
            hasContext: packet.header.hasContext,
            hasIFAC: packet.header.hasIFAC,
            transportType: .transport,
            destinationType: packet.header.destinationType,
            packetType: packet.header.packetType,
            hopCount: newHopCount
        )

        let newPacket = Packet(
            header: newHeader,
            destination: packet.destination,
            transportAddress: newTransportAddress,
            context: packet.context,
            data: packet.data
        )

        return newPacket.encode()
    }

    /// Rewrite a HEADER_2 packet as HEADER_1 (strip transport address).
    ///
    /// Used when the destination is on the last hop — no more transport routing needed.
    ///
    /// - Parameters:
    ///   - packet: Original HEADER_2 packet
    ///   - newHopCount: New hop count
    /// - Returns: Raw packet bytes ready to send
    func rewriteAsHeader1(packet: Packet, newHopCount: UInt8) -> Data {
        let newHeader = PacketHeader(
            headerType: .header1,
            hasContext: packet.header.hasContext,
            hasIFAC: packet.header.hasIFAC,
            transportType: .broadcast,
            destinationType: packet.header.destinationType,
            packetType: packet.header.packetType,
            hopCount: newHopCount
        )

        let newPacket = Packet(
            header: newHeader,
            destination: packet.destination,
            transportAddress: nil,
            context: packet.context,
            data: packet.data
        )

        return newPacket.encode()
    }

    /// Rewrite just the hop count byte in raw packet bytes.
    ///
    /// Byte 1 of the wire format is always the hop count.
    ///
    /// - Parameters:
    ///   - rawPacket: Raw packet bytes
    ///   - newHopCount: New hop count
    /// - Returns: Modified raw bytes
    func rewriteHopCount(rawPacket: Data, newHopCount: UInt8) -> Data {
        guard rawPacket.count >= 2 else { return rawPacket }
        var modified = rawPacket
        modified[1] = newHopCount
        return modified
    }

    // MARK: - Test Helpers

    /// Override transport identity hash for deterministic testing.
    public func setTransportIdentityHashForTest(_ hash: Data) {
        transportIdentityHash = hash
    }

    /// Insert pre-expired transport table entries for testing cleanup.
    func insertStaleTransportEntries() {
        let staleLink = Data(repeating: 0xEE, count: 16)
        linkTable[staleLink] = LinkTableEntry(
            timestamp: Date().addingTimeInterval(-1000),
            nextHopTransportId: Data(repeating: 0, count: 16),
            outboundInterfaceId: "x",
            remainingHops: 1,
            receivingInterfaceId: "y",
            takenHops: 1,
            destinationHash: Data(repeating: 0, count: 16),
            validated: false,
            proofTimeout: Date().addingTimeInterval(-100)
        )

        let staleReverse = Data(repeating: 0xFF, count: 16)
        reverseTable[staleReverse] = ReverseTableEntry(
            receivingInterfaceId: "x",
            outboundInterfaceId: "y",
            timestamp: Date().addingTimeInterval(-600)
        )
    }
}
