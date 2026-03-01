//
//  LinkTableEntry.swift
//  ReticulumSwift
//
//  Entry in the link table, matching Python Transport.link_table.
//  Populated when this transport node forwards a LINKREQUEST.
//  Used to route LINKPROOF back and forward link DATA bidirectionally.
//
//  Python reference: Transport.py ~line 1482
//  link_table[link_id] = [timestamp, next_hop, outbound_interface,
//                          remaining_hops, receiving_interface, hops,
//                          destination_hash, validated]
//

import Foundation

/// Entry in the transport link table.
///
/// Created when a LINKREQUEST is forwarded through this transport node.
/// Enables bidirectional link DATA forwarding and LINKPROOF routing.
public struct LinkTableEntry: Sendable {

    /// When this entry was created
    public var timestamp: Date

    /// 16-byte transport ID of the next hop toward the destination.
    /// Used for rewriting HEADER_2 packets when forwarding toward destination.
    public let nextHopTransportId: Data

    /// Interface ID toward the link destination (outbound direction)
    public let outboundInterfaceId: String

    /// Hops remaining from this transport node to the destination
    public let remainingHops: UInt8

    /// Interface ID toward the link requester (inbound direction)
    public let receivingInterfaceId: String

    /// Hops taken from the requester to this transport node
    public let takenHops: UInt8

    /// 16-byte destination hash the link targets
    public let destinationHash: Data

    /// True after the LINKPROOF has been successfully forwarded
    public var validated: Bool

    /// Deadline for receiving LINKPROOF before considering the entry stale
    public let proofTimeout: Date

    public init(
        timestamp: Date = Date(),
        nextHopTransportId: Data,
        outboundInterfaceId: String,
        remainingHops: UInt8,
        receivingInterfaceId: String,
        takenHops: UInt8,
        destinationHash: Data,
        validated: Bool = false,
        proofTimeout: Date
    ) {
        self.timestamp = timestamp
        self.nextHopTransportId = nextHopTransportId
        self.outboundInterfaceId = outboundInterfaceId
        self.remainingHops = remainingHops
        self.receivingInterfaceId = receivingInterfaceId
        self.takenHops = takenHops
        self.destinationHash = destinationHash
        self.validated = validated
        self.proofTimeout = proofTimeout
    }
}
