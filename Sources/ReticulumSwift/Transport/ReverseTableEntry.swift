// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ReverseTableEntry.swift
//  ReticulumSwift
//
//  Entry in the reverse table, matching Python Transport.reverse_table.
//  Populated when this transport node forwards a non-link DATA packet.
//  Used to route data PROOFs back through the transport chain.
//
//  Python reference: Transport.py ~line 1551
//  reverse_table[truncated_hash] = [receiving_interface, outbound_interface, destination_hash]
//

import Foundation

/// Entry in the transport reverse table.
///
/// Created when a non-link DATA packet is forwarded through this transport node.
/// Enables routing the corresponding PROOF back to the sender.
public struct ReverseTableEntry: Sendable {

    /// Interface that received the original packet (for routing proof back)
    public let receivingInterfaceId: String

    /// Interface the packet was forwarded on (toward destination)
    public let outboundInterfaceId: String

    /// When this entry was created (for expiration)
    public let timestamp: Date

    public init(
        receivingInterfaceId: String,
        outboundInterfaceId: String,
        timestamp: Date = Date()
    ) {
        self.receivingInterfaceId = receivingInterfaceId
        self.outboundInterfaceId = outboundInterfaceId
        self.timestamp = timestamp
    }
}
