// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  PacketConstants.swift
//  ReticulumSwift
//
//  Packet context byte constants matching Python RNS Packet.py.
//  These identify the semantic meaning of a packet's context field.
//

import Foundation

/// Packet context byte constants matching Python RNS Packet.py.
///
/// The context byte is always present in the wire format (1 byte after
/// destination address). These constants define the semantic values.
///
/// Reference: Python RNS/Packet.py context constants
public enum PacketContext {
    public static let NONE: UInt8 = 0x00
    public static let RESOURCE: UInt8 = 0x01
    public static let RESOURCE_ADV: UInt8 = 0x02
    public static let RESOURCE_REQ: UInt8 = 0x03
    public static let RESOURCE_HMU: UInt8 = 0x04
    public static let RESOURCE_PRF: UInt8 = 0x05
    public static let RESOURCE_ICL: UInt8 = 0x06
    public static let RESOURCE_RCL: UInt8 = 0x07
    public static let CACHE_REQUEST: UInt8 = 0x08
    public static let REQUEST: UInt8 = 0x09
    public static let RESPONSE: UInt8 = 0x0A
    public static let PATH_RESPONSE: UInt8 = 0x0B
    public static let COMMAND: UInt8 = 0x0C
    public static let COMMAND_STATUS: UInt8 = 0x0D
    public static let CHANNEL: UInt8 = 0x0E
    public static let KEEPALIVE: UInt8 = 0xFA
    public static let LINKIDENTIFY: UInt8 = 0xFB
    public static let LINKCLOSE: UInt8 = 0xFC
    public static let LRRTT: UInt8 = 0xFE
    public static let LRPROOF: UInt8 = 0xFF

    /// Whether a context is in the link-control range (KEEPALIVE..LRPROOF, 0xFA-0xFF).
    /// Python: `context >= Packet.KEEPALIVE and context <= Packet.LRPROOF`
    public static func isLinkContext(_ context: UInt8) -> Bool {
        context >= KEEPALIVE && context <= LRPROOF
    }

    /// Whether a context is in the resource range (RESOURCE..RESOURCE_RCL, 0x01-0x07).
    /// Python: `context >= Packet.RESOURCE and context <= Packet.RESOURCE_RCL`
    public static func isResourceContext(_ context: UInt8) -> Bool {
        context >= RESOURCE && context <= RESOURCE_RCL
    }
}
