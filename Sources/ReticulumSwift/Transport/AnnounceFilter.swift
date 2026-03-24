// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  AnnounceFilter.swift
//  ReticulumSwift
//
//  Per-outgoing-interface announce filtering matching Python Transport.py:1040-1084.
//  Determines whether an announce should be forwarded TO a specific outgoing interface
//  based on the outgoing interface's mode, the source interface's mode, and whether
//  the destination is local.
//

import Foundation

// MARK: - Announce Filter

/// Per-outgoing-interface announce forwarding filter.
///
/// Implements the decision table from Python Transport.py:1040-1084 that controls
/// which announces are forwarded to which interfaces based on their modes.
///
/// Decision table (outgoing mode vs source mode):
///
/// | Outgoing       | Local | nil   | ROAMING | BOUNDARY | FULL/GW/P2P/AP |
/// |----------------|-------|-------|---------|----------|----------------|
/// | ACCESS_POINT   | BLOCK | BLOCK | BLOCK   | BLOCK    | BLOCK          |
/// | ROAMING        | ALLOW | BLOCK | BLOCK   | BLOCK    | ALLOW          |
/// | BOUNDARY       | ALLOW | BLOCK | BLOCK   | ALLOW    | ALLOW          |
/// | FULL/GW/P2P    | ALLOW | ALLOW | ALLOW   | ALLOW    | ALLOW          |
public enum AnnounceFilter {

    /// Whether an announce should be forwarded TO a specific outgoing interface.
    ///
    /// - Parameters:
    ///   - outgoingMode: Mode of the interface we want to send the announce on
    ///   - sourceMode: Mode of the interface the announce was received from (nil = unknown/no interface)
    ///   - isLocalDestination: Whether the destination is registered on this node
    /// - Returns: true if the announce should be forwarded to the outgoing interface
    public static func shouldForward(
        outgoingMode: InterfaceMode,
        sourceMode: InterfaceMode?,
        isLocalDestination: Bool
    ) -> Bool {
        switch outgoingMode {
        case .accessPoint:
            // AP mode: block all announce broadcasts (Transport.py:1042-1044)
            return false

        case .roaming:
            // Roaming mode: allow local destinations; otherwise only allow from
            // full/gateway/p2p/accessPoint source modes (Transport.py:1046-1065)
            if isLocalDestination {
                return true
            }
            guard let source = sourceMode else {
                return false
            }
            switch source {
            case .roaming, .boundary:
                return false
            case .full, .gateway, .pointToPoint, .accessPoint:
                return true
            }

        case .boundary:
            // Boundary mode: allow local destinations; block from roaming or unknown;
            // allow from boundary, full, gateway, p2p, accessPoint (Transport.py:1067-1083)
            if isLocalDestination {
                return true
            }
            guard let source = sourceMode else {
                return false
            }
            switch source {
            case .roaming:
                return false
            case .boundary, .full, .gateway, .pointToPoint, .accessPoint:
                return true
            }

        case .full, .gateway, .pointToPoint:
            // Full/Gateway/P2P: allow all announces (Transport.py:1085)
            return true
        }
    }
}
