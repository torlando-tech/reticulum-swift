// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  InterfaceMode.swift
//  ReticulumSwift
//
//  Interface mode enum matching Python RNS interface modes.
//  Controls announce propagation behavior, path expiration, and path request proactivity.
//

import Foundation

// MARK: - Interface Mode

/// Interface mode controlling announce propagation and path expiration behavior.
///
/// Reticulum defines several interface modes that affect how announces are propagated
/// and how long path entries remain valid. These modes are designed to optimize
/// network behavior for different use cases.
///
/// - `full`: Default mode with all functionality enabled
/// - `gateway`: Proactively discovers paths for connected clients
/// - `accessPoint`: Suppresses announces until destinations are actively used
/// - `roaming`: Mobile interface with faster path expiration
/// - `boundary`: Links dissimilar network segments
/// - `pointToPoint`: Direct link with no announce propagation
public enum InterfaceMode: String, Codable, Sendable, Equatable {

    // MARK: - Cases

    /// Default mode: all functionality enabled, 7-day path expiration
    case full = "full"

    /// Gateway mode: proactively requests paths for connected clients
    case gateway = "gateway"

    /// Access point mode: suppresses announces until active use
    case accessPoint = "access_point"

    /// Roaming mode: mobile interface with faster path expiration (30 minutes)
    case roaming = "roaming"

    /// Boundary mode: links dissimilar network segments, 7-day expiration
    case boundary = "boundary"

    /// Point-to-point mode: direct link, no announce propagation
    case pointToPoint = "point_to_point"

    // MARK: - Computed Properties

    /// Path expiration interval for this interface mode.
    ///
    /// Different modes have different expiration times based on expected mobility.
    /// Values match Python RNS Transport.py for interoperability:
    /// - Full/Gateway/Boundary: 7 days (PATHFINDER_E, stationary destinations)
    /// - Roaming: 6 hours (ROAMING_PATH_TIME, mobile destinations)
    /// - AccessPoint: 1 day (AP_PATH_TIME, semi-mobile)
    /// - PointToPoint: 24 hours (direct links)
    public var pathExpiration: TimeInterval {
        switch self {
        case .full, .gateway, .boundary:
            return TransportConstants.PATHFINDER_E
        case .roaming:
            return TransportConstants.ROAMING_PATH_TIME
        case .accessPoint:
            return TransportConstants.AP_PATH_TIME
        case .pointToPoint:
            return TransportConstants.AP_PATH_TIME
        }
    }

    /// Whether announces should be propagated on this interface.
    ///
    /// Some interface modes suppress announce propagation to reduce bandwidth
    /// or because the network topology doesn't require it:
    /// - Full/Gateway/Boundary/Roaming: Propagate announces
    /// - AccessPoint/PointToPoint: Suppress announces
    public var shouldPropagateAnnounces: Bool {
        switch self {
        case .full, .gateway, .boundary, .roaming:
            return true
        case .accessPoint, .pointToPoint:
            return false
        }
    }

    /// Whether this interface should proactively request paths.
    ///
    /// Gateway mode proactively discovers paths for connected clients
    /// so they can reach destinations without waiting for announces.
    public var shouldProactivelyRequestPaths: Bool {
        switch self {
        case .gateway:
            return true
        case .full, .accessPoint, .roaming, .boundary, .pointToPoint:
            return false
        }
    }
}

// MARK: - CustomStringConvertible

extension InterfaceMode: CustomStringConvertible {
    public var description: String {
        rawValue
    }
}
