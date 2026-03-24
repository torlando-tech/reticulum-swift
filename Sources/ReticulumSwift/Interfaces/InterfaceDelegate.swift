// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  InterfaceDelegate.swift
//  ReticulumSwift
//
//  Protocol and state enum for interface event callbacks.
//  Interfaces notify delegates of state changes and received packets.
//

import Foundation

// MARK: - Interface State

/// State of an interface connection.
///
/// Interface state tracks the connection lifecycle including reconnection attempts.
/// Interfaces transition through these states as they connect, disconnect, and
/// attempt automatic reconnection.
///
/// - `disconnected`: Not connected, not attempting to connect
/// - `connecting`: Connection attempt in progress
/// - `connected`: Successfully connected and operational
/// - `reconnecting(attempt:)`: Disconnected, attempting to reconnect
public enum InterfaceState: Equatable, Sendable {

    /// Not connected, not attempting to connect
    case disconnected

    /// Connection attempt in progress
    case connecting

    /// Successfully connected and operational
    case connected

    /// Disconnected, attempting to reconnect
    /// - Parameter attempt: Current reconnection attempt number (1-based)
    case reconnecting(attempt: Int)

    // MARK: - Equatable

    public static func == (lhs: InterfaceState, rhs: InterfaceState) -> Bool {
        switch (lhs, rhs) {
        case (.disconnected, .disconnected),
             (.connecting, .connecting),
             (.connected, .connected):
            return true
        case (.reconnecting(let lhsAttempt), .reconnecting(let rhsAttempt)):
            return lhsAttempt == rhsAttempt
        default:
            return false
        }
    }
}

// MARK: - CustomStringConvertible

extension InterfaceState: CustomStringConvertible {
    public var description: String {
        switch self {
        case .disconnected:
            return "disconnected"
        case .connecting:
            return "connecting"
        case .connected:
            return "connected"
        case .reconnecting(let attempt):
            return "reconnecting(attempt: \(attempt))"
        }
    }
}

// MARK: - Interface Delegate

/// Protocol for receiving interface events.
///
/// Delegates receive callbacks when interface state changes, packets are received,
/// or errors occur. Methods are marked @MainActor for UI safety. Interfaces are
/// identified by their string ID to avoid actor isolation issues.
///
/// Example usage:
/// ```swift
/// class MyHandler: InterfaceDelegate {
///     func interface(id: String, didChangeState state: InterfaceState) {
///         print("Interface \(id) state: \(state)")
///     }
///
///     func interface(id: String, didReceivePacket data: Data) {
///         // Process incoming packet
///     }
///
///     func interface(id: String, didFailWithError error: Error) {
///         print("Interface \(id) error: \(error)")
///     }
/// }
/// ```
public protocol InterfaceDelegate: AnyObject, Sendable {

    /// Called when interface state changes.
    ///
    /// This includes transitions like connecting -> connected, connected -> reconnecting, etc.
    /// Use this to update UI or trigger other state-dependent logic.
    ///
    /// - Parameters:
    ///   - id: The interface's unique identifier
    ///   - state: The new state
    func interface(id: String, didChangeState state: InterfaceState)

    /// Called when a complete packet is received.
    ///
    /// The data has already been unframed (HDLC removed) and represents
    /// a complete Reticulum packet ready for processing.
    ///
    /// - Parameters:
    ///   - id: The interface's unique identifier
    ///   - data: The complete packet data (unframed)
    func interface(id: String, didReceivePacket data: Data)

    /// Called when an error occurs.
    ///
    /// This is called for errors that are notable but don't necessarily stop operation.
    /// Connection failures during reconnection attempts, for example, trigger this callback
    /// but the interface continues trying to reconnect.
    ///
    /// - Parameters:
    ///   - id: The interface's unique identifier
    ///   - error: The error that occurred
    func interface(id: String, didFailWithError error: Error)
}
