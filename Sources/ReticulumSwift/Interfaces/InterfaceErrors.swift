// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  InterfaceErrors.swift
//  ReticulumSwift
//
//  Error types for interface operations.
//

import Foundation

// MARK: - Interface Error

/// Errors that can occur during interface operations.
///
/// These errors represent failures in interface lifecycle management
/// and packet transmission. Connection-related errors wrap underlying
/// transport errors for context.
public enum InterfaceError: Error, Sendable, Equatable {

    /// Connection attempt failed.
    ///
    /// Wraps the underlying transport error that caused the failure.
    /// This can occur during initial connection or reconnection attempts.
    case connectionFailed(underlying: String)

    /// Sending data failed.
    ///
    /// Wraps the underlying transport error that caused the failure.
    /// This typically indicates a network issue or disconnection.
    case sendFailed(underlying: String)

    /// Operation requires a connection but interface is not connected.
    ///
    /// Thrown when attempting to send data while the interface is
    /// disconnected or in the process of reconnecting.
    case notConnected

    /// Interface configuration is invalid.
    ///
    /// - Parameter reason: Human-readable description of the configuration issue
    case invalidConfig(reason: String)

    // MARK: - Equatable

    public static func == (lhs: InterfaceError, rhs: InterfaceError) -> Bool {
        switch (lhs, rhs) {
        case (.connectionFailed(let lhsMsg), .connectionFailed(let rhsMsg)):
            return lhsMsg == rhsMsg
        case (.sendFailed(let lhsMsg), .sendFailed(let rhsMsg)):
            return lhsMsg == rhsMsg
        case (.notConnected, .notConnected):
            return true
        case (.invalidConfig(let lhsReason), .invalidConfig(let rhsReason)):
            return lhsReason == rhsReason
        default:
            return false
        }
    }
}

// MARK: - LocalizedError

extension InterfaceError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .connectionFailed(let underlying):
            return "Connection failed: \(underlying)"
        case .sendFailed(let underlying):
            return "Send failed: \(underlying)"
        case .notConnected:
            return "Interface is not connected"
        case .invalidConfig(let reason):
            return "Invalid configuration: \(reason)"
        }
    }
}
