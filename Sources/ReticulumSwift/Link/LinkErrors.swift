// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  LinkErrors.swift
//  ReticulumSwift
//
//  Error types for link operations.
//  Provides detailed diagnostics for link lifecycle errors.
//

import Foundation

// MARK: - Link Error

/// Errors that can occur during link operations.
///
/// These errors cover the full link lifecycle: establishment, encryption,
/// transport, and state management. Each error includes context for
/// debugging interoperability issues.
public enum LinkError: Error, Sendable, Equatable {

    // MARK: - Handshake Errors

    /// Operation requires an active link but link is not active.
    ///
    /// This error occurs when attempting to send data on a link
    /// that has not completed handshake or has been closed.
    case notActive

    /// Link is already in established state.
    ///
    /// This error occurs when attempting to establish a link
    /// that has already completed handshake.
    case alreadyEstablished

    /// Link establishment timed out waiting for PROOF.
    ///
    /// - Parameter seconds: The timeout duration that elapsed.
    case establishmentTimeout(seconds: TimeInterval)

    /// PROOF signature verification failed.
    ///
    /// The cryptographic proof from the destination could not be
    /// verified. This may indicate a corrupted message, replay attack,
    /// or incompatible implementations.
    ///
    /// - Parameter reason: Detailed description of the verification failure.
    case invalidProof(reason: String)

    // MARK: - Crypto Errors

    /// HKDF key derivation failed.
    ///
    /// The shared secret could not be derived into encryption keys.
    /// This typically indicates incompatible crypto implementations.
    case keyDerivationFailed

    /// Encryption token has not been created yet.
    ///
    /// The link must complete key exchange before data can be encrypted.
    case encryptionNotReady

    /// Token encryption operation failed.
    ///
    /// - Parameter reason: Detailed description of the encryption failure.
    case encryptionFailed(reason: String)

    /// Token decryption operation failed.
    ///
    /// - Parameter reason: Detailed description of the decryption failure.
    case decryptionFailed(reason: String)

    // MARK: - Transport Errors

    /// No transport available for sending packets.
    ///
    /// The link has no associated transport or the transport
    /// has been disconnected.
    case transportNotAvailable

    /// Sending packet over transport failed.
    ///
    /// - Parameter reason: Detailed description of the send failure.
    case sendFailed(reason: String)

    // MARK: - State Errors

    /// Operation requires a different link state.
    ///
    /// - Parameters:
    ///   - expected: The state(s) required for the operation.
    ///   - actual: The current state of the link.
    case invalidState(expected: String, actual: String)

    /// Link was closed with the specified reason.
    ///
    /// This error wraps a TeardownReason for operations that fail
    /// because the link has been terminated.
    ///
    /// - Parameter reason: Why the link was closed.
    case closedWithReason(TeardownReason)

    // MARK: - Equatable

    public static func == (lhs: LinkError, rhs: LinkError) -> Bool {
        switch (lhs, rhs) {
        case (.notActive, .notActive):
            return true
        case (.alreadyEstablished, .alreadyEstablished):
            return true
        case (.establishmentTimeout(let lhsSec), .establishmentTimeout(let rhsSec)):
            return lhsSec == rhsSec
        case (.invalidProof(let lhsReason), .invalidProof(let rhsReason)):
            return lhsReason == rhsReason
        case (.keyDerivationFailed, .keyDerivationFailed):
            return true
        case (.encryptionNotReady, .encryptionNotReady):
            return true
        case (.encryptionFailed(let lhsReason), .encryptionFailed(let rhsReason)):
            return lhsReason == rhsReason
        case (.decryptionFailed(let lhsReason), .decryptionFailed(let rhsReason)):
            return lhsReason == rhsReason
        case (.transportNotAvailable, .transportNotAvailable):
            return true
        case (.sendFailed(let lhsReason), .sendFailed(let rhsReason)):
            return lhsReason == rhsReason
        case (.invalidState(let lhsExp, let lhsAct), .invalidState(let rhsExp, let rhsAct)):
            return lhsExp == rhsExp && lhsAct == rhsAct
        case (.closedWithReason(let lhsReason), .closedWithReason(let rhsReason)):
            return lhsReason == rhsReason
        default:
            return false
        }
    }
}

// MARK: - LocalizedError

extension LinkError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notActive:
            return "Link error: operation requires active link state"
        case .alreadyEstablished:
            return "Link error: link is already established"
        case .establishmentTimeout(let seconds):
            return "Link error: establishment timed out after \(String(format: "%.1f", seconds)) seconds"
        case .invalidProof(let reason):
            return "Link error: invalid proof - \(reason)"
        case .keyDerivationFailed:
            return "Link error: HKDF key derivation failed"
        case .encryptionNotReady:
            return "Link error: encryption token not yet created"
        case .encryptionFailed(let reason):
            return "Link error: encryption failed - \(reason)"
        case .decryptionFailed(let reason):
            return "Link error: decryption failed - \(reason)"
        case .transportNotAvailable:
            return "Link error: no transport available for sending"
        case .sendFailed(let reason):
            return "Link error: send failed - \(reason)"
        case .invalidState(let expected, let actual):
            return "Link error: expected state \(expected), but link is \(actual)"
        case .closedWithReason(let reason):
            return "Link error: link closed with reason: \(reason)"
        }
    }
}
