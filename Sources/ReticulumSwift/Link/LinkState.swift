//
//  LinkState.swift
//  ReticulumSwift
//
//  Link state machine enums matching Python RNS Link.py semantics.
//

import Foundation

// MARK: - Teardown Reason

/// Reasons why a link was closed.
///
/// These reasons match the teardown scenarios in Python RNS Link.py,
/// enabling consistent handling of link lifecycle across implementations.
public enum TeardownReason: Sendable, Equatable, CustomStringConvertible {

    /// No response received within the timeout period.
    ///
    /// This typically occurs when the remote destination is unreachable
    /// or has stopped responding.
    case timeout

    /// Local side (initiator) closed the link intentionally.
    ///
    /// This is a normal close initiated by the local application.
    case initiatorClosed

    /// Remote side (destination) closed the link.
    ///
    /// The remote peer sent a close notification.
    case destinationClosed

    /// PROOF signature verification failed during handshake.
    ///
    /// The proof received from the destination could not be verified,
    /// indicating either a corrupted message or potential attack.
    case proofInvalid

    /// Encryption or decryption operation failed.
    ///
    /// This indicates the link's cryptographic session has been
    /// compromised and the link must be terminated.
    case cryptoError

    /// Underlying transport layer failed.
    ///
    /// The network transport (e.g., TCP connection) encountered
    /// an unrecoverable error.
    case transportError

    // MARK: - CustomStringConvertible

    public var description: String {
        switch self {
        case .timeout:
            return "timeout"
        case .initiatorClosed:
            return "initiator_closed"
        case .destinationClosed:
            return "destination_closed"
        case .proofInvalid:
            return "proof_invalid"
        case .cryptoError:
            return "crypto_error"
        case .transportError:
            return "transport_error"
        }
    }
}

// MARK: - Link State

/// State machine states for RNS link lifecycle.
///
/// Links progress through these states during establishment and operation:
/// 1. `.pending` - Link object created, not yet initiated
/// 2. `.handshake` - LINKREQUEST sent, awaiting PROOF
/// 3. `.active` - Encrypted communication established
/// 4. `.stale` - No traffic for keepalive*2 period
/// 5. `.closed` - Link terminated (terminal state)
///
/// These states match Python RNS Link.py for interoperability.
public enum LinkState: Sendable, Equatable, CustomStringConvertible {

    /// Link created but not yet initiated.
    ///
    /// This is the initial state when a Link object is created.
    /// Transition: `.pending` -> `.handshake` when LINKREQUEST is sent.
    case pending

    /// LINKREQUEST packet sent, awaiting PROOF response.
    ///
    /// The link is attempting to establish a cryptographic session
    /// with the remote destination.
    /// Transition: `.handshake` -> `.active` when valid PROOF received.
    /// Transition: `.handshake` -> `.closed(.timeout)` if no response.
    /// Transition: `.handshake` -> `.closed(.proofInvalid)` if verification fails.
    case handshake

    /// Link established, encrypted communication active.
    ///
    /// Data can be sent and received over the encrypted channel.
    /// Keepalive packets maintain the connection.
    /// Transition: `.active` -> `.stale` if no traffic for keepalive*2.
    /// Transition: `.active` -> `.closed(reason)` on error or close.
    case active

    /// No traffic received for keepalive*2 period.
    ///
    /// The link is suspected to be unresponsive but not yet timed out.
    /// A grace period allows for delayed packets.
    /// Transition: `.stale` -> `.active` if traffic resumes.
    /// Transition: `.stale` -> `.closed(.timeout)` after grace period.
    case stale

    /// Link has been terminated.
    ///
    /// This is a terminal state. The reason indicates why the link closed.
    /// No further transitions are possible from this state.
    case closed(reason: TeardownReason)

    // MARK: - Computed Properties

    /// Whether the link is in an established state capable of communication.
    ///
    /// Returns `true` for `.active` and `.stale` states where encrypted
    /// data can still be transmitted.
    public var isEstablished: Bool {
        switch self {
        case .active, .stale:
            return true
        case .pending, .handshake, .closed:
            return false
        }
    }

    /// Whether the link is in a terminal state.
    ///
    /// Returns `true` only for `.closed` state. Once closed, a link
    /// cannot be reused and a new link must be created.
    public var isTerminal: Bool {
        switch self {
        case .closed:
            return true
        case .pending, .handshake, .active, .stale:
            return false
        }
    }

    // MARK: - CustomStringConvertible

    public var description: String {
        switch self {
        case .pending:
            return "pending"
        case .handshake:
            return "handshake"
        case .active:
            return "active"
        case .stale:
            return "stale"
        case .closed(let reason):
            return "closed(\(reason))"
        }
    }
}
