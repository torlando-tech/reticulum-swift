//
//  ResourceState.swift
//  ReticulumSwift
//
//  Resource state machine enums matching Python RNS Resource.py semantics.
//

import Foundation

// MARK: - Resource State

/// State machine states for RNS resource lifecycle.
///
/// Resources progress through these states during transfer:
/// 1. `.none` - Resource object created, not yet queued
/// 2. `.queued` - Waiting to start transfer
/// 3. `.advertised` - Advertisement sent, awaiting acceptance
/// 4. `.transferring` - Data parts being transmitted
/// 5. `.awaitingProof` - All parts sent, awaiting validation proof
/// 6. `.assembling` - Receiver assembling received parts
/// 7. `.complete` - Transfer successful (terminal state)
/// 8. `.failed` - Transfer failed (terminal state)
/// 9. `.rejected` - Advertisement rejected by receiver (terminal state)
/// 10. `.cancelled` - Transfer cancelled by initiator (terminal state)
///
/// These states match Python RNS Resource.py for interoperability.
public enum ResourceState: Sendable, Equatable, CustomStringConvertible {

    /// Resource created but not yet queued for transfer.
    ///
    /// This is the initial state when a Resource object is created.
    /// Transition: `.none` -> `.queued` when resource is queued.
    case none

    /// Resource is queued and waiting to start transfer.
    ///
    /// The resource is ready to be advertised but has not yet sent
    /// its advertisement packet.
    /// Transition: `.queued` -> `.advertised` when advertisement is sent.
    case queued

    /// Advertisement sent, awaiting acceptance from receiver.
    ///
    /// The receiver must respond to accept or reject the resource transfer.
    /// Transition: `.advertised` -> `.transferring` when accepted.
    /// Transition: `.advertised` -> `.rejected` when receiver declines.
    case advertised

    /// Data parts are being transmitted to receiver.
    ///
    /// The resource is actively sending data packets and processing
    /// acknowledgments. Window size adapts to network conditions.
    /// Transition: `.transferring` -> `.awaitingProof` when all parts sent.
    /// Transition: `.transferring` -> `.failed` on unrecoverable error.
    case transferring

    /// All parts sent, awaiting proof of successful assembly.
    ///
    /// The receiver is assembling the parts and must send a cryptographic
    /// proof that it has correctly reconstructed the data.
    /// Transition: `.awaitingProof` -> `.complete` when proof received.
    /// Transition: `.awaitingProof` -> `.failed` on timeout or invalid proof.
    case awaitingProof

    /// Receiver is assembling received parts.
    ///
    /// This state is used on the receiving side while parts are being
    /// collected and validated against the hashmap.
    /// Transition: `.assembling` -> `.complete` when assembly succeeds.
    /// Transition: `.assembling` -> `.failed` on validation failure.
    case assembling

    /// Transfer completed successfully.
    ///
    /// This is a terminal state. The resource data has been fully
    /// transferred and validated by the receiver.
    /// No further transitions are possible from this state.
    case complete

    /// Transfer failed due to error.
    ///
    /// This is a terminal state. The transfer could not complete due to
    /// timeout, validation failure, or other error condition.
    /// No further transitions are possible from this state.
    case failed

    /// Advertisement rejected by receiver.
    ///
    /// This is a terminal state. The receiver declined to accept the
    /// resource transfer, possibly due to policy or resource constraints.
    /// No further transitions are possible from this state.
    case rejected

    /// Transfer cancelled by initiator.
    ///
    /// This is a terminal state. The sender cancelled the transfer before
    /// it could complete. Can occur from any non-terminal state.
    /// No further transitions are possible from this state.
    case cancelled

    // MARK: - Computed Properties

    /// Whether the resource is in a terminal state.
    ///
    /// Returns `true` for `.complete`, `.failed`, `.rejected`, and `.cancelled`.
    /// Once a resource reaches a terminal state, no further state transitions
    /// are possible and the resource cannot be reused.
    public var isTerminal: Bool {
        switch self {
        case .complete, .failed, .rejected, .cancelled:
            return true
        case .none, .queued, .advertised, .transferring, .awaitingProof, .assembling:
            return false
        }
    }

    /// Whether the resource is actively transferring or awaiting completion.
    ///
    /// Returns `true` for `.transferring`, `.awaitingProof`, and `.assembling`.
    /// These states indicate the resource is actively engaged in data transfer
    /// or validation operations.
    public var isActive: Bool {
        switch self {
        case .transferring, .awaitingProof, .assembling:
            return true
        case .none, .queued, .advertised, .complete, .failed, .rejected, .cancelled:
            return false
        }
    }

    /// Whether the resource has completed successfully.
    ///
    /// Returns `true` only for `.complete` state.
    public var isComplete: Bool {
        switch self {
        case .complete:
            return true
        case .none, .queued, .advertised, .transferring, .awaitingProof, .assembling, .failed, .rejected, .cancelled:
            return false
        }
    }

    // MARK: - State Transition Validation

    /// Validate whether a state transition is allowed.
    ///
    /// This method checks whether transitioning from one state to another
    /// is valid according to the resource state machine.
    ///
    /// Valid transitions:
    /// - `.none` -> `.queued` (start)
    /// - `.queued` -> `.advertised` (send advertisement)
    /// - `.advertised` -> `.transferring` (acceptance received)
    /// - `.advertised` -> `.rejected` (receiver declines)
    /// - `.transferring` -> `.awaitingProof` (all parts sent)
    /// - `.transferring` -> `.failed` (error during transfer)
    /// - `.awaitingProof` -> `.complete` (proof received)
    /// - `.awaitingProof` -> `.failed` (proof timeout or invalid)
    /// - `.assembling` -> `.complete` (all parts assembled)
    /// - `.assembling` -> `.failed` (validation failure)
    /// - Any non-terminal state -> `.cancelled` (initiator cancels)
    ///
    /// - Parameters:
    ///   - from: The current state.
    ///   - to: The target state.
    /// - Returns: `true` if the transition is valid, `false` otherwise.
    public static func canTransition(from: ResourceState, to: ResourceState) -> Bool {
        // Cannot transition from terminal states
        if from.isTerminal {
            return false
        }

        // Can always cancel from non-terminal states
        if to == .cancelled {
            return true
        }

        // Validate specific transitions
        switch (from, to) {
        case (.none, .queued):
            return true
        case (.queued, .advertised):
            return true
        case (.advertised, .transferring):
            return true
        case (.advertised, .rejected):
            return true
        case (.transferring, .awaitingProof):
            return true
        case (.transferring, .assembling):
            return true
        case (.transferring, .failed):
            return true
        case (.awaitingProof, .complete):
            return true
        case (.awaitingProof, .failed):
            return true
        case (.assembling, .complete):
            return true
        case (.assembling, .failed):
            return true
        default:
            return false
        }
    }

    // MARK: - CustomStringConvertible

    public var description: String {
        switch self {
        case .none:
            return "none"
        case .queued:
            return "queued"
        case .advertised:
            return "advertised"
        case .transferring:
            return "transferring"
        case .awaitingProof:
            return "awaitingProof"
        case .assembling:
            return "assembling"
        case .complete:
            return "complete"
        case .failed:
            return "failed"
        case .rejected:
            return "rejected"
        case .cancelled:
            return "cancelled"
        }
    }
}
