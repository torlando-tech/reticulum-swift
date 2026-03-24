// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ResourceErrors.swift
//  ReticulumSwift
//
//  Error types for resource operations.
//  Provides detailed diagnostics for resource transfer errors.
//

import Foundation

// MARK: - Resource Error

/// Errors that can occur during resource operations.
///
/// These errors cover the full resource lifecycle: advertisement, transfer,
/// compression, encoding, and validation. Each error includes context for
/// debugging interoperability issues.
public enum ResourceError: Error, Sendable, Equatable {

    // MARK: - State Errors

    /// Operation requires a different resource state.
    ///
    /// - Parameters:
    ///   - expected: The state(s) required for the operation.
    ///   - actual: The current state of the resource.
    case invalidState(expected: String, actual: String)

    /// Resource is not in an active transfer state.
    ///
    /// This error occurs when attempting operations that require
    /// active transfer (transferring, awaitingProof, or assembling).
    case notActive

    /// Resource has already completed.
    ///
    /// This error occurs when attempting to restart or modify a
    /// resource that has already reached the complete state.
    case alreadyComplete

    // MARK: - Transfer Errors

    /// Resource transfer failed.
    ///
    /// - Parameter reason: Detailed description of the failure.
    case transferFailed(reason: String)

    /// Transfer operation timed out.
    ///
    /// The transfer did not complete within the expected timeout period,
    /// either for proof reception or part acknowledgment.
    case timeout

    /// A required data part is missing.
    ///
    /// - Parameter index: The index of the missing part.
    case partMissing(index: Int)

    /// Hashmap validation failed for a part.
    ///
    /// The received part's hash does not match the expected hash
    /// from the hashmap, indicating data corruption.
    ///
    /// - Parameter partIndex: The index of the part that failed validation.
    case hashmapMismatch(partIndex: Int)

    /// Transfer window exhausted without progress.
    ///
    /// All outstanding parts in the window have timed out without
    /// acknowledgment, indicating severe network issues.
    case windowExhausted

    // MARK: - Advertisement Errors

    /// Resource advertisement failed.
    ///
    /// - Parameter reason: Detailed description of the advertisement failure.
    case advertisementFailed(reason: String)

    /// Advertisement was rejected by receiver.
    ///
    /// The receiver declined to accept the resource transfer,
    /// possibly due to policy or resource constraints.
    case rejected

    /// Resource strategy was rejected.
    ///
    /// The receiver does not support the compression, encryption,
    /// or other strategy flags in the advertisement.
    case strategyRejected

    // MARK: - Compression Errors

    /// Compression operation failed.
    ///
    /// - Parameter reason: Detailed description of the compression failure.
    case compressionFailed(reason: String)

    /// Decompression operation failed.
    ///
    /// - Parameter reason: Detailed description of the decompression failure.
    case decompressionFailed(reason: String)

    // MARK: - Encoding Errors

    /// MessagePack packing operation failed.
    ///
    /// - Parameter reason: Detailed description of the packing failure.
    case packingFailed(reason: String)

    /// MessagePack unpacking operation failed.
    ///
    /// - Parameter reason: Detailed description of the unpacking failure.
    case unpackingFailed(reason: String)

    // MARK: - Size Errors

    /// Data size exceeds maximum allowed.
    ///
    /// - Parameters:
    ///   - size: The actual data size.
    ///   - max: The maximum allowed size.
    case dataTooLarge(size: Int, max: Int)

    /// Part size does not match expected size.
    ///
    /// - Parameters:
    ///   - expected: The expected part size.
    ///   - actual: The actual part size received.
    case partSizeMismatch(expected: Int, actual: Int)

    // MARK: - Link Errors

    /// No active link available for resource transfer.
    ///
    /// Resources require an established link to transfer data.
    case linkNotActive

    /// Link has no send callback configured.
    ///
    /// The link must have a send callback to transmit resource packets.
    case noSendCallback

    /// Resource transfer was cancelled.
    ///
    /// The transfer was cancelled by the peer or due to link failure.
    case cancelled

    // MARK: - Equatable

    public static func == (lhs: ResourceError, rhs: ResourceError) -> Bool {
        switch (lhs, rhs) {
        case (.invalidState(let lhsExp, let lhsAct), .invalidState(let rhsExp, let rhsAct)):
            return lhsExp == rhsExp && lhsAct == rhsAct
        case (.notActive, .notActive):
            return true
        case (.alreadyComplete, .alreadyComplete):
            return true
        case (.transferFailed(let lhsReason), .transferFailed(let rhsReason)):
            return lhsReason == rhsReason
        case (.timeout, .timeout):
            return true
        case (.partMissing(let lhsIndex), .partMissing(let rhsIndex)):
            return lhsIndex == rhsIndex
        case (.hashmapMismatch(let lhsIndex), .hashmapMismatch(let rhsIndex)):
            return lhsIndex == rhsIndex
        case (.windowExhausted, .windowExhausted):
            return true
        case (.advertisementFailed(let lhsReason), .advertisementFailed(let rhsReason)):
            return lhsReason == rhsReason
        case (.rejected, .rejected):
            return true
        case (.strategyRejected, .strategyRejected):
            return true
        case (.compressionFailed(let lhsReason), .compressionFailed(let rhsReason)):
            return lhsReason == rhsReason
        case (.decompressionFailed(let lhsReason), .decompressionFailed(let rhsReason)):
            return lhsReason == rhsReason
        case (.packingFailed(let lhsReason), .packingFailed(let rhsReason)):
            return lhsReason == rhsReason
        case (.unpackingFailed(let lhsReason), .unpackingFailed(let rhsReason)):
            return lhsReason == rhsReason
        case (.dataTooLarge(let lhsSize, let lhsMax), .dataTooLarge(let rhsSize, let rhsMax)):
            return lhsSize == rhsSize && lhsMax == rhsMax
        case (.partSizeMismatch(let lhsExp, let lhsAct), .partSizeMismatch(let rhsExp, let rhsAct)):
            return lhsExp == rhsExp && lhsAct == rhsAct
        case (.linkNotActive, .linkNotActive):
            return true
        case (.noSendCallback, .noSendCallback):
            return true
        case (.cancelled, .cancelled):
            return true
        default:
            return false
        }
    }
}

// MARK: - LocalizedError

extension ResourceError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidState(let expected, let actual):
            return "Resource error: expected state \(expected), but resource is \(actual)"
        case .notActive:
            return "Resource error: operation requires active transfer state"
        case .alreadyComplete:
            return "Resource error: resource has already completed"
        case .transferFailed(let reason):
            return "Resource error: transfer failed - \(reason)"
        case .timeout:
            return "Resource error: transfer timed out"
        case .partMissing(let index):
            return "Resource error: part \(index) is missing"
        case .hashmapMismatch(let partIndex):
            return "Resource error: hashmap validation failed for part \(partIndex)"
        case .windowExhausted:
            return "Resource error: transfer window exhausted"
        case .advertisementFailed(let reason):
            return "Resource error: advertisement failed - \(reason)"
        case .rejected:
            return "Resource error: advertisement rejected by receiver"
        case .strategyRejected:
            return "Resource error: transfer strategy rejected by receiver"
        case .compressionFailed(let reason):
            return "Resource error: compression failed - \(reason)"
        case .decompressionFailed(let reason):
            return "Resource error: decompression failed - \(reason)"
        case .packingFailed(let reason):
            return "Resource error: MessagePack packing failed - \(reason)"
        case .unpackingFailed(let reason):
            return "Resource error: MessagePack unpacking failed - \(reason)"
        case .dataTooLarge(let size, let max):
            return "Resource error: data size \(size) exceeds maximum \(max)"
        case .partSizeMismatch(let expected, let actual):
            return "Resource error: expected part size \(expected), got \(actual)"
        case .linkNotActive:
            return "Resource error: no active link available"
        case .noSendCallback:
            return "Resource error: link has no send callback"
        case .cancelled:
            return "Resource error: transfer was cancelled"
        }
    }
}
