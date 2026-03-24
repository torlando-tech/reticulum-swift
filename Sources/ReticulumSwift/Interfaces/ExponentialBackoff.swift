// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ExponentialBackoff.swift
//  ReticulumSwift
//
//  Exponential backoff calculator for reconnection delays.
//  Prevents connection storms when multiple interfaces reconnect simultaneously.
//

import Foundation

// MARK: - Exponential Backoff

/// Calculates exponential backoff delays with jitter for reconnection logic.
///
/// Exponential backoff prevents connection storms by increasing wait time
/// between retries. Jitter (random variation) prevents synchronized retries
/// when multiple connections fail simultaneously ("thundering herd").
///
/// Example usage:
/// ```swift
/// let backoff = ExponentialBackoff()
/// var attempt = 0
///
/// while true {
///     do {
///         try await connect()
///         break // Success
///     } catch {
///         let delay = backoff.nextDelay(attempt: attempt)
///         try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
///         attempt += 1
///     }
/// }
/// ```
public struct ExponentialBackoff: Sendable {

    // MARK: - Properties

    /// Base delay for first retry (1 second default)
    public let baseDelay: TimeInterval

    /// Maximum delay cap (5 minutes default)
    public let maxDelay: TimeInterval

    /// Fraction of delay to use as jitter range (+/- 25% default)
    public let jitterFraction: Double

    // MARK: - Initialization

    /// Create a new exponential backoff calculator.
    ///
    /// - Parameters:
    ///   - baseDelay: Initial delay for attempt 0 (default: 1 second)
    ///   - maxDelay: Maximum delay cap (default: 5 minutes)
    ///   - jitterFraction: Random variation fraction (default: 0.25 for +/-25%)
    public init(
        baseDelay: TimeInterval = 1.0,
        maxDelay: TimeInterval = 300.0,
        jitterFraction: Double = 0.25
    ) {
        self.baseDelay = baseDelay
        self.maxDelay = maxDelay
        self.jitterFraction = jitterFraction
    }

    // MARK: - Calculation

    /// Calculate the next delay for a given attempt number.
    ///
    /// The delay grows exponentially: `2^attempt * baseDelay`, capped at `maxDelay`.
    /// Random jitter of +/- `jitterFraction` is applied to prevent synchronized retries.
    ///
    /// - Parameter attempt: Zero-based attempt number (0 for first retry)
    /// - Returns: Delay in seconds before next retry attempt
    public func nextDelay(attempt: Int) -> TimeInterval {
        // Calculate exponential delay: 2^attempt * baseDelay
        let exponential = pow(2.0, Double(attempt)) * baseDelay

        // Cap at maximum delay
        let capped = min(exponential, maxDelay)

        // Apply random jitter: +/- jitterFraction of the capped delay
        let jitter = capped * jitterFraction * Double.random(in: -1...1)

        // Ensure result is non-negative
        return max(0, capped + jitter)
    }
}

// MARK: - CustomStringConvertible

extension ExponentialBackoff: CustomStringConvertible {
    public var description: String {
        "ExponentialBackoff(base: \(baseDelay)s, max: \(maxDelay)s, jitter: \(jitterFraction * 100)%)"
    }
}
