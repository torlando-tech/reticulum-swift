//
//  ResourceWindow.swift
//  ReticulumSwift
//
//  Dynamic sliding window management for resource transfers.
//  Adapts window size based on transfer rate to optimize throughput.
//

import Foundation

/// Manages adaptive window sizing for resource transfers.
///
/// The window controls how many parts can be outstanding (requested but not
/// yet received) at any time. This provides flow control and adapts to
/// network conditions:
///
/// - **Fast connections** (>50 Kbps): Window expands to 75 parts after
///   sustained good performance
/// - **Normal connections**: Window varies between 2-10 parts
/// - **Very slow connections** (<2 Kbps): Window restricted to 4 parts max
///
/// The window adjusts based on:
/// - **Success**: All parts received → increase window
/// - **Timeout**: Part not acknowledged → decrease window
/// - **Transfer rate**: Measured bytes/second determines max ceiling
///
/// This matches the behavior of Python RNS Resource.py for interoperability.
public class ResourceWindow {

    // MARK: - Properties

    /// Current window size (number of parts that can be outstanding).
    private(set) var window: Int

    /// Minimum window size (never goes below this).
    private(set) var windowMin: Int

    /// Maximum window size (current ceiling based on performance).
    private(set) var windowMax: Int

    /// Number of consecutive fast rate rounds.
    private var fastRateRounds: Int = 0

    /// Number of consecutive very slow rate rounds.
    private var verySlowRateRounds: Int = 0

    /// Number of parts currently outstanding (requested but not received).
    private(set) var outstandingParts: Int = 0

    /// Highest consecutive completed part index (enables efficient requests).
    ///
    /// For example, if parts [0,1,2,5,6] are complete, height is 3 because
    /// parts 0-2 are consecutive. Part requests start from this height to
    /// avoid re-requesting already received parts.
    private(set) var consecutiveCompletedHeight: Int = 0

    // MARK: - Initialization

    /// Creates a new window manager with initial conservative settings.
    public init() {
        self.window = ResourceConstants.WINDOW_INITIAL
        self.windowMin = ResourceConstants.WINDOW_MIN
        self.windowMax = ResourceConstants.WINDOW_MAX_SLOW
    }

    // MARK: - Window Adjustment

    /// Adjusts window size after all requested parts are received.
    ///
    /// This is called when a batch of parts completes successfully. The window
    /// increases to request more parts in the next batch, improving throughput.
    ///
    /// Fast rate detection:
    /// - If transfer rate >= RATE_FAST (6250 bytes/sec), increment fast counter
    /// - After FAST_RATE_THRESHOLD consecutive fast rounds, unlock WINDOW_MAX_FAST
    ///
    /// Very slow rate handling:
    /// - If transfer rate < RATE_VERY_SLOW (250 bytes/sec), increment slow counter
    /// - After VERY_SLOW_RATE_THRESHOLD consecutive slow rounds, cap at WINDOW_MAX_VERY_SLOW
    ///
    /// - Parameter transferRate: Measured transfer rate in bytes per second.
    public func onAllPartsReceived(transferRate: Double) {
        // Increase window for next batch
        window += 1

        // Track rate performance
        if transferRate >= ResourceConstants.RATE_FAST {
            fastRateRounds += 1
            verySlowRateRounds = 0

            // Unlock fast window after sustained good performance
            if fastRateRounds >= ResourceConstants.FAST_RATE_THRESHOLD {
                windowMax = ResourceConstants.WINDOW_MAX_FAST
            }
        } else if transferRate < ResourceConstants.RATE_VERY_SLOW {
            verySlowRateRounds += 1
            fastRateRounds = 0

            // Cap window for very slow connections
            if verySlowRateRounds >= ResourceConstants.VERY_SLOW_RATE_THRESHOLD {
                windowMax = ResourceConstants.WINDOW_MAX_VERY_SLOW
            }
        } else {
            // Normal rate - reset counters
            fastRateRounds = 0
            verySlowRateRounds = 0
        }

        // Apply window ceiling
        if window > windowMax {
            window = windowMax
        }

        // Adjust minimum to maintain flexibility
        updateWindowMin()
    }

    /// Reduces window size after a timeout.
    ///
    /// When a part isn't acknowledged within the timeout period, it indicates
    /// congestion or packet loss. The window is halved to relieve pressure on
    /// the link.
    ///
    /// The window max is also reduced to prevent rapid re-expansion.
    public func onTimeout() {
        // Halve window to relieve congestion
        window = max(windowMin, window / 2)

        // Reduce max to prevent rapid re-expansion
        windowMax = max(windowMin, windowMax / 2)

        // Reset rate tracking
        fastRateRounds = 0
        verySlowRateRounds = 0

        // Adjust minimum to maintain flexibility
        updateWindowMin()
    }

    /// Updates window minimum based on current window size.
    ///
    /// The minimum tracks the window with some flexibility to prevent
    /// excessive oscillation. From RNS Resource.py:
    /// `window_min = max(1, window - WINDOW_FLEXIBILITY)`
    private func updateWindowMin() {
        windowMin = max(
            ResourceConstants.WINDOW_MIN,
            window - ResourceConstants.WINDOW_FLEXIBILITY
        )
    }

    // MARK: - Part Tracking

    /// Marks parts as requested (outstanding).
    ///
    /// Call this when parts are sent to the receiver but not yet acknowledged.
    ///
    /// - Parameter count: Number of parts being requested.
    public func markRequested(count: Int = 1) {
        outstandingParts += count
    }

    /// Marks a part as received and updates consecutive height.
    ///
    /// Call this when a part is acknowledged by the receiver.
    ///
    /// - Parameters:
    ///   - index: Index of the received part.
    ///   - totalParts: Total number of parts in the resource.
    public func markReceived(index: Int, totalParts: Int) {
        outstandingParts = max(0, outstandingParts - 1)

        // Update consecutive height if this completes the next expected part
        if index == consecutiveCompletedHeight {
            consecutiveCompletedHeight += 1
        }
    }

    /// Updates consecutive completed height by scanning forward.
    ///
    /// Scans the parts array from the current height to find the highest
    /// consecutive completed index. This enables efficient part requests
    /// that skip already-received parts.
    ///
    /// For example:
    /// - Parts [0,1,2,5,6] → height 3 (parts 0-2 consecutive)
    /// - Parts [0,1,2,3,4,5] → height 6 (all consecutive)
    ///
    /// - Parameter parts: Array of booleans indicating which parts are complete.
    public func updateConsecutiveHeight(parts: [Bool]) {
        // Scan forward from current height
        while consecutiveCompletedHeight < parts.count && parts[consecutiveCompletedHeight] {
            consecutiveCompletedHeight += 1
        }
    }

    /// Calculates the range of parts to request in the next batch.
    ///
    /// Returns indices of parts to request, starting from the consecutive
    /// completed height and respecting the window size.
    ///
    /// For example, if height=3, window=4, and parts [3,4,6,7] are incomplete:
    /// - Returns [3, 4, 6, 7] (up to window size of 4)
    ///
    /// - Parameter parts: Array of booleans indicating which parts are complete.
    /// - Returns: Array of part indices to request.
    public func getRequestRange(parts: [Bool]) -> [Int] {
        var indices: [Int] = []

        // Start from consecutive height (skip already-received parts)
        var index = consecutiveCompletedHeight

        // Collect incomplete parts up to window size
        while index < parts.count && indices.count < window {
            if !parts[index] {
                indices.append(index)
            }
            index += 1
        }

        return indices
    }

    // MARK: - State Accessors

    /// Current window size.
    public var currentWindow: Int {
        window
    }

    /// Number of parts currently outstanding.
    public var outstanding: Int {
        outstandingParts
    }

    /// Highest consecutive completed part index.
    public var height: Int {
        consecutiveCompletedHeight
    }
}
