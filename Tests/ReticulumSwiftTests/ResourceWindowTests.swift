//
//  ResourceWindowTests.swift
//  ReticulumSwiftTests
//
//  Tests for ResourceWindow sliding window management and the ghost
//  outstanding bug fix (markRequested must only count actually-sent parts).
//

import XCTest
@testable import ReticulumSwift

final class ResourceWindowTests: XCTestCase {

    // MARK: - Initialization

    func testInitialState() {
        let window = ResourceWindow()
        XCTAssertEqual(window.currentWindow, ResourceConstants.WINDOW_INITIAL)
        XCTAssertEqual(window.windowMin, ResourceConstants.WINDOW_MIN)
        XCTAssertEqual(window.windowMax, ResourceConstants.WINDOW_MAX_SLOW)
        XCTAssertEqual(window.outstanding, 0)
        XCTAssertEqual(window.height, 0)
    }

    // MARK: - Part Tracking (Ghost Outstanding Bug)

    /// The core bug: markRequested was called for ALL window indices,
    /// including those beyond hashmap coverage that weren't actually sent.
    /// This test verifies the correct behavior where only actually-sent
    /// parts are counted as outstanding.
    func testMarkRequestedOnlyCountsActualRequests() {
        let window = ResourceWindow()

        // Simulate requesting 3 parts out of 5 window indices
        // (2 were beyond hashmap coverage and not actually sent)
        window.markRequested(count: 3)
        XCTAssertEqual(window.outstanding, 3)

        // Receive all 3
        window.markReceived(index: 0, totalParts: 100)
        window.markReceived(index: 1, totalParts: 100)
        window.markReceived(index: 2, totalParts: 100)
        XCTAssertEqual(window.outstanding, 0,
                       "Outstanding should be 0 after receiving all actually-requested parts")
    }

    /// Test that demonstrates the ghost outstanding bug pattern.
    /// If markRequested counted 5 but only 3 were sent, outstanding
    /// would never reach 0 (ghost inflation).
    func testGhostOutstandingScenario() {
        let window = ResourceWindow()

        // This is the CORRECT flow (post-fix):
        // Window returns 5 indices, but only 3 have hashmap entries
        let actualRequestCount = 3
        window.markRequested(count: actualRequestCount)
        XCTAssertEqual(window.outstanding, 3)

        // Receive all 3 actually-sent parts
        for i in 0..<3 {
            window.markReceived(index: i, totalParts: 100)
        }
        XCTAssertEqual(window.outstanding, 0,
                       "Outstanding must reach 0 when all sent parts are received")

        // If we had marked 5 (the bug), outstanding would be 2 here
        // and would never decrease, stalling the transfer
    }

    /// Verify outstanding never goes negative.
    func testOutstandingFloorAtZero() {
        let window = ResourceWindow()
        window.markReceived(index: 0, totalParts: 10)
        XCTAssertEqual(window.outstanding, 0, "Outstanding should not go negative")
    }

    func testMarkRequestedAccumulates() {
        let window = ResourceWindow()
        window.markRequested(count: 2)
        window.markRequested(count: 3)
        XCTAssertEqual(window.outstanding, 5)
    }

    // MARK: - Consecutive Height

    func testConsecutiveHeightUpdatesOnReceive() {
        let window = ResourceWindow()
        // Receive part 0 — height should advance to 1
        window.markReceived(index: 0, totalParts: 10)
        XCTAssertEqual(window.height, 1)

        // Receive part 1 — height should advance to 2
        window.markReceived(index: 1, totalParts: 10)
        XCTAssertEqual(window.height, 2)
    }

    func testConsecutiveHeightDoesNotAdvanceOnGap() {
        let window = ResourceWindow()
        // Receive part 1 before part 0 — height stays at 0
        window.markReceived(index: 1, totalParts: 10)
        XCTAssertEqual(window.height, 0)

        // Now receive part 0 — height advances to 1 (not 2)
        window.markReceived(index: 0, totalParts: 10)
        XCTAssertEqual(window.height, 1)
    }

    func testUpdateConsecutiveHeightScansForward() {
        let window = ResourceWindow()

        // Parts [0,1,2] complete, [3] missing, [4,5] complete
        var parts = [true, true, true, false, true, true]
        window.updateConsecutiveHeight(parts: parts)
        XCTAssertEqual(window.height, 3)

        // Fill the gap
        parts[3] = true
        window.updateConsecutiveHeight(parts: parts)
        XCTAssertEqual(window.height, 6)
    }

    func testUpdateConsecutiveHeightAllComplete() {
        let window = ResourceWindow()
        let parts = [true, true, true, true, true]
        window.updateConsecutiveHeight(parts: parts)
        XCTAssertEqual(window.height, 5)
    }

    func testUpdateConsecutiveHeightNoneComplete() {
        let window = ResourceWindow()
        let parts = [false, false, false]
        window.updateConsecutiveHeight(parts: parts)
        XCTAssertEqual(window.height, 0)
    }

    // MARK: - Request Range

    func testGetRequestRangeBasic() {
        let window = ResourceWindow()
        // window=4 initially, all 10 parts incomplete
        let parts = Array(repeating: false, count: 10)
        let indices = window.getRequestRange(parts: parts)
        XCTAssertEqual(indices, [0, 1, 2, 3])
    }

    func testGetRequestRangeSkipsCompleteParts() {
        let window = ResourceWindow()
        // Parts [0,1] complete, [2,3] missing
        var parts = Array(repeating: false, count: 10)
        parts[0] = true
        parts[1] = true

        window.updateConsecutiveHeight(parts: parts)
        let indices = window.getRequestRange(parts: parts)
        // Should start from height=2, requesting [2,3,4,5]
        XCTAssertEqual(indices, [2, 3, 4, 5])
    }

    func testGetRequestRangeSkipsIntermediateCompleteParts() {
        let window = ResourceWindow()
        // Parts [0,1] complete, [2] missing, [3] complete, [4,5,6] missing
        var parts = Array(repeating: false, count: 10)
        parts[0] = true
        parts[1] = true
        parts[3] = true

        window.updateConsecutiveHeight(parts: parts)
        let indices = window.getRequestRange(parts: parts)
        // Height=2, window=4, skips complete [3], gets [2,4,5,6]
        XCTAssertEqual(indices, [2, 4, 5, 6])
    }

    func testGetRequestRangeRespectsTotalParts() {
        let window = ResourceWindow()
        // Only 2 parts total, all incomplete
        let parts = [false, false]
        let indices = window.getRequestRange(parts: parts)
        XCTAssertEqual(indices, [0, 1])
    }

    func testGetRequestRangeAllComplete() {
        let window = ResourceWindow()
        let parts = [true, true, true]
        window.updateConsecutiveHeight(parts: parts)
        let indices = window.getRequestRange(parts: parts)
        XCTAssertTrue(indices.isEmpty)
    }

    // MARK: - Window Adjustment

    func testWindowIncreasesOnSuccess() {
        let window = ResourceWindow()
        let initial = window.currentWindow
        window.onAllPartsReceived(transferRate: 1000.0) // Normal rate
        XCTAssertEqual(window.currentWindow, initial + 1)
    }

    func testWindowCappedAtMax() {
        let window = ResourceWindow()
        // Increase window many times at normal rate
        for _ in 0..<20 {
            window.onAllPartsReceived(transferRate: 1000.0)
        }
        XCTAssertLessThanOrEqual(window.currentWindow, ResourceConstants.WINDOW_MAX_SLOW)
    }

    func testFastRateUnlocksLargerWindow() {
        let window = ResourceWindow()
        // Need FAST_RATE_THRESHOLD consecutive fast rounds
        for _ in 0..<(ResourceConstants.FAST_RATE_THRESHOLD + 5) {
            window.onAllPartsReceived(transferRate: ResourceConstants.RATE_FAST + 100)
        }
        XCTAssertEqual(window.windowMax, ResourceConstants.WINDOW_MAX_FAST)
    }

    func testVerySlowRateRestrictsWindow() {
        let window = ResourceWindow()
        for _ in 0..<(ResourceConstants.VERY_SLOW_RATE_THRESHOLD + 1) {
            window.onAllPartsReceived(transferRate: ResourceConstants.RATE_VERY_SLOW - 1)
        }
        XCTAssertEqual(window.windowMax, ResourceConstants.WINDOW_MAX_VERY_SLOW)
    }

    func testTimeoutHalvesWindow() {
        let window = ResourceWindow()
        // First grow the window
        for _ in 0..<5 {
            window.onAllPartsReceived(transferRate: 1000.0)
        }
        let beforeTimeout = window.currentWindow
        window.onTimeout()
        XCTAssertLessThanOrEqual(window.currentWindow, beforeTimeout / 2 + 1)
        XCTAssertGreaterThanOrEqual(window.currentWindow, window.windowMin)
    }

    func testTimeoutResetsRateTracking() {
        let window = ResourceWindow()
        // Build up fast rate rounds
        for _ in 0..<3 {
            window.onAllPartsReceived(transferRate: ResourceConstants.RATE_FAST + 100)
        }
        // Timeout should reset counters
        window.onTimeout()
        // Need full FAST_RATE_THRESHOLD again after timeout
        for _ in 0..<(ResourceConstants.FAST_RATE_THRESHOLD - 1) {
            window.onAllPartsReceived(transferRate: ResourceConstants.RATE_FAST + 100)
        }
        // Should NOT have unlocked fast window yet (threshold not met after reset)
        XCTAssertNotEqual(window.windowMax, ResourceConstants.WINDOW_MAX_FAST)
    }

    // MARK: - Integration: Simulated Transfer

    /// Simulate a realistic transfer with partial hashmap coverage.
    /// This is the scenario that triggered the ghost outstanding bug.
    func testSimulatedTransferWithHashmapExhaustion() {
        let window = ResourceWindow()
        let totalParts = 178
        var parts = Array(repeating: false, count: totalParts)
        let hashmapCoverage = 148 // Only first 148 parts have hashmap entries

        // First batch: window=4, all within hashmap
        let batch1 = window.getRequestRange(parts: parts)
        XCTAssertEqual(batch1.count, min(ResourceConstants.WINDOW_INITIAL, totalParts))

        // Count only requestable indices (within hashmap coverage)
        let requestable1 = batch1.filter { $0 < hashmapCoverage }
        window.markRequested(count: requestable1.count)
        XCTAssertEqual(window.outstanding, requestable1.count)

        // Receive all parts from batch 1
        for index in requestable1 {
            parts[index] = true
            window.markReceived(index: index, totalParts: totalParts)
        }
        window.updateConsecutiveHeight(parts: parts)
        XCTAssertEqual(window.outstanding, 0)

        // Simulate progression until we hit hashmap boundary
        // Fast-forward: mark parts 0..<148 as complete
        for i in 0..<148 {
            parts[i] = true
        }
        window.updateConsecutiveHeight(parts: parts)
        XCTAssertEqual(window.height, 148)

        // Now get request range — will include parts beyond hashmap coverage
        let batchN = window.getRequestRange(parts: parts)
        // All remaining parts 148-177 are incomplete
        let requestableN = batchN.filter { $0 < hashmapCoverage }
        let beyondHashmap = batchN.filter { $0 >= hashmapCoverage }

        // All requested parts are beyond hashmap — 0 requestable
        XCTAssertEqual(requestableN.count, 0)
        XCTAssertGreaterThan(beyondHashmap.count, 0)

        // Only mark 0 as requested (none are within hashmap)
        window.markRequested(count: requestableN.count)
        XCTAssertEqual(window.outstanding, 0,
                       "No ghost outstanding: beyond-hashmap parts not counted")
    }

    /// End-to-end: receive all parts in order, outstanding reaches 0 each batch.
    func testFullTransferOutstandingReachesZero() {
        let window = ResourceWindow()
        let totalParts = 20
        var parts = Array(repeating: false, count: totalParts)
        var idx = 0

        while idx < totalParts {
            let batch = window.getRequestRange(parts: parts)
            if batch.isEmpty { break }

            window.markRequested(count: batch.count)
            for i in batch {
                parts[i] = true
                window.markReceived(index: i, totalParts: totalParts)
            }
            window.updateConsecutiveHeight(parts: parts)
            XCTAssertEqual(window.outstanding, 0,
                           "Outstanding must be 0 after each complete batch (batch starting at \(idx))")

            idx = window.height
            window.onAllPartsReceived(transferRate: 1000.0)
        }

        XCTAssertEqual(window.height, totalParts)
    }
}
