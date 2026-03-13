//
//  InteropTestBase.swift
//  ReticulumSwiftTests
//
//  Base class for interoperability tests with Python RNS.
//  Provides a shared Python bridge instance and utility methods.
//
//  Mirrors: reticulum-kt/rns-test/.../interop/InteropTestBase.kt
//

import XCTest
import Foundation
@testable import ReticulumSwift

/// Base class for interoperability tests with Python RNS.
///
/// Subclass this and add test methods that compare Swift results
/// against the Python reference implementation via the bridge.
///
/// Tests are automatically skipped when Python/RNS is not available.
class InteropTestBase: XCTestCase {

    var bridge: PythonBridge!

    override func setUpWithError() throws {
        try super.setUpWithError()
        try XCTSkipUnless(PythonBridge.isAvailable, "Python RNS not available")
        bridge = try PythonBridge.start()
    }

    override func tearDown() {
        bridge?.close()
        bridge = nil
        super.tearDown()
    }

    // MARK: - Convenience

    /// Execute a Python command with auto hex-encoding of Data params.
    /// Note: Most tests call bridge.execute() directly for clearer syntax.
    @discardableResult
    func python(_ command: String, _ params: [(String, Any?)]) throws -> [String: Any] {
        try bridge.executeArray(command, params)
    }

    // MARK: - Assertions

    /// Assert that two Data values are byte-equal, with detailed diff on failure.
    func assertBytesEqual(_ expected: Data, _ actual: Data, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
        if expected == actual { return }

        var diff = ""
        if !message.isEmpty { diff += "Byte mismatch: \(message)\n" }
        diff += "Expected (\(expected.count) bytes): \(expected.hexString)\n"
        diff += "Actual   (\(actual.count) bytes): \(actual.hexString)\n"

        let maxLen = max(expected.count, actual.count)
        var diffs: [String] = []
        for i in 0..<maxLen {
            let exp = i < expected.count ? expected[expected.startIndex + i] : nil
            let act = i < actual.count ? actual[actual.startIndex + i] : nil
            if exp != act {
                let expStr = exp.map { String(format: "%02x", $0) } ?? "??"
                let actStr = act.map { String(format: "%02x", $0) } ?? "??"
                diffs.append("[\(i)] \(expStr) != \(actStr)")
                if diffs.count >= 10 {
                    diffs.append("... (\(maxLen - i - 1) more)")
                    break
                }
            }
        }
        if !diffs.isEmpty {
            diff += "Differences:\n" + diffs.map { "  \($0)" }.joined(separator: "\n")
        }

        XCTFail(diff, file: file, line: line)
    }
}
