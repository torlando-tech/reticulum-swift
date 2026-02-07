//
//  PathTableAcceptanceTests.swift
//  ReticulumSwiftTests
//
//  Tests for the 5-path decision tree matching Python Transport.py:1614-1686.
//

import XCTest
@testable import ReticulumSwift

final class PathTableAcceptanceTests: XCTestCase {

    // MARK: - Helpers

    /// Create a random blob with a specific emission timestamp embedded at bytes[5:10].
    private func makeBlob(timestamp: UInt64, prefix: Data? = nil) -> Data {
        var blob = prefix ?? Data((0..<5).map { _ in UInt8.random(in: 0...255) })
        if blob.count < 5 { blob.append(contentsOf: Data(repeating: 0, count: 5 - blob.count)) }
        if blob.count > 5 { blob = Data(blob.prefix(5)) }
        // Append 5 bytes of big-endian timestamp
        for i in (0..<5).reversed() {
            blob.append(UInt8((timestamp >> (i * 8)) & 0xFF))
        }
        return blob
    }

    private func makeDummyEntry(
        destHash: Data = Data(repeating: 0xAA, count: 16),
        hopCount: UInt8 = 1,
        blob: Data,
        expiration: TimeInterval = PathEntry.standardExpiration
    ) -> PathEntry {
        PathEntry(
            destinationHash: destHash,
            publicKeys: Data(repeating: 0, count: 64),
            interfaceId: "test-iface",
            hopCount: hopCount,
            expiration: expiration,
            randomBlob: blob
        )
    }

    private func makeDummyEntryWithExpires(
        destHash: Data = Data(repeating: 0xAA, count: 16),
        hopCount: UInt8 = 1,
        blob: Data,
        expires: Date
    ) -> PathEntry {
        PathEntry(
            destinationHash: destHash,
            publicKeys: Data(repeating: 0, count: 64),
            interfaceId: "test-iface",
            hopCount: hopCount,
            timestamp: Date(),
            expires: expires,
            randomBlob: blob
        )
    }

    // MARK: - Path 1: Unknown destination

    func testUnknownDestinationAccepted() async throws {
        let table = PathTable()
        let blob = makeBlob(timestamp: 1000)
        let entry = makeDummyEntry(hopCount: 3, blob: blob)
        let result = await table.record(entry: entry)
        XCTAssertTrue(result, "Unknown destination should always be accepted")

        let stored = await table.lookup(destinationHash: entry.destinationHash)
        XCTAssertNotNil(stored)
        XCTAssertEqual(stored?.hopCount, 3)
    }

    // MARK: - Path 2: Equal/better hops + new blob + fresher timestamp

    func testBetterHopsNewBlobFresherTimestamp() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0xBB, count: 16)
        let blob1 = makeBlob(timestamp: 1000)
        let blob2 = makeBlob(timestamp: 2000)

        let entry1 = makeDummyEntry(destHash: destHash, hopCount: 3, blob: blob1)
        await table.record(entry: entry1)

        let entry2 = makeDummyEntry(destHash: destHash, hopCount: 2, blob: blob2)
        let result = await table.record(entry: entry2)
        XCTAssertTrue(result, "Better hops with new blob and fresher timestamp should be accepted")

        let stored = await table.lookup(destinationHash: destHash)
        XCTAssertEqual(stored?.hopCount, 2)
    }

    func testEqualHopsNewBlobFresherTimestamp() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0xCC, count: 16)
        let blob1 = makeBlob(timestamp: 1000)
        let blob2 = makeBlob(timestamp: 2000)

        await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 3, blob: blob1))
        let result = await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 3, blob: blob2))
        XCTAssertTrue(result, "Equal hops with new blob and fresher timestamp should be accepted")
    }

    func testEqualHopsDuplicateBlobRejected() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0xDD, count: 16)
        let blob = makeBlob(timestamp: 1000)

        await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 3, blob: blob))
        let result = await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 3, blob: blob))
        XCTAssertFalse(result, "Duplicate blob should be rejected")
    }

    func testEqualHopsStaleTimestampRejected() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0xEE, count: 16)
        let blob1 = makeBlob(timestamp: 2000)
        let blob2 = makeBlob(timestamp: 1000) // older

        await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 3, blob: blob1))
        let result = await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 3, blob: blob2))
        XCTAssertFalse(result, "Stale timestamp should be rejected for equal hops")
    }

    // MARK: - Path 3: Worse hops + expired path + new blob

    func testWorseHopsExpiredPathNewBlob() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0x11, count: 16)
        let blob1 = makeBlob(timestamp: 1000)
        let blob2 = makeBlob(timestamp: 2000)

        // Insert entry that's already expired
        let expiredEntry = makeDummyEntryWithExpires(
            destHash: destHash, hopCount: 2, blob: blob1,
            expires: Date().addingTimeInterval(-1) // expired 1 second ago
        )
        await table.record(entry: expiredEntry)

        let worseEntry = makeDummyEntry(destHash: destHash, hopCount: 5, blob: blob2)
        let result = await table.record(entry: worseEntry)
        XCTAssertTrue(result, "Worse hops should be accepted when path is expired and blob is new")
    }

    func testWorseHopsExpiredPathDuplicateBlobRejected() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0x22, count: 16)
        let blob = makeBlob(timestamp: 1000)

        let expiredEntry = makeDummyEntryWithExpires(
            destHash: destHash, hopCount: 2, blob: blob,
            expires: Date().addingTimeInterval(-1)
        )
        await table.record(entry: expiredEntry)

        let worseEntry = makeDummyEntry(destHash: destHash, hopCount: 5, blob: blob)
        let result = await table.record(entry: worseEntry)
        XCTAssertFalse(result, "Worse hops with duplicate blob should be rejected even when expired")
    }

    // MARK: - Path 4: Worse hops + not expired + fresher emission + new blob

    func testWorseHopsNotExpiredFresherEmission() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0x33, count: 16)
        let blob1 = makeBlob(timestamp: 1000)
        let blob2 = makeBlob(timestamp: 3000) // much fresher

        await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 2, blob: blob1))
        let result = await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 5, blob: blob2))
        XCTAssertTrue(result, "Worse hops should be accepted when emission is fresher and blob is new")
    }

    func testWorseHopsNotExpiredStaleEmissionRejected() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0x44, count: 16)
        let blob1 = makeBlob(timestamp: 3000)
        let blob2 = makeBlob(timestamp: 2000) // older emission

        await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 2, blob: blob1))
        let result = await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 5, blob: blob2))
        XCTAssertFalse(result, "Worse hops with stale emission should be rejected")
    }

    // MARK: - Path 5: Same emission + unresponsive path

    func testSameEmissionUnresponsivePath() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0x55, count: 16)
        let blob1 = makeBlob(timestamp: 1000)
        let blob2 = makeBlob(timestamp: 1000) // same emission timestamp, different blob

        await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 2, blob: blob1))
        await table.markPathUnresponsive(destHash)

        let result = await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 5, blob: blob2))
        XCTAssertTrue(result, "Same emission should be accepted when path is unresponsive")
    }

    func testSameEmissionResponsivePathRejected() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0x66, count: 16)
        let blob1 = makeBlob(timestamp: 1000)
        let blob2 = makeBlob(timestamp: 1000)

        await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 2, blob: blob1))
        // Path is NOT unresponsive (default unknown state)

        let result = await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 5, blob: blob2))
        XCTAssertFalse(result, "Same emission should be rejected when path is not unresponsive")
    }

    // MARK: - Blob merging

    func testBlobsMergedOnAccept() async throws {
        let table = PathTable()
        let destHash = Data(repeating: 0x77, count: 16)
        let blob1 = makeBlob(timestamp: 1000)
        let blob2 = makeBlob(timestamp: 2000)

        await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 3, blob: blob1))
        await table.record(entry: makeDummyEntry(destHash: destHash, hopCount: 2, blob: blob2))

        let stored = await table.lookup(destinationHash: destHash)
        XCTAssertEqual(stored?.randomBlobs.count, 2, "Both blobs should be stored")
        XCTAssertTrue(stored?.randomBlobs.contains(blob1) == true)
        XCTAssertTrue(stored?.randomBlobs.contains(blob2) == true)
    }

    // MARK: - Emission timestamp extraction

    func testEmissionTimestampExtraction() {
        // Create a blob with known timestamp bytes at positions 5-9
        var blob = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        // Timestamp = 0x00_00_01_86_A0 = 100000
        blob.append(contentsOf: [0x00, 0x00, 0x01, 0x86, 0xA0])

        let ts = PathEntry.emissionTimestamp(from: blob)
        XCTAssertEqual(ts, 100000)
    }
}
