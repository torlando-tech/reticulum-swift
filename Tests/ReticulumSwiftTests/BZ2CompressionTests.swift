//
//  BZ2CompressionTests.swift
//  ReticulumSwiftTests
//
//  Tests for BZ2 compression/decompression via the system libbz2 library.
//  Verifies round-trip correctness, Python interoperability (magic bytes),
//  and the ResourceCompression API behavior.
//

import XCTest
@testable import ReticulumSwift

final class BZ2CompressionTests: XCTestCase {

    // MARK: - Round-Trip Tests

    /// Verify basic compress/decompress round-trip produces identical data.
    func testRoundTripBasic() throws {
        let original = "Hello, Reticulum! This is a BZ2 compression test.".data(using: .utf8)!
        let compressed = try ResourceCompression.bz2Compress(original)
        let decompressed = try ResourceCompression.bz2Decompress(compressed)
        XCTAssertEqual(decompressed, original)
    }

    /// Round-trip with repeated data (high compression ratio).
    func testRoundTripRepeatedData() throws {
        let pattern = "ABCDEFGH".data(using: .utf8)!
        var original = Data()
        for _ in 0..<1000 {
            original.append(pattern)
        }
        XCTAssertEqual(original.count, 8000)

        let compressed = try ResourceCompression.bz2Compress(original)
        XCTAssertLessThan(compressed.count, original.count,
                          "Repeated data should compress significantly")

        let decompressed = try ResourceCompression.bz2Decompress(compressed)
        XCTAssertEqual(decompressed, original)
    }

    /// Round-trip with random data (low compression ratio).
    func testRoundTripRandomData() throws {
        var original = Data(count: 4096)
        _ = original.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 4096, buffer.baseAddress!)
        }

        let compressed = try ResourceCompression.bz2Compress(original)
        // Random data typically does not compress well; may be larger
        let decompressed = try ResourceCompression.bz2Decompress(compressed)
        XCTAssertEqual(decompressed, original)
    }

    /// Round-trip with empty data.
    func testRoundTripEmpty() throws {
        let original = Data()
        let compressed = try ResourceCompression.bz2Compress(original)
        XCTAssertEqual(compressed, Data())
        let decompressed = try ResourceCompression.bz2Decompress(compressed)
        XCTAssertEqual(decompressed, Data())
    }

    /// Round-trip with single byte.
    func testRoundTripSingleByte() throws {
        let original = Data([0x42])
        let compressed = try ResourceCompression.bz2Compress(original)
        let decompressed = try ResourceCompression.bz2Decompress(compressed)
        XCTAssertEqual(decompressed, original)
    }

    /// Round-trip with larger data (~100KB).
    func testRoundTripLargeData() throws {
        // Create 100KB of semi-compressible data (repeating pattern with variation)
        var original = Data()
        for i in 0..<(100 * 1024) {
            original.append(UInt8(i % 256))
        }

        let compressed = try ResourceCompression.bz2Compress(original)
        let decompressed = try ResourceCompression.bz2Decompress(compressed)
        XCTAssertEqual(decompressed, original)
        XCTAssertEqual(decompressed.count, 100 * 1024)
    }

    // MARK: - BZ2 Magic Bytes

    /// Verify BZ2 compressed output starts with "BZh" magic bytes.
    func testBZ2MagicBytes() throws {
        let original = "Test data for magic byte verification".data(using: .utf8)!
        let compressed = try ResourceCompression.bz2Compress(original)

        XCTAssertGreaterThanOrEqual(compressed.count, 3)
        XCTAssertEqual(compressed[0], 0x42, "First byte should be 'B' (0x42)")
        XCTAssertEqual(compressed[1], 0x5A, "Second byte should be 'Z' (0x5A)")
        XCTAssertEqual(compressed[2], 0x68, "Third byte should be 'h' (0x68)")
    }

    /// Verify isBZ2Compressed detects BZ2 format correctly.
    func testIsBZ2CompressedDetection() throws {
        let original = "Some data to compress".data(using: .utf8)!
        let compressed = try ResourceCompression.bz2Compress(original)

        XCTAssertTrue(ResourceCompression.isBZ2Compressed(compressed))
        XCTAssertFalse(ResourceCompression.isBZ2Compressed(original))
        XCTAssertFalse(ResourceCompression.isBZ2Compressed(Data()))
        XCTAssertFalse(ResourceCompression.isBZ2Compressed(Data([0x42, 0x5A])))
    }

    // MARK: - ResourceCompression API Tests

    /// Verify ResourceCompression.compress() uses BZ2 and produces compressible output.
    func testResourceCompressionCompressAPI() throws {
        // Create compressible data
        let original = String(repeating: "Reticulum ", count: 500).data(using: .utf8)!

        let result = try ResourceCompression.compress(original)
        XCTAssertTrue(result.compressed, "Repeated text should compress")
        XCTAssertLessThan(result.processedSize, result.originalSize)
        XCTAssertEqual(result.originalSize, original.count)

        // Verify it is valid BZ2
        XCTAssertTrue(ResourceCompression.isBZ2Compressed(result.data))

        // Verify decompression
        let decompressed = try ResourceCompression.decompress(result.data)
        XCTAssertEqual(decompressed, original)
    }

    /// Verify compression is skipped when autoCompress is false.
    func testResourceCompressionDisabled() throws {
        let original = String(repeating: "Test ", count: 200).data(using: .utf8)!

        let result = try ResourceCompression.compress(original, autoCompress: false)
        XCTAssertFalse(result.compressed)
        XCTAssertEqual(result.data, original)
    }

    /// Verify compression is skipped for data larger than maxSize.
    func testResourceCompressionMaxSize() throws {
        let original = String(repeating: "X", count: 100).data(using: .utf8)!

        let result = try ResourceCompression.compress(original, maxSize: 50)
        XCTAssertFalse(result.compressed)
        XCTAssertEqual(result.data, original)
    }

    /// Verify compression falls back to uncompressed for random data.
    func testResourceCompressionFallbackForRandom() throws {
        var original = Data(count: 4096)
        _ = original.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 4096, buffer.baseAddress!)
        }

        let result = try ResourceCompression.compress(original)
        // Random data typically cannot be compressed; result may be uncompressed
        if result.compressed {
            // If BZ2 did compress it (unlikely but possible), verify round-trip
            let decompressed = try ResourceCompression.decompress(result.data)
            XCTAssertEqual(decompressed, original)
        } else {
            XCTAssertEqual(result.data, original)
        }
    }

    // MARK: - Decompression Error Handling

    /// Verify decompression of invalid data throws an error.
    func testDecompressInvalidData() {
        let garbage = Data([0xFF, 0xFE, 0xFD, 0xFC, 0xFB])
        XCTAssertThrowsError(try ResourceCompression.decompress(garbage)) { error in
            guard case ResourceError.decompressionFailed = error else {
                XCTFail("Expected ResourceError.decompressionFailed, got \(error)")
                return
            }
        }
    }

    /// Verify decompression with truncated BZ2 data throws an error.
    func testDecompressTruncatedBZ2() throws {
        let original = String(repeating: "Hello ", count: 100).data(using: .utf8)!
        let compressed = try ResourceCompression.bz2Compress(original)

        // Truncate to half
        let truncated = compressed.prefix(compressed.count / 2)
        XCTAssertThrowsError(try ResourceCompression.bz2Decompress(Data(truncated)))
    }

    // MARK: - Block Size Parameter

    /// Verify different block sizes all produce valid compressed data.
    func testDifferentBlockSizes() throws {
        let original = String(repeating: "Block size test data ", count: 100).data(using: .utf8)!

        for blockSize: Int32 in 1...9 {
            let compressed = try ResourceCompression.bz2Compress(original, blockSize: blockSize)
            XCTAssertTrue(ResourceCompression.isBZ2Compressed(compressed),
                          "Block size \(blockSize) should produce valid BZ2")
            let decompressed = try ResourceCompression.bz2Decompress(compressed)
            XCTAssertEqual(decompressed, original,
                           "Round-trip with block size \(blockSize) should be lossless")
        }
    }

    // MARK: - Python Interop Verification

    /// Verify BZ2 output has the correct block size indicator byte.
    /// Python bz2.compress(data, compresslevel=9) produces "BZh9" header.
    func testBZ2BlockSizeIndicator() throws {
        let original = "Test".data(using: .utf8)!

        // Block size 9 (default, matching Python default)
        let compressed9 = try ResourceCompression.bz2Compress(original, blockSize: 9)
        XCTAssertGreaterThanOrEqual(compressed9.count, 4)
        // BZ2 header: "BZh" + ASCII digit for block size
        // Block size 9 -> 0x39 ('9')
        XCTAssertEqual(compressed9[3], 0x39,
                        "Block size 9 should produce 'BZh9' header")

        // Block size 1
        let compressed1 = try ResourceCompression.bz2Compress(original, blockSize: 1)
        XCTAssertEqual(compressed1[3], 0x31,
                        "Block size 1 should produce 'BZh1' header")
    }

    /// Known BZ2 compressed bytes from Python for cross-platform verification.
    /// Generated with: python3 -c "import bz2; print(list(bz2.compress(b'Hello')))"
    func testDecompressPythonBZ2Output() throws {
        let pythonCompressed = Data([
            66, 90, 104, 57, 49, 65, 89, 38, 83, 89, 26, 84, 100, 146,
            0, 0, 0, 5, 0, 0, 64, 2, 4, 160, 0, 33, 154, 104, 51, 77,
            19, 51, 139, 185, 34, 156, 40, 72, 13, 42, 50, 73, 0
        ])

        let decompressed = try ResourceCompression.bz2Decompress(pythonCompressed)
        let expected = "Hello".data(using: .utf8)!
        XCTAssertEqual(decompressed, expected,
                       "Should decompress Python bz2.compress(b'Hello') correctly")
    }
}
