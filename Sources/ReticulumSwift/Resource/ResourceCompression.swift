//
//  ResourceCompression.swift
//  ReticulumSwift
//
//  Compression utilities for resource data.
//  Matches Python RNS Resource.py compression behavior where possible.
//
//  Note: Python RNS uses bz2 compression. Apple's Compression framework
//  does not support bz2, so we use LZMA which provides similar compression
//  ratios. For full Python RNS interop, compression should be disabled
//  or a bz2 library added as a dependency.
//

import Foundation
import Compression

// MARK: - Compression Result

/// Result of compression attempt.
public struct CompressionResult: Sendable {
    /// Processed data (compressed or original)
    public let data: Data

    /// Whether compression was used
    public let compressed: Bool

    /// Original uncompressed size
    public let originalSize: Int

    /// Compressed size (or original size if not compressed)
    public var processedSize: Int {
        return data.count
    }

    /// Compression ratio (compressed / original)
    public var ratio: Double {
        return Double(processedSize) / Double(originalSize)
    }
}

// MARK: - Resource Compression

/// Compression utilities for resource data.
///
/// Python RNS compresses data < 64MB and uses uncompressed if
/// compressed output is larger than input (e.g., for random/encrypted data).
///
/// This fallback behavior is critical for efficiency: attempting to
/// compress already-compressed or encrypted data typically produces
/// output larger than the input due to compression overhead.
///
/// Note: For full Python RNS interoperability, set autoCompress to false
/// since Python uses bz2 compression which is not natively available on Apple platforms.
public enum ResourceCompression {

    // MARK: - Compression Algorithm

    /// Compression algorithm to use.
    /// LZMA provides good compression ratios similar to bz2.
    private static let algorithm = COMPRESSION_LZMA

    // MARK: - Compression

    /// Compress data, falling back to uncompressed if larger.
    ///
    /// From Python RNS Resource.py:
    /// ```python
    /// if uncompressed_size < Resource.AUTO_COMPRESS_MAX_SIZE:
    ///     compressed_data = bz2.compress(data)
    ///     if len(compressed_data) < len(data):
    ///         self.compressed = True
    ///         data = compressed_data
    /// ```
    ///
    /// - Parameters:
    ///   - data: Data to compress
    ///   - autoCompress: Whether to attempt compression (default true)
    ///   - maxSize: Maximum size for compression attempt (default 64MB)
    /// - Returns: CompressionResult with data and compression flag
    /// - Throws: ResourceError.compressionFailed on compression error
    public static func compress(
        _ data: Data,
        autoCompress: Bool = true,
        maxSize: Int = ResourceConstants.AUTO_COMPRESS_MAX_SIZE
    ) throws -> CompressionResult {
        let originalSize = data.count

        // Skip compression if disabled or data too large
        guard autoCompress && originalSize <= maxSize && originalSize > 0 else {
            return CompressionResult(
                data: data,
                compressed: false,
                originalSize: originalSize
            )
        }

        // Attempt compression using Apple's Compression framework
        let destinationBufferSize = originalSize + 1024  // Allow some overhead
        var destinationBuffer = [UInt8](repeating: 0, count: destinationBufferSize)

        let compressedSize = data.withUnsafeBytes { sourceBuffer -> Int in
            guard let sourcePointer = sourceBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return 0
            }
            return compression_encode_buffer(
                &destinationBuffer,
                destinationBufferSize,
                sourcePointer,
                originalSize,
                nil,
                algorithm
            )
        }

        // Check if compression succeeded and produced smaller output
        if compressedSize > 0 && compressedSize < originalSize {
            let compressed = Data(bytes: destinationBuffer, count: compressedSize)
            return CompressionResult(
                data: compressed,
                compressed: true,
                originalSize: originalSize
            )
        } else {
            // Compression failed or output larger than input, use original
            return CompressionResult(
                data: data,
                compressed: false,
                originalSize: originalSize
            )
        }
    }

    // MARK: - Decompression

    /// Decompress compressed data.
    ///
    /// - Parameters:
    ///   - data: Compressed data
    ///   - expectedSize: Expected decompressed size (for buffer allocation)
    /// - Returns: Decompressed data
    /// - Throws: ResourceError.decompressionFailed on error
    public static func decompress(_ data: Data, expectedSize: Int? = nil) throws -> Data {
        guard !data.isEmpty else {
            return Data()
        }

        // Start with expected size or reasonable estimate
        var bufferSize = expectedSize ?? (data.count * 10)
        var attempts = 0
        let maxAttempts = 5

        while attempts < maxAttempts {
            var destinationBuffer = [UInt8](repeating: 0, count: bufferSize)

            let decompressedSize = data.withUnsafeBytes { sourceBuffer -> Int in
                guard let sourcePointer = sourceBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return 0
                }
                return compression_decode_buffer(
                    &destinationBuffer,
                    bufferSize,
                    sourcePointer,
                    data.count,
                    nil,
                    algorithm
                )
            }

            if decompressedSize > 0 {
                return Data(bytes: destinationBuffer, count: decompressedSize)
            } else if decompressedSize == 0 && bufferSize < data.count * 100 {
                // Buffer might be too small, try larger
                bufferSize *= 2
                attempts += 1
            } else {
                break
            }
        }

        throw ResourceError.decompressionFailed(
            reason: "Decompression failed after \(attempts) attempts"
        )
    }

    // MARK: - Python RNS Interoperability

    /// Check if data appears to be bz2 compressed (Python RNS format).
    ///
    /// bz2 magic bytes: 0x42 0x5A 0x68 ("BZh")
    ///
    /// - Parameter data: Data to check
    /// - Returns: true if data starts with bz2 magic bytes
    public static func isBZ2Compressed(_ data: Data) -> Bool {
        guard data.count >= 3 else { return false }
        return data[0] == 0x42 && data[1] == 0x5A && data[2] == 0x68
    }

    /// Check if data appears to be LZMA compressed (Swift format).
    ///
    /// LZMA magic bytes vary, but we use a simple heuristic.
    ///
    /// - Parameter data: Data to check
    /// - Returns: true if data might be LZMA compressed
    public static func isLZMACompressed(_ data: Data) -> Bool {
        // LZMA streams typically start with specific property bytes
        // This is a heuristic, not a guarantee
        guard data.count >= 5 else { return false }
        // LZMA properties byte is usually in a specific range
        return data[0] <= 0xE0
    }
}
