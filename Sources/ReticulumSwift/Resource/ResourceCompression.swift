//
//  ResourceCompression.swift
//  ReticulumSwift
//
//  BZ2 compression utilities for resource data.
//  Matches Python RNS Resource.py compression behavior using bz2.compress/decompress.
//
//  Uses the system libbz2 library available on all Apple platforms
//  (macOS, iOS, watchOS, tvOS, visionOS) via the CBZ2 system library target.
//

import Foundation
import CBZ2

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

// MARK: - BZ2 Error

/// Errors specific to BZ2 compression/decompression operations.
public enum BZ2Error: Error, CustomStringConvertible {
    case compressFailed(code: Int32)
    case decompressFailed(code: Int32)
    case outputBufferTooSmall

    public var description: String {
        switch self {
        case .compressFailed(let code):
            return "BZ2 compression failed with code \(code) (\(BZ2Error.errorName(code)))"
        case .decompressFailed(let code):
            return "BZ2 decompression failed with code \(code) (\(BZ2Error.errorName(code)))"
        case .outputBufferTooSmall:
            return "BZ2 output buffer too small after maximum retries"
        }
    }

    /// Map BZ2 error codes to human-readable names.
    static func errorName(_ code: Int32) -> String {
        switch code {
        case BZ_OK:              return "BZ_OK"
        case BZ_RUN_OK:          return "BZ_RUN_OK"
        case BZ_FLUSH_OK:        return "BZ_FLUSH_OK"
        case BZ_FINISH_OK:       return "BZ_FINISH_OK"
        case BZ_STREAM_END:      return "BZ_STREAM_END"
        case BZ_SEQUENCE_ERROR:  return "BZ_SEQUENCE_ERROR"
        case BZ_PARAM_ERROR:     return "BZ_PARAM_ERROR"
        case BZ_MEM_ERROR:       return "BZ_MEM_ERROR"
        case BZ_DATA_ERROR:      return "BZ_DATA_ERROR"
        case BZ_DATA_ERROR_MAGIC: return "BZ_DATA_ERROR_MAGIC"
        case BZ_IO_ERROR:        return "BZ_IO_ERROR"
        case BZ_UNEXPECTED_EOF:  return "BZ_UNEXPECTED_EOF"
        case BZ_OUTBUFF_FULL:    return "BZ_OUTBUFF_FULL"
        case BZ_CONFIG_ERROR:    return "BZ_CONFIG_ERROR"
        default:                 return "UNKNOWN(\(code))"
        }
    }
}

// MARK: - Resource Compression

/// BZ2 compression utilities for resource data.
///
/// Python RNS compresses data < 64MB using `bz2.compress()` and uses
/// uncompressed if compressed output is larger than input (e.g., for
/// random/encrypted data).
///
/// This implementation uses the system libbz2 library (available on all
/// Apple platforms) for full Python RNS interoperability.
public enum ResourceCompression {

    // MARK: - BZ2 Parameters

    /// Default BZ2 block size (1-9). Python bz2.compress() defaults to 9.
    /// Block size 9 = 900KB blocks, best compression ratio.
    private static let defaultBlockSize: Int32 = 9

    /// BZ2 work factor. 0 = default (30). Controls fallback algorithm behavior.
    private static let workFactor: Int32 = 0

    /// BZ2 small decompress flag. 0 = normal, 1 = reduced memory mode.
    private static let smallDecompress: Int32 = 0

    // MARK: - Low-Level BZ2 API

    /// Compress data using BZ2.
    ///
    /// Calls `BZ2_bzBuffToBuffCompress` from the system libbz2 library.
    /// This matches Python's `bz2.compress(data, compresslevel=9)`.
    ///
    /// - Parameters:
    ///   - data: Input data to compress
    ///   - blockSize: BZ2 block size (1-9, default 9)
    /// - Returns: BZ2-compressed data (starts with "BZh" magic bytes)
    /// - Throws: BZ2Error on compression failure
    public static func bz2Compress(_ data: Data, blockSize: Int32 = 9) throws -> Data {
        guard !data.isEmpty else {
            return Data()
        }

        // BZ2 worst case: output can be ~1% larger than input + 600 bytes overhead
        var destLen = UInt32(data.count + data.count / 100 + 600)
        var destBuffer = [UInt8](repeating: 0, count: Int(destLen))

        let result = data.withUnsafeBytes { sourceBuffer -> Int32 in
            guard let sourcePointer = sourceBuffer.baseAddress else {
                return BZ_PARAM_ERROR
            }
            return BZ2_bzBuffToBuffCompress(
                &destBuffer,
                &destLen,
                UnsafeMutableRawPointer(mutating: sourcePointer).assumingMemoryBound(to: CChar.self),
                UInt32(data.count),
                blockSize,
                0,          // verbosity
                workFactor
            )
        }

        guard result == BZ_OK else {
            throw BZ2Error.compressFailed(code: result)
        }

        return Data(bytes: destBuffer, count: Int(destLen))
    }

    /// Decompress BZ2-compressed data.
    ///
    /// Calls `BZ2_bzBuffToBuffDecompress` from the system libbz2 library.
    /// This matches Python's `bz2.decompress(data)`.
    ///
    /// Uses progressive buffer sizing: starts at 4x input size, doubles up to
    /// 5 attempts to handle unknown decompressed sizes.
    ///
    /// - Parameters:
    ///   - data: BZ2-compressed input data
    ///   - expectedSize: Optional hint for output buffer size
    /// - Returns: Decompressed data
    /// - Throws: BZ2Error on decompression failure
    public static func bz2Decompress(_ data: Data, expectedSize: Int? = nil) throws -> Data {
        guard !data.isEmpty else {
            return Data()
        }

        // Start with expected size or 4x input as estimate
        var bufferSize = expectedSize ?? (data.count * 4)
        // Minimum buffer to avoid trivially small allocations
        if bufferSize < 1024 {
            bufferSize = 1024
        }

        let maxAttempts = 6

        for attempt in 0..<maxAttempts {
            var destLen = UInt32(bufferSize)
            var destBuffer = [UInt8](repeating: 0, count: bufferSize)

            let result = data.withUnsafeBytes { sourceBuffer -> Int32 in
                guard let sourcePointer = sourceBuffer.baseAddress else {
                    return BZ_PARAM_ERROR
                }
                return BZ2_bzBuffToBuffDecompress(
                    &destBuffer,
                    &destLen,
                    UnsafeMutableRawPointer(mutating: sourcePointer).assumingMemoryBound(to: CChar.self),
                    UInt32(data.count),
                    smallDecompress,
                    0  // verbosity
                )
            }

            if result == BZ_OK {
                return Data(bytes: destBuffer, count: Int(destLen))
            } else if result == BZ_OUTBUFF_FULL && attempt < maxAttempts - 1 {
                // Double buffer and retry
                bufferSize *= 2
                continue
            } else {
                throw BZ2Error.decompressFailed(code: result)
            }
        }

        throw BZ2Error.outputBufferTooSmall
    }

    // MARK: - Resource Compression API

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

        // Attempt BZ2 compression
        do {
            let compressed = try bz2Compress(data, blockSize: defaultBlockSize)

            // Use compressed only if smaller than original
            if compressed.count < originalSize {
                return CompressionResult(
                    data: compressed,
                    compressed: true,
                    originalSize: originalSize
                )
            } else {
                // Compressed output is larger, use original
                return CompressionResult(
                    data: data,
                    compressed: false,
                    originalSize: originalSize
                )
            }
        } catch {
            // Compression failed, fall back to uncompressed
            return CompressionResult(
                data: data,
                compressed: false,
                originalSize: originalSize
            )
        }
    }

    // MARK: - Decompression

    /// Decompress BZ2 compressed data.
    ///
    /// - Parameters:
    ///   - data: BZ2-compressed data
    ///   - expectedSize: Expected decompressed size (for buffer allocation)
    /// - Returns: Decompressed data
    /// - Throws: ResourceError.decompressionFailed on error
    public static func decompress(_ data: Data, expectedSize: Int? = nil) throws -> Data {
        guard !data.isEmpty else {
            return Data()
        }

        do {
            return try bz2Decompress(data, expectedSize: expectedSize)
        } catch {
            throw ResourceError.decompressionFailed(
                reason: "BZ2 decompression failed: \(error)"
            )
        }
    }

    // MARK: - Python RNS Interoperability

    /// Check if data appears to be BZ2 compressed (Python RNS format).
    ///
    /// BZ2 magic bytes: 0x42 0x5A 0x68 ("BZh")
    ///
    /// - Parameter data: Data to check
    /// - Returns: true if data starts with BZ2 magic bytes
    public static func isBZ2Compressed(_ data: Data) -> Bool {
        guard data.count >= 3 else { return false }
        return data[0] == 0x42 && data[1] == 0x5A && data[2] == 0x68
    }
}
