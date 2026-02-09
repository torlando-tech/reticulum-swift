//
//  ResourceAdvertisement.swift
//  ReticulumSwift
//
//  Resource advertisement packet construction and MessagePack encoding.
//  Matches Python RNS Resource.py advertisement format.
//

import Foundation

/// Resource advertisement packet for initiating transfers.
///
/// Advertisement structure from Python RNS Resource.py:
/// - "t": Transfer size (encrypted data size)
/// - "d": Data size (original uncompressed size)
/// - "n": Number of parts
/// - "h": Resource hash (32 bytes SHA256)
/// - "r": Random hash (4 bytes, collision detection)
/// - "o": Original/first segment hash (32 bytes)
/// - "i": Current segment index (1-based)
/// - "l": Total segments
/// - "q": Associated request ID (16 bytes) or nil
/// - "f": Resource flags
/// - "m": Hashmap chunk for this segment
///
/// Example:
/// ```swift
/// let adv = ResourceAdvertisement(
///     transferSize: 1024,
///     dataSize: 2048,
///     numParts: 10,
///     hash: resourceHash,
///     randomHash: randomHash,
///     originalHash: originalHash,
///     segmentIndex: 1,
///     totalSegments: 1,
///     requestId: nil,
///     flags: [.encrypted],
///     hashmapChunk: hashmapData
/// )
/// let packed = try adv.pack()
/// ```
public struct ResourceAdvertisement: Sendable, Codable {
    /// Encrypted data size (transfer size)
    public let transferSize: Int

    /// Original uncompressed data size
    public let dataSize: Int

    /// Number of parts
    public let numParts: Int

    /// Resource hash (32 bytes SHA256)
    public let hash: Data

    /// Random hash (4 bytes, for collision detection)
    public let randomHash: Data

    /// Original/first segment hash (32 bytes)
    public let originalHash: Data

    /// Current segment index (1-based)
    public let segmentIndex: Int

    /// Total segments
    public let totalSegments: Int

    /// Associated request ID (16 bytes) or nil
    public let requestId: Data?

    /// Resource flags
    public let flags: ResourceFlags

    /// Hashmap chunk for this segment
    public let hashmapChunk: Data

    // MARK: - Initialization

    public init(
        transferSize: Int,
        dataSize: Int,
        numParts: Int,
        hash: Data,
        randomHash: Data,
        originalHash: Data,
        segmentIndex: Int,
        totalSegments: Int,
        requestId: Data?,
        flags: ResourceFlags,
        hashmapChunk: Data
    ) {
        self.transferSize = transferSize
        self.dataSize = dataSize
        self.numParts = numParts
        self.hash = hash
        self.randomHash = randomHash
        self.originalHash = originalHash
        self.segmentIndex = segmentIndex
        self.totalSegments = totalSegments
        self.requestId = requestId
        self.flags = flags
        self.hashmapChunk = hashmapChunk
    }

    // MARK: - Codable

    /// Coding keys matching Python RNS Resource.py field names.
    enum CodingKeys: String, CodingKey {
        case transferSize = "t"
        case dataSize = "d"
        case numParts = "n"
        case hash = "h"
        case randomHash = "r"
        case originalHash = "o"
        case segmentIndex = "i"
        case totalSegments = "l"
        case requestId = "q"
        case flags = "f"
        case hashmapChunk = "m"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        transferSize = try container.decode(Int.self, forKey: .transferSize)
        dataSize = try container.decode(Int.self, forKey: .dataSize)
        numParts = try container.decode(Int.self, forKey: .numParts)
        hash = try container.decode(Data.self, forKey: .hash)
        randomHash = try container.decode(Data.self, forKey: .randomHash)
        originalHash = try container.decode(Data.self, forKey: .originalHash)
        segmentIndex = try container.decode(Int.self, forKey: .segmentIndex)
        totalSegments = try container.decode(Int.self, forKey: .totalSegments)
        requestId = try container.decodeIfPresent(Data.self, forKey: .requestId)

        // Decode flags as UInt8 raw value
        let flagsRawValue = try container.decode(UInt8.self, forKey: .flags)
        flags = ResourceFlags(rawValue: flagsRawValue)

        hashmapChunk = try container.decode(Data.self, forKey: .hashmapChunk)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(transferSize, forKey: .transferSize)
        try container.encode(dataSize, forKey: .dataSize)
        try container.encode(numParts, forKey: .numParts)
        try container.encode(hash, forKey: .hash)
        try container.encode(randomHash, forKey: .randomHash)
        try container.encode(originalHash, forKey: .originalHash)
        try container.encode(segmentIndex, forKey: .segmentIndex)
        try container.encode(totalSegments, forKey: .totalSegments)
        try container.encodeIfPresent(requestId, forKey: .requestId)

        // Encode flags as UInt8 raw value
        try container.encode(flags.rawValue, forKey: .flags)

        try container.encode(hashmapChunk, forKey: .hashmapChunk)
    }
}

// MARK: - MessagePack Encoding/Decoding

extension ResourceAdvertisement {
    /// Pack advertisement to MessagePack format.
    ///
    /// - Returns: MessagePack-encoded advertisement data
    /// - Throws: EncodingError if encoding fails
    public func pack() throws -> Data {
        let map: [MessagePackValue: MessagePackValue] = [
            .string("t"): .int(Int64(transferSize)),
            .string("d"): .int(Int64(dataSize)),
            .string("n"): .int(Int64(numParts)),
            .string("h"): .binary(hash),
            .string("r"): .binary(randomHash),
            .string("o"): .binary(originalHash),
            .string("i"): .int(Int64(segmentIndex)),
            .string("l"): .int(Int64(totalSegments)),
            // MUST always include "q" key — Python's ResourceAdvertisement.unpack()
            // unconditionally accesses dictionary["q"], so omitting it causes KeyError
            .string("q"): requestId.map { MessagePackValue.binary($0) } ?? .null,
            .string("f"): .uint(UInt64(flags.rawValue)),
            .string("m"): .binary(hashmapChunk)
        ]
        return packMsgPack(.map(map))
    }

    /// Unpack advertisement from MessagePack format.
    ///
    /// - Parameter data: MessagePack-encoded advertisement
    /// - Returns: Decoded ResourceAdvertisement
    /// - Throws: DecodingError if decoding fails
    public static func unpack(_ data: Data) throws -> ResourceAdvertisement {
        let value = try unpackMsgPack(data)
        guard case .map(let map) = value else {
            throw MessagePackError.decodingFailed("Expected map for ResourceAdvertisement")
        }

        func getInt(_ key: String) throws -> Int {
            guard let val = map[.string(key)] else {
                throw MessagePackError.decodingFailed("Missing key: \(key)")
            }
            switch val {
            case .int(let i): return Int(i)
            case .uint(let u): return Int(u)
            default: throw MessagePackError.decodingFailed("Expected int for \(key)")
            }
        }

        func getBinary(_ key: String) throws -> Data {
            guard let val = map[.string(key)] else {
                throw MessagePackError.decodingFailed("Missing key: \(key)")
            }
            guard case .binary(let d) = val else {
                throw MessagePackError.decodingFailed("Expected binary for \(key)")
            }
            return d
        }

        func getOptionalBinary(_ key: String) -> Data? {
            guard let val = map[.string(key)] else { return nil }
            guard case .binary(let d) = val else { return nil }
            return d
        }

        return ResourceAdvertisement(
            transferSize: try getInt("t"),
            dataSize: try getInt("d"),
            numParts: try getInt("n"),
            hash: try getBinary("h"),
            randomHash: try getBinary("r"),
            originalHash: try getBinary("o"),
            segmentIndex: try getInt("i"),
            totalSegments: try getInt("l"),
            requestId: getOptionalBinary("q"),
            flags: ResourceFlags(rawValue: UInt8(try getInt("f"))),
            hashmapChunk: try getBinary("m")
        )
    }
}

// MARK: - Factory Methods

extension ResourceAdvertisement {
    /// Create advertisement for a resource segment.
    ///
    /// - Parameters:
    ///   - transferSize: Encrypted data size
    ///   - dataSize: Original uncompressed data size
    ///   - numParts: Number of parts in resource
    ///   - resourceHash: SHA256 hash of resource data (32 bytes)
    ///   - randomHash: Random collision-detection hash (4 bytes)
    ///   - hashmap: Full hashmap data (will be segmented)
    ///   - segment: Current segment index (1-based)
    ///   - totalSegments: Total number of segments
    ///   - requestId: Associated request ID (16 bytes) or nil
    ///   - flags: Resource flags
    ///   - linkMDU: Link MDU for hashmap segmentation
    /// - Returns: ResourceAdvertisement for the specified segment
    public static func create(
        transferSize: Int,
        dataSize: Int,
        numParts: Int,
        resourceHash: Data,
        randomHash: Data,
        hashmap: Data,
        segment: Int,
        totalSegments: Int,
        requestId: Data?,
        flags: ResourceFlags,
        linkMDU: Int
    ) -> ResourceAdvertisement {
        // Calculate max hashmap length from link MDU
        let maxLength = ResourceHashmap.hashmapMaxLength(linkMDU: linkMDU)

        // Get hashmap segment for this advertisement (0-based segment index)
        let hashmapChunk = ResourceHashmap.getHashmapSegment(
            hashmap: hashmap,
            segment: segment - 1,  // Convert 1-based to 0-based
            maxLength: maxLength
        ) ?? Data()  // Default to empty if out of range

        // First segment uses resource hash as original hash
        // Subsequent segments would use first segment's hash (not implemented yet)
        let originalHash = resourceHash

        return ResourceAdvertisement(
            transferSize: transferSize,
            dataSize: dataSize,
            numParts: numParts,
            hash: resourceHash,
            randomHash: randomHash,
            originalHash: originalHash,
            segmentIndex: segment,
            totalSegments: totalSegments,
            requestId: requestId,
            flags: flags,
            hashmapChunk: hashmapChunk
        )
    }
}
