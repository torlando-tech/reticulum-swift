//
//  ResourceHashmap.swift
//  ReticulumSwift
//
//  Part hashing and hashmap generation for resource validation.
//  Matches Python RNS Resource.py hashmap behavior.
//

import Foundation

// MARK: - Resource Hashmap

/// Utilities for resource part hashing and hashmap generation.
///
/// In RNS, large resources are split into parts (each part is Link.SDU bytes).
/// The hashmap contains a 4-byte truncated SHA256 hash of each part,
/// allowing the receiver to validate each part's integrity as it arrives.
///
/// For large resources (>HASHMAP_MAX_LEN parts), the hashmap is split across
/// multiple advertisement segments.
public enum ResourceHashmap {

    // MARK: - Part Hash Calculation

    /// Calculate 4-byte hash for a resource part.
    ///
    /// Uses first 4 bytes of SHA256 hash (MAPHASH_LEN).
    /// This matches Python RNS Resource.py part hash calculation.
    ///
    /// - Parameter data: Part data to hash
    /// - Returns: 4-byte truncated SHA256 hash
    public static func partHash(_ data: Data) -> Data {
        return Hashing.truncatedHash(data, length: ResourceConstants.MAPHASH_LEN)
    }

    /// Get expected hash for a part from hashmap.
    ///
    /// Extracts the 4-byte hash at the specified part index from the hashmap.
    /// The hashmap is a concatenation of 4-byte hashes, so the hash for part N
    /// is at bytes [N*4, (N+1)*4).
    ///
    /// - Parameters:
    ///   - hashmap: Complete or partial hashmap data
    ///   - index: Part index (0-based)
    /// - Returns: 4-byte expected hash from hashmap
    public static func getPartHash(from hashmap: Data, at index: Int) -> Data {
        let startByte = index * ResourceConstants.MAPHASH_LEN
        let endByte = startByte + ResourceConstants.MAPHASH_LEN
        return hashmap[startByte..<endByte]
    }

    // MARK: - Hashmap Generation

    /// Generate hashmap for resource data.
    ///
    /// Splits data into parts of `partSize` bytes and computes
    /// a 4-byte hash for each part. The hashmap is the concatenation
    /// of all part hashes.
    ///
    /// Example: For 10 parts, hashmap = hash1 || hash2 || ... || hash10
    /// Total hashmap size = 10 * 4 = 40 bytes
    ///
    /// - Parameters:
    ///   - data: Resource data to hash
    ///   - partSize: Size of each part (Link SDU)
    /// - Returns: Concatenated 4-byte hashes for all parts
    public static func generateHashmap(data: Data, partSize: Int) -> Data {
        var hashmap = Data()

        // Calculate total number of parts
        let totalParts = (data.count + partSize - 1) / partSize

        // Hash each part
        for partIndex in 0..<totalParts {
            let startOffset = partIndex * partSize
            let endOffset = min(startOffset + partSize, data.count)
            let partData = data[startOffset..<endOffset]

            let hash = partHash(partData)
            hashmap.append(hash)
        }

        return hashmap
    }

    // MARK: - Hashmap Segmentation

    /// Maximum parts that fit in one hashmap segment.
    ///
    /// Calculated as: (Link.MDU - ADVERTISEMENT_OVERHEAD) / MAPHASH_LEN
    /// For MDU=464 (from Protocol/Constants.swift), this is:
    /// (464 - 134) / 4 = 330 / 4 = 82 parts (integer division)
    ///
    /// However, Python RNS uses a different MDU value that results in 74.
    /// We calculate dynamically to support different link configurations.
    ///
    /// - Parameter linkMDU: Link Maximum Data Unit
    /// - Returns: Maximum parts per segment
    public static func hashmapMaxLength(linkMDU: Int) -> Int {
        let availableBytes = linkMDU - ResourceConstants.ADVERTISEMENT_OVERHEAD
        return availableBytes / ResourceConstants.MAPHASH_LEN
    }

    /// Get hashmap segment for advertisement.
    ///
    /// Segments hashmap into chunks that fit in Link MDU.
    /// First segment (index 0) goes in initial advertisement,
    /// subsequent segments sent via RESOURCE_HMU packets.
    ///
    /// Example: If hashmap contains 200 parts and maxLength=74:
    /// - Segment 0: parts 0-73 (74 hashes, 296 bytes)
    /// - Segment 1: parts 74-147 (74 hashes, 296 bytes)
    /// - Segment 2: parts 148-199 (52 hashes, 208 bytes)
    ///
    /// - Parameters:
    ///   - hashmap: Complete hashmap data
    ///   - segment: Segment index (0-based)
    ///   - maxLength: Max parts per segment
    /// - Returns: Hashmap chunk for this segment, or nil if segment out of range
    public static func getHashmapSegment(
        hashmap: Data,
        segment: Int,
        maxLength: Int
    ) -> Data? {
        let totalParts = hashmap.count / ResourceConstants.MAPHASH_LEN
        let startPart = segment * maxLength

        // Check if segment is out of range
        guard startPart < totalParts else {
            return nil
        }

        let endPart = min(startPart + maxLength, totalParts)
        let startByte = startPart * ResourceConstants.MAPHASH_LEN
        let endByte = endPart * ResourceConstants.MAPHASH_LEN

        return hashmap[startByte..<endByte]
    }

    /// Calculate total number of hashmap segments.
    ///
    /// - Parameters:
    ///   - totalParts: Total number of resource parts
    ///   - maxLength: Max parts per segment
    /// - Returns: Number of segments needed
    public static func segmentCount(totalParts: Int, maxLength: Int) -> Int {
        return (totalParts + maxLength - 1) / maxLength
    }

    /// Find part index by hash.
    ///
    /// Searches the hashmap for a 4-byte part hash and returns the part index.
    /// Used by sender to find which parts were requested by receiver.
    ///
    /// - Parameters:
    ///   - partHash: 4-byte part hash to find
    ///   - hashmap: Complete hashmap data
    /// - Returns: Part index, or nil if not found
    public static func findPartIndex(for partHash: Data, in hashmap: Data) -> Int? {
        guard partHash.count == ResourceConstants.MAPHASH_LEN else { return nil }

        let totalParts = hashmap.count / ResourceConstants.MAPHASH_LEN
        for index in 0..<totalParts {
            let expectedHash = getPartHash(from: hashmap, at: index)
            if expectedHash == partHash {
                return index
            }
        }
        return nil
    }

    // MARK: - Collision Guard

    /// Size of collision guard for hashmap.
    ///
    /// From Python RNS:
    /// ```python
    /// COLLISION_GUARD_SIZE = 2 * WINDOW_MAX + HASHMAP_MAX_LEN
    /// ```
    ///
    /// Used to regenerate random_hash if collision detected.
    /// The collision guard ensures that if two resources have the same
    /// resource hash, they won't conflict within the windowing system.
    ///
    /// - Parameter hashmapMaxLength: Maximum parts per segment
    /// - Returns: Collision guard size
    public static func collisionGuardSize(hashmapMaxLength: Int) -> Int {
        return 2 * ResourceConstants.WINDOW_MAX_FAST + hashmapMaxLength
    }
}

// MARK: - Hashing Extension

extension Hashing {
    /// Truncated hash with custom length.
    ///
    /// Returns first `length` bytes of SHA256 hash.
    ///
    /// - Parameters:
    ///   - data: Data to hash
    ///   - length: Number of bytes to return
    /// - Returns: Truncated SHA256 hash
    public static func truncatedHash(_ data: Data, length: Int) -> Data {
        let full = fullHash(data)
        return full.prefix(length)
    }
}
