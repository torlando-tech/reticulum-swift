// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Hashing.swift
//  ReticulumSwift
//
//  SHA-256 hashing utilities matching Python RNS.
//  Full hash is 32 bytes, truncated hash is 16 bytes (identity/destination hash).
//

import Foundation
import CryptoKit

// MARK: - Hash Length Constants

/// Full SHA-256 hash length (256 bits)
public let FULL_HASH_LENGTH = 32

/// Identity/destination hash length (128 bits, first 16 bytes of SHA-256)
/// Note: This matches TRUNCATED_HASH_LENGTH in Protocol/Constants.swift
public let IDENTITY_HASH_LENGTH = 16

/// Name hash length for destination computation (80 bits, first 10 bytes of SHA-256)
/// Python RNS: RNS.Identity.NAME_HASH_LENGTH = 80
/// Used when computing destination hash from full dotted name (e.g., "lxmf.delivery")
public let NAME_HASH_LENGTH = 10

// MARK: - Hashing Utilities

public enum Hashing {
    /// Full SHA-256 hash (32 bytes)
    /// - Parameter data: Data to hash
    /// - Returns: 32-byte SHA-256 digest
    public static func fullHash(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    /// Truncated hash (first 16 bytes of SHA-256)
    /// Used for identity hashes, destination hashes, and packet hashes.
    /// - Parameter data: Data to hash
    /// - Returns: 16-byte truncated SHA-256 digest
    public static func truncatedHash(_ data: Data) -> Data {
        let full = fullHash(data)
        return full.prefix(IDENTITY_HASH_LENGTH)
    }

    /// Identity hash from public keys.
    /// Concatenates encryption public key (32 bytes) + signing public key (32 bytes),
    /// then returns truncated SHA-256 hash (16 bytes).
    ///
    /// Order matches Python RNS: encryption || signing
    ///
    /// - Parameters:
    ///   - encryptionPublicKey: 32-byte X25519 public key
    ///   - signingPublicKey: 32-byte Ed25519 public key
    /// - Returns: 16-byte identity hash
    public static func identityHash(
        encryptionPublicKey: Data,
        signingPublicKey: Data
    ) -> Data {
        var combined = Data()
        combined.append(encryptionPublicKey)
        combined.append(signingPublicKey)
        return truncatedHash(combined)
    }

    /// Name hash for destination hash computation.
    ///
    /// Computes SHA-256 of the full dotted name (e.g., "lxmf.delivery") and returns
    /// the first 10 bytes (NAME_HASH_LENGTH = 80 bits).
    ///
    /// This is used for computing destination hashes, NOT for announce payloads.
    /// Announce payloads use concatenated 16-byte aspect hashes (see `aspectNameHash`).
    ///
    /// Python RNS equivalent:
    /// ```python
    /// name_hash = RNS.Identity.full_hash(
    ///     Destination.expand_name(None, app_name, *aspects).encode("utf-8")
    /// )[:(RNS.Identity.NAME_HASH_LENGTH//8)]
    /// ```
    ///
    /// - Parameters:
    ///   - appName: Application name (e.g., "lxmf")
    ///   - aspects: Additional aspects (e.g., ["delivery"])
    /// - Returns: 10-byte name hash for destination hash computation
    public static func destinationNameHash(appName: String, aspects: [String] = []) -> Data {
        // Build full dotted name: "appName.aspect1.aspect2..."
        var fullName = appName
        for aspect in aspects {
            fullName += "." + aspect
        }

        // Hash the full name and take first 10 bytes
        let fullNameData = fullName.data(using: .utf8) ?? Data()
        let full = fullHash(fullNameData)
        return full.prefix(NAME_HASH_LENGTH)
    }

    /// Concatenated aspect hashes for announce payloads.
    ///
    /// Each aspect (including app name) is hashed separately with truncatedHash (16 bytes),
    /// then concatenated. This is used in announce payloads, NOT for destination hash computation.
    ///
    /// - Parameters:
    ///   - appName: Application name (e.g., "lxmf")
    ///   - aspects: Additional aspects (e.g., ["delivery"])
    /// - Returns: Concatenated 16-byte hashes (16 * (1 + aspects.count) bytes total)
    public static func aspectNameHash(appName: String, aspects: [String] = []) -> Data {
        var result = Data()

        // Hash app name
        let appNameData = appName.data(using: .utf8) ?? Data()
        result.append(truncatedHash(appNameData))

        // Hash each aspect
        for aspect in aspects {
            let aspectData = aspect.data(using: .utf8) ?? Data()
            result.append(truncatedHash(aspectData))
        }

        return result
    }
}

// MARK: - Data Extensions

extension Data {
    /// Truncated hash with custom length.
    ///
    /// Returns the first N bytes of SHA-256 hash.
    /// Used for resource part hashes (4 bytes).
    ///
    /// - Parameter length: Number of bytes to return (e.g., 4 for part hash)
    /// - Returns: Truncated SHA-256 digest
    public func truncatedHash(length: Int) -> Data {
        let full = Hashing.fullHash(self)
        return full.prefix(length)
    }

    /// Hex string representation of data.
    ///
    /// Converts data to lowercase hex string without separators.
    /// Example: Data([0x01, 0xAB, 0xFF]) -> "01abff"
    ///
    /// - Returns: Hex string
    public var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
