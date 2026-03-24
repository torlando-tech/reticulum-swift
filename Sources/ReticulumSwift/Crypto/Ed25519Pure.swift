// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Ed25519Pure.swift
//  ReticulumSwift
//
//  Pure deterministic Ed25519 signing matching RFC 8032.
//  Uses the ORLP/ed25519 C library (public domain) for interop with
//  Python's cryptography library, which also produces deterministic signatures.
//
//  Apple's CryptoKit Ed25519 uses randomized nonces (hedged signing),
//  producing non-deterministic signatures. IFAC requires deterministic
//  signatures so both sender and receiver produce identical output.
//

import Foundation
import CEd25519

/// Deterministic Ed25519 signing for IFAC interop.
///
/// Wraps the ORLP/ed25519 C library which implements RFC 8032
/// with deterministic nonce derivation (SHA-512(prefix || message)).
public enum Ed25519Pure {

    /// Sign a message with a 32-byte Ed25519 seed.
    ///
    /// Produces a deterministic 64-byte signature matching Python's
    /// `Ed25519PrivateKey.from_private_bytes(seed).sign(message)`.
    ///
    /// - Parameters:
    ///   - message: Data to sign
    ///   - seed: 32-byte Ed25519 private key seed
    /// - Returns: 64-byte Ed25519 signature, or nil if seed is wrong size
    public static func sign(message: Data, seed: Data) -> Data? {
        guard seed.count == 32 else { return nil }

        // Derive keypair from seed
        var publicKey = Data(count: 32)
        var privateKey = Data(count: 64)

        seed.withUnsafeBytes { seedPtr in
            publicKey.withUnsafeMutableBytes { pubPtr in
                privateKey.withUnsafeMutableBytes { privPtr in
                    ed25519_create_keypair(
                        pubPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        privPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        seedPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        // Sign the message (requires both public and private key)
        var signature = Data(count: 64)

        message.withUnsafeBytes { msgPtr in
            publicKey.withUnsafeBytes { pubPtr in
                privateKey.withUnsafeBytes { privPtr in
                    signature.withUnsafeMutableBytes { sigPtr in
                        ed25519_sign(
                            sigPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            msgPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            message.count,
                            pubPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            privPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }

        return signature
    }
}
