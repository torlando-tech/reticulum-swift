//
//  Token.swift
//  ReticulumSwift
//
//  Symmetric encryption token matching Reticulum Token.py format.
//  Format: [IV 16B][ciphertext][HMAC 32B]
//
//  Uses AES-256-CBC with PKCS7 padding for encryption and HMAC-SHA256
//  for authentication (encrypt-then-MAC pattern).
//

import Foundation
import CryptoKit
import CryptoSwift

public enum TokenError: Error, Equatable {
    case invalidFormat
    case hmacVerificationFailed
    case decryptionFailed
    case invalidKeyLength
}

/// Symmetric encryption token matching Reticulum Token.py format.
///
/// Format: [IV 16B][ciphertext][HMAC 32B]
///
/// Token uses a 64-byte derived key split into two 32-byte keys:
/// - Bytes 0-31: HMAC signing key
/// - Bytes 32-63: AES-256 encryption key
///
/// Security properties:
/// - Encrypt-then-MAC: HMAC is computed over IV + ciphertext
/// - HMAC verified before decryption to prevent padding oracle attacks
/// - Constant-time HMAC comparison to prevent timing attacks
public struct Token {
    /// 32-byte HMAC signing key
    public let signingKey: Data

    /// 32-byte AES-256 encryption key
    public let encryptionKey: Data

    // MARK: - Initialization

    /// Create token from a 64-byte derived key (as RNS does)
    ///
    /// Key layout matches Python RNS Token.py:
    /// - First 32 bytes: signing key (HMAC)
    /// - Last 32 bytes: encryption key (AES-256)
    ///
    /// - Parameter derivedKey: 64 bytes - first 32 for signing, last 32 for encryption
    /// - Throws: `TokenError.invalidKeyLength` if key is too short
    public init(derivedKey: Data) throws {
        guard derivedKey.count >= 64 else {
            throw TokenError.invalidKeyLength
        }
        self.signingKey = Data(derivedKey.prefix(32))
        self.encryptionKey = Data(derivedKey.dropFirst(32).prefix(32))
    }

    /// Create token from separate keys
    ///
    /// - Parameters:
    ///   - signingKey: 32-byte HMAC key
    ///   - encryptionKey: 32-byte AES-256 key
    /// - Throws: `TokenError.invalidKeyLength` if either key is not 32 bytes
    public init(signingKey: Data, encryptionKey: Data) throws {
        guard signingKey.count == 32, encryptionKey.count == 32 else {
            throw TokenError.invalidKeyLength
        }
        self.signingKey = signingKey
        self.encryptionKey = encryptionKey
    }

    // MARK: - Encryption

    /// Encrypt data using AES-256-CBC with HMAC-SHA256
    ///
    /// Generates a random 16-byte IV and encrypts the plaintext with PKCS7 padding.
    /// Computes HMAC-SHA256 over IV + ciphertext (encrypt-then-MAC).
    ///
    /// - Parameter plaintext: Data to encrypt
    /// - Returns: Encrypted token: [IV 16B][ciphertext][HMAC 32B]
    /// - Throws: `TokenError.decryptionFailed` if IV generation fails
    public func encrypt(_ plaintext: Data) throws -> Data {
        // Generate random IV using secure random
        var ivBytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, 16, &ivBytes)
        guard status == errSecSuccess else {
            throw TokenError.decryptionFailed
        }

        return try encrypt(plaintext, iv: Data(ivBytes))
    }

    /// Encrypt with explicit IV (for testing with known vectors)
    ///
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - iv: 16-byte initialization vector
    /// - Returns: Encrypted token: [IV 16B][ciphertext][HMAC 32B]
    /// - Throws: `TokenError.invalidFormat` if IV is not 16 bytes
    public func encrypt(_ plaintext: Data, iv: Data) throws -> Data {
        guard iv.count == 16 else {
            throw TokenError.invalidFormat
        }

        // AES-256-CBC encryption with PKCS7 padding
        let aes = try AES(
            key: Array(encryptionKey),
            blockMode: CBC(iv: Array(iv)),
            padding: .pkcs7
        )
        let ciphertext = try aes.encrypt(Array(plaintext))

        // Build signed portion: IV + ciphertext
        var signedParts = Data()
        signedParts.append(iv)
        signedParts.append(contentsOf: ciphertext)

        // HMAC-SHA256 over IV + ciphertext (encrypt-then-MAC)
        let hmac = HMAC<SHA256>.authenticationCode(
            for: signedParts,
            using: SymmetricKey(data: signingKey)
        )

        // Final format: [IV][ciphertext][HMAC]
        var token = signedParts
        token.append(contentsOf: hmac)
        return token
    }

    // MARK: - Decryption

    /// Decrypt a token
    ///
    /// Verifies HMAC before decryption (encrypt-then-MAC pattern) to prevent
    /// padding oracle attacks. Uses constant-time comparison for HMAC.
    ///
    /// - Parameter token: Encrypted token: [IV 16B][ciphertext][HMAC 32B]
    /// - Returns: Decrypted plaintext
    /// - Throws: `TokenError.invalidFormat` if token is too short,
    ///           `TokenError.hmacVerificationFailed` if HMAC doesn't match,
    ///           `TokenError.decryptionFailed` if decryption fails
    public func decrypt(_ token: Data) throws -> Data {
        // Minimum size: 16 (IV) + 16 (min cipher block) + 32 (HMAC) = 64
        guard token.count >= 64 else {
            throw TokenError.invalidFormat
        }

        // Extract components
        let iv = Data(token.prefix(16))
        let ciphertext = Data(token.dropFirst(16).dropLast(32))
        let receivedHMAC = Data(token.suffix(32))

        // Verify HMAC FIRST (encrypt-then-MAC pattern)
        let signedParts = token.prefix(token.count - 32)
        let expectedHMAC = HMAC<SHA256>.authenticationCode(
            for: signedParts,
            using: SymmetricKey(data: signingKey)
        )

        // Constant-time comparison to prevent timing attacks
        guard constantTimeEqual(Data(expectedHMAC), receivedHMAC) else {
            throw TokenError.hmacVerificationFailed
        }

        // Decrypt only after HMAC verification passes
        let aes = try AES(
            key: Array(encryptionKey),
            blockMode: CBC(iv: Array(iv)),
            padding: .pkcs7
        )

        do {
            let plaintext = try aes.decrypt(Array(ciphertext))
            return Data(plaintext)
        } catch {
            throw TokenError.decryptionFailed
        }
    }

    // MARK: - Constant-Time Comparison

    /// Constant-time comparison to prevent timing attacks
    ///
    /// This function takes the same amount of time regardless of where
    /// the first difference occurs, preventing timing side-channel attacks.
    ///
    /// - Parameters:
    ///   - a: First data to compare
    ///   - b: Second data to compare
    /// - Returns: true if equal, false otherwise
    private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }

        var result: UInt8 = 0
        for (x, y) in zip(a, b) {
            result |= x ^ y
        }
        return result == 0
    }
}
