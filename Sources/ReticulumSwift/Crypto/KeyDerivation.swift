//
//  KeyDerivation.swift
//  ReticulumSwift
//
//  HKDF key derivation matching Reticulum's non-standard implementation.
//  RNS HKDF adds a custom "context" parameter during the expand phase,
//  which differs from RFC 5869.
//

import Foundation
import CryptoKit

public enum KeyDerivation {
    /// HKDF key derivation matching Reticulum's non-standard implementation.
    ///
    /// RNS HKDF adds a custom "context" parameter that is appended during the
    /// expand phase. This differs from RFC 5869 which only has "info".
    ///
    /// Format of each expand block: HMAC(PRK, previous || context || counter)
    ///
    /// - Parameters:
    ///   - length: Number of bytes to derive
    ///   - inputKeyMaterial: The input keying material
    ///   - salt: Optional salt (defaults to 32 zero bytes if nil)
    ///   - context: Optional context appended to each expand block (RNS-specific)
    /// - Returns: Derived key material of requested length
    public static func deriveKey(
        length: Int,
        inputKeyMaterial: Data,
        salt: Data? = nil,
        context: Data? = nil
    ) -> Data {
        // Extract phase: PRK = HMAC-SHA256(salt, IKM)
        let saltData = salt ?? Data(repeating: 0, count: 32)
        let prk = extractPRK(inputKeyMaterial: inputKeyMaterial, salt: saltData)

        // Expand phase with RNS context modification
        return expandKey(prk: prk, context: context, length: length)
    }

    /// Standard HKDF extract: PRK = HMAC-SHA256(salt, IKM)
    private static func extractPRK(inputKeyMaterial: Data, salt: Data) -> SymmetricKey {
        let key = SymmetricKey(data: salt)
        let code = HMAC<SHA256>.authenticationCode(for: inputKeyMaterial, using: key)
        return SymmetricKey(data: Data(code))
    }

    /// RNS-specific HKDF expand phase.
    /// Each block: HMAC(PRK, previous || context || counter)
    /// Note: Standard RFC 5869 would be HMAC(PRK, previous || info || counter)
    /// RNS uses "context" instead of "info" and the semantics may differ.
    private static func expandKey(prk: SymmetricKey, context: Data?, length: Int) -> Data {
        var output = Data()
        var previousBlock = Data()
        var counter: UInt8 = 1

        while output.count < length {
            // Build HMAC input: previous || context || counter
            var hmacInput = previousBlock
            if let ctx = context {
                hmacInput.append(ctx)
            }
            hmacInput.append(counter)

            // Compute block
            let code = HMAC<SHA256>.authenticationCode(for: hmacInput, using: prk)
            previousBlock = Data(code)
            output.append(previousBlock)
            counter += 1
        }

        return output.prefix(length)
    }

    /// Convenience method using SymmetricKey input
    public static func deriveKey(
        length: Int,
        inputKeyMaterial: SymmetricKey,
        salt: Data? = nil,
        context: Data? = nil
    ) -> Data {
        return deriveKey(
            length: length,
            inputKeyMaterial: inputKeyMaterial.withUnsafeBytes { Data($0) },
            salt: salt,
            context: context
        )
    }
}
