//
//  Identity.swift
//  ReticulumSwift
//
//  Reticulum Identity containing Ed25519 signing and X25519 encryption keypairs.
//  The identity hash is the truncated SHA-256 of concatenated public keys.
//
//  Matches Python RNS Identity.py for byte-perfect interoperability.
//

import Foundation
import CryptoKit
import Security

/// Reticulum Identity containing Ed25519 signing and X25519 encryption keypairs.
///
/// Each identity has two keypairs:
/// - **Encryption keypair (X25519):** Used for Diffie-Hellman key agreement
/// - **Signing keypair (Ed25519):** Used for digital signatures
///
/// The identity hash is derived from the SHA-256 of concatenated public keys,
/// truncated to 16 bytes (128 bits).
///
/// Public key concatenation order matches Python RNS: encryption (32 bytes) + signing (32 bytes)
public struct Identity {
    // MARK: - Keys

    /// X25519 private key for key agreement (encryption/decryption)
    /// Nil for public-key-only identities (remote peers)
    public let encryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey?

    /// X25519 public key for key agreement
    /// Stored directly for public-key-only identities
    private let _encryptionPublicKey: Curve25519.KeyAgreement.PublicKey?

    /// X25519 public key for key agreement
    public var encryptionPublicKey: Curve25519.KeyAgreement.PublicKey {
        if let privateKey = encryptionPrivateKey {
            return privateKey.publicKey
        }
        return _encryptionPublicKey!
    }

    /// Ed25519 private key for signing
    /// Nil for public-key-only identities (remote peers)
    public let signingPrivateKey: Curve25519.Signing.PrivateKey?

    /// Stored signing public key for public-key-only identities
    private let _signingPublicKey: Curve25519.Signing.PublicKey?

    /// Ed25519 public key for signature verification
    public var signingPublicKey: Curve25519.Signing.PublicKey {
        if let privateKey = signingPrivateKey {
            return privateKey.publicKey
        }
        return _signingPublicKey!
    }

    /// Whether this identity has private keys (can sign)
    public var hasPrivateKeys: Bool {
        signingPrivateKey != nil
    }

    // MARK: - Derived Properties

    /// 16-byte identity hash (truncated SHA-256 of public keys)
    ///
    /// Computed as: SHA256(encryptionPublicKey || signingPublicKey)[:16]
    public var hash: Data {
        Hashing.identityHash(
            encryptionPublicKey: encryptionPublicKey.rawRepresentation,
            signingPublicKey: signingPublicKey.rawRepresentation
        )
    }

    /// 64-byte concatenated public keys (encryption || signing)
    ///
    /// This is the format used in announce packets and for hash computation.
    public var publicKeys: Data {
        var data = Data()
        data.append(encryptionPublicKey.rawRepresentation)
        data.append(signingPublicKey.rawRepresentation)
        return data
    }

    /// Hex string representation of the identity hash
    public var hexHash: String {
        hash.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Initialization

    /// Generate a new random identity
    ///
    /// Creates fresh Ed25519 and X25519 keypairs using secure random generation.
    public init() {
        self.encryptionPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        self.signingPrivateKey = Curve25519.Signing.PrivateKey()
        self._encryptionPublicKey = nil
        self._signingPublicKey = nil
    }

    /// Create identity from existing private keys
    ///
    /// Used for testing with known keys or restoring from storage.
    ///
    /// - Parameters:
    ///   - encryptionPrivateKey: X25519 private key for encryption
    ///   - signingPrivateKey: Ed25519 private key for signing
    public init(
        encryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        signingPrivateKey: Curve25519.Signing.PrivateKey
    ) {
        self.encryptionPrivateKey = encryptionPrivateKey
        self.signingPrivateKey = signingPrivateKey
        self._encryptionPublicKey = nil
        self._signingPublicKey = nil
    }

    /// Create identity from raw private key bytes (32 bytes each)
    ///
    /// Used for test vector validation and key import.
    ///
    /// - Parameters:
    ///   - encryptionPrivateKeyBytes: 32-byte X25519 private key
    ///   - signingPrivateKeyBytes: 32-byte Ed25519 private key
    /// - Throws: `IdentityError.invalidKeyLength` if key bytes are wrong size
    public init(
        encryptionPrivateKeyBytes: Data,
        signingPrivateKeyBytes: Data
    ) throws {
        guard encryptionPrivateKeyBytes.count == 32 else {
            throw IdentityError.invalidKeyLength(
                expected: 32,
                actual: encryptionPrivateKeyBytes.count,
                keyType: "encryption"
            )
        }
        guard signingPrivateKeyBytes.count == 32 else {
            throw IdentityError.invalidKeyLength(
                expected: 32,
                actual: signingPrivateKeyBytes.count,
                keyType: "signing"
            )
        }

        self.encryptionPrivateKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: encryptionPrivateKeyBytes
        )
        self.signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: signingPrivateKeyBytes
        )
        self._encryptionPublicKey = nil
        self._signingPublicKey = nil
    }

    /// Create identity from concatenated private key bytes (64 bytes total)
    ///
    /// Used for restoring identity from storage or keychain.
    ///
    /// - Parameter privateKeyBytes: 64-byte concatenated private keys (encryption || signing)
    /// - Throws: `IdentityError.invalidKeyLength` if bytes are wrong size
    public init(privateKeyBytes: Data) throws {
        guard privateKeyBytes.count == 64 else {
            throw IdentityError.invalidKeyLength(
                expected: 64,
                actual: privateKeyBytes.count,
                keyType: "private keys"
            )
        }

        let encPrivBytes = privateKeyBytes[privateKeyBytes.startIndex..<privateKeyBytes.startIndex + 32]
        let sigPrivBytes = privateKeyBytes[privateKeyBytes.startIndex + 32..<privateKeyBytes.startIndex + 64]

        self.encryptionPrivateKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: encPrivBytes
        )
        self.signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: sigPrivBytes
        )
        self._encryptionPublicKey = nil
        self._signingPublicKey = nil
    }

    /// Create a public-key-only identity from raw public key bytes.
    ///
    /// Used for remote peer identities where we only have their public keys.
    /// This identity can verify signatures but cannot sign.
    ///
    /// - Parameter publicKeyBytes: 64-byte concatenated public keys (encryption || signing)
    /// - Throws: `IdentityError.invalidKeyLength` if bytes are wrong size
    public init(publicKeyBytes: Data) throws {
        guard publicKeyBytes.count == 64 else {
            throw IdentityError.invalidKeyLength(
                expected: 64,
                actual: publicKeyBytes.count,
                keyType: "public keys"
            )
        }

        let encryptionPubBytes = publicKeyBytes[publicKeyBytes.startIndex..<publicKeyBytes.startIndex + 32]
        let signingPubBytes = publicKeyBytes[publicKeyBytes.startIndex + 32..<publicKeyBytes.startIndex + 64]

        self.encryptionPrivateKey = nil
        self.signingPrivateKey = nil
        self._encryptionPublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: encryptionPubBytes
        )
        self._signingPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: signingPubBytes
        )
    }

    /// Create public-key-only identity from separate encryption and signing keys
    ///
    /// Used for creating identities from LXMF test vectors or other sources
    /// where keys are provided separately.
    ///
    /// - Parameters:
    ///   - encryptionPublicKey: 32-byte X25519 public key
    ///   - signingPublicKey: 32-byte Ed25519 public key
    /// - Throws: `IdentityError.invalidKeyLength` if keys are wrong size
    public init(
        encryptionPublicKey: Data,
        signingPublicKey: Data
    ) throws {
        guard encryptionPublicKey.count == 32 else {
            throw IdentityError.invalidKeyLength(
                expected: 32,
                actual: encryptionPublicKey.count,
                keyType: "encryption public"
            )
        }
        guard signingPublicKey.count == 32 else {
            throw IdentityError.invalidKeyLength(
                expected: 32,
                actual: signingPublicKey.count,
                keyType: "signing public"
            )
        }

        self.encryptionPrivateKey = nil
        self.signingPrivateKey = nil
        self._encryptionPublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: encryptionPublicKey
        )
        self._signingPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: signingPublicKey
        )
    }

    // MARK: - Signing

    /// Sign data with the identity's Ed25519 private key
    ///
    /// - Parameter data: Data to sign
    /// - Returns: 64-byte Ed25519 signature
    /// - Throws: `IdentityError.noPrivateKey` if this is a public-key-only identity
    /// - Throws: CryptoKit error if signing fails
    public func sign(_ data: Data) throws -> Data {
        guard let privateKey = signingPrivateKey else {
            throw IdentityError.noPrivateKey
        }
        let signature = try privateKey.signature(for: data)
        return Data(signature)
    }

    /// Verify a signature against this identity's signing public key
    ///
    /// - Parameters:
    ///   - signature: 64-byte Ed25519 signature
    ///   - data: Original data that was signed
    /// - Returns: true if signature is valid, false otherwise
    public func verify(signature: Data, for data: Data) -> Bool {
        signingPublicKey.isValidSignature(signature, for: data)
    }

    /// Static verification with just public key bytes (for received announces)
    ///
    /// This is used when verifying signatures from remote identities where
    /// we only have the public key, not the full identity.
    ///
    /// - Parameters:
    ///   - signature: 64-byte Ed25519 signature
    ///   - data: Original data that was signed
    ///   - publicKey: Ed25519 public key bytes (32 bytes)
    /// - Returns: true if signature is valid
    /// - Throws: `IdentityError.invalidKeyLength` if public key is wrong size
    public static func verify(
        signature: Data,
        for data: Data,
        publicKey: Data
    ) throws -> Bool {
        guard publicKey.count == 32 else {
            throw IdentityError.invalidKeyLength(
                expected: 32,
                actual: publicKey.count,
                keyType: "signing public"
            )
        }
        guard signature.count == 64 else {
            return false
        }

        let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        return key.isValidSignature(signature, for: data)
    }

    // MARK: - Encryption (SINGLE Destination)

    /// Encrypt data to this identity's public key for SINGLE destination delivery.
    ///
    /// Uses Reticulum's encryption pattern:
    /// 1. Generate ephemeral X25519 keypair
    /// 2. Perform ECDH with recipient's encryption public key
    /// 3. Derive 64-byte key via HKDF using identity hash as salt
    /// 4. Encrypt with Token (AES-256-CBC + HMAC-SHA256)
    /// 5. Prepend ephemeral public key
    ///
    /// Output format: [ephemeral_pub 32B][IV 16B][ciphertext][HMAC 32B]
    ///
    /// IMPORTANT: The HKDF salt is the **identity hash** (SHA256(publicKeys)[:16]),
    /// NOT the destination hash. This matches Python RNS Identity.get_salt().
    ///
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - identityHash: 16-byte identity hash (used as HKDF salt)
    /// - Returns: Encrypted token with prepended ephemeral public key
    /// - Throws: `IdentityError.encryptionFailed` if encryption fails
    public static func encrypt(
        _ plaintext: Data,
        to encryptionPublicKey: Curve25519.KeyAgreement.PublicKey,
        identityHash: Data
    ) throws -> Data {
        // 1. Generate ephemeral X25519 keypair
        let ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey

        // 2. Perform ECDH to get shared secret
        let sharedSecret: SharedSecret
        do {
            sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: encryptionPublicKey)
        } catch {
            throw IdentityError.encryptionFailed(reason: "ECDH failed: \(error.localizedDescription)")
        }

        // 3. Derive 64-byte key via HKDF using identity hash as salt
        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
        let derivedKey = KeyDerivation.deriveKey(
            length: 64,
            inputKeyMaterial: sharedSecretData,
            salt: identityHash,
            context: nil
        )

        // 4. Encrypt with Token
        let token: Token
        do {
            token = try Token(derivedKey: derivedKey)
        } catch {
            throw IdentityError.encryptionFailed(reason: "Token creation failed: \(error.localizedDescription)")
        }

        let ciphertext: Data
        do {
            ciphertext = try token.encrypt(plaintext)
        } catch {
            throw IdentityError.encryptionFailed(reason: "Token encryption failed: \(error.localizedDescription)")
        }

        // 5. Prepend ephemeral public key
        var result = Data()
        result.append(ephemeralPublicKey.rawRepresentation)
        result.append(ciphertext)

        return result
    }

    /// Encrypt data to this identity (convenience method).
    ///
    /// IMPORTANT: The HKDF salt is the **identity hash** (SHA256(publicKeys)[:16]),
    /// NOT the destination hash. This matches Python RNS Identity.get_salt().
    ///
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - identityHash: 16-byte identity hash (used as HKDF salt)
    /// - Returns: Encrypted token with prepended ephemeral public key
    /// - Throws: `IdentityError.encryptionFailed` if encryption fails
    public func encryptTo(_ plaintext: Data, identityHash: Data) throws -> Data {
        return try Identity.encrypt(plaintext, to: encryptionPublicKey, identityHash: identityHash)
    }

    /// Decrypt data encrypted to this identity.
    ///
    /// Reverses the encryption process:
    /// 1. Extract ephemeral public key (first 32 bytes)
    /// 2. Perform ECDH with our private key
    /// 3. Derive key via HKDF using identity hash as salt
    /// 4. Decrypt with Token
    ///
    /// IMPORTANT: The HKDF salt is the **identity hash** (SHA256(publicKeys)[:16]),
    /// NOT the destination hash. This matches Python RNS Identity.get_salt().
    ///
    /// - Parameters:
    ///   - ciphertext: Encrypted token with prepended ephemeral public key
    ///   - identityHash: 16-byte identity hash (used as HKDF salt)
    /// - Returns: Decrypted plaintext
    /// - Throws: `IdentityError.noPrivateKey` if this is a public-key-only identity
    /// - Throws: `IdentityError.decryptionFailed` if decryption fails
    public func decrypt(_ ciphertext: Data, identityHash: Data) throws -> Data {
        guard let privateKey = encryptionPrivateKey else {
            throw IdentityError.noPrivateKey
        }

        // Minimum size: 32 (ephemeral pub) + 64 (minimum token: 16 IV + 16 cipher + 32 HMAC)
        guard ciphertext.count >= 96 else {
            throw IdentityError.decryptionFailed(reason: "Ciphertext too short")
        }

        // 1. Extract ephemeral public key
        let ephemeralPubBytes = ciphertext.prefix(32)
        let tokenData = ciphertext.dropFirst(32)

        let ephemeralPublicKey: Curve25519.KeyAgreement.PublicKey
        do {
            ephemeralPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPubBytes)
        } catch {
            throw IdentityError.decryptionFailed(reason: "Invalid ephemeral public key")
        }

        // 2. Perform ECDH
        let sharedSecret: SharedSecret
        do {
            sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        } catch {
            throw IdentityError.decryptionFailed(reason: "ECDH failed: \(error.localizedDescription)")
        }

        // 3. Derive key via HKDF using identity hash as salt
        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
        let derivedKey = KeyDerivation.deriveKey(
            length: 64,
            inputKeyMaterial: sharedSecretData,
            salt: identityHash,
            context: nil
        )

        // 4. Decrypt with Token
        let token: Token
        do {
            token = try Token(derivedKey: derivedKey)
        } catch {
            throw IdentityError.decryptionFailed(reason: "Token creation failed")
        }

        do {
            return try token.decrypt(Data(tokenData))
        } catch {
            throw IdentityError.decryptionFailed(reason: "Token decryption failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Persistence

    /// Export private keys for storage (64 bytes: enc_priv + sig_priv)
    ///
    /// This exports the raw private key bytes in a format suitable for secure storage.
    /// The format is: [encryption_private_key: 32 bytes][signing_private_key: 32 bytes]
    ///
    /// - Returns: 64-byte concatenated private keys
    /// - Throws: `IdentityError.noPrivateKey` if this is a public-key-only identity
    public func exportPrivateKeys() throws -> Data {
        guard let encPriv = encryptionPrivateKey,
              let sigPriv = signingPrivateKey else {
            throw IdentityError.noPrivateKey
        }
        var data = Data()
        data.append(encPriv.rawRepresentation)
        data.append(sigPriv.rawRepresentation)
        return data
    }

    /// Save identity to Keychain
    ///
    /// Stores the private keys securely in the system Keychain.
    /// The keys are stored as a generic password item.
    ///
    /// - Parameters:
    ///   - service: Service name for Keychain (e.g., "com.myapp.reticulum")
    ///   - account: Account name for Keychain (e.g., "identity")
    /// - Throws: `IdentityError.noPrivateKey` if no private keys
    /// - Throws: `IdentityError.keychainError` if Keychain operation fails
    public func saveToKeychain(service: String, account: String) throws {
        let privateKeyData = try exportPrivateKeys()

        // Delete any existing item first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Add new item
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: privateKeyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw IdentityError.keychainError(status: status)
        }
    }

    /// Load identity from Keychain
    ///
    /// Retrieves the private keys from the system Keychain and reconstructs
    /// the Identity.
    ///
    /// - Parameters:
    ///   - service: Service name for Keychain (e.g., "com.myapp.reticulum")
    ///   - account: Account name for Keychain (e.g., "identity")
    /// - Returns: The loaded Identity, or nil if not found
    /// - Throws: `IdentityError.keychainError` if Keychain operation fails (other than not found)
    /// - Throws: `IdentityError.invalidKeyLength` if stored data is corrupt
    public static func loadFromKeychain(service: String, account: String) throws -> Identity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess else {
            throw IdentityError.keychainError(status: status)
        }

        guard let privateKeyData = result as? Data else {
            throw IdentityError.keychainError(status: errSecDecode)
        }

        return try Identity(privateKeyBytes: privateKeyData)
    }

    /// Delete identity from Keychain
    ///
    /// - Parameters:
    ///   - service: Service name for Keychain
    ///   - account: Account name for Keychain
    /// - Returns: true if deleted, false if not found
    @discardableResult
    public static func deleteFromKeychain(service: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
}

// MARK: - Errors

public enum IdentityError: Error, Equatable {
    /// Key has incorrect length
    case invalidKeyLength(expected: Int, actual: Int, keyType: String)

    /// Signature verification failed
    case signatureVerificationFailed

    /// No private key available (public-key-only identity)
    case noPrivateKey

    /// Encryption failed
    case encryptionFailed(reason: String)

    /// Decryption failed
    case decryptionFailed(reason: String)

    /// Keychain operation failed
    case keychainError(status: OSStatus)
}

// MARK: - CustomStringConvertible

extension Identity: CustomStringConvertible {
    public var description: String {
        "Identity<\(hexHash)>"
    }
}
