import Foundation
import ReticulumSwift
import CryptoKit
import CryptoSwift

// MARK: - JSON Protocol Types

struct Request: Decodable {
    let id: String
    let command: String
    let params: [String: JSONValue]
}

struct Response: Encodable {
    let id: String
    let success: Bool
    let result: [String: JSONValue]?
    let error: String?
}

enum JSONValue: Codable, Equatable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case null
    case array([JSONValue])
    case dict([String: JSONValue])

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let b = try? container.decode(Bool.self) {
            self = .bool(b)
        } else if let i = try? container.decode(Int.self) {
            self = .int(i)
        } else if let d = try? container.decode(Double.self) {
            self = .double(d)
        } else if let s = try? container.decode(String.self) {
            self = .string(s)
        } else if let a = try? container.decode([JSONValue].self) {
            self = .array(a)
        } else if let d = try? container.decode([String: JSONValue].self) {
            self = .dict(d)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value")
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let s): try container.encode(s)
        case .int(let i): try container.encode(i)
        case .double(let d): try container.encode(d)
        case .bool(let b): try container.encode(b)
        case .null: try container.encodeNil()
        case .array(let a): try container.encode(a)
        case .dict(let d): try container.encode(d)
        }
    }

    var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }
    var intValue: Int? {
        if case .int(let i) = self { return i }
        return nil
    }
    var doubleValue: Double? {
        switch self {
        case .double(let d): return d
        case .int(let i): return Double(i)
        default: return nil
        }
    }
    var boolValue: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }
    var arrayValue: [JSONValue]? {
        if case .array(let a) = self { return a }
        return nil
    }
}

// MARK: - Hex Utilities

func hexToBytes(_ hex: String) -> Data {
    var data = Data()
    var hex = hex
    while hex.count >= 2 {
        let byte = String(hex.prefix(2))
        hex = String(hex.dropFirst(2))
        data.append(UInt8(byte, radix: 16)!)
    }
    return data
}

func bytesToHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

// MARK: - Parameter Helpers

func getHex(_ params: [String: JSONValue], _ key: String) throws -> Data {
    guard let val = params[key]?.stringValue else {
        throw BridgeError.missingParam(key)
    }
    return hexToBytes(val)
}

func getHexOptional(_ params: [String: JSONValue], _ key: String) -> Data? {
    guard let val = params[key]?.stringValue else { return nil }
    return hexToBytes(val)
}

func getInt(_ params: [String: JSONValue], _ key: String) throws -> Int {
    guard let val = params[key]?.intValue else {
        throw BridgeError.missingParam(key)
    }
    return val
}

func getIntOptional(_ params: [String: JSONValue], _ key: String) -> Int? {
    params[key]?.intValue
}

func getDouble(_ params: [String: JSONValue], _ key: String) throws -> Double {
    guard let val = params[key]?.doubleValue else {
        throw BridgeError.missingParam(key)
    }
    return val
}

func getString(_ params: [String: JSONValue], _ key: String) throws -> String {
    guard let val = params[key]?.stringValue else {
        throw BridgeError.missingParam(key)
    }
    return val
}

func getStringOptional(_ params: [String: JSONValue], _ key: String) -> String? {
    params[key]?.stringValue
}

func getBool(_ params: [String: JSONValue], _ key: String) throws -> Bool {
    guard let val = params[key]?.boolValue else {
        throw BridgeError.missingParam(key)
    }
    return val
}

func getBoolOptional(_ params: [String: JSONValue], _ key: String) -> Bool? {
    params[key]?.boolValue
}

func getStringArray(_ params: [String: JSONValue], _ key: String) -> [String] {
    guard let arr = params[key]?.arrayValue else { return [] }
    return arr.compactMap { $0.stringValue }
}

enum BridgeError: Error {
    case missingParam(String)
    case unknownCommand(String)
    case invalidData(String)
}

// MARK: - Result builder

typealias Result = [String: JSONValue]

func hex(_ data: Data) -> JSONValue { .string(bytesToHex(data)) }
func str(_ s: String) -> JSONValue { .string(s) }
func num(_ i: Int) -> JSONValue { .int(i) }
func num(_ d: Double) -> JSONValue { .double(d) }
func boolean(_ b: Bool) -> JSONValue { .bool(b) }

// MARK: - Command Handlers

func handleCommand(_ req: Request) throws -> Result {
    let p = req.params
    switch req.command {

    // === 1. Crypto — Key Generation & Exchange ===

    case "x25519_generate":
        let seed = try getHex(p, "seed")
        let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: seed)
        return [
            "private_key": hex(privKey.rawRepresentation),
            "public_key": hex(privKey.publicKey.rawRepresentation)
        ]

    case "x25519_public_from_private":
        let privBytes = try getHex(p, "private_key")
        let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privBytes)
        return ["public_key": hex(privKey.publicKey.rawRepresentation)]

    case "x25519_exchange":
        let privBytes = try getHex(p, "private_key")
        let peerPubBytes = try getHex(p, "peer_public_key")
        let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privBytes)
        let peerPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPubBytes)
        let shared = try privKey.sharedSecretFromKeyAgreement(with: peerPub)
        let sharedData = shared.withUnsafeBytes { Data($0) }
        return ["shared_secret": hex(sharedData)]

    case "ed25519_generate":
        let seed = try getHex(p, "seed")
        let privKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return [
            "private_key": hex(privKey.rawRepresentation),
            "public_key": hex(privKey.publicKey.rawRepresentation)
        ]

    case "ed25519_sign":
        let privBytes = try getHex(p, "private_key")
        let message = try getHex(p, "message")
        // Use Ed25519Pure for deterministic signatures matching Python
        guard let sig = Ed25519Pure.sign(message: message, seed: privBytes) else {
            throw BridgeError.invalidData("Ed25519 signing failed")
        }
        return ["signature": hex(sig)]

    case "ed25519_verify":
        let pubBytes = try getHex(p, "public_key")
        let message = try getHex(p, "message")
        let signature = try getHex(p, "signature")
        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: pubBytes)
        let valid = pubKey.isValidSignature(signature, for: message)
        return ["valid": boolean(valid)]

    // === 2. Crypto — Hashing ===

    case "sha256":
        let data = try getHex(p, "data")
        return ["hash": hex(Hashing.fullHash(data))]

    case "sha512":
        let data = try getHex(p, "data")
        let digest = SHA512.hash(data: data)
        return ["hash": hex(Data(digest))]

    case "hmac_sha256":
        let key = try getHex(p, "key")
        let message = try getHex(p, "message")
        let code = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return ["hmac": hex(Data(code))]

    case "truncated_hash":
        let data = try getHex(p, "data")
        return ["hash": hex(Hashing.truncatedHash(data))]

    // === 3. Crypto — Key Derivation ===

    case "hkdf":
        let length = try getInt(p, "length")
        let ikm = try getHex(p, "ikm")
        let salt = getHexOptional(p, "salt")
        let info = getHexOptional(p, "info")
        let derived = KeyDerivation.deriveKey(
            length: length,
            inputKeyMaterial: ikm,
            salt: salt,
            context: info
        )
        return ["derived_key": hex(derived)]

    // === 4. Crypto — Symmetric Encryption ===

    case "aes_encrypt":
        let plaintext = try getHex(p, "plaintext")
        let key = try getHex(p, "key")
        let iv = try getHex(p, "iv")
        let aes = try AES(key: Array(key), blockMode: CBC(iv: Array(iv)), padding: .pkcs7)
        let encrypted = try aes.encrypt(Array(plaintext))
        return ["ciphertext": hex(Data(encrypted))]

    case "aes_decrypt":
        let ciphertext = try getHex(p, "ciphertext")
        let key = try getHex(p, "key")
        let iv = try getHex(p, "iv")
        let aes = try AES(key: Array(key), blockMode: CBC(iv: Array(iv)), padding: .pkcs7)
        let decrypted = try aes.decrypt(Array(ciphertext))
        return ["plaintext": hex(Data(decrypted))]

    case "pkcs7_pad":
        let data = try getHex(p, "data")
        let padded = Padding.pkcs7.add(to: Array(data), blockSize: 16)
        return ["padded": hex(Data(padded))]

    case "pkcs7_unpad":
        let data = try getHex(p, "data")
        let unpadded = try Padding.pkcs7.remove(from: Array(data), blockSize: 16)
        return ["unpadded": hex(Data(unpadded))]

    // === 5. Token Encryption ===

    case "token_encrypt":
        let key = try getHex(p, "key")
        let plaintext = try getHex(p, "plaintext")
        let token = try Token(derivedKey: key)
        let encrypted: Data
        if let iv = getHexOptional(p, "iv") {
            encrypted = try token.encrypt(plaintext, iv: iv)
        } else {
            encrypted = try token.encrypt(plaintext)
        }
        return ["token": hex(encrypted)]

    case "token_decrypt":
        let key = try getHex(p, "key")
        let tokenData = try getHex(p, "token")
        let token = try Token(derivedKey: key)
        let decrypted = try token.decrypt(tokenData)
        return ["plaintext": hex(decrypted)]

    case "token_verify_hmac":
        let key = try getHex(p, "key")
        let tokenData = try getHex(p, "token")
        guard tokenData.count >= 64 else {
            return ["valid": boolean(false)]
        }
        let signingKey = key.prefix(32)
        let signedParts = tokenData.prefix(tokenData.count - 32)
        let receivedHMAC = tokenData.suffix(32)
        let expectedHMAC = HMAC<SHA256>.authenticationCode(
            for: signedParts,
            using: SymmetricKey(data: signingKey)
        )
        let valid = Data(expectedHMAC) == receivedHMAC
        return ["valid": boolean(valid)]

    // === 6. Identity ===

    case "identity_from_private_key":
        let privBytes = try getHex(p, "private_key")
        let identity = try Identity(privateKeyBytes: privBytes)
        return [
            "public_key": hex(identity.publicKeys),
            "hash": hex(identity.hash),
            "hexhash": str(identity.hexHash)
        ]

    case "identity_encrypt":
        let pubBytes = try getHex(p, "public_key")
        let plaintext = try getHex(p, "plaintext")
        let identityHash = try getHex(p, "identity_hash")
        let encPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pubBytes.prefix(32))

        if let ephPrivBytes = getHexOptional(p, "ephemeral_private"), let iv = getHexOptional(p, "iv") {
            // Deterministic encryption with provided ephemeral key and IV
            let ephPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ephPrivBytes)
            let shared = try ephPriv.sharedSecretFromKeyAgreement(with: encPub)
            let sharedData = shared.withUnsafeBytes { Data($0) }
            let derived = KeyDerivation.deriveKey(length: 64, inputKeyMaterial: sharedData, salt: identityHash, context: nil)
            let token = try Token(derivedKey: derived)
            let encrypted = try token.encrypt(plaintext, iv: iv)
            var result = Data()
            result.append(ephPriv.publicKey.rawRepresentation)
            result.append(encrypted)
            return [
                "ciphertext": hex(result),
                "ephemeral_public": hex(ephPriv.publicKey.rawRepresentation),
                "shared_key": hex(sharedData),
                "derived_key": hex(derived)
            ]
        } else {
            // Random ephemeral key
            let ciphertext = try Identity.encrypt(plaintext, to: encPub, identityHash: identityHash)
            return [
                "ciphertext": hex(ciphertext),
                "ephemeral_public": hex(ciphertext.prefix(32)),
                "shared_key": str(""),
                "derived_key": str("")
            ]
        }

    case "identity_decrypt":
        let privBytes = try getHex(p, "private_key")
        let ciphertext = try getHex(p, "ciphertext")
        let identityHash = try getHex(p, "identity_hash")
        let identity = try Identity(privateKeyBytes: privBytes)
        let plaintext = try identity.decrypt(ciphertext, identityHash: identityHash)
        return [
            "plaintext": hex(plaintext),
            "shared_key": str(""),
            "derived_key": str("")
        ]

    case "identity_sign":
        let privBytes = try getHex(p, "private_key")
        let message = try getHex(p, "message")
        // Use Ed25519Pure for deterministic signatures
        let sigPriv = privBytes.suffix(32)
        guard let sig = Ed25519Pure.sign(message: message, seed: Data(sigPriv)) else {
            throw BridgeError.invalidData("Ed25519 signing failed")
        }
        return ["signature": hex(sig)]

    case "identity_verify":
        let pubBytes = try getHex(p, "public_key")
        let message = try getHex(p, "message")
        let signature = try getHex(p, "signature")
        let sigPub = pubBytes.suffix(32)
        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: sigPub)
        let valid = pubKey.isValidSignature(signature, for: message)
        return ["valid": boolean(valid)]

    case "identity_hash":
        let pubBytes = try getHex(p, "public_key")
        let hash = Hashing.identityHash(
            encryptionPublicKey: pubBytes.prefix(32),
            signingPublicKey: Data(pubBytes.suffix(32))
        )
        return ["hash": hex(hash)]

    // === 7. Destination ===

    case "name_hash":
        let name = try getString(p, "name")
        let parts = name.split(separator: ".")
        let appName = String(parts[0])
        let aspects = parts.dropFirst().map(String.init)
        let hash = Hashing.destinationNameHash(appName: appName, aspects: aspects)
        return ["hash": hex(hash)]

    case "destination_hash":
        let identityHash = try getHex(p, "identity_hash")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)
        var combined = Data()
        combined.append(nameHash)
        combined.append(identityHash)
        let destHash = Hashing.truncatedHash(combined)
        return [
            "destination_hash": hex(destHash),
            "name_hash": hex(nameHash)
        ]

    case "packet_hash":
        let raw = try getHex(p, "raw")
        let packet = try Packet(from: raw)
        let hashablePart = packet.getHashablePart()
        let fullHash = Hashing.fullHash(hashablePart)
        let truncHash = Data(fullHash.prefix(16))
        return [
            "hash": hex(fullHash),
            "truncated_hash": hex(truncHash),
            "hashable_part": hex(hashablePart)
        ]

    // === 8. Packet ===

    case "packet_flags":
        let ht = try getInt(p, "header_type")
        let cf = try getInt(p, "context_flag")
        let tt = try getInt(p, "transport_type")
        let dt = try getInt(p, "destination_type")
        let pt = try getInt(p, "packet_type")
        var flags: UInt8 = 0
        flags |= UInt8(ht & 1) << 6
        if cf != 0 { flags |= 0x20 }
        flags |= UInt8(tt & 1) << 4
        flags |= UInt8(dt & 3) << 2
        flags |= UInt8(pt & 3)
        return ["flags": num(Int(flags))]

    case "packet_parse_flags":
        let flags = try getInt(p, "flags")
        let f = UInt8(flags)
        return [
            "header_type": num(Int((f >> 6) & 1)),
            "context_flag": num(Int((f >> 5) & 1)),
            "transport_type": num(Int((f >> 4) & 1)),
            "destination_type": num(Int((f >> 2) & 3)),
            "packet_type": num(Int(f & 3))
        ]

    case "packet_pack":
        let ht = try getInt(p, "header_type")
        let cf = try getInt(p, "context_flag")
        let tt = try getInt(p, "transport_type")
        let dt = try getInt(p, "destination_type")
        let pt = try getInt(p, "packet_type")
        let hops = try getInt(p, "hops")
        let destHash = try getHex(p, "destination_hash")
        let transportId = getHexOptional(p, "transport_id")
        let context = try getInt(p, "context")
        let data = try getHex(p, "data")
        let header = PacketHeader(
            headerType: HeaderType(rawValue: UInt8(ht)) ?? .header1,
            hasContext: cf != 0,
            hasIFAC: false,
            transportType: TransportType(rawValue: UInt8(tt)) ?? .broadcast,
            destinationType: DestinationType(rawValue: UInt8(dt)) ?? .single,
            packetType: PacketType(rawValue: UInt8(pt)) ?? .data,
            hopCount: UInt8(hops)
        )
        let packet = Packet(
            header: header,
            destination: destHash,
            transportAddress: transportId,
            context: UInt8(context),
            data: data
        )
        let raw = packet.encode()
        return [
            "raw": hex(raw),
            "header": hex(raw.prefix(2)),
            "size": num(raw.count)
        ]

    case "packet_unpack":
        let raw = try getHex(p, "raw")
        let packet = try Packet(from: raw)
        var result: Result = [
            "header_type": num(Int(packet.header.headerType.rawValue)),
            "context_flag": num(packet.header.hasContext ? 1 : 0),
            "transport_type": num(Int(packet.header.transportType.rawValue)),
            "destination_type": num(Int(packet.header.destinationType.rawValue)),
            "packet_type": num(Int(packet.header.packetType.rawValue)),
            "hops": num(Int(packet.header.hopCount)),
            "destination_hash": hex(packet.destination),
            "context": num(Int(packet.context)),
            "data": hex(packet.data)
        ]
        if let transport = packet.transportAddress {
            result["transport_id"] = hex(transport)
        }
        return result

    case "packet_parse_header":
        let raw = try getHex(p, "raw")
        guard raw.count >= 2 else {
            throw BridgeError.invalidData("Packet too short")
        }
        let flags = raw[0]
        let hops = raw[1]
        let headerType = Int((flags >> 6) & 1)
        let contextFlag = Int((flags >> 5) & 1)
        let transportType = Int((flags >> 4) & 1)
        let destinationType = Int((flags >> 2) & 3)
        let packetType = Int(flags & 3)

        let hashLen = 16
        var transportId: Data? = nil
        var destHash: Data
        var context: Int = 0

        if headerType == 0 {
            destHash = Data(raw[2..<min(2 + hashLen, raw.count)])
            if raw.count > 2 + hashLen {
                context = Int(raw[2 + hashLen])
            }
        } else {
            transportId = Data(raw[2..<min(2 + hashLen, raw.count)])
            destHash = Data(raw[(2 + hashLen)..<min(2 + 2 * hashLen, raw.count)])
            if raw.count > 2 + 2 * hashLen {
                context = Int(raw[2 + 2 * hashLen])
            }
        }

        var result: Result = [
            "header_type": num(headerType),
            "transport_type": num(transportType),
            "destination_type": num(destinationType),
            "packet_type": num(packetType),
            "context_flag": num(contextFlag),
            "hops": num(Int(hops)),
            "destination_hash": hex(destHash),
            "context": num(context)
        ]
        if let tid = transportId {
            result["transport_id"] = hex(tid)
        }
        return result

    // === 9. Framing ===

    case "hdlc_escape":
        let data = try getHex(p, "data")
        return ["escaped": hex(HDLC.escape(data))]

    case "hdlc_frame":
        let data = try getHex(p, "data")
        return ["framed": hex(HDLC.frame(data))]

    case "kiss_escape":
        let data = try getHex(p, "data")
        return ["escaped": hex(KISS.escape(data))]

    case "kiss_frame":
        let data = try getHex(p, "data")
        return ["framed": hex(KISS.frame(data))]

    // === 10. Announce ===

    case "random_hash":
        let randomBytes = getHexOptional(p, "random_bytes")
        let timestamp = getIntOptional(p, "timestamp")
        var hash = Data(count: 10)
        if let rb = randomBytes {
            hash.replaceSubrange(0..<min(5, rb.count), with: rb.prefix(5))
        } else {
            for i in 0..<5 { hash[i] = UInt8.random(in: 0...255) }
        }
        let ts: UInt64
        if let t = timestamp {
            ts = UInt64(t)
        } else {
            ts = UInt64(Date().timeIntervalSince1970)
        }
        hash[5] = UInt8((ts >> 32) & 0xFF)
        hash[6] = UInt8((ts >> 24) & 0xFF)
        hash[7] = UInt8((ts >> 16) & 0xFF)
        hash[8] = UInt8((ts >> 8) & 0xFF)
        hash[9] = UInt8(ts & 0xFF)
        let tsBytes = Data([hash[5], hash[6], hash[7], hash[8], hash[9]])
        return [
            "random_hash": hex(hash),
            "random_bytes": hex(hash.prefix(5)),
            "timestamp": num(Int(ts)),
            "timestamp_bytes": hex(tsBytes)
        ]

    case "announce_pack":
        let publicKey = try getHex(p, "public_key")
        let nameHash = try getHex(p, "name_hash")
        let randomHash = try getHex(p, "random_hash")
        let ratchet = getHexOptional(p, "ratchet")
        let signature = try getHex(p, "signature")
        let appData = getHexOptional(p, "app_data")
        var payload = Data()
        payload.append(publicKey)
        payload.append(nameHash)
        payload.append(randomHash)
        if let r = ratchet { payload.append(r) }
        payload.append(signature)
        if let ad = appData { payload.append(ad) }
        return [
            "announce_data": hex(payload),
            "size": num(payload.count),
            "has_ratchet": boolean(ratchet != nil)
        ]

    case "announce_unpack":
        let data = try getHex(p, "announce_data")
        let hasRatchet = getBoolOptional(p, "has_ratchet") ?? false
        var offset = 0
        let publicKey = Data(data[offset..<offset+64]); offset += 64
        let nameHash = Data(data[offset..<offset+10]); offset += 10
        let randomHash = Data(data[offset..<offset+10]); offset += 10
        var ratchet: Data? = nil
        if hasRatchet {
            ratchet = Data(data[offset..<offset+32]); offset += 32
        }
        let signature = Data(data[offset..<offset+64]); offset += 64
        let appData = offset < data.count ? Data(data[offset...]) : nil
        var result: Result = [
            "public_key": hex(publicKey),
            "name_hash": hex(nameHash),
            "random_hash": hex(randomHash),
            "signature": hex(signature)
        ]
        if let r = ratchet { result["ratchet"] = hex(r) }
        if let ad = appData, !ad.isEmpty { result["app_data"] = hex(ad) }
        return result

    case "announce_sign":
        let privBytes = try getHex(p, "private_key")
        let destHash = try getHex(p, "destination_hash")
        let publicKey = try getHex(p, "public_key")
        let nameHash = try getHex(p, "name_hash")
        let randomHash = try getHex(p, "random_hash")
        let appData = getHexOptional(p, "app_data")
        var signedData = Data()
        signedData.append(destHash)
        signedData.append(publicKey)
        signedData.append(nameHash)
        signedData.append(randomHash)
        if let ad = appData { signedData.append(ad) }
        let sigPriv = privBytes.suffix(32)
        guard let sig = Ed25519Pure.sign(message: signedData, seed: Data(sigPriv)) else {
            throw BridgeError.invalidData("Ed25519 signing failed")
        }
        return [
            "signature": hex(sig),
            "signed_data": hex(signedData)
        ]

    case "announce_verify":
        let pubBytes = try getHex(p, "public_key")
        let announceData = try getHex(p, "announce_data")
        let destHash = try getHex(p, "destination_hash")
        let hasRatchet = getBoolOptional(p, "has_ratchet") ?? false
        // Unpack announce data
        let keySize = 64
        let nameHashLen = 10
        let randomHashLen = 10
        let ratchetSize = hasRatchet ? 32 : 0
        let sigLen = 64
        let publicKey = announceData.prefix(keySize)
        let nameHash = Data(announceData[keySize..<keySize+nameHashLen])
        let randomHash = Data(announceData[keySize+nameHashLen..<keySize+nameHashLen+randomHashLen])
        let sigStart = keySize + nameHashLen + randomHashLen + ratchetSize
        let signature = Data(announceData[sigStart..<sigStart+sigLen])
        let appData = announceData.count > sigStart + sigLen ? Data(announceData[(sigStart+sigLen)...]) : Data()
        var ratchetData = Data()
        if hasRatchet {
            ratchetData = Data(announceData[keySize+nameHashLen+randomHashLen..<keySize+nameHashLen+randomHashLen+32])
        }
        // Build signed data: dest_hash + public_key + name_hash + random_hash + [ratchet] + app_data
        var signedData = Data()
        signedData.append(destHash)
        signedData.append(publicKey)
        signedData.append(nameHash)
        signedData.append(randomHash)
        if hasRatchet { signedData.append(ratchetData) }
        if !appData.isEmpty { signedData.append(appData) }
        let sigPub = Data(pubBytes.suffix(32))
        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: sigPub)
        let sigValid = pubKey.isValidSignature(signature, for: signedData)
        // Validate destination hash
        let identityHash = Hashing.truncatedHash(publicKey)
        var hashMaterial = Data()
        hashMaterial.append(nameHash)
        hashMaterial.append(identityHash)
        let expectedDestHash = Hashing.truncatedHash(hashMaterial)
        let destValid = destHash == expectedDestHash
        return [
            "valid": boolean(sigValid && destValid),
            "signature_valid": boolean(sigValid),
            "dest_hash_valid": boolean(destValid)
        ]

    // === 11. Link ===

    case "link_derive_key":
        let sharedKey = try getHex(p, "shared_key")
        let linkId = try getHex(p, "link_id")
        let derived = KeyDerivation.deriveKey(
            length: 64,
            inputKeyMaterial: sharedKey,
            salt: linkId,
            context: nil
        )
        return [
            "derived_key": hex(derived),
            "encryption_key": hex(Data(derived.suffix(32))),
            "signing_key": hex(derived.prefix(32))
        ]

    case "link_encrypt":
        let derivedKey = try getHex(p, "derived_key")
        let plaintext = try getHex(p, "plaintext")
        let token = try Token(derivedKey: derivedKey)
        let encrypted: Data
        if let iv = getHexOptional(p, "iv") {
            encrypted = try token.encrypt(plaintext, iv: iv)
        } else {
            encrypted = try token.encrypt(plaintext)
        }
        return ["ciphertext": hex(encrypted)]

    case "link_decrypt":
        let derivedKey = try getHex(p, "derived_key")
        let ciphertext = try getHex(p, "ciphertext")
        let token = try Token(derivedKey: derivedKey)
        let plaintext = try token.decrypt(ciphertext)
        return ["plaintext": hex(plaintext)]

    case "link_prove":
        let identityPriv = try getHex(p, "identity_private")
        let linkId = try getHex(p, "link_id")
        let receiverPub = try getHex(p, "receiver_pub")
        let receiverSigPub = try getHex(p, "receiver_sig_pub")
        let signalling = getHexOptional(p, "signalling_bytes") ?? LinkConstants.DEFAULT_MTU_SIGNALING
        var signedData = Data()
        signedData.append(linkId)
        signedData.append(receiverPub)
        signedData.append(receiverSigPub)
        signedData.append(signalling)
        let sigPriv = identityPriv.suffix(32)
        guard let sig = Ed25519Pure.sign(message: signedData, seed: Data(sigPriv)) else {
            throw BridgeError.invalidData("Ed25519 signing failed")
        }
        return [
            "signature": hex(sig),
            "signed_data": hex(signedData)
        ]

    case "link_verify_proof":
        let identityPub = try getHex(p, "identity_public")
        let linkId = try getHex(p, "link_id")
        let receiverPub = try getHex(p, "receiver_pub")
        let receiverSigPub = try getHex(p, "receiver_sig_pub")
        let signature = try getHex(p, "signature")
        let signalling = getHexOptional(p, "signalling_bytes") ?? LinkConstants.DEFAULT_MTU_SIGNALING
        var signedData = Data()
        signedData.append(linkId)
        signedData.append(receiverPub)
        signedData.append(receiverSigPub)
        signedData.append(signalling)
        let sigPub = identityPub.suffix(32)
        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: Data(sigPub))
        let valid = pubKey.isValidSignature(signature, for: signedData)
        return ["valid": boolean(valid)]

    case "link_id_from_packet":
        let raw = try getHex(p, "raw")
        let packet = try Packet(from: raw)
        // Link ID = truncated hash of hashable part, trimming signaling
        var hashable = packet.getHashablePart()
        // If data > 64 bytes (ECPUBSIZE), trim signaling (3 bytes)
        if packet.data.count > 64 {
            let diff = packet.data.count - 64
            if hashable.count > diff {
                hashable = hashable.prefix(hashable.count - diff)
            }
        }
        let linkId = Hashing.truncatedHash(hashable)
        return [
            "link_id": hex(linkId),
            "hashable_part": hex(hashable)
        ]

    case "link_signalling_bytes":
        let mtu = try getInt(p, "mtu")
        let mode = getIntOptional(p, "mode") ?? 1
        let sigBytes = IncomingLinkRequest.encodeSignaling(mtu: UInt32(mtu), mode: UInt8(mode))
        let (decodedMtu, _) = IncomingLinkRequest.decodeSignaling(sigBytes)
        return [
            "signalling_bytes": hex(sigBytes),
            "decoded_mtu": num(Int(decodedMtu))
        ]

    case "link_parse_signalling":
        let sigBytes = try getHex(p, "signalling_bytes")
        let (mtu, mode) = IncomingLinkRequest.decodeSignaling(sigBytes)
        return [
            "mtu": num(Int(mtu)),
            "mode": num(Int(mode))
        ]

    case "link_request_pack":
        let timestamp = try getDouble(p, "timestamp")
        let pathHash = try getHex(p, "path_hash")
        // data can be hex string or null
        var reqData: MessagePackValue = .null
        if let dataHex = getHexOptional(p, "data") {
            reqData = .binary(dataHex)
        }
        let request: [MessagePackValue] = [
            .double(timestamp),
            .binary(pathHash),
            reqData
        ]
        let packed = packMsgPack(.array(request))
        return ["packed": hex(packed)]

    case "link_request_unpack":
        let packed = try getHex(p, "packed")
        let value = try unpackMsgPack(packed)
        guard case .array(let arr) = value, arr.count >= 3 else {
            throw BridgeError.invalidData("Expected array with 3 elements for link request")
        }
        var timestamp: Double = 0
        switch arr[0] {
        case .double(let d): timestamp = d
        case .float(let f): timestamp = Double(f)
        case .int(let i): timestamp = Double(i)
        default: break
        }
        var pathHash = Data()
        if case .binary(let d) = arr[1] { pathHash = d }
        var result: Result = [
            "timestamp": num(timestamp),
            "path_hash": hex(pathHash)
        ]
        switch arr[2] {
        case .binary(let d): result["data"] = hex(d)
        case .null: result["data"] = .null
        default: result["data"] = .null
        }
        return result

    case "link_rtt_pack":
        let rtt = try getDouble(p, "rtt")
        // Pack RTT as msgpack float64 (matching Python's struct.pack)
        let packed = packMsgPack(.double(rtt))
        return ["packed": hex(packed)]

    case "link_rtt_unpack":
        let packed = try getHex(p, "packed")
        let value = try unpackMsgPack(packed)
        let rtt: Double
        switch value {
        case .float(let f): rtt = Double(f)
        case .double(let d): rtt = d
        case .int(let i): rtt = Double(i)
        case .uint(let u): rtt = Double(u)
        default: throw BridgeError.invalidData("Expected float for RTT")
        }
        return ["rtt": num(rtt)]

    // === 12. Resource ===

    case "resource_adv_pack":
        let transferSize = try getInt(p, "transfer_size")
        let dataSize = try getInt(p, "data_size")
        let numParts = try getInt(p, "num_parts")
        let resourceHash = try getHex(p, "resource_hash")
        let randomHash = try getHex(p, "random_hash")
        let originalHash = getHexOptional(p, "original_hash") ?? resourceHash
        let segmentIndex = try getInt(p, "segment_index")
        let totalSegments = try getInt(p, "total_segments")
        let requestId = getHexOptional(p, "request_id")
        let flags = try getInt(p, "flags")
        let hashmap = try getHex(p, "hashmap")
        let adv = ResourceAdvertisement(
            transferSize: transferSize,
            dataSize: dataSize,
            numParts: numParts,
            hash: resourceHash,
            randomHash: randomHash,
            originalHash: originalHash,
            segmentIndex: segmentIndex,
            totalSegments: totalSegments,
            requestId: requestId,
            flags: ResourceFlags(rawValue: UInt8(flags)),
            hashmapChunk: hashmap
        )
        let packed = try adv.pack()
        return ["packed": hex(packed), "size": num(packed.count)]

    case "resource_adv_unpack":
        let packed = try getHex(p, "packed")
        let adv = try ResourceAdvertisement.unpack(packed)
        var result: Result = [
            "transfer_size": num(adv.transferSize),
            "data_size": num(adv.dataSize),
            "num_parts": num(adv.numParts),
            "resource_hash": hex(adv.hash),
            "random_hash": hex(adv.randomHash),
            "original_hash": hex(adv.originalHash),
            "segment_index": num(adv.segmentIndex),
            "total_segments": num(adv.totalSegments),
            "flags": num(Int(adv.flags.rawValue)),
            "hashmap": hex(adv.hashmapChunk),
            "encrypted": boolean(adv.flags.isEncrypted),
            "compressed": boolean(adv.flags.isCompressed),
            "split": boolean(adv.flags.isSplit),
            "is_request": boolean(adv.flags.isRequestFlag),
            "is_response": boolean(adv.flags.isResponseFlag),
            "has_metadata": boolean(adv.flags.hasMetadataFlag)
        ]
        if let rid = adv.requestId {
            result["request_id"] = hex(rid)
        }
        return result

    case "resource_hash":
        let data = try getHex(p, "data")
        let randomHash = try getHex(p, "random_hash")
        // Hash material: random_hash + data (matches Python RNS)
        var combined = Data(randomHash)
        combined.append(data)
        let fullHash = Hashing.fullHash(combined)
        return [
            "hash": hex(Data(fullHash.prefix(16))),
            "full_hash": hex(fullHash)
        ]

    case "resource_flags":
        let mode = try getString(p, "mode")
        if mode == "encode" {
            let encrypted = getBoolOptional(p, "encrypted") ?? false
            let compressed = getBoolOptional(p, "compressed") ?? false
            let split = getBoolOptional(p, "split") ?? false
            let isRequest = getBoolOptional(p, "is_request") ?? false
            let isResponse = getBoolOptional(p, "is_response") ?? false
            let hasMetadata = getBoolOptional(p, "has_metadata") ?? false
            let flags = ResourceFlags(
                encrypted: encrypted,
                compressed: compressed,
                split: split,
                isRequest: isRequest,
                isResponse: isResponse,
                hasMetadata: hasMetadata
            )
            return ["flags": num(Int(flags.rawValue))]
        } else {
            let flagsVal = try getInt(p, "flags")
            let flags = ResourceFlags(rawValue: UInt8(flagsVal))
            return [
                "encrypted": boolean(flags.isEncrypted),
                "compressed": boolean(flags.isCompressed),
                "split": boolean(flags.isSplit),
                "is_request": boolean(flags.isRequestFlag),
                "is_response": boolean(flags.isResponseFlag),
                "has_metadata": boolean(flags.hasMetadataFlag)
            ]
        }

    case "resource_map_hash":
        let partData = try getHex(p, "part_data")
        let randomHash = try getHex(p, "random_hash")
        let mapHash = ResourceHashmap.partHash(partData, randomHash: randomHash)
        return ["map_hash": hex(mapHash)]

    case "resource_build_hashmap":
        let partsHex = getStringArray(p, "parts")
        let randomHash = try getHex(p, "random_hash")
        var hashmap = Data()
        for partHex in partsHex {
            let partData = hexToBytes(partHex)
            let hash = ResourceHashmap.partHash(partData, randomHash: randomHash)
            hashmap.append(hash)
        }
        return [
            "hashmap": hex(hashmap),
            "num_parts": num(partsHex.count)
        ]

    case "resource_proof":
        let data = try getHex(p, "data")
        let resourceHash = try getHex(p, "resource_hash")
        let fullHash = Hashing.fullHash(data + resourceHash)
        let proof = Data(fullHash.prefix(16))
        return ["proof": hex(proof)]

    // === 13. Ratchet ===

    case "ratchet_id":
        let ratchetPub = try getHex(p, "ratchet_public")
        // Ratchet ID = SHA256[:10] (NAME_HASH_LENGTH = 10 bytes)
        let fullHash = Hashing.fullHash(ratchetPub)
        let ratchetId = Data(fullHash.prefix(10))
        return ["ratchet_id": hex(ratchetId)]

    case "ratchet_public_from_private":
        let ratchetPriv = try getHex(p, "ratchet_private")
        let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ratchetPriv)
        return ["ratchet_public": hex(privKey.publicKey.rawRepresentation)]

    case "ratchet_derive_key":
        let ephPriv = try getHex(p, "ephemeral_private")
        let ratchetPub = try getHex(p, "ratchet_public")
        let identityHash = try getHex(p, "identity_hash")
        let ephKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ephPriv)
        let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ratchetPub)
        let shared = try ephKey.sharedSecretFromKeyAgreement(with: pubKey)
        let sharedData = shared.withUnsafeBytes { Data($0) }
        let derived = KeyDerivation.deriveKey(length: 64, inputKeyMaterial: sharedData, salt: identityHash, context: nil)
        return [
            "shared_key": hex(sharedData),
            "derived_key": hex(derived)
        ]

    case "ratchet_encrypt":
        let ratchetPub = try getHex(p, "ratchet_public")
        let identityHash = try getHex(p, "identity_hash")
        let plaintext = try getHex(p, "plaintext")
        let ciphertext = try Identity.encrypt(plaintext, toRatchetKey: ratchetPub, identityHash: identityHash)
        return ["ciphertext": hex(ciphertext)]

    case "ratchet_decrypt":
        let ratchetPriv = try getHex(p, "ratchet_private")
        let identityHash = try getHex(p, "identity_hash")
        let ciphertext = try getHex(p, "ciphertext")
        // Decrypt using ratchet private key
        let ephPubBytes = ciphertext.prefix(32)
        let tokenData = Data(ciphertext.dropFirst(32))
        let ratchetKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ratchetPriv)
        let ephPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPubBytes)
        let shared = try ratchetKey.sharedSecretFromKeyAgreement(with: ephPub)
        let sharedData = shared.withUnsafeBytes { Data($0) }
        let derived = KeyDerivation.deriveKey(length: 64, inputKeyMaterial: sharedData, salt: identityHash, context: nil)
        let token = try Token(derivedKey: derived)
        let plaintext = try token.decrypt(tokenData)
        return ["plaintext": hex(plaintext)]

    case "ratchet_extract_from_announce":
        let data = try getHex(p, "announce_data")
        // Check if announce has ratchet by looking at size
        // Without ratchet: 64 (pubkeys) + 10 (name_hash) + 10 (random_hash) + 64 (sig) = 148 min
        // With ratchet: 64 + 10 + 10 + 32 (ratchet) + 64 = 180 min
        // Name hash can vary but is typically 10 bytes for destination hash computation
        // For announces, name_hash is concatenated 16-byte aspect hashes
        // We need the has_ratchet flag from the packet header to know, but for extraction
        // we look at the data structure
        let hasRatchet = data.count >= 180
        if hasRatchet {
            let ratchetStart = 64 + 10 + 10  // After pubkeys + name_hash + random_hash
            let ratchet = Data(data[ratchetStart..<ratchetStart + 32])
            let ratchetId = Data(Hashing.fullHash(ratchet).prefix(10))
            return [
                "has_ratchet": boolean(true),
                "ratchet": hex(ratchet),
                "ratchet_id": hex(ratchetId)
            ]
        } else {
            return ["has_ratchet": boolean(false)]
        }

    // === 14. Channel ===

    case "envelope_pack":
        let msgType = try getInt(p, "msgtype")
        let sequence = getIntOptional(p, "sequence") ?? 0
        let envelopeData = try getHex(p, "data")
        // Envelope wire format: [MSGTYPE:2BE][SEQ:2BE][LEN:2BE][payload]
        var d = Data(capacity: 6 + envelopeData.count)
        d.append(UInt8(msgType >> 8))
        d.append(UInt8(msgType & 0xFF))
        d.append(UInt8(sequence >> 8))
        d.append(UInt8(sequence & 0xFF))
        let len = UInt16(envelopeData.count)
        d.append(UInt8(len >> 8))
        d.append(UInt8(len & 0xFF))
        d.append(envelopeData)
        return [
            "envelope": hex(d),
            "msgtype": num(msgType),
            "sequence": num(sequence),
            "length": num(Int(len))
        ]

    case "envelope_unpack":
        let data = try getHex(p, "envelope")
        guard data.count >= 6 else {
            throw BridgeError.invalidData("Envelope too short")
        }
        let msgType = Int(data[0]) << 8 | Int(data[1])
        let sequence = Int(data[2]) << 8 | Int(data[3])
        let len = Int(data[4]) << 8 | Int(data[5])
        let payload = data.count >= 6 + len ? Data(data[6..<(6 + len)]) : Data()
        return [
            "msgtype": num(msgType),
            "sequence": num(sequence),
            "length": num(len),
            "data": hex(payload)
        ]

    case "stream_msg_pack":
        let streamId = try getInt(p, "stream_id")
        let data = try getHex(p, "data")
        let eof = getBoolOptional(p, "eof") ?? false
        let compressed = getBoolOptional(p, "compressed") ?? false
        let msg = StreamDataMessage(streamId: UInt16(streamId), eof: eof, compressed: compressed, data: data)
        let packed = try msg.pack()
        return [
            "message": hex(packed),
            "stream_id": num(streamId),
            "eof": boolean(eof),
            "compressed": boolean(compressed)
        ]

    case "stream_msg_unpack":
        let packed = try getHex(p, "message")
        let msg = try StreamDataMessage.unpack(from: packed)
        return [
            "stream_id": num(Int(msg.streamId)),
            "eof": boolean(msg.eof),
            "compressed": boolean(msg.compressed),
            "data": hex(msg.data)
        ]

    // === 15. Transport ===

    case "path_entry_serialize":
        let destHash = try getHex(p, "destination_hash")
        let timestamp = try getDouble(p, "timestamp")
        let receivedFrom = try getHex(p, "received_from")
        let hops = try getInt(p, "hops")
        let expires = try getDouble(p, "expires")
        let randomBlobsHex = getStringArray(p, "random_blobs")
        let interfaceHash = try getHex(p, "interface_hash")
        let packetHash = try getHex(p, "packet_hash")
        // Serialize as msgpack array: [dest_hash, timestamp, received_from, hops, expires, random_blobs, interface_hash, packet_hash]
        let randomBlobValues: [MessagePackValue] = randomBlobsHex.map { .binary(hexToBytes($0)) }
        let entry: [MessagePackValue] = [
            .binary(destHash),
            .double(timestamp),
            .binary(receivedFrom),
            .int(Int64(hops)),
            .double(expires),
            .array(randomBlobValues),
            .binary(interfaceHash),
            .binary(packetHash)
        ]
        let packed = packMsgPack(.array(entry))
        return ["serialized": hex(packed)]

    case "path_entry_deserialize":
        let serialized = try getHex(p, "serialized")
        let value = try unpackMsgPack(serialized)
        guard case .array(let arr) = value, arr.count >= 8 else {
            throw BridgeError.invalidData("Expected array with 8 elements for path entry")
        }
        func extractBin(_ v: MessagePackValue) -> Data {
            if case .binary(let d) = v { return d }
            return Data()
        }
        func extractDouble(_ v: MessagePackValue) -> Double {
            if case .double(let d) = v { return d }
            if case .float(let f) = v { return Double(f) }
            if case .int(let i) = v { return Double(i) }
            if case .uint(let u) = v { return Double(u) }
            return 0
        }
        func extractInt(_ v: MessagePackValue) -> Int {
            if case .int(let i) = v { return Int(i) }
            if case .uint(let u) = v { return Int(u) }
            return 0
        }
        var randomBlobs: [JSONValue] = []
        if case .array(let blobs) = arr[5] {
            randomBlobs = blobs.map { blob -> JSONValue in
                if case .binary(let d) = blob { return .string(bytesToHex(d)) }
                return .string("")
            }
        }
        return [
            "destination_hash": hex(extractBin(arr[0])),
            "timestamp": num(extractDouble(arr[1])),
            "received_from": hex(extractBin(arr[2])),
            "hops": num(extractInt(arr[3])),
            "expires": num(extractDouble(arr[4])),
            "random_blobs": .array(randomBlobs),
            "interface_hash": hex(extractBin(arr[6])),
            "packet_hash": hex(extractBin(arr[7]))
        ]

    case "path_request_pack":
        let destHash = try getHex(p, "destination_hash")
        let pathHash = getHexOptional(p, "path_hash")
        var data = Data()
        data.append(destHash)
        if let ph = pathHash { data.append(ph) }
        return ["data": hex(data)]

    case "path_request_unpack":
        let data = try getHex(p, "data")
        let destHash = data.prefix(16)
        let pathHash = data.count > 16 ? Data(data.suffix(from: 16)) : nil
        var result: Result = ["destination_hash": hex(destHash)]
        if let ph = pathHash { result["path_hash"] = hex(ph) }
        return result

    case "packet_hashlist_pack":
        let hashesHex = getStringArray(p, "hashes")
        let hashValues: [MessagePackValue] = hashesHex.map { .binary(hexToBytes($0)) }
        let packed = packMsgPack(.array(hashValues))
        return [
            "serialized": hex(packed),
            "count": num(hashesHex.count)
        ]

    case "packet_hashlist_unpack":
        let packed = try getHex(p, "serialized")
        let value = try unpackMsgPack(packed)
        guard case .array(let arr) = value else {
            throw BridgeError.invalidData("Expected array for packet hashlist")
        }
        var hashes: [JSONValue] = []
        for item in arr {
            if case .binary(let d) = item {
                hashes.append(.string(bytesToHex(d)))
            }
        }
        return [
            "hashes": .array(hashes),
            "count": num(hashes.count)
        ]

    // === 16. IFAC ===

    case "ifac_derive_key":
        let ifacOrigin = try getHex(p, "ifac_origin")
        // IFAC key derivation: HKDF(ifac_origin, salt=IFAC_SALT, length=64)
        let ifacSalt = hexToBytes("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
        let ifacKey = KeyDerivation.deriveKey(length: 64, inputKeyMaterial: ifacOrigin, salt: ifacSalt, context: nil)
        return [
            "ifac_key": hex(ifacKey),
            "ifac_salt": hex(ifacSalt)
        ]

    case "ifac_compute":
        let ifacKey = try getHex(p, "ifac_key")
        let packetData = try getHex(p, "packet_data")
        let ifacSize = getIntOptional(p, "ifac_size") ?? 16
        // IFAC: Ed25519 sign(packet_data), take last ifac_size bytes
        // The 64-byte ifac_key: bytes 0-31 = X25519, bytes 32-63 = Ed25519 signing seed
        let ed25519Seed = Data(ifacKey[32..<64])
        guard let signature = Ed25519Pure.sign(message: packetData, seed: ed25519Seed) else {
            throw BridgeError.invalidData("Ed25519 signing failed")
        }
        let ifac = Data(signature.suffix(ifacSize))
        return [
            "ifac": hex(ifac),
            "signature": hex(signature)
        ]

    case "ifac_verify":
        let ifacKey = try getHex(p, "ifac_key")
        let packetData = try getHex(p, "packet_data")
        let expectedIfac = try getHex(p, "expected_ifac")
        let ifacSize = expectedIfac.count
        // Recompute IFAC and compare
        let ed25519Seed = Data(ifacKey[32..<64])
        guard let signature = Ed25519Pure.sign(message: packetData, seed: ed25519Seed) else {
            throw BridgeError.invalidData("Ed25519 signing failed")
        }
        let computedIfac = Data(signature.suffix(ifacSize))
        let valid = computedIfac == expectedIfac
        return [
            "valid": boolean(valid),
            "computed_ifac": hex(computedIfac)
        ]

    case "ifac_mask_packet":
        let ifacKey = try getHex(p, "ifac_key")
        let raw = try getHex(p, "packet_data")
        let ifacSize = getIntOptional(p, "ifac_size") ?? 16
        // 1. Compute IFAC: Ed25519 sign(raw), take last ifac_size bytes
        let ed25519Seed = Data(ifacKey[32..<64])
        guard let signature = Ed25519Pure.sign(message: raw, seed: ed25519Seed) else {
            throw BridgeError.invalidData("Ed25519 signing failed")
        }
        let ifac = Data(signature.suffix(ifacSize))
        // 2-3. Set flag and insert IFAC after 2-byte header
        var newRaw = Data([raw[0] | 0x80, raw[1]]) + ifac + raw[2...]
        // 4. Generate mask
        let mask = KeyDerivation.deriveKey(length: newRaw.count, inputKeyMaterial: ifac, salt: ifacKey, context: nil)
        // 5. Apply mask: header and payload masked, IFAC bytes NOT masked
        for i in 0..<newRaw.count {
            if i == 0 {
                newRaw[i] = newRaw[i] ^ mask[i] | 0x80
            } else if i == 1 || i > ifacSize + 1 {
                newRaw[i] = newRaw[i] ^ mask[i]
            }
            // else: IFAC bytes (2..2+ifacSize-1) not masked
        }
        return [
            "masked_packet": hex(newRaw),
            "ifac": hex(ifac),
        ]

    case "ifac_unmask_packet":
        let ifacKey = try getHex(p, "ifac_key")
        let masked = try getHex(p, "masked_packet")
        let ifacSize = getIntOptional(p, "ifac_size") ?? 16
        // 1. Check flag
        guard masked[0] & 0x80 == 0x80 else {
            return ["valid": boolean(false), "error": .string("ifac_flag_not_set")]
        }
        guard masked.count > 2 + ifacSize else {
            return ["valid": boolean(false), "error": .string("packet_too_short")]
        }
        // 2. Extract IFAC (not masked)
        let extractedIfac = Data(masked[2..<(2 + ifacSize)])
        // 3. Generate mask
        let unmaskMask = KeyDerivation.deriveKey(length: masked.count, inputKeyMaterial: extractedIfac, salt: ifacKey, context: nil)
        // 4. Unmask
        var unmasked = Data(count: masked.count)
        for i in 0..<masked.count {
            if i <= 1 || i > ifacSize + 1 {
                unmasked[i] = masked[i] ^ unmaskMask[i]
            } else {
                unmasked[i] = masked[i]
            }
        }
        // 5. Clear flag and remove IFAC
        let recoveredRaw = Data([unmasked[0] & 0x7f, unmasked[1]]) + unmasked[(2 + ifacSize)...]
        // 6. Validate
        guard let verifySig = Ed25519Pure.sign(message: recoveredRaw, seed: Data(ifacKey[32..<64])) else {
            throw BridgeError.invalidData("Ed25519 signing failed")
        }
        let expectedIfac = Data(verifySig.suffix(ifacSize))
        let ifacValid = extractedIfac == expectedIfac
        var unmaskResult: [String: JSONValue] = [
            "valid": boolean(ifacValid),
            "ifac": hex(extractedIfac),
        ]
        if ifacValid {
            unmaskResult["packet_data"] = hex(recoveredRaw)
        }
        return unmaskResult

    // === 17. Compression ===

    case "bz2_compress":
        let data = try getHex(p, "data")
        let compressed = try ResourceCompression.bz2Compress(data)
        return ["compressed": hex(compressed)]

    case "bz2_decompress":
        let compressed = try getHex(p, "compressed")
        let decompressed = try ResourceCompression.bz2Decompress(compressed)
        return [
            "decompressed": hex(decompressed),
            "size": num(decompressed.count)
        ]

    // === 18. LXMF ===

    case "lxmf_pack":
        let destHash = try getHex(p, "destination_hash")
        let srcHash = try getHex(p, "source_hash")
        let timestamp = try getDouble(p, "timestamp")
        let titleVal = getStringOptional(p, "title") ?? ""
        let contentVal = getStringOptional(p, "content") ?? ""
        // Title and content are UTF-8 strings, encode to bytes (matches Python)
        let titleBytes = titleVal.data(using: .utf8) ?? Data()
        let contentBytes = contentVal.data(using: .utf8) ?? Data()
        // Build payload: [timestamp, title_bytes, content_bytes, fields]
        var elements: [MessagePackValue] = [
            .double(timestamp),
            .binary(titleBytes),
            .binary(contentBytes),
        ]
        // TODO: handle fields parameter properly
        elements.append(.map([:]))
        let packedPayload = packMsgPack(.array(elements))
        // Hash = SHA256(dest_hash + source_hash + packed_payload)
        var hashedPart = Data()
        hashedPart.append(destHash)
        hashedPart.append(srcHash)
        hashedPart.append(packedPayload)
        let msgHash = Hashing.fullHash(hashedPart)
        // Signed part = hashed_part + hash
        var signedPart = Data(hashedPart)
        signedPart.append(msgHash)
        return [
            "packed_payload": hex(packedPayload),
            "hashed_part": hex(hashedPart),
            "message_hash": hex(msgHash),
            "signed_part": hex(signedPart)
        ]

    case "lxmf_unpack":
        let lxmfBytes = try getHex(p, "lxmf_bytes")
        let DEST_LEN = 16
        let SIG_LEN = 64
        guard lxmfBytes.count >= 2 * DEST_LEN + SIG_LEN else {
            throw BridgeError.invalidData("LXMF data too short")
        }
        let destHash = Data(lxmfBytes[0..<DEST_LEN])
        let srcHash = Data(lxmfBytes[DEST_LEN..<2*DEST_LEN])
        let signature = Data(lxmfBytes[2*DEST_LEN..<2*DEST_LEN+SIG_LEN])
        let packedPayload = Data(lxmfBytes[(2*DEST_LEN+SIG_LEN)...])
        let value = try unpackMsgPack(packedPayload)
        guard case .array(var elements) = value, elements.count >= 3 else {
            throw BridgeError.invalidData("Invalid LXMF msgpack array")
        }
        // Extract stamp if present (5th element)
        var stamp: Data? = nil
        if elements.count > 4, case .binary(let s) = elements[4] {
            stamp = s
            elements = Array(elements.prefix(4))
        }
        var ts: Double = 0
        if case .float(let f) = elements[0] { ts = Double(f) }
        else if case .int(let i) = elements[0] { ts = Double(i) }
        else if case .double(let d) = elements[0] { ts = d }
        var titleData = Data()
        if case .binary(let d) = elements[1] { titleData = d }
        else if case .string(let s) = elements[1] { titleData = s.data(using: .utf8) ?? Data() }
        var contentData = Data()
        if case .binary(let d) = elements[2] { contentData = d }
        else if case .string(let s) = elements[2] { contentData = s.data(using: .utf8) ?? Data() }
        let title = String(data: titleData, encoding: .utf8) ?? ""
        let content = String(data: contentData, encoding: .utf8) ?? ""
        // Recompute hash without stamp
        let repackedPayload = stamp != nil ? packMsgPack(.array(elements)) : packedPayload
        var hashedPart = Data()
        hashedPart.append(destHash)
        hashedPart.append(srcHash)
        hashedPart.append(repackedPayload)
        let msgHash = Hashing.fullHash(hashedPart)
        var result: Result = [
            "destination_hash": hex(destHash),
            "source_hash": hex(srcHash),
            "signature": hex(signature),
            "timestamp": num(ts),
            "title": str(title),
            "content": str(content),
            "message_hash": hex(msgHash)
        ]
        if let s = stamp {
            result["stamp"] = hex(s)
        } else {
            result["stamp"] = .null
        }
        return result

    case "lxmf_hash":
        let destHash = try getHex(p, "destination_hash")
        let srcHash = try getHex(p, "source_hash")
        let timestamp = try getDouble(p, "timestamp")
        let titleVal = getStringOptional(p, "title") ?? ""
        let contentVal = getStringOptional(p, "content") ?? ""
        let titleBytes = titleVal.data(using: .utf8) ?? Data()
        let contentBytes = contentVal.data(using: .utf8) ?? Data()
        var elements: [MessagePackValue] = [
            .double(timestamp),
            .binary(titleBytes),
            .binary(contentBytes),
            .map([:])
        ]
        let packed = packMsgPack(.array(elements))
        var hashInput = Data()
        hashInput.append(destHash)
        hashInput.append(srcHash)
        hashInput.append(packed)
        let msgHash = Hashing.fullHash(hashInput)
        return ["message_hash": hex(msgHash)]

    case "lxmf_stamp_workblock":
        let messageId = try getHex(p, "message_id")
        let expandRounds = getIntOptional(p, "expand_rounds") ?? 3000
        // Match Python LXStamper.stamp_workblock exactly:
        // for n in range(expand_rounds):
        //   workblock += HKDF(256, material, salt=full_hash(material + msgpack.packb(n)))
        var workblock = Data()
        for n in 0..<expandRounds {
            let nPacked = packMsgPack(.int(Int64(n)))
            let salt = Hashing.fullHash(messageId + nPacked)
            let block = KeyDerivation.deriveKey(length: 256, inputKeyMaterial: messageId, salt: salt, context: nil)
            workblock.append(block)
        }
        return [
            "workblock": hex(workblock),
            "size": num(workblock.count)
        ]

    case "lxmf_stamp_generate":
        let messageId = try getHex(p, "message_id")
        let stampCost = try getInt(p, "stamp_cost")
        let expandRounds = getIntOptional(p, "expand_rounds") ?? 3000
        // Generate workblock matching LXStamper
        var workblock = Data()
        for n in 0..<expandRounds {
            let nPacked = packMsgPack(.int(Int64(n)))
            let salt = Hashing.fullHash(messageId + nPacked)
            let block = KeyDerivation.deriveKey(length: 256, inputKeyMaterial: messageId, salt: salt, context: nil)
            workblock.append(block)
        }
        // Brute-force stamp: find 32 random bytes where full_hash(workblock + stamp)
        // has >= stampCost leading zero bits
        var stamp = Data(count: 32)
        var value = 0
        while true {
            // Generate random stamp
            for i in 0..<32 { stamp[i] = UInt8.random(in: 0...255) }
            let hash = Hashing.fullHash(workblock + stamp)
            var zeros = 0
            for byte in hash {
                if byte == 0 { zeros += 8 }
                else {
                    var b = byte
                    while b & 0x80 == 0 { zeros += 1; b <<= 1 }
                    break
                }
            }
            if zeros >= stampCost {
                value = zeros
                break
            }
        }
        return [
            "stamp": hex(stamp),
            "value": num(value)
        ]

    case "lxmf_stamp_valid":
        let stamp = try getHex(p, "stamp")
        let targetCost = try getInt(p, "target_cost")
        let workblock = try getHex(p, "workblock")
        let hash = Hashing.fullHash(workblock + stamp)
        var zeros = 0
        for byte in hash {
            if byte == 0 { zeros += 8 }
            else {
                var b = byte
                while b & 0x80 == 0 { zeros += 1; b <<= 1 }
                break
            }
        }
        let valid = zeros >= targetCost
        return [
            "valid": boolean(valid),
            "value": num(valid ? zeros : 0)
        ]

    default:
        throw BridgeError.unknownCommand(req.command)
    }
}

// MARK: - Main Loop

print("READY")
fflush(stdout)

while let line = readLine() {
    let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { continue }

    do {
        let request = try JSONDecoder().decode(Request.self, from: Data(trimmed.utf8))
        do {
            let result = try handleCommand(request)
            let response = Response(id: request.id, success: true, result: result, error: nil)
            let data = try JSONEncoder().encode(response)
            print(String(data: data, encoding: .utf8)!)
            fflush(stdout)
        } catch {
            let response = Response(id: request.id, success: false, result: nil, error: "\(error)")
            let data = try JSONEncoder().encode(response)
            print(String(data: data, encoding: .utf8)!)
            fflush(stdout)
        }
    } catch {
        let response = Response(id: "parse_error", success: false, result: nil, error: "JSON parse error: \(error)")
        if let data = try? JSONEncoder().encode(response) {
            print(String(data: data, encoding: .utf8)!)
            fflush(stdout)
        }
    }
}
