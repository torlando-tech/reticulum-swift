//
//  MessagePack.swift
//  ReticulumSwift
//
//  Simple MessagePack encoding/decoding for Reticulum wire format.
//  Provides low-level control for exact wire compatibility with Python Reticulum.
//
//  MessagePack format reference: https://github.com/msgpack/msgpack/blob/master/spec.md
//

import Foundation

/// MessagePack value type for encoding/decoding.
///
/// Supports the subset of MessagePack types used by Reticulum protocol.
public enum MessagePackValue: Equatable, Hashable, Sendable {
    case null
    case bool(Bool)
    case int(Int64)
    case uint(UInt64)
    case float(Float)
    case double(Double)
    case string(String)
    case binary(Data)
    case array([MessagePackValue])
    case map([MessagePackValue: MessagePackValue])
}

// MARK: - MessagePack Errors

/// Errors during MessagePack operations
public enum MessagePackError: Error, Sendable {
    case decodingFailed(String)
    case encodingFailed(String)
}

// MARK: - Encoding

/// Pack a MessagePack value to bytes.
///
/// - Parameter value: Value to pack
/// - Returns: MessagePack encoded bytes
public func packMsgPack(_ value: MessagePackValue) -> Data {
    var data = Data()
    encodeValue(value, to: &data)
    return data
}

private func encodeValue(_ value: MessagePackValue, to data: inout Data) {
    switch value {
    case .null:
        data.append(0xc0)

    case .bool(let b):
        data.append(b ? 0xc3 : 0xc2)

    case .int(let i):
        encodeInt(i, to: &data)

    case .uint(let u):
        encodeUInt(u, to: &data)

    case .float(let f):
        data.append(0xca)
        var value = f.bitPattern.bigEndian
        withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }

    case .double(let d):
        data.append(0xcb)
        var value = d.bitPattern.bigEndian
        withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }

    case .string(let s):
        let bytes = Data(s.utf8)
        encodeStringHeader(bytes.count, to: &data)
        data.append(bytes)

    case .binary(let b):
        encodeBinaryHeader(b.count, to: &data)
        data.append(b)

    case .array(let arr):
        encodeArrayHeader(arr.count, to: &data)
        for element in arr {
            encodeValue(element, to: &data)
        }

    case .map(let m):
        encodeMapHeader(m.count, to: &data)
        for (key, val) in m {
            encodeValue(key, to: &data)
            encodeValue(val, to: &data)
        }
    }
}

private func encodeInt(_ value: Int64, to data: inout Data) {
    if value >= 0 {
        encodeUInt(UInt64(value), to: &data)
    } else if value >= -32 {
        // Negative fixint
        data.append(UInt8(bitPattern: Int8(value)))
    } else if value >= Int64(Int8.min) {
        data.append(0xd0)
        data.append(UInt8(bitPattern: Int8(value)))
    } else if value >= Int64(Int16.min) {
        data.append(0xd1)
        var v = Int16(value).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    } else if value >= Int64(Int32.min) {
        data.append(0xd2)
        var v = Int32(value).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    } else {
        data.append(0xd3)
        var v = value.bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    }
}

private func encodeUInt(_ value: UInt64, to data: inout Data) {
    if value <= 0x7f {
        // Positive fixint
        data.append(UInt8(value))
    } else if value <= UInt64(UInt8.max) {
        data.append(0xcc)
        data.append(UInt8(value))
    } else if value <= UInt64(UInt16.max) {
        data.append(0xcd)
        var v = UInt16(value).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    } else if value <= UInt64(UInt32.max) {
        data.append(0xce)
        var v = UInt32(value).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    } else {
        data.append(0xcf)
        var v = value.bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    }
}

private func encodeStringHeader(_ length: Int, to data: inout Data) {
    if length <= 31 {
        // fixstr
        data.append(0xa0 | UInt8(length))
    } else if length <= Int(UInt8.max) {
        data.append(0xd9)
        data.append(UInt8(length))
    } else if length <= Int(UInt16.max) {
        data.append(0xda)
        var v = UInt16(length).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    } else {
        data.append(0xdb)
        var v = UInt32(length).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    }
}

private func encodeBinaryHeader(_ length: Int, to data: inout Data) {
    if length <= Int(UInt8.max) {
        data.append(0xc4)
        data.append(UInt8(length))
    } else if length <= Int(UInt16.max) {
        data.append(0xc5)
        var v = UInt16(length).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    } else {
        data.append(0xc6)
        var v = UInt32(length).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    }
}

private func encodeArrayHeader(_ count: Int, to data: inout Data) {
    if count <= 15 {
        // fixarray
        data.append(0x90 | UInt8(count))
    } else if count <= Int(UInt16.max) {
        data.append(0xdc)
        var v = UInt16(count).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    } else {
        data.append(0xdd)
        var v = UInt32(count).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    }
}

private func encodeMapHeader(_ count: Int, to data: inout Data) {
    if count <= 15 {
        // fixmap
        data.append(0x80 | UInt8(count))
    } else if count <= Int(UInt16.max) {
        data.append(0xde)
        var v = UInt16(count).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    } else {
        data.append(0xdf)
        var v = UInt32(count).bigEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    }
}

// MARK: - Decoding

/// Unpack MessagePack bytes to a value.
///
/// - Parameter data: MessagePack encoded bytes
/// - Returns: Decoded value
/// - Throws: Error if decoding fails
public func unpackMsgPack(_ data: Data) throws -> MessagePackValue {
    var offset = 0
    return try decodeValue(from: data, at: &offset)
}

/// Unpack MessagePack bytes to a value (slice version).
///
/// - Parameter data: MessagePack encoded bytes (can be a slice)
/// - Returns: Decoded value
/// - Throws: Error if decoding fails
public func unpackMsgPack<D: DataProtocol>(_ data: D) throws -> MessagePackValue {
    let fullData = Data(data)
    var offset = 0
    return try decodeValue(from: fullData, at: &offset)
}

private func decodeValue(from data: Data, at offset: inout Int) throws -> MessagePackValue {
    guard offset < data.count else {
        throw MessagePackError.decodingFailed("Unexpected end of data")
    }

    let byte = data[offset]
    offset += 1

    // Positive fixint (0x00 - 0x7f)
    if byte <= 0x7f {
        return .uint(UInt64(byte))
    }

    // Fixmap (0x80 - 0x8f)
    if byte >= 0x80 && byte <= 0x8f {
        let count = Int(byte & 0x0f)
        return try decodeMap(count: count, from: data, at: &offset)
    }

    // Fixarray (0x90 - 0x9f)
    if byte >= 0x90 && byte <= 0x9f {
        let count = Int(byte & 0x0f)
        return try decodeArray(count: count, from: data, at: &offset)
    }

    // Fixstr (0xa0 - 0xbf)
    if byte >= 0xa0 && byte <= 0xbf {
        let length = Int(byte & 0x1f)
        return try decodeString(length: length, from: data, at: &offset)
    }

    // Negative fixint (0xe0 - 0xff)
    if byte >= 0xe0 {
        return .int(Int64(Int8(bitPattern: byte)))
    }

    switch byte {
    case 0xc0:
        return .null
    case 0xc2:
        return .bool(false)
    case 0xc3:
        return .bool(true)

    // Binary
    case 0xc4:
        let length = Int(try readUInt8(from: data, at: &offset))
        return try decodeBinary(length: length, from: data, at: &offset)
    case 0xc5:
        let length = Int(try readUInt16(from: data, at: &offset))
        return try decodeBinary(length: length, from: data, at: &offset)
    case 0xc6:
        let length = Int(try readUInt32(from: data, at: &offset))
        return try decodeBinary(length: length, from: data, at: &offset)

    // Float
    case 0xca:
        let bits = try readUInt32(from: data, at: &offset)
        return .float(Float(bitPattern: bits))

    // Double
    case 0xcb:
        let bits = try readUInt64(from: data, at: &offset)
        return .double(Double(bitPattern: bits))

    // Unsigned int
    case 0xcc:
        return .uint(UInt64(try readUInt8(from: data, at: &offset)))
    case 0xcd:
        return .uint(UInt64(try readUInt16(from: data, at: &offset)))
    case 0xce:
        return .uint(UInt64(try readUInt32(from: data, at: &offset)))
    case 0xcf:
        return .uint(try readUInt64(from: data, at: &offset))

    // Signed int
    case 0xd0:
        return .int(Int64(Int8(bitPattern: try readUInt8(from: data, at: &offset))))
    case 0xd1:
        return .int(Int64(Int16(bitPattern: try readUInt16(from: data, at: &offset))))
    case 0xd2:
        return .int(Int64(Int32(bitPattern: try readUInt32(from: data, at: &offset))))
    case 0xd3:
        return .int(Int64(bitPattern: try readUInt64(from: data, at: &offset)))

    // String
    case 0xd9:
        let length = Int(try readUInt8(from: data, at: &offset))
        return try decodeString(length: length, from: data, at: &offset)
    case 0xda:
        let length = Int(try readUInt16(from: data, at: &offset))
        return try decodeString(length: length, from: data, at: &offset)
    case 0xdb:
        let length = Int(try readUInt32(from: data, at: &offset))
        return try decodeString(length: length, from: data, at: &offset)

    // Array
    case 0xdc:
        let count = Int(try readUInt16(from: data, at: &offset))
        return try decodeArray(count: count, from: data, at: &offset)
    case 0xdd:
        let count = Int(try readUInt32(from: data, at: &offset))
        return try decodeArray(count: count, from: data, at: &offset)

    // Map
    case 0xde:
        let count = Int(try readUInt16(from: data, at: &offset))
        return try decodeMap(count: count, from: data, at: &offset)
    case 0xdf:
        let count = Int(try readUInt32(from: data, at: &offset))
        return try decodeMap(count: count, from: data, at: &offset)

    default:
        throw MessagePackError.decodingFailed("Unknown MessagePack type: 0x\(String(byte, radix: 16))")
    }
}

private func readUInt8(from data: Data, at offset: inout Int) throws -> UInt8 {
    guard offset < data.count else {
        throw MessagePackError.decodingFailed("Unexpected end of data")
    }
    let value = data[offset]
    offset += 1
    return value
}

private func readUInt16(from data: Data, at offset: inout Int) throws -> UInt16 {
    guard offset + 2 <= data.count else {
        throw MessagePackError.decodingFailed("Unexpected end of data")
    }
    let value = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    offset += 2
    return value
}

private func readUInt32(from data: Data, at offset: inout Int) throws -> UInt32 {
    guard offset + 4 <= data.count else {
        throw MessagePackError.decodingFailed("Unexpected end of data")
    }
    let value = UInt32(data[offset]) << 24 |
                UInt32(data[offset + 1]) << 16 |
                UInt32(data[offset + 2]) << 8 |
                UInt32(data[offset + 3])
    offset += 4
    return value
}

private func readUInt64(from data: Data, at offset: inout Int) throws -> UInt64 {
    guard offset + 8 <= data.count else {
        throw MessagePackError.decodingFailed("Unexpected end of data")
    }
    let value = UInt64(data[offset]) << 56 |
                UInt64(data[offset + 1]) << 48 |
                UInt64(data[offset + 2]) << 40 |
                UInt64(data[offset + 3]) << 32 |
                UInt64(data[offset + 4]) << 24 |
                UInt64(data[offset + 5]) << 16 |
                UInt64(data[offset + 6]) << 8 |
                UInt64(data[offset + 7])
    offset += 8
    return value
}

private func decodeString(length: Int, from data: Data, at offset: inout Int) throws -> MessagePackValue {
    guard offset + length <= data.count else {
        throw MessagePackError.decodingFailed("Unexpected end of data")
    }
    let bytes = data[offset..<(offset + length)]
    offset += length
    guard let string = String(data: Data(bytes), encoding: .utf8) else {
        throw MessagePackError.decodingFailed("Invalid UTF-8 string")
    }
    return .string(string)
}

private func decodeBinary(length: Int, from data: Data, at offset: inout Int) throws -> MessagePackValue {
    guard offset + length <= data.count else {
        throw MessagePackError.decodingFailed("Unexpected end of data")
    }
    let bytes = Data(data[offset..<(offset + length)])
    offset += length
    return .binary(bytes)
}

private func decodeArray(count: Int, from data: Data, at offset: inout Int) throws -> MessagePackValue {
    var elements: [MessagePackValue] = []
    elements.reserveCapacity(count)
    for _ in 0..<count {
        elements.append(try decodeValue(from: data, at: &offset))
    }
    return .array(elements)
}

private func decodeMap(count: Int, from data: Data, at offset: inout Int) throws -> MessagePackValue {
    var map: [MessagePackValue: MessagePackValue] = [:]
    map.reserveCapacity(count)
    for _ in 0..<count {
        let key = try decodeValue(from: data, at: &offset)
        let value = try decodeValue(from: data, at: &offset)
        map[key] = value
    }
    return .map(map)
}
