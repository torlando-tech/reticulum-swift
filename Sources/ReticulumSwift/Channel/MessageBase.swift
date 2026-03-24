// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  MessageBase.swift
//  ReticulumSwift
//
//  Protocol and factory for typed channel messages.
//  Matches Python RNS Channel.MessageBase.
//

import Foundation

// MARK: - Channel Errors

/// Errors for Channel and Buffer operations.
public enum ChannelError: Error, Sendable, Equatable {
    case envelopeTooShort
    case payloadTruncated
    case bufferTooShort
    case channelNotReady
    case maxRetriesExceeded
    case messageTooLarge(size: Int, max: Int)
}

// MARK: - MessageBase Protocol

/// Protocol for typed channel messages.
///
/// Each message type has a unique MSGTYPE uint16 identifier.
/// System types use 0xff00-0xffff. App types use 0x0000-0xfeff.
///
/// Matches Python RNS/Channel.py MessageBase.
public protocol MessageBase: Sendable {
    /// Unique message type identifier (2 bytes big-endian on wire).
    static var MSGTYPE: UInt16 { get }

    /// Serialize message payload to bytes.
    func pack() throws -> Data

    /// Deserialize message payload from bytes.
    static func unpack(from data: Data) throws -> Self
}

// MARK: - MessageFactory

/// Registry mapping MSGTYPE -> factory closure for creating typed messages.
///
/// Thread-safe via NSLock since MessageFactory is shared across actors.
public final class MessageFactory: @unchecked Sendable {
    private let lock = NSLock()
    private var types: [UInt16: @Sendable (Data) throws -> any MessageBase] = [:]

    public init() {}

    /// Register a message type for deserialization.
    public func register<T: MessageBase>(_ type: T.Type) {
        lock.withLock {
            types[type.MSGTYPE] = { data in try T.unpack(from: data) }
        }
    }

    /// Create a message instance from wire data.
    /// Returns nil if the MSGTYPE is not registered.
    public func create(msgtype: UInt16, data: Data) throws -> (any MessageBase)? {
        let factory: (@Sendable (Data) throws -> any MessageBase)? = lock.withLock {
            types[msgtype]
        }
        guard let factory else { return nil }
        return try factory(data)
    }

    /// Check if a MSGTYPE is registered.
    public func isRegistered(_ msgtype: UInt16) -> Bool {
        lock.withLock { types[msgtype] != nil }
    }
}
