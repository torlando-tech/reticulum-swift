// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  BLEFragmentation.swift
//  ReticulumSwift
//
//  BLE mesh fragmentation and reassembly.
//  Wire-compatible with Python ble-reticulum and Kotlin reticulum-kt.
//
//  Fragment header: [type:1][seq:2 BE][total:2 BE] = 5 bytes
//  Fragment types: START=0x01, CONTINUE=0x02, END=0x03
//  Single-fragment packets use START type (matching Python/Kotlin).
//
//  Pure Swift — no CoreBluetooth dependency. Fully unit-testable.
//

import Foundation

// MARK: - BLE Fragmenter

/// Fragments packets into BLE-sized chunks with 5-byte headers.
///
/// Each fragment has a header: `[type:1][seq:2 big-endian][total:2 big-endian]`
/// followed by payload data. Single-fragment packets use START type.
///
/// Wire format example for 3 fragments:
/// ```
/// Fragment 0: [0x01, 0x00, 0x00, 0x00, 0x03, ...payload...]  // START, seq=0, total=3
/// Fragment 1: [0x02, 0x00, 0x01, 0x00, 0x03, ...payload...]  // CONTINUE, seq=1, total=3
/// Fragment 2: [0x03, 0x00, 0x02, 0x00, 0x03, ...payload...]  // END, seq=2, total=3
/// ```
public struct BLEFragmenter: Sendable {

    /// Maximum payload bytes per fragment (MTU - header size).
    public let maxPayload: Int

    /// MTU this fragmenter was configured with.
    public let mtu: Int

    /// Create a fragmenter for the given MTU.
    ///
    /// - Parameter mtu: BLE MTU size (default 185). Must be >= 6 (header + 1 byte payload).
    public init(mtu: Int = BLEMeshConstants.defaultMTU) {
        precondition(mtu >= BLEMeshConstants.headerSize + 1, "MTU must be at least \(BLEMeshConstants.headerSize + 1)")
        self.mtu = mtu
        self.maxPayload = mtu - BLEMeshConstants.headerSize
    }

    /// Fragment a packet into BLE-sized chunks.
    ///
    /// - Parameter packet: Raw packet data to fragment
    /// - Returns: Array of fragments, each <= MTU bytes, with 5-byte headers
    public func fragment(_ packet: Data) -> [Data] {
        guard !packet.isEmpty else { return [] }

        var chunks: [Data] = []
        var offset = 0
        while offset < packet.count {
            let end = min(offset + maxPayload, packet.count)
            chunks.append(packet[offset..<end])
            offset = end
        }

        let totalFragments = UInt16(chunks.count)
        var fragments: [Data] = []
        fragments.reserveCapacity(chunks.count)

        for (index, chunk) in chunks.enumerated() {
            let seq = UInt16(index)
            let type: UInt8
            if chunks.count == 1 {
                type = BLEMeshConstants.fragmentStart
            } else if index == 0 {
                type = BLEMeshConstants.fragmentStart
            } else if index == chunks.count - 1 {
                type = BLEMeshConstants.fragmentEnd
            } else {
                type = BLEMeshConstants.fragmentContinue
            }

            var header = Data(capacity: BLEMeshConstants.headerSize + chunk.count)
            header.append(type)
            header.append(UInt8(seq >> 8))       // seq high byte (big-endian)
            header.append(UInt8(seq & 0xFF))     // seq low byte
            header.append(UInt8(totalFragments >> 8))  // total high byte
            header.append(UInt8(totalFragments & 0xFF)) // total low byte
            header.append(contentsOf: chunk)

            fragments.append(header)
        }

        return fragments
    }
}

// MARK: - Reassembly Statistics

/// Statistics for a BLE reassembler instance.
public struct ReassemblyStatistics: Sendable {
    public var packetsCompleted: Int = 0
    public var fragmentsReceived: Int = 0
    public var duplicatesIgnored: Int = 0
    public var timeoutsExpired: Int = 0
    public var errorsEncountered: Int = 0
}

// MARK: - Reassembly Error

public enum BLEReassemblyError: Error, Sendable {
    case invalidHeader(String)
    case duplicateMismatch(senderId: String, seq: UInt16)
    case totalMismatch(senderId: String, expected: UInt16, got: UInt16)
}

// MARK: - Reassembly Buffer

private struct ReassemblyBuffer {
    let senderId: String
    let totalFragments: UInt16
    var fragments: [UInt16: Data]
    var lastActivity: Date

    var isComplete: Bool {
        fragments.count == Int(totalFragments)
    }

    func assemble() -> Data {
        var result = Data()
        for seq in 0..<totalFragments {
            if let chunk = fragments[seq] {
                result.append(chunk)
            }
        }
        return result
    }
}

// MARK: - BLE Reassembler

/// Reassembles fragmented BLE packets from multiple senders.
///
/// Thread-safe via NSLock. Each sender has an independent reassembly buffer.
/// Stale buffers are cleaned up after the reassembly timeout (30s).
public final class BLEReassembler: @unchecked Sendable {

    private let lock = NSLock()
    private var buffers: [String: ReassemblyBuffer] = [:]
    private let timeout: TimeInterval

    /// Reassembly statistics.
    public private(set) var statistics = ReassemblyStatistics()

    /// Create a reassembler with the given timeout.
    ///
    /// - Parameter timeout: How long to keep incomplete buffers (default 30s)
    public init(timeout: TimeInterval = BLEMeshConstants.reassemblyTimeout) {
        self.timeout = timeout
    }

    /// Receive a fragment and attempt reassembly.
    ///
    /// - Parameters:
    ///   - fragment: Raw fragment data (header + payload)
    ///   - senderId: Identifier of the sending peer
    /// - Returns: Complete reassembled packet, or nil if more fragments are needed
    /// - Throws: `BLEReassemblyError` on duplicate mismatch or header parse failure
    public func receiveFragment(_ fragment: Data, senderId: String) throws -> Data? {
        guard fragment.count >= BLEMeshConstants.headerSize else {
            throw BLEReassemblyError.invalidHeader("Fragment too short: \(fragment.count) bytes")
        }

        let type = fragment[fragment.startIndex]
        let seqHigh = fragment[fragment.startIndex + 1]
        let seqLow = fragment[fragment.startIndex + 2]
        let totalHigh = fragment[fragment.startIndex + 3]
        let totalLow = fragment[fragment.startIndex + 4]

        let seq = UInt16(seqHigh) << 8 | UInt16(seqLow)
        let total = UInt16(totalHigh) << 8 | UInt16(totalLow)

        guard type == BLEMeshConstants.fragmentStart ||
              type == BLEMeshConstants.fragmentContinue ||
              type == BLEMeshConstants.fragmentEnd else {
            throw BLEReassemblyError.invalidHeader("Unknown fragment type: 0x\(String(format: "%02x", type))")
        }

        guard total > 0 else {
            throw BLEReassemblyError.invalidHeader("Total fragments cannot be zero")
        }

        guard seq < total else {
            throw BLEReassemblyError.invalidHeader("Sequence \(seq) >= total \(total)")
        }

        let payload = fragment.suffix(from: fragment.startIndex + BLEMeshConstants.headerSize)

        lock.lock()
        defer { lock.unlock() }

        statistics.fragmentsReceived += 1

        if var buffer = buffers[senderId] {
            // Check total consistency
            if buffer.totalFragments != total {
                // Mismatch — discard old buffer and start fresh
                statistics.errorsEncountered += 1
                buffers.removeValue(forKey: senderId)
                throw BLEReassemblyError.totalMismatch(
                    senderId: senderId,
                    expected: buffer.totalFragments,
                    got: total
                )
            }

            // Check for duplicate
            if let existing = buffer.fragments[seq] {
                if existing == Data(payload) {
                    // Benign duplicate — ignore
                    statistics.duplicatesIgnored += 1
                    return nil
                } else {
                    // Different data for same seq — discard and throw
                    buffers.removeValue(forKey: senderId)
                    statistics.errorsEncountered += 1
                    throw BLEReassemblyError.duplicateMismatch(senderId: senderId, seq: seq)
                }
            }

            buffer.fragments[seq] = Data(payload)
            buffer.lastActivity = Date()
            buffers[senderId] = buffer

            if buffer.isComplete {
                let result = buffer.assemble()
                buffers.removeValue(forKey: senderId)
                statistics.packetsCompleted += 1
                return result
            }
            return nil
        } else {
            // New buffer
            var frags: [UInt16: Data] = [:]
            frags[seq] = Data(payload)
            let buffer = ReassemblyBuffer(
                senderId: senderId,
                totalFragments: total,
                fragments: frags,
                lastActivity: Date()
            )
            buffers[senderId] = buffer

            if buffer.isComplete {
                let result = buffer.assemble()
                buffers.removeValue(forKey: senderId)
                statistics.packetsCompleted += 1
                return result
            }
            return nil
        }
    }

    /// Remove stale reassembly buffers older than the timeout.
    ///
    /// - Returns: Number of expired buffers removed
    @discardableResult
    public func cleanupStale() -> Int {
        lock.lock()
        defer { lock.unlock() }

        let now = Date()
        var removed = 0
        for (key, buffer) in buffers {
            if now.timeIntervalSince(buffer.lastActivity) > timeout {
                buffers.removeValue(forKey: key)
                statistics.timeoutsExpired += 1
                removed += 1
            }
        }
        return removed
    }

    /// Reset all state including statistics.
    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        buffers.removeAll()
        statistics = ReassemblyStatistics()
    }
}
