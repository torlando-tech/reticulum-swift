// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  PacketHashlist.swift
//  ReticulumSwift
//
//  Rotating packet hash deduplication list, matching Python Transport.packet_hashlist.
//  Two sets rotate: when current exceeds threshold, it becomes prev and a new
//  current is created. Inbound packets are checked against both sets.
//
//  Python reference: Transport.py ~line 1230
//  hashlist_maxsize = 1_000_000 (two rotating sets of 500K each)
//

import Foundation

/// Rotating packet hash deduplication list.
///
/// Prevents duplicate packet processing by tracking recently-seen packet hashes.
/// Uses two rotating sets: when the current set exceeds half maxSize, it replaces
/// the previous set and a fresh current set is created. Announces bypass dedup.
///
/// Persistence: saves/loads hashes to disk so dedup state survives restarts.
public actor PacketHashlist {

    /// Maximum total capacity across both sets
    private let maxSize: Int

    /// Current set of packet hashes
    private var current: Set<Data> = []

    /// Previous set (rotated out)
    private var previous: Set<Data> = []

    /// File URL for persistence
    private let persistURL: URL?

    /// Rotation threshold: rotate when current exceeds this
    private var rotationThreshold: Int { maxSize / 2 }

    public init(maxSize: Int = TransportConstants.HASHLIST_MAXSIZE, persistPath: String? = nil) {
        self.maxSize = maxSize
        if let path = persistPath {
            self.persistURL = URL(fileURLWithPath: path)
        } else {
            self.persistURL = nil
        }
    }

    /// Check if a packet hash has been seen before.
    ///
    /// - Parameter hash: 32-byte full packet hash
    /// - Returns: true if this is a NEW hash (should be accepted), false if duplicate
    public func shouldAccept(_ hash: Data) -> Bool {
        return !current.contains(hash) && !previous.contains(hash)
    }

    /// Record a packet hash as seen.
    ///
    /// If the current set exceeds the rotation threshold, rotates sets.
    ///
    /// - Parameter hash: 32-byte full packet hash
    public func record(_ hash: Data) {
        current.insert(hash)

        if current.count > rotationThreshold {
            previous = current
            current = Set<Data>()
        }
    }

    /// E17: Remove a packet hash from both sets.
    ///
    /// Used when a packet is rejected after being recorded (e.g., hop count mismatch
    /// on a link DATA packet) so it can be re-received on the correct interface.
    ///
    /// - Parameter hash: 32-byte full packet hash to remove
    public func remove(_ hash: Data) {
        current.remove(hash)
        previous.remove(hash)
    }

    /// Number of hashes tracked across both sets.
    public var count: Int {
        current.count + previous.count
    }

    /// Save current state to disk for persistence across restarts.
    public func save() {
        guard let url = persistURL else { return }

        // Simple binary format: [4-byte count][N × 32-byte hashes]
        var data = Data()
        let allHashes = current.union(previous)
        var count = UInt32(allHashes.count).bigEndian
        data.append(Data(bytes: &count, count: 4))
        for hash in allHashes {
            data.append(hash.prefix(32))
        }

        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: url, options: .atomic)
        } catch {
            // Non-fatal: dedup state loss just means some duplicates get through briefly
        }
    }

    /// Load previously saved state from disk.
    public func load() {
        guard let url = persistURL else { return }
        guard let data = try? Data(contentsOf: url) else { return }
        guard data.count >= 4 else { return }

        let count = data.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        var offset = 4
        var loaded = Set<Data>()

        for _ in 0..<count {
            guard offset + 32 <= data.count else { break }
            loaded.insert(Data(data[offset..<(offset + 32)]))
            offset += 32
        }

        // Put all loaded hashes into previous so they're checked but will rotate out
        previous = loaded
        current = Set<Data>()
    }
}
