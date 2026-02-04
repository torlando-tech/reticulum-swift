//
//  PathTable.swift
//  ReticulumSwift
//
//  In-memory path table for storing learned routes from announces.
//  When an announce is received and validated, the path is recorded here.
//  When sending a packet, the path table is consulted to find the route.
//
//  Phase 3: In-memory only. GRDB persistence added in Phase 4 for App Group sharing.
//

import Foundation

// MARK: - Path Table Errors

/// Errors from path table operations
public enum PathTableError: Error, Sendable, Equatable {
    /// Path not found in table
    case pathNotFound

    /// Path exists but has expired
    case pathExpired
}

// MARK: - Path Table

/// In-memory path table for routing.
///
/// The path table stores routing information learned from validated announces.
/// It enables routing packets to known destinations by looking up the best path.
///
/// Key operations:
/// - **record()**: Store a path from a validated announce
/// - **lookup()**: Find a path for a destination hash
/// - **cleanup()**: Remove expired entries
/// - **pathUpdates**: AsyncStream for real-time path notifications
///
/// Thread safety is ensured via actor isolation.
///
/// Phase 3 uses in-memory storage only. GRDB persistence will be added
/// in Phase 4 when we need App Group sharing with Network Extension.
public actor PathTable {

    // MARK: - Storage

    /// Paths indexed by destination hash
    private var paths: [Data: PathEntry] = [:]

    // MARK: - Event Stream

    /// Continuation for emitting path updates
    private var pathUpdateContinuation: AsyncStream<PathEntry>.Continuation?

    /// Stream of path updates for real-time UI notifications.
    /// Emits whenever a new path is recorded (not duplicates or worse paths).
    public nonisolated var pathUpdates: AsyncStream<PathEntry> {
        AsyncStream { continuation in
            Task {
                await self.setPathUpdateContinuation(continuation)
            }
        }
    }

    /// Set the continuation for path updates (called from AsyncStream initializer)
    private func setPathUpdateContinuation(_ continuation: AsyncStream<PathEntry>.Continuation) {
        self.pathUpdateContinuation = continuation
        continuation.onTermination = { @Sendable _ in
            Task { await self.clearPathUpdateContinuation() }
        }
    }

    /// Clear the continuation when stream is terminated
    private func clearPathUpdateContinuation() {
        self.pathUpdateContinuation = nil
    }

    // MARK: - Initialization

    /// Create an empty path table.
    public init() {}

    // MARK: - Record

    /// Record a path entry.
    ///
    /// The path is stored if:
    /// - No existing path for this destination
    /// - OR the new path has a better (lower) hop count
    ///
    /// The path is ignored if:
    /// - Same randomBlob (replay attack detection)
    /// - Existing path has equal or better hop count
    ///
    /// - Parameter entry: Path entry to record
    /// - Returns: true if path was recorded, false if ignored
    @discardableResult
    public func record(entry: PathEntry) -> Bool {
        let key = entry.destinationHash
        let keyHex = key.prefix(8).map { String(format: "%02x", $0) }.joined()

        // Check for existing entry
        if let existing = paths[key] {
            // Replay detection: same random blob means duplicate announce
            if existing.randomBlob == entry.randomBlob {
                print("[PATHTABLE] Ignored \(keyHex): duplicate random blob")
                return false
            }

            // Only accept better (lower hop count) paths
            if entry.hopCount >= existing.hopCount {
                print("[PATHTABLE] Ignored \(keyHex): existing path has equal/better hop count")
                return false
            }
        }

        // Store the new entry
        paths[key] = entry
        print("[PATHTABLE] Recorded path to \(keyHex), hops=\(entry.hopCount), total paths=\(paths.count)")

        // Emit event for real-time UI updates
        pathUpdateContinuation?.yield(entry)

        return true
    }

    /// Record a path from announce parameters.
    ///
    /// Convenience method for recording directly from announce data.
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash
    ///   - publicKeys: 64-byte concatenated public keys
    ///   - randomBlob: 10-byte random blob from announce
    ///   - interfaceId: Interface identifier where path was learned
    ///   - hopCount: Number of hops to destination
    ///   - expiration: Time interval until expiration (defaults to 7 days)
    ///   - ratchet: Optional 32-byte ratchet public key for forward secrecy
    ///   - appData: Optional application data from announce
    ///   - nextHop: Optional 16-byte next hop transport node hash for routing
    /// - Returns: true if path was recorded, false if ignored
    @discardableResult
    public func record(
        destinationHash: Data,
        publicKeys: Data,
        randomBlob: Data,
        interfaceId: String,
        hopCount: UInt8,
        expiration: TimeInterval = PathEntry.standardExpiration,
        ratchet: Data? = nil,
        appData: Data? = nil,
        nextHop: Data? = nil
    ) -> Bool {
        let entry = PathEntry(
            destinationHash: destinationHash,
            publicKeys: publicKeys,
            interfaceId: interfaceId,
            hopCount: hopCount,
            expiration: expiration,
            randomBlob: randomBlob,
            ratchet: ratchet,
            appData: appData,
            nextHop: nextHop
        )
        return record(entry: entry)
    }

    // MARK: - Lookup

    /// Look up a path for a destination.
    ///
    /// Returns the path entry if found and not expired.
    /// Returns nil if not found or expired.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: Path entry if found and valid, nil otherwise
    public func lookup(destinationHash: Data) -> PathEntry? {
        guard let entry = paths[destinationHash] else {
            return nil
        }

        // Don't return expired entries
        if entry.isExpired {
            return nil
        }

        return entry
    }

    /// Look up a path, throwing on not found or expired.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: Path entry
    /// - Throws: `PathTableError.pathNotFound` or `PathTableError.pathExpired`
    public func lookupOrThrow(destinationHash: Data) throws -> PathEntry {
        guard let entry = paths[destinationHash] else {
            throw PathTableError.pathNotFound
        }

        if entry.isExpired {
            throw PathTableError.pathExpired
        }

        return entry
    }

    // MARK: - Removal

    /// Remove a path from the table.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    public func remove(destinationHash: Data) {
        paths.removeValue(forKey: destinationHash)
    }

    /// Remove all paths from the table.
    public func removeAll() {
        paths.removeAll()
    }

    // MARK: - Cleanup

    /// Remove all expired entries.
    ///
    /// - Returns: Number of entries removed
    @discardableResult
    public func cleanup() -> Int {
        let beforeCount = paths.count
        paths = paths.filter { !$0.value.isExpired }
        return beforeCount - paths.count
    }

    // MARK: - Properties

    /// Number of valid (non-expired) paths in the table.
    public var count: Int {
        paths.values.filter { !$0.isExpired }.count
    }

    /// Total number of entries including expired ones.
    ///
    /// Expired entries are lazily removed by cleanup() or filtered by lookup().
    public var totalCount: Int {
        paths.count
    }

    /// All destination hashes with valid paths.
    public var destinations: [Data] {
        paths.filter { !$0.value.isExpired }.map { $0.key }
    }

    /// Check if a path exists for a destination (and is not expired).
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: true if valid path exists
    public func hasPath(for destinationHash: Data) -> Bool {
        guard let entry = paths[destinationHash] else {
            return false
        }
        return !entry.isExpired
    }
}

// MARK: - Debug Support

extension PathTable {
    /// Get all entries for debugging (includes expired).
    ///
    /// Not for production use.
    public func allEntries() -> [PathEntry] {
        Array(paths.values)
    }
}
