//
//  PathTable.swift
//  ReticulumSwift
//
//  Path table for storing learned routes from announces with SQLite persistence.
//  When an announce is received and validated, the path is recorded here.
//  When sending a packet, the path table is consulted to find the route.
//

import Foundation
import SQLite3

// MARK: - Path Table Errors

/// Errors from path table operations
public enum PathTableError: Error, Sendable, Equatable {
    /// Path not found in table
    case pathNotFound

    /// Path exists but has expired
    case pathExpired

    /// Database error
    case databaseError(String)
}

// MARK: - Path Table

/// Path table for routing with optional SQLite persistence.
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
/// When initialized with a database path, paths persist across app launches.
public actor PathTable {

    // MARK: - Storage

    /// Paths indexed by destination hash (in-memory cache)
    private var paths: [Data: PathEntry] = [:]

    /// SQLite database handle for persistence
    private var db: OpaquePointer?

    /// Path to database file (nil for in-memory only)
    private let databasePath: String?

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

    /// Create a path table with optional SQLite persistence.
    ///
    /// - Parameter databasePath: Path to SQLite database file, or nil for in-memory only
    /// - Throws: PathTableError.databaseError if database cannot be opened
    public init(databasePath: String? = nil) throws {
        self.databasePath = databasePath

        if let dbPath = databasePath {
            // Open or create database
            if sqlite3_open(dbPath, &db) != SQLITE_OK {
                let error = String(cString: sqlite3_errmsg(db))
                throw PathTableError.databaseError("Failed to open database: \(error)")
            }

            // Create table if needed
            let createSQL = """
                CREATE TABLE IF NOT EXISTS paths (
                    destination_hash BLOB PRIMARY KEY,
                    public_keys BLOB NOT NULL,
                    interface_id TEXT NOT NULL,
                    hop_count INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    expires REAL NOT NULL,
                    random_blob BLOB NOT NULL,
                    ratchet BLOB,
                    app_data BLOB,
                    next_hop BLOB
                )
                """
            if sqlite3_exec(db, createSQL, nil, nil, nil) != SQLITE_OK {
                let error = String(cString: sqlite3_errmsg(db))
                throw PathTableError.databaseError("Failed to create table: \(error)")
            }

            // Load existing paths into memory
            loadFromDatabase()
            print("[PATHTABLE] Loaded \(paths.count) paths from database: \(dbPath)")
        }
    }

    deinit {
        if let db = db {
            sqlite3_close(db)
        }
    }

    /// Create an empty in-memory path table (convenience initializer).
    public init() {
        self.databasePath = nil
        self.db = nil
    }

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

        // Persist to database if available
        saveToDatabase(entry)

        let nextHopStr = entry.nextHop?.prefix(8).map { String(format: "%02x", $0) }.joined() ?? "nil"
        print("[PATHTABLE] Recorded path to \(keyHex), hops=\(entry.hopCount), nextHop=\(nextHopStr), total paths=\(paths.count)")

        // Emit event for real-time UI updates
        pathUpdateContinuation?.yield(entry)

        return true
    }

    // MARK: - Database Persistence

    /// Load all paths from database into memory cache.
    private func loadFromDatabase() {
        guard let db = db else { return }

        let selectSQL = "SELECT destination_hash, public_keys, interface_id, hop_count, timestamp, expires, random_blob, ratchet, app_data, next_hop FROM paths"
        var stmt: OpaquePointer?

        guard sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nil) == SQLITE_OK else {
            print("[PATHTABLE] Failed to prepare select statement")
            return
        }
        defer { sqlite3_finalize(stmt) }

        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let destHashPtr = sqlite3_column_blob(stmt, 0) else { continue }
            let destHashLen = sqlite3_column_bytes(stmt, 0)
            let destinationHash = Data(bytes: destHashPtr, count: Int(destHashLen))

            guard let pubKeysPtr = sqlite3_column_blob(stmt, 1) else { continue }
            let pubKeysLen = sqlite3_column_bytes(stmt, 1)
            let publicKeys = Data(bytes: pubKeysPtr, count: Int(pubKeysLen))

            guard let interfaceIdCStr = sqlite3_column_text(stmt, 2) else { continue }
            let interfaceId = String(cString: interfaceIdCStr)

            let hopCount = UInt8(sqlite3_column_int(stmt, 3))
            let timestamp = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))
            let expires = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 5))

            guard let randomBlobPtr = sqlite3_column_blob(stmt, 6) else { continue }
            let randomBlobLen = sqlite3_column_bytes(stmt, 6)
            let randomBlob = Data(bytes: randomBlobPtr, count: Int(randomBlobLen))

            var ratchet: Data? = nil
            if let ratchetPtr = sqlite3_column_blob(stmt, 7) {
                let ratchetLen = sqlite3_column_bytes(stmt, 7)
                ratchet = Data(bytes: ratchetPtr, count: Int(ratchetLen))
            }

            var appData: Data? = nil
            if let appDataPtr = sqlite3_column_blob(stmt, 8) {
                let appDataLen = sqlite3_column_bytes(stmt, 8)
                appData = Data(bytes: appDataPtr, count: Int(appDataLen))
            }

            var nextHop: Data? = nil
            if let nextHopPtr = sqlite3_column_blob(stmt, 9) {
                let nextHopLen = sqlite3_column_bytes(stmt, 9)
                nextHop = Data(bytes: nextHopPtr, count: Int(nextHopLen))
            }

            let entry = PathEntry(
                destinationHash: destinationHash,
                publicKeys: publicKeys,
                interfaceId: interfaceId,
                hopCount: hopCount,
                timestamp: timestamp,
                expires: expires,
                randomBlob: randomBlob,
                ratchet: ratchet,
                appData: appData,
                nextHop: nextHop
            )

            // Only load non-expired entries
            if !entry.isExpired {
                paths[destinationHash] = entry
            }
        }
    }

    /// Save a path entry to the database.
    private func saveToDatabase(_ entry: PathEntry) {
        guard let db = db else { return }

        let upsertSQL = """
            INSERT OR REPLACE INTO paths (destination_hash, public_keys, interface_id, hop_count, timestamp, expires, random_blob, ratchet, app_data, next_hop)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
        var stmt: OpaquePointer?

        guard sqlite3_prepare_v2(db, upsertSQL, -1, &stmt, nil) == SQLITE_OK else {
            print("[PATHTABLE] Failed to prepare insert statement")
            return
        }
        defer { sqlite3_finalize(stmt) }

        entry.destinationHash.withUnsafeBytes { ptr in
            sqlite3_bind_blob(stmt, 1, ptr.baseAddress, Int32(entry.destinationHash.count), nil)
        }
        entry.publicKeys.withUnsafeBytes { ptr in
            sqlite3_bind_blob(stmt, 2, ptr.baseAddress, Int32(entry.publicKeys.count), nil)
        }
        sqlite3_bind_text(stmt, 3, entry.interfaceId, -1, nil)
        sqlite3_bind_int(stmt, 4, Int32(entry.hopCount))
        sqlite3_bind_double(stmt, 5, entry.timestamp.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 6, entry.expires.timeIntervalSince1970)
        entry.randomBlob.withUnsafeBytes { ptr in
            sqlite3_bind_blob(stmt, 7, ptr.baseAddress, Int32(entry.randomBlob.count), nil)
        }

        if let ratchet = entry.ratchet {
            ratchet.withUnsafeBytes { ptr in
                sqlite3_bind_blob(stmt, 8, ptr.baseAddress, Int32(ratchet.count), nil)
            }
        } else {
            sqlite3_bind_null(stmt, 8)
        }

        if let appData = entry.appData {
            appData.withUnsafeBytes { ptr in
                sqlite3_bind_blob(stmt, 9, ptr.baseAddress, Int32(appData.count), nil)
            }
        } else {
            sqlite3_bind_null(stmt, 9)
        }

        if let nextHop = entry.nextHop {
            nextHop.withUnsafeBytes { ptr in
                sqlite3_bind_blob(stmt, 10, ptr.baseAddress, Int32(nextHop.count), nil)
            }
        } else {
            sqlite3_bind_null(stmt, 10)
        }

        if sqlite3_step(stmt) != SQLITE_DONE {
            print("[PATHTABLE] Failed to save path: \(String(cString: sqlite3_errmsg(db)))")
        }
    }

    /// Remove a path from the database.
    private func removeFromDatabase(_ destinationHash: Data) {
        guard let db = db else { return }

        let deleteSQL = "DELETE FROM paths WHERE destination_hash = ?"
        var stmt: OpaquePointer?

        guard sqlite3_prepare_v2(db, deleteSQL, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        destinationHash.withUnsafeBytes { ptr in
            sqlite3_bind_blob(stmt, 1, ptr.baseAddress, Int32(destinationHash.count), nil)
        }

        _ = sqlite3_step(stmt)
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
        removeFromDatabase(destinationHash)
    }

    /// Remove all paths from the table and database.
    public func removeAll() {
        paths.removeAll()
        clearDatabase()
    }

    /// Clear all paths from the database.
    private func clearDatabase() {
        guard let db = db else { return }
        sqlite3_exec(db, "DELETE FROM paths", nil, nil, nil)
    }

    // MARK: - Cleanup

    /// Remove all expired entries from memory and database.
    ///
    /// - Returns: Number of entries removed
    @discardableResult
    public func cleanup() -> Int {
        let beforeCount = paths.count
        let expiredKeys = paths.filter { $0.value.isExpired }.map { $0.key }
        paths = paths.filter { !$0.value.isExpired }

        // Remove expired entries from database
        for key in expiredKeys {
            removeFromDatabase(key)
        }

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
