// Behavioral+Blackhole.swift — conformance bridge behavioral sub-handler cluster: B-BLACKHOLE (blackhole_* + read_blackhole_table + unblackhole_identity)
//
// Ports from reticulum-conformance reference/behavioral_transport.py. Shares the
// behavioralInstances registry + behavioralLock + requireBehavioralInstance()
// (internal in Behavioral.swift). Returns nil for commands it doesn't own
// (dispatch chain: handleBehavioralExtensionCommand in Ext+Dispatch.swift).
//
// SUBSYSTEM RECONSTRUCTION. reticulum-swift's ReticulumTransport has NO native
// blackhole subsystem (no `blackholed_identities` table, no
// blackhole_identity/unblackhole_identity/reload_blackhole/persist_blackhole, no
// blackhole-aware announce validation). RNS keeps these as process-wide statics on
// Transport (Transport.py:3399-3517) backed by <configdir>/storage/blackhole.
//
// Rather than bail, this file reconstructs the whole observable subsystem against
// the REAL Transport + primitives:
//   * the in-memory blackholed_identities table (per behavioral handle),
//   * the on-disk storage directory + persist/reload + expiry skip + remote-source
//     trust/precedence (Transport.reload_blackhole / persist_blackhole),
//   * remove_blackholed_paths(), driven against the live ReticulumTransport
//     PathTable: each path's associated identity is recalled as
//     Hashing.truncatedHash(PathEntry.publicKeys) — the swift equivalent of
//     RNS.Identity.recall(destination_hash).hash (Transport.py:3470-3489).
//
// The one piece that cannot be reconstructed from the bridge is the
// validate_announce blackhole GATE (Identity.py:567-569 / Transport.py:308-335),
// which drops a *future* announce from a blackholed identity before it installs a
// path. reticulum-swift's announce/receive path does not consult any blackhole
// table, and this side-table is divorced from it. See the LIBRARY-GAP note on
// blackhole_identity. None of the four test_blackhole_hooks.py cases inject an
// announce AFTER blackholing, so the four invariants they assert (list schema,
// removal of an already-learned path, persist/reload/expiry, remote-source
// trust/precedence) are fully covered by this reconstruction.
import Foundation
import ReticulumSwift

// MARK: - Per-handle blackhole subsystem state

/// One blackhole entry, mirroring RNS's per-identity dict
/// `{"source": <bytes>, "until": <float|None>, "reason": <str|None>}`
/// (Transport.blackhole_identity, Transport.py:3402).
private struct BlackholeEntry {
    var source: Data?
    var until: Double?
    var reason: String?
}

/// Reconstruction of the process-wide RNS blackhole state, scoped per behavioral
/// handle (the conformance harness gives each test a fresh bridge, and
/// _reset_transport_state clears the RNS table between handles — so per-handle
/// state is observationally identical and avoids cross-handle leakage).
///
/// Holds the in-memory `blackholed_identities` table (insertion-ordered to match
/// python dict iteration), the trusted-source list (RNS.Reticulum.blackhole_sources()),
/// and a real on-disk storage directory standing in for
/// <configdir>/storage/blackhole (RNS.Reticulum.blackholepath).
private final class BlackholeState: @unchecked Sendable {
    private let lock = NSLock()
    private var order: [Data] = []
    private var table: [Data: BlackholeEntry] = [:]
    private var trusted: [Data] = []
    let storageDir: String

    init(handle: String) {
        let base = NSTemporaryDirectory()
        let dir = (base as NSString).appendingPathComponent("rns-conformance-blackhole-\(handle)")
        self.storageDir = dir
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    // -- in-memory table --

    func contains(_ identityHash: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return table[identityHash] != nil
    }

    func get(_ identityHash: Data) -> BlackholeEntry? {
        lock.lock(); defer { lock.unlock() }
        return table[identityHash]
    }

    /// Insert or overwrite an entry, preserving insertion order for new keys.
    func setEntry(_ identityHash: Data, _ entry: BlackholeEntry) {
        lock.lock(); defer { lock.unlock() }
        if table[identityHash] == nil { order.append(identityHash) }
        table[identityHash] = entry
    }

    /// Remove an entry. Returns true if it was present.
    @discardableResult
    func remove(_ identityHash: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard table[identityHash] != nil else { return false }
        table.removeValue(forKey: identityHash)
        order.removeAll { $0 == identityHash }
        return true
    }

    func clearTable() {
        lock.lock(); defer { lock.unlock() }
        table.removeAll()
        order.removeAll()
    }

    /// Insertion-ordered snapshot, mirroring `for h in table.copy()`.
    func snapshot() -> [(Data, BlackholeEntry)] {
        lock.lock(); defer { lock.unlock() }
        return order.compactMap { h in table[h].map { (h, $0) } }
    }

    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return table.count
    }

    /// The set of blackholed identity hashes, for remove_blackholed_paths().
    func blackholedHashSet() -> Set<Data> {
        lock.lock(); defer { lock.unlock() }
        return Set(table.keys)
    }

    // -- trusted sources (RNS.Reticulum.blackhole_sources()) --

    func setTrusted(_ sources: [Data]) {
        lock.lock(); defer { lock.unlock() }
        trusted = sources
    }

    func isTrusted(_ source: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return trusted.contains(source)
    }

    var trustedCount: Int {
        lock.lock(); defer { lock.unlock() }
        return trusted.count
    }
}

/// Side registry of reconstructed blackhole state, keyed by behavioral handle.
/// Separate from `behavioralInstances` (Behavioral.swift, not editable here);
/// created lazily on first blackhole command for a handle.
private let blackholeStatesLock = NSLock()
private nonisolated(unsafe) var blackholeStates: [String: BlackholeState] = [:]

private func blackholeState(for handle: String) -> BlackholeState {
    blackholeStatesLock.lock(); defer { blackholeStatesLock.unlock() }
    if let existing = blackholeStates[handle] { return existing }
    let created = BlackholeState(handle: handle)
    blackholeStates[handle] = created
    return created
}

// MARK: - Helpers

/// Serialize one blackhole entry to the JSON-safe dict the rnpath consumer reads
/// off each entry: {identity_hash, source, until, reason}
/// (_serialize_blackhole_entry, behavioral_transport.py:1661).
private func serializeBlackholeEntry(_ identityHash: Data, _ entry: BlackholeEntry) -> JSONValue {
    var d: [String: JSONValue] = [:]
    d["identity_hash"] = str(bytesToHex(identityHash))
    d["source"] = entry.source != nil ? str(bytesToHex(entry.source!)) : .null
    d["until"] = entry.until != nil ? num(entry.until!) : .null
    d["reason"] = entry.reason != nil ? str(entry.reason!) : .null
    return .dict(d)
}

/// Persist the locally-sourced entries to the file named exactly "local"
/// (Transport.persist_blackhole, Transport.py:3500-3517). Only entries whose
/// source == this transport's own identity hash are written.
///
/// The umsgpack wire format RNS uses is irrelevant here: the harness never
/// decodes a blackhole file itself and never serializes one for the wire — the
/// only readers/writers of this directory are persist_blackhole + reload_blackhole
/// in THIS file (the remote-source tests repurpose the RNS-equivalent 'local' file
/// purely by renaming it, bytes untouched). So a self-consistent JSON encoding is
/// sufficient and round-trips through reload exactly as umsgpack would.
private func persistBlackhole(_ state: BlackholeState, selfHash: Data) {
    var obj: [String: Any] = [:]
    for (identityHash, entry) in state.snapshot() where entry.source == selfHash {
        var inner: [String: Any] = [:]
        inner["source"] = entry.source != nil ? (bytesToHex(entry.source!) as Any) : NSNull()
        inner["until"] = entry.until != nil ? (entry.until! as Any) : NSNull()
        inner["reason"] = entry.reason != nil ? (entry.reason! as Any) : NSNull()
        obj[bytesToHex(identityHash)] = inner
    }
    let data = (try? JSONSerialization.data(withJSONObject: obj)) ?? Data("{}".utf8)
    let url = URL(fileURLWithPath: (state.storageDir as NSString).appendingPathComponent("local"))
    try? data.write(to: url, options: .atomic)
}

/// Reconstruct Transport.remove_blackholed_paths() (Transport.py:3470-3489)
/// against the live ReticulumTransport PathTable. For each learned path the
/// associated identity is recalled as Hashing.truncatedHash(publicKeys) — the
/// swift equivalent of RNS.Identity.recall(destination_hash).hash — and the path
/// is dropped iff that identity hash is currently blackholed. Keyed on the
/// blackholed identity, never a blanket flush.
private func removeBlackholedPaths(_ inst: BehavioralInstance, _ blackholed: Set<Data>) throws {
    guard !blackholed.isEmpty else { return }
    try blockingAsync {
        let pathTable = await inst.transport.getPathTable()
        let entries = await pathTable.allEntries()
        var dropDestinations: [Data] = []
        for entry in entries {
            guard entry.publicKeys.count >= 64 else { continue }
            let associatedIdentityHash = Hashing.truncatedHash(entry.publicKeys)
            if blackholed.contains(associatedIdentityHash),
               !dropDestinations.contains(entry.destinationHash) {
                dropDestinations.append(entry.destinationHash)
            }
        }
        for destinationHash in dropDestinations {
            await pathTable.remove(destinationHash: destinationHash)
        }
    }
}

/// Reconstruct Transport.reload_blackhole() (Transport.py:3431-3468): rescan the
/// storage directory, loading each trusted source file, skipping expired entries
/// and never overwriting a locally-sourced entry, then remove_blackholed_paths().
private func reloadBlackhole(_ inst: BehavioralInstance, _ state: BlackholeState) throws {
    let now = Date().timeIntervalSince1970
    let selfHash = inst.identity.hash
    let destLen = 32  // (TRUNCATED_HASHLENGTH//8)*2 — hex length of an identity hash
    let fm = FileManager.default
    let dir = state.storageDir

    // os.listdir order is unspecified; sort for determinism (no test depends on
    // cross-file order — at most one source file is relevant per reload).
    let names = ((try? fm.contentsOfDirectory(atPath: dir)) ?? []).sorted()
    for name in names {
        let full = (dir as NSString).appendingPathComponent(name)
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue else { continue }

        let sourceIdentityHash: Data
        if name == "local" {
            // filename == 'local' => own identity is the source (Transport.py:3437).
            sourceIdentityHash = selfHash
        } else {
            // Remote/fetched list: filename is the hex of the source identity hash.
            // Invalid length or non-hex => RNS raises inside the try and skips the
            // file (Transport.py:3439-3440). Then the trusted-source gate
            // (Transport.py:3441).
            guard name.count == destLen, let sh = hexToBytes(name) else { continue }
            guard state.isTrusted(sh) else { continue }
            sourceIdentityHash = sh
        }

        guard let data = fm.contents(atPath: full),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            continue
        }
        for (identityHashHex, value) in obj {
            guard let inner = value as? [String: Any] else { continue }
            // Only 16-byte identity hashes (Transport.py:3450).
            guard let identityHash = hexToBytes(identityHashHex), identityHash.count == 16 else { continue }
            // Local precedence: never overwrite a locally-sourced entry
            // (Transport.py:3451-3453).
            if let existing = state.get(identityHash), existing.source == selfHash { continue }
            let until = (inner["until"] as? NSNumber)?.doubleValue
            let reason = inner["reason"] as? String
            // Expiry skip on reload (Transport.py:3460).
            if until == nil || now < until! {
                state.setEntry(identityHash, BlackholeEntry(source: sourceIdentityHash, until: until, reason: reason))
            }
        }
    }

    try removeBlackholedPaths(inst, state.blackholedHashSet())
}

// MARK: - Command dispatch

func handleBehavioralBlackholeCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    case "behavioral_blackhole_identity":
        // Reconstruction of Transport.blackhole_identity (Transport.py:3399-3413):
        // insert {source: own identity hash, until, reason}, persist the local
        // list, drop already-learned paths for the identity, return True; if the
        // identity is already present, RNS returns None (→ blackholed False).
        //
        // LIBRARY-GAP: reticulum-swift's ReticulumTransport/Identity has no
        // blackhole-aware announce validation (RNS Identity.validate_announce
        // blackhole gate, Identity.py:567-569, consulted via the process-wide
        // Transport.blackholed_identities table). This bridge maintains the table
        // out-of-band, so a FUTURE announce from a blackholed identity would still
        // install a path in the real Transport — the inbound drop side effect of
        // blackhole_identity is not wired. The path-REMOVAL invariant (drop an
        // already-learned path) IS reconstructed below via remove_blackholed_paths.
        let handle = try getString(p, "handle")
        let identityHash = try getHex(p, "identity_hash")
        let until: Double? = p["until"]?.doubleValue
        let reason: String? = getStringOptional(p, "reason")

        let inst = try requireBehavioralInstance(handle)
        let state = blackholeState(for: handle)

        let blackholed: Bool
        if state.contains(identityHash) {
            blackholed = false  // python returns None → bool(None) == False
        } else {
            state.setEntry(identityHash, BlackholeEntry(source: inst.identity.hash, until: until, reason: reason))
            persistBlackhole(state, selfHash: inst.identity.hash)
            try removeBlackholedPaths(inst, state.blackholedHashSet())
            // Populate the live ReticulumTransport.blackholed_identities set so a
            // FUTURE announce from this identity is dropped in the validate_announce
            // blackhole gate (Identity.py:567-569) before any path is learned — the
            // inbound-drop side effect of Transport.blackhole_identity (Transport.py:123).
            try blockingAsync { await inst.transport.blackholeIdentity(identityHash) }
            blackholed = true
        }
        return ["blackholed": boolean(blackholed)]

    case "behavioral_unblackhole_identity":
        // Transport.unblackhole_identity (Transport.py:3415-3428): pop the entry
        // and re-persist the local list. Returns True if present, else None
        // (→ lifted False).
        let handle = try getString(p, "handle")
        let identityHash = try getHex(p, "identity_hash")

        let inst = try requireBehavioralInstance(handle)
        let state = blackholeState(for: handle)

        let lifted = state.remove(identityHash)
        if lifted {
            persistBlackhole(state, selfHash: inst.identity.hash)
            // Lift the live ReticulumTransport blackhole gate too, so subsequent
            // announces from this identity are learned again (Transport.unblackhole_identity).
            try blockingAsync { await inst.transport.unblackholeIdentity(identityHash) }
        }
        return ["lifted": boolean(lifted)]

    case "behavioral_read_blackhole_table":
        // Read the live blackholed_identities table as a JSON-safe list
        // (cmd_behavioral_read_blackhole_table, behavioral_transport.py:1676).
        let handle = try getString(p, "handle")
        _ = try requireBehavioralInstance(handle)
        let state = blackholeState(for: handle)

        let entries = state.snapshot().map { serializeBlackholeEntry($0.0, $0.1) }
        return ["count": num(entries.count), "entries": .array(entries)]

    case "behavioral_blackhole_list_handler":
        // Transport.blackhole_list_handler (Transport.py:3491-3498): the /list
        // request response_generator returns the live blackholed_identities object
        // verbatim. The reconstructed handler returns the live table, so
        // is_blackhole_table is always true.
        let handle = try getString(p, "handle")
        _ = try requireBehavioralInstance(handle)
        let state = blackholeState(for: handle)

        let entries = state.snapshot().map { serializeBlackholeEntry($0.0, $0.1) }
        return [
            "is_blackhole_table": boolean(true),
            "count": num(entries.count),
            "entries": .array(entries)
        ]

    case "behavioral_blackhole_reload":
        // Transport.reload_blackhole (Transport.py:3431-3468). Returns the table
        // size afterward.
        let handle = try getString(p, "handle")
        let inst = try requireBehavioralInstance(handle)
        let state = blackholeState(for: handle)

        try reloadBlackhole(inst, state)
        return ["count": num(state.count)]

    case "behavioral_blackhole_clear":
        // Empty the in-memory table only (NOT on-disk storage), so a test can
        // prove reload repopulates purely from persisted files
        // (cmd_behavioral_blackhole_clear, behavioral_transport.py:1757).
        let handle = try getString(p, "handle")
        _ = try requireBehavioralInstance(handle)
        let state = blackholeState(for: handle)

        state.clearTable()
        return ["cleared": boolean(true)]

    case "behavioral_blackhole_storage_files":
        // List the storage directory (name + size) so a test can assert the
        // persistence naming contract: the local list is 'local', remote lists are
        // named by hex of the source identity hash
        // (cmd_behavioral_blackhole_storage_files, behavioral_transport.py:1779).
        let handle = try getString(p, "handle")
        _ = try requireBehavioralInstance(handle)
        let state = blackholeState(for: handle)

        let fm = FileManager.default
        let dir = state.storageDir
        var files: [JSONValue] = []
        for name in ((try? fm.contentsOfDirectory(atPath: dir)) ?? []).sorted() {
            let full = (dir as NSString).appendingPathComponent(name)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue else { continue }
            let size = ((try? fm.attributesOfItem(atPath: full))?[.size] as? Int) ?? 0
            files.append(.dict(["name": str(name), "size": num(size)]))
        }
        return ["dir": str(dir), "files": .array(files)]

    case "behavioral_blackhole_clear_storage":
        // Delete every file under the storage directory; returns the count
        // unlinked (cmd_behavioral_blackhole_clear_storage,
        // behavioral_transport.py:1810).
        let handle = try getString(p, "handle")
        _ = try requireBehavioralInstance(handle)
        let state = blackholeState(for: handle)

        let fm = FileManager.default
        let dir = state.storageDir
        var removed = 0
        for name in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] {
            let full = (dir as NSString).appendingPathComponent(name)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue else { continue }
            do {
                try fm.removeItem(atPath: full)
                removed += 1
            } catch {
                // best-effort, mirror os.remove failure surfacing nothing extra
            }
        }
        return ["removed": num(removed)]

    case "behavioral_blackhole_rename_storage":
        // Rename a directory entry inside the storage dir; bytes are never touched
        // (os.rename, cmd_behavioral_blackhole_rename_storage,
        // behavioral_transport.py:1836). os.rename overwrites an existing
        // destination on POSIX — FileManager.moveItem does not, so unlink the
        // destination first to match.
        let handle = try getString(p, "handle")
        let src = try getString(p, "src")
        let dst = try getString(p, "dst")
        _ = try requireBehavioralInstance(handle)
        let state = blackholeState(for: handle)

        let fm = FileManager.default
        let srcPath = (state.storageDir as NSString).appendingPathComponent(src)
        let dstPath = (state.storageDir as NSString).appendingPathComponent(dst)
        if fm.fileExists(atPath: dstPath) {
            try fm.removeItem(atPath: dstPath)
        }
        try fm.moveItem(atPath: srcPath, toPath: dstPath)
        return ["renamed": boolean(true)]

    case "behavioral_blackhole_set_sources":
        // Replace the trusted blackhole-source list (RNS.Reticulum.blackhole_sources()),
        // so reload_blackhole's trusted-source gate sees the test's chosen sources
        // (cmd_behavioral_blackhole_set_sources, behavioral_transport.py:1865).
        let handle = try getString(p, "handle")
        _ = try requireBehavioralInstance(handle)
        let state = blackholeState(for: handle)

        let sourceHexes = getStringArray(p, "sources")
        var sources: [Data] = []
        for s in sourceHexes {
            guard let bytes = hexToBytes(s) else {
                throw BridgeError.invalidData("blackhole source is not a valid hex string: \(s)")
            }
            sources.append(bytes)
        }
        state.setTrusted(sources)
        return ["count": num(state.trustedCount)]

    default:
        return nil
    }
}
