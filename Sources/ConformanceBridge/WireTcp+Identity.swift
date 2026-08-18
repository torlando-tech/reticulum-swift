// WireTcp+Identity.swift — conformance bridge wire sub-handler cluster: W-IDENTITY (wire_identity_*, wire_ifac_*, wire_get_adopted_ratchet, wire_read_ratchets, wire_reannounce, wire_known_key_validate, wire_group_create)
//
// Ports from reticulum-conformance reference/wire_tcp.py. Shares the global
// wireInstances registry + wireLock + requireInstance()/newHandle() helpers
// (now internal in WireTcp.swift). Returns nil for any command it does not own
// (dispatch chain: handleWireExtensionCommand in Ext+Dispatch.swift).
//
// The ratchet/recall commands now delegate to the real library Identity /
// Destination ratchet+recall APIs (Identity.knownDestinations / knownRatchets
// stores, Destination.latestRatchetId / ratchetInterval / retainedRatchets /
// rotateRatchets). Where the announce-RECEPTION hook that would populate the
// receiver-side stores is not wired into AnnounceHandler, the bridge seeds the
// store from the announce-populated transport path table (PathEntry.publicKeys /
// .ratchet / .appData) via the real Identity.remember — additive, never replacing
// the library's own machinery. The IFAC Ed25519 sign is still rebuilt from the
// interface's ifac_key. See per-case comments + the structured libraryGaps.
import CryptoKit
import Foundation
import ReticulumSwift

func handleWireIdentityCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // MARK: wire_identity_keypair

    case "wire_identity_keypair":
        // Pure crypto (no started wire instance). RNS.Identity() →
        // get_private_key()/get_public_key()/hash. Swift Identity.exportPrivateKeys()
        // returns enc_priv(32)||sig_priv(32) (== RNS get_private_key); publicKeys
        // returns enc_pub(32)||sig_pub(32) (== RNS get_public_key); hash is the
        // 16-byte truncated identity hash.
        let identity = Identity()
        let priv = try identity.exportPrivateKeys()
        return [
            "private_key": hex(priv),
            "public_key": hex(identity.publicKeys),
            "hash": hex(identity.hash),
        ]

    // MARK: wire_ratchet_keypair

    case "wire_ratchet_keypair":
        // RNS reference cmd_wire_ratchet_keypair (wire_tcp.py:5246-5258): a fresh
        // X25519 ratchet keypair. public_key feeds wire_identity_encrypt(ratchet_pub=),
        // private_key feeds wire_identity_decrypt(ratchets=[...]). No started instance.
        // RatchetManager.generateRatchet() == RNS.Identity._generate_ratchet()
        // (X25519 private); publicBytes(from:) derives the X25519 public.
        let ratchetPriv = RatchetManager.generateRatchet()
        let ratchetPub: Data
        do {
            ratchetPub = try RatchetManager.publicBytes(from: ratchetPriv)
        } catch {
            throw BridgeError.invalidData("wire_ratchet_keypair: public derivation failed: \(error)")
        }
        return [
            "private_key": hex(ratchetPriv),
            "public_key": hex(ratchetPub),
        ]

    // MARK: wire_group_create

    case "wire_group_create":
        let handle = try getString(p, "handle")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let keyHex = getHexOptional(p, "key")
        let inst = try requireInstance(handle)

        // RNS.Destination(None, IN, GROUP, app_name, *aspects): GROUP hash is
        // identity-independent — truncated_hash(name_hash). Swift's
        // Destination.plainHash is byte-identical (name-only hash).
        let destHash = Destination.plainHash(appName: appName, aspects: aspects)

        // create_keys() / load_private_key(): the GROUP key is a symmetric Token
        // key. RNS Destination.create_keys() -> Token.generate_key() defaults to
        // AES_256_CBC == os.urandom(64) (Token.py:53-55), i.e. a 64-byte key
        // (32-byte HMAC signing key + 32-byte AES-256 key), NOT 32. When `key`
        // is supplied we echo it back (load_private_key -> get_private_key
        // round-trips the same bytes); otherwise generate 64 fresh bytes.
        // The key is retained on the WireInstance group store (keyed by the GROUP
        // destination hash hex) so wire_group_encrypt / wire_group_decrypt can
        // back it with the library Token type (AES-256-CBC + HMAC), exactly as
        // Ext+Destination.swift destination_group_encrypt does.
        let key: Data
        if let provided = keyHex, !provided.isEmpty {
            key = provided
        } else {
            key = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        }
        wireLock.lock()
        inst.groupKeys[bytesToHex(destHash)] = key
        wireLock.unlock()
        return [
            "destination_hash": hex(destHash),
            "key": hex(key),
        ]

    // MARK: wire_group_encrypt

    case "wire_group_encrypt":
        // RNS Destination.encrypt() for a GROUP destination -> prv.encrypt() ->
        // Token(key).encrypt() (Destination.py:602-651). Look up the symmetric key
        // by GROUP destination hash, then Token(derivedKey:).encrypt(). Fresh
        // per-message IV (Token.encrypt -> os.urandom) makes repeat ciphertext
        // differ. Mirrors Ext+Destination.swift:303-307 + python cmd_wire_group_encrypt.
        let handle = try getString(p, "handle")
        let destHashHex = try getString(p, "destination_hash")
        let plaintext = try getHex(p, "plaintext")
        let inst = try requireInstance(handle)

        wireLock.lock()
        let groupKey = inst.groupKeys[destHashHex.lowercased()]
        wireLock.unlock()
        guard let keyBytes = groupKey else {
            throw BridgeError.invalidData("No GROUP destination \(destHashHex) on handle \(handle)")
        }
        let token = try Token(derivedKey: keyBytes)
        let ciphertext = try token.encrypt(plaintext)
        return ["ciphertext": hex(ciphertext)]

    // MARK: wire_group_decrypt

    case "wire_group_decrypt":
        // RNS Destination.decrypt() for a GROUP destination -> prv.decrypt() ->
        // Token(key).decrypt(); on Token HMAC auth failure RNS returns None rather
        // than garbage (Destination.py:647-651). Mirror that: Token decrypt success
        // -> {decrypted:true, plaintext}; any TokenError (wrong key -> HMAC verify
        // fails) -> {decrypted:false}. Mirrors python cmd_wire_group_decrypt.
        let handle = try getString(p, "handle")
        let destHashHex = try getString(p, "destination_hash")
        let ciphertext = try getHex(p, "ciphertext")
        let inst = try requireInstance(handle)

        wireLock.lock()
        let groupKey = inst.groupKeys[destHashHex.lowercased()]
        wireLock.unlock()
        guard let keyBytes = groupKey else {
            throw BridgeError.invalidData("No GROUP destination \(destHashHex) on handle \(handle)")
        }
        let token = try Token(derivedKey: keyBytes)
        do {
            let plaintext = try token.decrypt(ciphertext)
            return [
                "decrypted": boolean(true),
                "plaintext": hex(plaintext),
            ]
        } catch is TokenError {
            return ["decrypted": boolean(false)]
        }

    // MARK: wire_ifac_compute

    case "wire_ifac_compute":
        // RNS Transport.transmit IFAC tag: sign(packet_data) with the live
        // interface's ifac_identity, tag = signature[-ifac_size:]. ifac_identity =
        // Identity.from_bytes(ifac_key) → Ed25519 signing seed = ifac_key[32:64]
        // (ReticulumTransport caches exactly this seed). Reproduces the
        // reticulum-kt#29 golden vector via deterministic Ed25519, not a re-derive.
        let handle = try getString(p, "handle")
        let packetData = try getHex(p, "packet_data")
        let sizeOverride = getIntOptional(p, "ifac_size")
        let inst = try requireInstance(handle)

        let (ifacKey, configIfacSize) = try identityClusterIfacConfig(inst)
        let size = sizeOverride ?? configIfacSize
        let signingSeed = Data(ifacKey.suffix(32))
        guard let signature = Ed25519Pure.sign(message: packetData, seed: signingSeed) else {
            throw BridgeError.invalidData("wire_ifac_compute: Ed25519 signing failed")
        }
        let ifacTag = Data(signature.suffix(size))
        return [
            "ifac_key": hex(ifacKey),
            "ifac_size": .int(size),
            "signature": hex(signature),
            "ifac": hex(ifacTag),
        ]

    // MARK: wire_ifac_signature

    case "wire_ifac_signature":
        // RNS Reticulum.py:916: interface.ifac_signature =
        // ifac_identity.sign(full_hash(ifac_key)). full_hash == SHA-256; the
        // signing seed is ifac_key[32:64]. reticulum-swift does not retain a
        // computed ifac_signature on the interface, so rebuild it from the key.
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)

        let (ifacKey, configIfacSize) = try identityClusterIfacConfig(inst)
        let signingSeed = Data(ifacKey.suffix(32))
        let fullHash = Data(SHA256.hash(data: ifacKey))
        guard let ifacSignature = Ed25519Pure.sign(message: fullHash, seed: signingSeed) else {
            throw BridgeError.invalidData("wire_ifac_signature: Ed25519 signing failed")
        }
        return [
            "ifac_signature": hex(ifacSignature),
            "ifac_key": hex(ifacKey),
            "ifac_size": .int(configIfacSize),
            // TCPServerInterface/TCPInterface DEFAULT_IFAC_SIZE == 16
            // (RNS Interfaces/TCPInterface.py:77). reticulum-swift has no
            // per-type DEFAULT_IFAC_SIZE constant; both wire roles are TCP.
            "default_ifac_size": .int(16),
        ]

    // MARK: wire_identity_recall

    case "wire_identity_recall":
        // RNS.Identity.recall(dest_hash[, from_identity_hash]) resolves an
        // announcing peer's Identity from the receiver's announce-populated
        // known_destinations table — refreshed IN PLACE on EVERY validated announce
        // (Identity.remember, Identity.py:591/108-113). Source the identity AND its
        // last-heard app_data from the library Identity.recall / Identity.recallAppData
        // store (now populated by AnnounceHandler) rather than the transport PathEntry,
        // whose freshness gate rejects a same-second re-announce and would pin app_data
        // to the first value (tests/wire/test_identity_v2.py::test_reannounce_refreshes_*).
        let handle = try getString(p, "handle")
        let targetHash = try getHex(p, "destination_hash")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 0
        let fromIdentityHash = getBoolOptional(p, "from_identity_hash") ?? false
        let inst = try requireInstance(handle)

        if fromIdentityHash {
            // recall(..., from_identity_hash=True): match truncated_hash(public_key)
            // (== Identity.hash) over known_destinations; no path poll (has_path keys
            // on destination hashes). app_data rides on the recalled identity
            // (Identity.recall sets id.appData, Identity.py:128-141).
            if let id = Identity.recall(targetHash, fromIdentityHash: true) {
                return identityClusterRecallResult(id: id, appData: id.appData)
            }
            return ["found": boolean(false), "app_data": .null]
        }

        // Destination-hash recall: poll until the announce lands or the deadline
        // passes (mirrors python's recall-in-a-loop). recall reads the in-place-
        // updated known_destinations entry, and recallAppData returns the same
        // last-heard app_data (Identity.py:162-174).
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while true {
            if let id = Identity.recall(targetHash) {
                let appData = Identity.recallAppData(targetHash) ?? id.appData
                return identityClusterRecallResult(id: id, appData: appData)
            }
            if Date() >= deadline { break }
            Thread.sleep(forTimeInterval: 0.05)
        }

        // RNS.Identity.recall Transport.destinations fallback (Identity.py:151-159):
        // a hash absent from the announce-populated table but matching a LOCALLY-
        // registered destination resolves to THAT destination's own identity, with
        // app_data None. An instance never receives its own announces, so its own
        // registered destination is never in the path table — this fallback is the
        // ONLY path by which recall of one's own destination hash resolves (LXMF
        // source resolution on the announcing node relies on it).
        for (id, dest) in inst.destinations where dest.hash == targetHash {
            return identityClusterRecallResult(id: id, appData: nil)
        }
        return ["found": boolean(false), "app_data": .null]

    // MARK: wire_get_adopted_ratchet

    case "wire_get_adopted_ratchet":
        // RNS reference cmd_wire_get_adopted_ratchet (wire_tcp.py:5829-5853):
        // Identity.get_ratchet(dest_hash) -> the ratchet PUBLIC key this peer
        // ADOPTED after hearing the remote's ratcheted announce; ratchet_id =
        // _get_ratchet_id = SHA-256(pub)[:NAME_HASH_LENGTH//8] (Identity.py:409-411).
        //
        // Primary source is the new library Identity.knownRatchets store
        // (Identity.getRatchet). The announce-RECEPTION hook that would populate
        // that store is not wired into AnnounceHandler, and on a separate-process
        // receiver the remote's self-remember never reaches us, so fall back to the
        // announce-populated PathEntry.ratchet (AnnounceHandler stores parsed.ratchet)
        // — the same 32-byte adopted public key. See port-deviations.md / libraryGaps.
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)

        var adoptedPub = Identity.getRatchet(destHash)
        if adoptedPub == nil || adoptedPub?.count != Identity.RATCHETSIZE_BYTES {
            let entry: PathEntry? = try blockingAsync { await inst.transport.pathEntry(for: destHash) }
            if let pe = entry?.ratchet, pe.count == Identity.RATCHETSIZE_BYTES {
                adoptedPub = pe
            }
        }
        guard let ratchetPub = adoptedPub, ratchetPub.count == Identity.RATCHETSIZE_BYTES else {
            return ["found": boolean(false), "ratchet_public": .null, "ratchet_id": .null]
        }
        // Identity._getRatchetId == SHA-256(pub)[:10] (Identity.py:409-411).
        let ratchetId = Identity._getRatchetId(ratchetPub)
        return [
            "found": boolean(true),
            "ratchet_public": hex(ratchetPub),
            "ratchet_id": hex(ratchetId),
        ]

    // MARK: wire_read_ratchets

    case "wire_read_ratchets":
        // Snapshot a ratchet-enabled LOCAL destination's ratchet state
        // (Destination.ratchets / latest_ratchet_id, Destination.py:227-241).
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)

        guard let destination = identityClusterFindDestination(inst, destHash) else {
            throw BridgeError.invalidData(
                "No registered destination with hash \(bytesToHex(destHash)) on "
                + "handle \(handle); call wire_announce(enable_ratchets=True) first."
            )
        }
        guard destination.ratchetsEnabled, let rm = destination.ratchetManager else {
            throw BridgeError.invalidData(
                "Destination \(bytesToHex(destHash)) does not have ratchets enabled; "
                + "call wire_announce(enable_ratchets=True)."
            )
        }
        let ratchetCount: Int = try blockingAsync { await rm.count() }
        let currentId: Data? = try blockingAsync { await rm.ratchetId() }
        // previous_ratchet_id == _get_ratchet_id(ratchets[1]) (wire_tcp.py:5381-5388).
        let previousPub: Data? = try blockingAsync { await rm.previousRatchetPublicBytes() }
        let previousId: Data? = previousPub.map { Identity._getRatchetId($0) }
        // latest_ratchet_time == Destination.latest_ratchet_time (wire_tcp.py:5422).
        let latestTime: TimeInterval = try blockingAsync { await rm.latestTime() }
        // latest_ratchet_id is set only by a real Destination.encrypt/decrypt
        // (Destination.latestRatchetId via RatchetIdReceiver, Destination.py:587-599).
        let latestRatchetId = destination.latestRatchetId
        return [
            "ratchet_count": .int(ratchetCount),
            "current_ratchet_id": currentId != nil ? hex(currentId!) : .null,
            "previous_ratchet_id": previousId != nil ? hex(previousId!) : .null,
            // Per-destination ratchet_interval / retained_ratchets, now real
            // (RNS Destination.set_ratchet_interval / set_retained_ratchets,
            // Destination.py:519-531 / :504-517).
            "ratchet_interval": .int(destination.ratchetInterval),
            "retained_ratchets": .int(destination.retainedRatchets),
            "latest_ratchet_id": latestRatchetId != nil ? hex(latestRatchetId!) : .null,
            "latest_ratchet_time": .double(latestTime),
        ]

    // MARK: wire_reannounce

    case "wire_reannounce":
        // Re-announce an already-registered IN destination (RNS.Destination.announce,
        // Destination.py:265-311). For a ratchet-enabled destination, backdate the
        // rotation clock (rotate_ago_s) so rotate_ratchets opens the interval gate
        // and the announce carries a genuinely new ratchet public key.
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let appData = getHexOptional(p, "app_data")
        let rotateAgoS: Double? = p["rotate_ago_s"]?.doubleValue
        let inst = try requireInstance(handle)

        guard let destination = identityClusterFindDestination(inst, destHash) else {
            throw BridgeError.invalidData(
                "No registered destination with hash \(bytesToHex(destHash)) on handle \(handle)."
            )
        }
        if let rotate = rotateAgoS, let rm = destination.ratchetManager {
            // Backdate the rotation clock, then rotate via the real library
            // Destination.rotateRatchets — it honors the per-destination interval
            // and re-remembers the new current ratchet (Destination.py:227-241,:286),
            // keeping encrypt()'s Identity.getRatchet(self.hash) selection in sync.
            try blockingAsync {
                await rm._setLatestRatchetTime(Date().timeIntervalSince1970 - rotate)
                _ = await destination.rotateRatchets()
            }
        }
        let ratchetPub: Data? = try blockingAsync {
            await destination.ratchetManager?.currentRatchetPublicBytes()
        }
        let announceAppData: Data? = (appData?.isEmpty == false) ? appData : nil
        let announce = Announce(destination: destination, appData: announceAppData, ratchet: ratchetPub)
        let packet: Packet
        do {
            packet = try announce.buildPacket()
        } catch {
            throw BridgeError.invalidData("wire_reannounce buildPacket failed: \(error)")
        }
        try blockingAsync {
            await inst.transport.registerDestination(destination)
            try await inst.transport.send(packet: packet)
        }
        let currentRatchetId: Data? = try blockingAsync {
            await destination.ratchetManager?.ratchetId()
        }
        return [
            "announced": boolean(true),
            "current_ratchet_id": currentRatchetId != nil ? hex(currentRatchetId!) : .null,
        ]

    // MARK: wire_known_key_validate

    case "wire_known_key_validate":
        // Identity.validate_announce known-key guard (Identity.py:583-589): an
        // otherwise-valid announce is REJECTED when its destination hash is already
        // bound to a DIFFERENT public key (anti-path-hijack). Build a genuine
        // SINGLE destination + signed announce, verify its signature, then apply
        // the stored-key consistency check by `plant`.
        let handle = try getString(p, "handle")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let plant = (getStringOptional(p, "plant") ?? "mismatch").lowercased()
        guard plant == "mismatch" || plant == "match" || plant == "none" else {
            throw BridgeError.invalidData(
                "plant must be 'mismatch', 'match' or 'none' (got \(plant))"
            )
        }
        let appData = getHexOptional(p, "app_data")
        _ = try requireInstance(handle)

        let identity = Identity()
        let destination = Destination(
            identity: identity, appName: appName, aspects: aspects,
            type: .single, direction: .in
        )
        let realPub = identity.publicKeys
        let destHash = destination.hash

        // Build a genuine signed announce; verify its signature (always valid for
        // a self-built announce — the discriminator is solely the planted key).
        let announceAppData: Data? = (appData?.isEmpty == false) ? appData : nil
        let announce = Announce(destination: destination, appData: announceAppData)
        let packet: Packet
        do {
            packet = try announce.buildPacket()
        } catch {
            throw BridgeError.invalidData("wire_known_key_validate buildPacket failed: \(error)")
        }
        var signatureValid = false
        if let parsed = try? AnnounceValidator.parse(packet: packet) {
            signatureValid = ((try? AnnounceValidator.validate(parsed: parsed)) ?? false)
        }

        var planted: Data? = nil
        if plant == "match" {
            planted = realPub
        } else if plant == "mismatch" {
            planted = Identity().publicKeys  // a different, valid key
        }
        // Stored-key consistency: accept iff signature valid AND (no stored key OR
        // stored key == announced key). A mismatched plant rejects.
        let validated = signatureValid && (planted == nil || planted == realPub)

        return [
            "validated": boolean(validated),
            "destination_hash": hex(destHash),
            "public_key": hex(realPub),
            "planted_public_key": planted != nil ? hex(planted!) : .null,
            "plant": str(plant),
        ]

    // MARK: wire_identity_ratchet_persist

    case "wire_identity_ratchet_persist":
        // RNS reference cmd_wire_identity_ratchet_persist (wire_tcp.py:5618-5707):
        // drive the real Identity-side RECEIVED-ratchet store —
        // Identity.rememberRatchet (atomic <hash>.out -> <hash> write of
        // {ratchet, received}) -> getRatchet (on-disk load, 32-byte RATCHETSIZE//8
        // gate) -> cleanRatchets (not-in-use removal), Identity.py:424-522.
        //
        // A per-call temp storagePath scopes the Identity file store so the on-disk
        // machinery is genuinely exercised without cross-test contamination; it is
        // restored afterwards (so wire_announce/wire_listen enableRatchets stays
        // in-memory only on instances that did not opt into persistence).
        let handle = try getString(p, "handle")
        _ = try requireInstance(handle)

        // TRUNCATED_HASHLENGTH//8 == 16: a random, never-announced dest — absent
        // from knownDestinations, so cleanRatchets' not-in-use branch removes it.
        let destHash = Data((0..<Identity.TRUNCATED_HASHLENGTH_BYTES).map { _ in UInt8.random(in: 0...255) })
        // Identity._generate_ratchet() == 32 genuine X25519 ratchet bytes.
        let ratchet = RatchetManager.generateRatchet()

        let savedStoragePath = Identity.storagePath
        let tmpRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("rns-swift-idratchet-\(UUID().uuidString)", isDirectory: true)
        Identity.storagePath = tmpRoot.path
        defer {
            Identity.storagePath = savedStoragePath
            try? FileManager.default.removeItem(at: tmpRoot)
        }

        let ratchetsDir = tmpRoot.appendingPathComponent("ratchets", isDirectory: true)
        let hexhash = bytesToHex(destHash)
        let finalURL = ratchetsDir.appendingPathComponent(hexhash)
        let outURL = ratchetsDir.appendingPathComponent(hexhash + ".out")

        // _remember_ratchet: in-mem cache + atomic temp <hash>.out -> <hash> write.
        Identity.rememberRatchet(destinationHash: destHash, ratchet: ratchet)
        let fileWritten = FileManager.default.fileExists(atPath: finalURL.path)
        let tmpLeftover = FileManager.default.fileExists(atPath: outURL.path)

        // get_ratchet: read back the stored ratchet (32-byte RATCHETSIZE//8 gate).
        let reloaded = Identity.getRatchet(destHash)
        let reloadMatch = (reloaded == ratchet)
        let reloadedLen = reloaded?.count
        let acceptedSize = Identity.RATCHETSIZE_BYTES  // RNS Identity.RATCHETSIZE // 8 == 32

        // _clean_ratchets not-in-use branch: the dest is never registered, so its
        // file is removed (Identity.py:484-489).
        Identity.cleanRatchets()
        let cleanedRemoved = !FileManager.default.fileExists(atPath: finalURL.path)

        return [
            "dest_hash": hex(destHash),
            "ratchet_len": .int(ratchet.count),
            "file_written": boolean(fileWritten),
            "tmp_leftover": boolean(tmpLeftover),
            "reload_match": boolean(reloadMatch),
            "reloaded_len": reloadedLen != nil ? .int(reloadedLen!) : .null,
            "accepted_size": .int(acceptedSize),
            "cleaned_removed": boolean(cleanedRemoved),
        ]

    // MARK: wire_known_destinations_roundtrip

    case "wire_known_destinations_roundtrip":
        // RNS reference cmd_wire_known_destinations_roundtrip (wire_tcp.py:5710-5773):
        // save -> clear -> reload the on-disk known_destinations table and confirm a
        // previously-known destination round-trips (Identity.saveKnownDestinations /
        // loadKnownDestinations, Identity.py:176-265).
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)

        // save/load need a storagePath. Set a stable process-wide temp root once.
        if Identity.storagePath == nil {
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("rns-swift-knowndests", isDirectory: true)
            try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            Identity.storagePath = root.path
        }

        // The announce-RECEPTION hook (validate_announce -> Identity.remember,
        // Identity.py:520-617) is not wired into AnnounceHandler, so seed the entry
        // from the announce-populated transport path table via the real
        // Identity.remember — the same 5-element record RNS would store. Additive:
        // only when absent (a no-op if a future receive hook already populated it).
        if Identity.knownDestinationEntryLength(destHash) == nil {
            if let entry = try blockingAsync({ await inst.transport.pathEntry(for: destHash) }),
               entry.publicKeys.count == Identity.KEYSIZE_BYTES {
                // packet_hash is stored as entry[1]; not asserted by the test. Use a
                // stable 16-byte synthesis so re-runs are deterministic.
                let synthPacketHash = Data(SHA256.hash(data: destHash).prefix(16))
                try? Identity.remember(
                    packetHash: synthPacketHash,
                    destinationHash: destHash,
                    publicKey: entry.publicKeys,
                    appData: entry.appData
                )
            }
        }

        let presentBefore = Identity.knownDestinationEntryLength(destHash) != nil

        // Persist the whole table to disk through the library serializer.
        _ = Identity.saveKnownDestinations()

        // Clear in-memory; recall must MISS for this received dest (it is not
        // locally registered, so the Transport.destinations fallback can't resolve
        // it) — proving the reload below, not residual memory, restores it.
        Identity.clearKnownDestinations()
        let afterClearFound = Identity.recall(destHash) != nil

        // Reload from disk; recall HITS again with byte-identical app_data.
        _ = Identity.loadKnownDestinations()
        let reloaded = Identity.recall(destHash)
        let reloadFound = reloaded != nil
        let appDataAfter = reloaded?.appData
        let entryLen = Identity.knownDestinationEntryLength(destHash)
        let tableSize = Identity.knownDestinationsCount

        return [
            "present_before_save": boolean(presentBefore),
            "recall_after_clear_found": boolean(afterClearFound),
            "recall_after_load_found": boolean(reloadFound),
            "app_data_after_load": appDataAfter != nil ? hex(appDataAfter!) : .null,
            "entry_len_after_load": entryLen != nil ? .int(entryLen!) : .null,
            "table_size_after_load": .int(tableSize),
        ]

    // MARK: wire_identity_encrypt

    case "wire_identity_encrypt":
        // RNS reference cmd_wire_identity_encrypt (wire_tcp.py:5261-5277): pure
        // crypto, no started instance. Identity(create_keys=False).load_public_key
        // (64-byte enc||sig public key) then encrypt(plaintext[, ratchet=ratchet_pub]).
        // Swift: Identity(publicKeyBytes:) + Identity.encrypt(_:toRatchetKey:identityHash:)
        // / encryptTo(_:identityHash:) (salt = identity.hash == RNS get_salt).
        let publicKey = try getHex(p, "public_key")
        let plaintext = getHexOptional(p, "plaintext") ?? Data()
        let ratchetPub = getHexOptional(p, "ratchet_pub")
        let identity: Identity
        do {
            identity = try Identity(publicKeyBytes: publicKey)
        } catch {
            throw BridgeError.invalidData("wire_identity_encrypt: load_public_key failed: \(error)")
        }
        let ciphertext: Data
        do {
            if let rp = ratchetPub, !rp.isEmpty {
                ciphertext = try Identity.encrypt(plaintext, toRatchetKey: rp, identityHash: identity.hash)
            } else {
                ciphertext = try identity.encryptTo(plaintext, identityHash: identity.hash)
            }
        } catch {
            throw BridgeError.invalidData("wire_identity_encrypt: encrypt failed: \(error)")
        }
        return ["ciphertext": hex(ciphertext)]

    // MARK: wire_identity_decrypt

    case "wire_identity_decrypt":
        // RNS reference cmd_wire_identity_decrypt (wire_tcp.py:5280-5303): pure
        // crypto. Identity.from_bytes(64-byte private key).decrypt(ciphertext,
        // ratchets=[priv...], enforce_ratchets) — returns None on enforce-reject
        // (forward secrecy, Identity.py:897-901) BEFORE the static fallback. Swift:
        // the nil-returning decrypt(_:identityHash:ratchets:enforceRatchets:
        // ratchetIdReceiver:) overload (no receiver needed here).
        let privateKey = try getHex(p, "private_key")
        let ciphertext = try getHex(p, "ciphertext")
        let enforce = getBoolOptional(p, "enforce_ratchets") ?? false
        let ratchetHexes = getStringArray(p, "ratchets")
        let ratchets: [Data]? = ratchetHexes.isEmpty
            ? nil
            : ratchetHexes.compactMap { hexToBytes($0) }
        let identity: Identity
        do {
            identity = try Identity(privateKeyBytes: privateKey)
        } catch {
            throw BridgeError.invalidData("wire_identity_decrypt: from_bytes rejected the private key: \(error)")
        }
        let plaintext = identity.decrypt(
            ciphertext,
            identityHash: identity.hash,
            ratchets: ratchets,
            enforceRatchets: enforce,
            ratchetIdReceiver: nil
        )
        return [
            "plaintext": plaintext != nil ? hex(plaintext!) : .null,
            "decrypted": boolean(plaintext != nil),
        ]

    // MARK: wire_destination_decrypt

    case "wire_destination_decrypt":
        // RNS reference cmd_wire_destination_decrypt (wire_tcp.py:5896-5934): decrypt
        // on a local SINGLE destination, exposing WHICH ratchet (if any) decrypted via
        // latest_ratchet_id. Destination.decrypt passes ratchet_id_receiver=self, so
        // a ratchet hit sets latest_ratchet_id, a static-key decrypt leaves it None
        // (the inbound ratchet-vs-static discriminator). NOT ratchet-enabled-gated —
        // python uses _find_destination_by_hash directly.
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let ciphertext = try getHex(p, "ciphertext")
        let inst = try requireInstance(handle)
        guard let destination = identityClusterFindDestination(inst, destHash) else {
            throw BridgeError.invalidData(
                "No registered destination with hash \(bytesToHex(destHash)) on handle \(handle)."
            )
        }
        // Clear stale tracking so the read-back reflects only this call
        // (Destination.decrypt re-sets it via ratchet_id_receiver).
        destination.latestRatchetId = nil
        let plaintext: Data? = try blockingAsync { await destination.decrypt(ciphertext) }
        let latest = destination.latestRatchetId
        return [
            "decrypted": boolean(plaintext != nil),
            "plaintext": plaintext != nil ? hex(plaintext!) : .null,
            "latest_ratchet_id": latest != nil ? hex(latest!) : .null,
        ]

    // MARK: wire_destination_latest_ratchet_id

    case "wire_destination_latest_ratchet_id":
        // RNS reference cmd_wire_destination_latest_ratchet_id (wire_tcp.py:5776-5817):
        // drive a real Destination.encrypt + Destination.decrypt round trip on a
        // ratchet-enabled SINGLE destination and expose latest_ratchet_id. encrypt()
        // auto-selects the current ratchet and records latest_ratchet_id; decrypt()
        // re-derives it via ratchet_id_receiver=self — both equal the current id when
        // the SINGLE auto-ratchet path tracked a ratchet (Destination.py:595-643).
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let probeParam = getHexOptional(p, "data")
        let probe = (probeParam?.isEmpty == false) ? probeParam! : Data("ratchet-probe".utf8)
        let inst = try requireInstance(handle)
        let destination = try identityClusterRatchetDestOrThrow(inst, destHash, handle)

        let ciphertext: Data
        do {
            ciphertext = try destination.encrypt(probe)
        } catch {
            throw BridgeError.invalidData("wire_destination_latest_ratchet_id: encrypt failed: \(error)")
        }
        let encId = destination.latestRatchetId
        let plaintext: Data? = try blockingAsync { await destination.decrypt(ciphertext) }
        let decId = destination.latestRatchetId
        let currentId: Data? = try blockingAsync { await destination.ratchetManager?.ratchetId() }
        let ratchetCount: Int = try blockingAsync { await destination.ratchetManager?.count() ?? 0 }
        let decrypted = (plaintext == probe)
        let match = (encId != nil && decId != nil && encId == decId)
        return [
            "decrypted": boolean(decrypted),
            "plaintext": plaintext != nil ? hex(plaintext!) : .null,
            "latest_ratchet_id": decId != nil ? hex(decId!) : .null,
            "encrypt_ratchet_id": encId != nil ? hex(encId!) : .null,
            "current_ratchet_id": currentId != nil ? hex(currentId!) : .null,
            "match": boolean(match),
            "ratchet_count": .int(ratchetCount),
        ]

    // MARK: wire_set_ratchet_interval

    case "wire_set_ratchet_interval":
        // RNS reference cmd_wire_set_ratchet_interval (wire_tcp.py:5444-5464):
        // Destination.set_ratchet_interval(int) — ok False for a non-positive value
        // (RNS rejects it, interval unchanged), Destination.py:519-531.
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let seconds = try identityClusterReadIntArg(p, "seconds")
        let inst = try requireInstance(handle)
        let destination = try identityClusterRatchetDestOrThrow(inst, destHash, handle)
        let ok = destination.setRatchetInterval(seconds)
        return ["ok": boolean(ok), "ratchet_interval": .int(destination.ratchetInterval)]

    // MARK: wire_rotate_ratchet

    case "wire_rotate_ratchet":
        // RNS reference cmd_wire_rotate_ratchet (wire_tcp.py:5467-5507): backdate
        // latest_ratchet_time (= now - last_rotation_ago_s) so the rotation-INTERVAL
        // gate (Destination.py:227-241) either opens (ago > interval -> new ratchet,
        // prior current becomes previous) or stays shut (ago < interval -> unchanged),
        // WITHOUT a real wait. rotated = after_count > before_count.
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let lastRotationAgoS: Double? = p["last_rotation_ago_s"]?.doubleValue
        let inst = try requireInstance(handle)
        let destination = try identityClusterRatchetDestOrThrow(inst, destHash, handle)

        let snap: (Int, Int, Data?, Data?, Data?, TimeInterval) = try blockingAsync {
            guard let rm = destination.ratchetManager else {
                return (0, 0, nil, nil, nil, 0)
            }
            if let ago = lastRotationAgoS {
                await rm._setLatestRatchetTime(Date().timeIntervalSince1970 - ago)
            }
            let beforeCount = await rm.count()
            let beforeCurrentPub = await rm.currentRatchetPublicBytes()
            _ = await destination.rotateRatchets()
            let afterCount = await rm.count()
            let currentPub = await rm.currentRatchetPublicBytes()
            let previousPub = await rm.previousRatchetPublicBytes()
            let latestTime = await rm.latestTime()
            return (beforeCount, afterCount, beforeCurrentPub, currentPub, previousPub, latestTime)
        }
        let (beforeCount, afterCount, beforeCurrentPub, currentPub, previousPub, latestTime) = snap
        // ratchet ids == _get_ratchet_id(public) == SHA-256(public)[:10] (Identity.py:409-411).
        let beforeCurrentId = beforeCurrentPub.map { Identity._getRatchetId($0) }
        let currentId = currentPub.map { Identity._getRatchetId($0) }
        let previousId = previousPub.map { Identity._getRatchetId($0) }
        return [
            "rotated": boolean(afterCount > beforeCount),
            "before_count": .int(beforeCount),
            "after_count": .int(afterCount),
            "before_current_id": beforeCurrentId != nil ? hex(beforeCurrentId!) : .null,
            "current_ratchet_id": currentId != nil ? hex(currentId!) : .null,
            "previous_ratchet_id": previousId != nil ? hex(previousId!) : .null,
            "ratchet_interval": .int(destination.ratchetInterval),
            "latest_ratchet_time": .double(latestTime),
        ]

    // MARK: wire_set_retained_ratchets

    case "wire_set_retained_ratchets":
        // RNS reference cmd_wire_set_retained_ratchets (wire_tcp.py:5510-5547):
        // optionally inflate the ratchet list with `pad_to` real freshly-generated
        // ratchets (Identity._generate_ratchet), then set_retained_ratchets(n) — which
        // runs _clean_ratchets, truncating to Destination.RATCHET_COUNT (512) when the
        // list exceeds the cap (Destination.py:504-517/:205-208). ok False for a
        // non-positive n.
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let n = try identityClusterReadIntArg(p, "n")
        let padTo = getIntOptional(p, "pad_to")
        let inst = try requireInstance(handle)
        let destination = try identityClusterRatchetDestOrThrow(inst, destHash, handle)

        let (ok, ratchetCount): (Bool, Int) = try blockingAsync {
            if let pad = padTo {
                await destination.ratchetManager?._padRatchets(to: pad)
            }
            let ok = await destination.setRetainedRatchets(n)
            let count = await destination.ratchetManager?.count() ?? 0
            return (ok, count)
        }
        return [
            "ok": boolean(ok),
            "retained_ratchets": .int(destination.retainedRatchets),
            "ratchet_count": .int(ratchetCount),
            "ratchet_count_cap": .int(RatchetManager.RATCHET_COUNT),
        ]

    // MARK: wire_ratchet_file_roundtrip

    case "wire_ratchet_file_roundtrip":
        // RNS reference cmd_wire_ratchet_file_roundtrip (wire_tcp.py:5550-5615):
        // Destination._persist_ratchets writes the signed on-disk store; clear the
        // in-memory list; Destination._reload_ratchets validates the embedded
        // signature and only repopulates the ratchet list when it verifies (raising
        // otherwise -> reload_ok False), Destination.py:210-225/:426-464. The bridge
        // drives RNS's OWN persist/reload (RatchetManager.persistRatchets /
        // reloadRatchets) — no on-disk format re-parse.
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)
        let destination = try identityClusterRatchetDestOrThrow(inst, destHash, handle)
        guard destination.ratchetManager != nil else {
            throw BridgeError.invalidData(
                "Destination \(bytesToHex(destHash)) has no ratchets_path; ratchets must "
                + "be enabled with a file path (wire_announce enable_ratchets=True)."
            )
        }

        let snap: (Int, [Data], Int, [Data], Bool) = try blockingAsync {
            guard let rm = destination.ratchetManager else { return (0, [], 0, [], false) }
            let beforePrivs = await rm.allRatchetPrivateKeys()
            // Force a fresh signed write to disk.
            try await rm.persistRatchets()
            // Reload from disk; signature-validated (throws -> reload_ok False).
            var reloadOk = true
            do {
                _ = try await rm.reloadRatchets()
            } catch {
                reloadOk = false
            }
            let afterPrivs = await rm.allRatchetPrivateKeys()
            return (beforePrivs.count, beforePrivs, afterPrivs.count, afterPrivs, reloadOk)
        }
        let (countBefore, beforePrivs, countAfter, afterPrivs, reloadOk) = snap
        // ratchet ids == _ratchet_id_hex(private) == _get_ratchet_id(_ratchet_public_bytes(priv)).
        func ratchetIds(_ privs: [Data]) -> [Data] {
            privs.compactMap { try? RatchetManager.publicBytes(from: $0) }.map { Identity._getRatchetId($0) }
        }
        let idsBefore = ratchetIds(beforePrivs)
        let idsAfter = ratchetIds(afterPrivs)
        let roundtripMatch = (idsBefore == idsAfter) && (countBefore == countAfter)
        return [
            "ratchets_path_set": boolean(true),
            "reload_ok": boolean(reloadOk),
            "ratchet_count_before": .int(countBefore),
            "ratchet_count_after": .int(countAfter),
            "roundtrip_match": boolean(roundtripMatch),
            "ratchet_ids": .array(idsAfter.map { hex($0) }),
        ]

    default:
        return nil
    }
}

// MARK: - Cluster-private helpers

/// Read the live IFAC-configured interface's (ifac_key, ifac_size) off the
/// instance. Throws (python RuntimeError parity) when the peer was not started
/// with network_name + passphrase, so no ifac_key was derived.
private func identityClusterIfacConfig(_ inst: WireInstance) throws -> (key: Data, size: Int) {
    let ifacKey: Data?
    let ifacSize: Int
    if let server = inst.serverInterface {
        ifacKey = server.config.ifacKey
        ifacSize = server.config.ifacSize
    } else if let client = inst.clientInterface {
        let cfg: InterfaceConfig = try blockingAsync { await client.config }
        ifacKey = cfg.ifacKey
        ifacSize = cfg.ifacSize
    } else {
        ifacKey = nil
        ifacSize = 0
    }
    guard let key = ifacKey, ifacSize > 0, key.count == 64 else {
        throw BridgeError.invalidData(
            "No IFAC-configured interface on this handle. Start the peer with "
            + "network_name + passphrase so RNS derives an ifac_key."
        )
    }
    return (key, ifacSize)
}

/// Build the recall result dict for a resolved identity, matching python's
/// {found, public_key, hash, app_data} shape (app_data is hex when heard,
/// null when the announce carried none).
private func identityClusterRecallResult(id: Identity, appData: Data?) -> Result {
    return [
        "found": boolean(true),
        "public_key": hex(id.publicKeys),
        "hash": hex(id.hash),
        "app_data": appData != nil ? hex(appData!) : .null,
    ]
}

/// Locate a registered LOCAL destination by hash on the instance
/// (parity with python's _find_destination_by_hash).
private func identityClusterFindDestination(_ inst: WireInstance, _ destHash: Data) -> Destination? {
    for (_, dest) in inst.destinations where dest.hash == destHash {
        return dest
    }
    return nil
}

/// Locate a ratchet-ENABLED SINGLE destination by hash, or throw (parity with
/// python's _ratchet_dest_or_raise, wire_tcp.py:5391-5408): the destination must
/// have been created with wire_announce/listen enable_ratchets=True (so
/// `destination.ratchets` is a list, not None).
private func identityClusterRatchetDestOrThrow(
    _ inst: WireInstance, _ destHash: Data, _ handle: String
) throws -> Destination {
    guard let destination = identityClusterFindDestination(inst, destHash) else {
        throw BridgeError.invalidData(
            "No registered destination with hash \(bytesToHex(destHash)) on "
            + "handle \(handle); call wire_announce(enable_ratchets=True) first."
        )
    }
    guard destination.ratchetsEnabled, destination.ratchetManager != nil else {
        throw BridgeError.invalidData(
            "Destination \(bytesToHex(destHash)) does not have ratchets enabled; "
            + "call wire_announce(enable_ratchets=True)."
        )
    }
    return destination
}

/// Read an integer command arg that python forwards as an int but may arrive as
/// a JSON int or float (python coerces non-positive values through as-is so the
/// library rejection stays observable). Throws when the key is absent.
private func identityClusterReadIntArg(_ p: [String: JSONValue], _ key: String) throws -> Int {
    if let i = p[key]?.intValue { return i }
    if let d = p[key]?.doubleValue { return Int(d) }
    throw BridgeError.missingParam(key)
}
