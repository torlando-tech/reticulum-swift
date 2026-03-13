import Foundation
import ReticulumSwift

// MARK: - Stderr JSON Emitter

func emit(_ dict: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: dict),
          let line = String(data: data, encoding: .utf8) else { return }
    FileHandle.standardError.write(Data((line + "\n").utf8))
}

func hexString(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func dataFromHex(_ hex: String) -> Data? {
    var data = Data()
    var hex = hex
    while hex.count >= 2 {
        let pair = String(hex.prefix(2))
        hex = String(hex.dropFirst(2))
        guard let byte = UInt8(pair, radix: 16) else { return nil }
        data.append(byte)
    }
    return hex.isEmpty ? data : nil
}

func parseMode(_ str: String) -> InterfaceMode {
    switch str.lowercased() {
    case "ap", "access_point": return .accessPoint
    case "roaming": return .roaming
    case "boundary": return .boundary
    case "gateway": return .gateway
    case "p2p", "point_to_point": return .pointToPoint
    default: return .full
    }
}

// MARK: - IFAC Key Derivation (matches Python Reticulum._add_interface)

func deriveIFACKey(passphrase: String?, netname: String?) -> Data? {
    guard passphrase != nil || netname != nil else { return nil }

    // Python: ifac_origin = full_hash(netname) + full_hash(netkey/passphrase)
    var ifacOrigin = Data()
    if let netname = netname {
        ifacOrigin.append(Hashing.fullHash(Data(netname.utf8)))
    }
    if let passphrase = passphrase {
        ifacOrigin.append(Hashing.fullHash(Data(passphrase.utf8)))
    }

    // Python: ifac_origin_hash = full_hash(ifac_origin)
    let ifacOriginHash = Hashing.fullHash(ifacOrigin)

    // Python: ifac_key = hkdf(length=64, derive_from=ifac_origin_hash, salt=IFAC_SALT)
    return KeyDerivation.deriveKey(
        length: 64,
        inputKeyMaterial: ifacOriginHash,
        salt: TransportConstants.IFAC_SALT
    )
}

// MARK: - Main

let env = ProcessInfo.processInfo.environment
let action = env["PIPE_PEER_ACTION"] ?? "announce"
let appName = env["PIPE_PEER_APP_NAME"] ?? "pipetest"
let aspectsStr = env["PIPE_PEER_ASPECTS"] ?? "routing"
let aspects = aspectsStr.split(separator: ",").map(String.init)
let enableTransport = env["PIPE_PEER_TRANSPORT"]?.lowercased() == "true"
let modeStr = env["PIPE_PEER_MODE"] ?? "full"
let ifacPassphrase = env["PIPE_PEER_IFAC_PASSPHRASE"]
let ifacNetname = env["PIPE_PEER_IFAC_NETNAME"]
let numIfaces = Int(env["PIPE_PEER_NUM_IFACES"] ?? "0") ?? 0

let mode = parseMode(modeStr)

// Derive IFAC key if configured
let ifacKey = deriveIFACKey(passphrase: ifacPassphrase, netname: ifacNetname)
let ifacSize = ifacKey != nil ? TransportConstants.DEFAULT_IFAC_SIZE : 0

// Create transport
let transport = ReticulumTransport()

Task {
    do {
        if numIfaces > 0 {
            // Multi-interface mode: create N interfaces from fd pairs
            for i in 0..<numIfaces {
                guard let fdInStr = env["PIPE_PEER_IFACE_\(i)_FD_IN"],
                      let fdOutStr = env["PIPE_PEER_IFACE_\(i)_FD_OUT"],
                      let fdIn = Int32(fdInStr),
                      let fdOut = Int32(fdOutStr) else {
                    emit(["type": "error", "message": "Missing fd env for interface \(i)"])
                    return
                }
                let ifaceMode = parseMode(env["PIPE_PEER_IFACE_\(i)_MODE"] ?? modeStr)
                let inputHandle = FileHandle(fileDescriptor: fdIn, closeOnDealloc: true)
                let outputHandle = FileHandle(fileDescriptor: fdOut, closeOnDealloc: true)

                let pipeIface = PipeInterface(
                    id: "pipe\(i)",
                    name: "Pipe\(i)",
                    mode: ifaceMode,
                    inputHandle: inputHandle,
                    outputHandle: outputHandle,
                    ifacSize: ifacSize,
                    ifacKey: ifacKey
                )
                try await transport.addInterface(pipeIface)
            }
        } else {
            // Single interface mode: stdin/stdout
            let pipeInterface = PipeInterface(
                id: "pipe",
                name: "StdioPipe",
                mode: mode,
                inputHandle: .standardInput,
                outputHandle: .standardOutput,
                ifacSize: ifacSize,
                ifacKey: ifacKey
            )
            try await transport.addInterface(pipeInterface)
        }

        if enableTransport {
            await transport.setTransportEnabled(true)
        }

        // Register path request handler for transport nodes and destination_only
        // (needed to respond to path requests for local destinations)
        if enableTransport || action == "destination_only" {
            await transport.registerPathRequestHandler()
        }

        emit(["type": "ready", "identity_hash": ""])

        switch action {
        case "announce":
            let identity = Identity()
            let destination = Destination(
                identity: identity,
                appName: appName,
                aspects: aspects,
                type: .single,
                direction: .in
            )
            await transport.registerDestination(destination)

            let announce = Announce(destination: destination)
            let packet = try announce.buildPacket()
            try await transport.send(packet: packet)

            emit([
                "type": "announced",
                "destination_hash": hexString(destination.hash),
                "identity_hash": hexString(identity.hash),
                "identity_public_key": hexString(identity.publicKeys),
            ])

        case "listen":
            break

        case "destination_only":
            // Create destination but do NOT announce it.
            // When a path request arrives for this destination, Swift's
            // handlePathRequest auto-responds with an announce (same as Python).
            let identity = Identity()
            let destination = Destination(
                identity: identity,
                appName: appName,
                aspects: aspects,
                type: .single,
                direction: .in
            )
            await transport.registerDestination(destination)

            emit([
                "type": "destination_created",
                "destination_hash": hexString(destination.hash),
                "identity_hash": hexString(identity.hash),
                "identity_public_key": hexString(identity.publicKeys),
            ])

            // Write hash to output file if specified
            if let hashOutputFile = env["PIPE_PEER_HASH_OUTPUT_FILE"], !hashOutputFile.isEmpty {
                try hexString(destination.hash).write(
                    toFile: hashOutputFile, atomically: true, encoding: .utf8
                )
            }

        case "path_request":
            // Send a path request for a specific destination hash.
            var destHashHex = env["PIPE_PEER_PATH_REQUEST_DEST"] ?? ""

            if destHashHex.isEmpty {
                // Poll a file for the destination hash
                let destFile = env["PIPE_PEER_PATH_REQUEST_DEST_FILE"] ?? ""
                if !destFile.isEmpty {
                    emit(["type": "waiting_for_dest_file", "file": destFile])
                    let deadline = Date().addingTimeInterval(30)
                    while Date() < deadline {
                        if FileManager.default.fileExists(atPath: destFile),
                           let contents = try? String(contentsOfFile: destFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
                           !contents.isEmpty {
                            destHashHex = contents
                            break
                        }
                        try await Task.sleep(nanoseconds: 500_000_000)
                    }
                }
            }

            guard !destHashHex.isEmpty,
                  let destHash = dataFromHex(destHashHex) else {
                emit(["type": "error", "message": "No destination hash (set PIPE_PEER_PATH_REQUEST_DEST or PIPE_PEER_PATH_REQUEST_DEST_FILE)"])
                break
            }

            emit(["type": "path_request_queued", "destination_hash": destHashHex])

            // Wait a moment for the pipe to be fully connected
            try await Task.sleep(nanoseconds: 1_000_000_000)

            // Send the path request and wait for result
            let found = await transport.awaitPath(for: destHash, timeout: 20.0)

            if found {
                let pathTable = await transport.getPathTable()
                let entry = await pathTable.lookup(destinationHash: destHash)
                emit([
                    "type": "path_discovered",
                    "destination_hash": destHashHex,
                    "hops": entry.map { Int($0.hopCount) } ?? -1,
                ])
            } else {
                emit([
                    "type": "path_not_found",
                    "destination_hash": destHashHex,
                ])
            }

        default:
            emit(["type": "error", "message": "Unknown action: \(action)"])
        }

        // Keep alive — path table dumper + announce detection
        var knownDestinations = Set<Data>()
        while !Task.isCancelled {
            try await Task.sleep(nanoseconds: 1_000_000_000)

            // Poll path table for changes
            let pathTable = await transport.getPathTable()
            let entries = await pathTable.allEntries()

            // Detect new announces
            for entry in entries {
                if !knownDestinations.contains(entry.destinationHash) {
                    knownDestinations.insert(entry.destinationHash)
                    emit([
                        "type": "announce_received",
                        "destination_hash": hexString(entry.destinationHash),
                        "identity_hash": hexString(Hashing.truncatedHash(entry.publicKeys)),
                        "hops": Int(entry.hopCount),
                    ])
                }
            }

            // Emit path table snapshot
            let tableEntries: [[String: Any]] = entries.map { entry in
                var dict: [String: Any] = [
                    "destination_hash": hexString(entry.destinationHash),
                    "hops": Int(entry.hopCount),
                    "expired": entry.isExpired,
                ]
                if let nextHop = entry.nextHop {
                    dict["next_hop"] = hexString(nextHop)
                } else {
                    dict["next_hop"] = NSNull()
                }
                return dict
            }
            if !tableEntries.isEmpty {
                emit([
                    "type": "path_table",
                    "entries": tableEntries,
                ])
            }
        }
    } catch {
        emit(["type": "error", "message": error.localizedDescription])
    }
}

dispatchMain()
