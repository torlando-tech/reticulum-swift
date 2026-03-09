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
