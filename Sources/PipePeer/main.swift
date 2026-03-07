import Foundation
import ReticulumSwift

// MARK: - Stderr JSON Emitter

func emit(_ dict: [String: String]) {
    guard let data = try? JSONSerialization.data(withJSONObject: dict),
          let line = String(data: data, encoding: .utf8) else { return }
    FileHandle.standardError.write(Data((line + "\n").utf8))
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

let mode: InterfaceMode = {
    switch modeStr.lowercased() {
    case "ap", "access_point": return .accessPoint
    case "roaming": return .roaming
    case "boundary": return .boundary
    default: return .full
    }
}()

// Derive IFAC key if configured
let ifacKey = deriveIFACKey(passphrase: ifacPassphrase, netname: ifacNetname)
let ifacSize = ifacKey != nil ? TransportConstants.DEFAULT_IFAC_SIZE : 0

// Create transport
let transport = ReticulumTransport()

// Create pipe interface
let pipeInterface = PipeInterface(
    id: "pipe",
    name: "StdioPipe",
    mode: mode,
    inputHandle: .standardInput,
    outputHandle: .standardOutput,
    ifacSize: ifacSize,
    ifacKey: ifacKey
)

Task {
    do {
        try await transport.addInterface(pipeInterface)

        if enableTransport {
            await transport.setTransportEnabled(true)
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
                "destination_hash": destination.hash.map { String(format: "%02x", $0) }.joined(),
                "identity_hash": identity.hash.map { String(format: "%02x", $0) }.joined()
            ])

        case "listen":
            break

        default:
            emit(["type": "error", "message": "Unknown action: \(action)"])
        }

        // Keep alive — path table dumper
        while !Task.isCancelled {
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
    } catch {
        emit(["type": "error", "message": error.localizedDescription])
    }
}

dispatchMain()
