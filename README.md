# ReticulumSwift

[![CI](https://github.com/torlando-tech/reticulum-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/torlando-tech/reticulum-swift/actions/workflows/ci.yml)
[![Conformance](https://github.com/torlando-tech/reticulum-swift/actions/workflows/conformance.yml/badge.svg)](https://github.com/torlando-tech/reticulum-swift/actions/workflows/conformance.yml)

A Swift implementation of the [Reticulum](https://reticulum.network) cryptographic networking stack. Provides encrypted, identity-based peer-to-peer communication over TCP, BLE, AutoInterface, and RNode radio interfaces.

Designed for interoperability with the [Python reference implementation](https://github.com/markqvist/Reticulum).

## Implementation Status

Comparison with [Python RNS](https://github.com/markqvist/Reticulum) reference implementation. Interoperability is validated by automated tests against the Python reference.

### Core Protocol

| Component | Status | Notes |
|-----------|--------|-------|
| Identity | Complete | X25519/Ed25519 via CryptoKit, ratchets, Keychain persistence |
| Destination | Complete | All types (SINGLE, GROUP, PLAIN, LINK), announce name hashing |
| Packet | Complete | Full wire format, HEADER_1/HEADER_2, context byte |
| Transport | ~95% | Routing, path management, announces, announce caching, link management, IFAC, mode-based filtering. Held announces and cache requests stubbed (low priority for iOS) |
| Link | Complete | Establishment, ECDH encryption, channels, resources, request/response, MTU discovery, identification |
| Channel | Complete | Windowed flow control, ordered delivery, retransmission, message type registry |
| Buffer | Complete | Stream I/O over channels |
| Resource | Complete | Chunked transfer, BZ2 compression, progress tracking, hashmap integrity |
| Crypto | Complete | CryptoKit + CryptoSwift: X25519, Ed25519, HKDF, AES-256-CBC, HMAC-SHA256, SHA-256/512, Token |

### Interfaces

| Interface | Status | Notes |
|-----------|--------|-------|
| TCP Client | Complete | HDLC framing, exponential backoff reconnect, async/await |
| RNode (LoRa) | Complete | Full KISS protocol, firmware checking, radio config, flow control |
| BLE Mesh | Complete | Dual-role GATT via CoreBluetooth, identity handshake, fragmentation, peer scoring |
| Auto | Complete | IPv6 multicast peer discovery, per-peer UDP connections |
| Multipeer Connectivity | Complete | Apple MPC for peer-to-peer WiFi without infrastructure |
| Pipe | Complete | HDLC-framed stdin/stdout transport for testing and IPC |
| KISS Framing | Complete | Used by RNode interface |
| HDLC Framing | Complete | Used by TCP and Pipe interfaces |
| TCP Server | Not implemented | Client/relay mode only |
| UDP | Not implemented | AutoInterface covers LAN discovery; standalone UDP not needed |
| Local (Shared Instance) | Not implemented | No inter-app IPC interface |
| I2P | Not implemented | |
| Serial | Not implemented | RNode covers most serial use cases |

### Testing

| Component | Status | Notes |
|-----------|--------|-------|
| Unit/integration tests | 421 methods | Across 34 test files |
| Python interop tests | 79 methods | JSON bridge to Python RNS reference |
| Conformance suite | CI workflow | Runs pytest against Python RNS weekly and on PRs |
| ConformanceBridge | 89 commands | JSON RPC bridge covering crypto, framing, IFAC, announces, packets |

### Remaining Work

Features that exist in the Python reference but are not yet implemented:

| Feature | Priority | Description |
|---------|----------|-------------|
| Request handlers | Medium | Server-side request handler registration and dispatch (client-side works) |
| Tunnels | Medium | Tunnel synthesis and persistence for transport nodes |
| Interface discovery | Medium | `InterfaceAnnouncer`/`InterfaceDiscovery` for discovering remote interfaces |
| Blackhole system | Medium | Network-wide identity blacklisting (BLE has per-peer blacklist) |
| TCP Server | Low | Accept incoming TCP connections (currently client/relay only) |
| Remote management | Low | Control destinations for remote `/path` and `/status` queries |
| CLI utilities | Low | `rnstatus`, `rnpath`, `rnprobe` equivalents |
| SerialInterface | Low | Direct serial port (RNode covers most use cases) |
| I2PInterface | Low | I2P anonymity network integration |

## Requirements

- Swift 5.9+
- macOS 13+ / iOS 16+

## Installation

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/torlando-tech/reticulum-swift.git", from: "0.1.0"),
]
```

Then add `"ReticulumSwift"` to your target's dependencies.

## Overview

- **Identity** — Ed25519 signing + X25519 key agreement, matching Python RNS identity format
- **Destination** — Addressable network endpoints with configurable packet handling
- **Link** — Encrypted sessions with ECDH key exchange, keepalive, and resource transfers
- **Transport** — Packet routing, path discovery, and announce propagation
- **Interfaces** — TCP, AutoInterface (multicast discovery), BLE mesh, RNode (LoRa), and Multipeer Connectivity transports
- **Resource** — Reliable large data transfer with BZ2 compression and hashmap-based integrity verification

## Usage

```swift
import ReticulumSwift

// Create an identity
let identity = Identity()

// Set up transport and connect
let transport = ReticuLumTransport()
let iface = TCPInterface(name: "tcp0", config: InterfaceConfig(
    address: "my-relay.example.com",
    port: 4242
))
await transport.addInterface(iface)

// Create a destination and announce it
let dest = Destination(identity: identity, direction: .in, type: .single, appName: "myapp", aspects: "echo")
await transport.registerDestination(dest)
await transport.announce(destination: dest)
```

## Acknowledgements
- This work was partially funded by the [Solarkpunk Pioneers Fund](https://solarpunk-pioneers.org)
- K8 and 405nm for generously donating for an iPhone
- [Reticulum](https://reticulum.network), [LXMF](https://github.com/markqvist/LXMF) and [LXST](https://github.com/markqvist/LXST) by Mark Qvist

## License

[MPL-2.0](LICENSE)

Copyright (c) 2026 Torlando Tech LLC
