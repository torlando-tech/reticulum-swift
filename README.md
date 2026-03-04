# ReticulumSwift

A Swift implementation of the [Reticulum](https://reticulum.network) cryptographic networking stack. Provides encrypted, identity-based peer-to-peer communication over TCP, BLE, AutoInterface, and RNode radio interfaces.

Designed for interoperability with the [Python reference implementation](https://github.com/markqvist/Reticulum).

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
- **Interfaces** — TCP, AutoInterface (multicast discovery), BLE, and RNode (LoRa) transports
- **Resource** — Reliable large data transfer with hashmap-based integrity verification

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
