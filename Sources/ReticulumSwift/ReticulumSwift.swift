// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ReticulumSwift.swift
//  ReticulumSwift
//
//  Main entry point for the ReticulumSwift library.
//  Re-exports all public API types for convenient import.
//
//  This package provides the core Reticulum network stack for Swift applications,
//  enabling encrypted peer-to-peer communication over various transports.
//

import Foundation

// MARK: - Module Information

/// ReticulumSwift library version
public let ReticulumSwiftVersion = "1.0.0"

/// Protocol version matching Python RNS
public let ReticulumProtocolVersion = "0.8.0"

// MARK: - Public API Overview
//
// The following types are publicly exported:
//
// Crypto:
// - Identity: Cryptographic identity with Ed25519 signing and X25519 encryption
// - Destination: Addressable endpoint in the Reticulum network
// - Hashing: SHA-256 hashing utilities
// - KeyDerivation: HKDF key derivation
// - Token: AES-256-CBC encryption with HMAC-SHA256
//
// Protocol:
// - Packet: Network packet structure
// - PacketHeader: Packet header parsing
// - HDLC: Frame encoding/decoding
// - Announce: Identity announcement
// - AnnounceValidator: Announce verification
// - MessagePack: Binary encoding
// - Constants: Protocol constants
//
// Transport:
// - ReticulumTransport: Central routing engine
// - NetworkInterface: Interface protocol
// - TCPInterface: TCP network interface
// - FramedTransport: HDLC-framed transport helper
//
// Link:
// - Link: Encrypted peer-to-peer session
// - LinkRequest: Link establishment request
// - LinkProof: Link proof validation
// - LinkState: Link lifecycle states
//
// Routing:
// - PathTable: Route storage
// - PathEntry: Route information
// - AnnounceHandler: Announce processing
//
// Resource:
// - Resource: Large data transfer
// - ResourceAdvertisement: Resource metadata
// - ResourceCallbacks: Transfer notifications
//
// Callbacks:
// - DefaultCallbackManager: Packet delivery management
// - DestinationCallbackManager: Callback protocol
