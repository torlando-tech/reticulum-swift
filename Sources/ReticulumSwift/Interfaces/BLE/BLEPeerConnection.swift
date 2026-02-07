//
//  BLEPeerConnection.swift
//  ReticulumSwift
//
//  Protocol for a single BLE GATT connection to a peer.
//  Port of BLEPeerConnection from reticulum-kt BLEDriver.kt.
//

import Foundation

// MARK: - BLE Peer Connection

/// A single BLE GATT connection to a mesh peer.
///
/// Abstracts the CoreBluetooth peripheral/central connection details.
/// Implementations handle characteristic read/write/notify operations.
public protocol BLEPeerConnection: AnyObject, Sendable {

    /// BLE address or peripheral identifier for this peer.
    var address: String { get }

    /// Negotiated MTU for this connection.
    var mtu: Int { get }

    /// Remote identity hash (16 bytes), available after handshake.
    var identity: Data? { get }

    /// Send a fragment to this peer via the RX characteristic.
    ///
    /// - Parameter data: Fragment data (header + payload)
    /// - Throws: If the write fails
    func sendFragment(_ data: Data) async throws

    /// Stream of received fragments from this peer's TX characteristic.
    var receivedFragments: AsyncStream<Data> { get }

    /// Read the remote peer's identity from the Identity characteristic.
    ///
    /// - Returns: 16-byte identity hash
    /// - Throws: If the read fails or returns invalid data
    func readIdentity() async throws -> Data

    /// Write our identity to the remote peer's RX characteristic.
    ///
    /// - Parameter identity: Our 16-byte identity hash
    /// - Throws: If the write fails
    func writeIdentity(_ identity: Data) async throws

    /// Read the remote peer's current RSSI.
    ///
    /// - Returns: RSSI in dBm
    /// - Throws: If the read fails
    func readRemoteRssi() async throws -> Int

    /// Close this connection.
    func close()
}
