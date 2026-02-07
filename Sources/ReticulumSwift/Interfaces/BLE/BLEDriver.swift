//
//  BLEDriver.swift
//  ReticulumSwift
//
//  Protocol for BLE mesh driver abstraction.
//  Port of BLEDriver.kt from reticulum-kt.
//
//  Abstracts CoreBluetooth so the mesh logic can be tested
//  with mock drivers.
//

import Foundation

// MARK: - BLE Driver

/// Platform abstraction for BLE mesh operations.
///
/// The driver handles advertising, scanning, and connection management.
/// BLEInterface consumes the driver's async streams for discovered peers,
/// incoming connections, and disconnection events.
///
/// iOS implementation: `CoreBluetoothBLEDriver`
public protocol BLEDriver: AnyObject, Sendable {

    /// Start advertising the mesh service.
    ///
    /// Makes this device discoverable as a GATT server with the
    /// BLE mesh service UUID and characteristics.
    func startAdvertising() async throws

    /// Stop advertising.
    func stopAdvertising() async

    /// Start scanning for nearby mesh peers.
    ///
    /// Discovered peers are emitted on the `discoveredPeers` stream.
    func startScanning() async throws

    /// Stop scanning.
    func stopScanning() async

    /// Initiate a GATT client connection to a discovered peer.
    ///
    /// - Parameter address: BLE address/identifier of the peer
    /// - Returns: An established peer connection
    /// - Throws: If connection fails or times out
    func connect(address: String) async throws -> any BLEPeerConnection

    /// Disconnect from a peer.
    ///
    /// - Parameter address: BLE address/identifier of the peer
    func disconnect(address: String) async

    /// Shut down the driver, releasing all CoreBluetooth resources.
    func shutdown()

    /// Stream of newly discovered peers from scanning.
    var discoveredPeers: AsyncStream<DiscoveredPeer> { get }

    /// Stream of incoming connections from remote centrals.
    var incomingConnections: AsyncStream<any BLEPeerConnection> { get }

    /// Stream of disconnected peer addresses.
    var connectionLost: AsyncStream<String> { get }

    /// This device's BLE address or identifier (available after power on).
    var localAddress: String? { get }

    /// Whether the driver is currently running (advertising or scanning).
    var isRunning: Bool { get }
}
