//
//  Transport.swift
//  ReticulumSwift
//
//  Defines the transport layer protocol for network connections.
//

import Foundation

/// Connection state for transports.
public enum TransportState: Equatable, Sendable {
    case disconnected
    case connecting
    case connected
    case failed(Error)

    public static func == (lhs: TransportState, rhs: TransportState) -> Bool {
        switch (lhs, rhs) {
        case (.disconnected, .disconnected),
             (.connecting, .connecting),
             (.connected, .connected):
            return true
        case (.failed, .failed):
            return true
        default:
            return false
        }
    }
}

/// Protocol for network transports (TCP, UDP, etc.)
public protocol Transport: AnyObject {
    /// Current connection state.
    var state: TransportState { get }

    /// Callback invoked when connection state changes.
    var onStateChange: ((TransportState) -> Void)? { get set }

    /// Callback invoked when data is received.
    var onDataReceived: ((Data) -> Void)? { get set }

    /// Connect to the remote endpoint.
    func connect()

    /// Send data to the remote endpoint.
    /// - Parameter data: Data to send.
    /// - Parameter completion: Optional callback with error on failure.
    func send(_ data: Data, completion: ((Error?) -> Void)?)

    /// Disconnect and clean up.
    func disconnect()
}
