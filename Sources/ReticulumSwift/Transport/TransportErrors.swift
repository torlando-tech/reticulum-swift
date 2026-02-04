//
//  TransportErrors.swift
//  ReticulumSwift
//
//  Error types for transport operations.
//  Used by ReticuLumTransport for routing and dispatch errors.
//

import Foundation

// MARK: - Transport Error

/// Errors that can occur during transport routing operations.
///
/// These errors represent failures in packet dispatch, routing, and
/// destination management. They are distinct from InterfaceError which
/// handles lower-level connection issues.
public enum TransportError: Error, Sendable, Equatable {

    /// Transport is not connected.
    ///
    /// Occurs when attempting to send data while the transport is disconnected.
    case notConnected

    /// No path found in path table for the given destination.
    ///
    /// Occurs when attempting to send a routed packet to a destination
    /// that has no known path. Consider sending a path request or waiting
    /// for an announce.
    case noPathAvailable(destinationHash: Data)

    /// Interface with the specified ID not found.
    ///
    /// The interface may have been removed or never added.
    case interfaceNotFound(id: String)

    /// No interfaces are available for sending.
    ///
    /// Occurs when attempting to send but all interfaces are disconnected
    /// or no interfaces have been added.
    case noInterfacesAvailable

    /// Destination hash is not registered locally.
    ///
    /// Occurs when a packet arrives for a destination that has not been
    /// registered with the transport.
    case destinationNotRegistered(hash: Data)

    /// Send operation failed on a specific interface.
    ///
    /// Wraps the underlying error from the interface for context.
    case sendFailed(interfaceId: String, underlying: String)

    /// Packet is invalid and cannot be processed.
    ///
    /// The reason describes what is wrong with the packet.
    case invalidPacket(reason: String)

    // MARK: - Equatable

    public static func == (lhs: TransportError, rhs: TransportError) -> Bool {
        switch (lhs, rhs) {
        case (.notConnected, .notConnected):
            return true
        case (.noPathAvailable(let lhsHash), .noPathAvailable(let rhsHash)):
            return lhsHash == rhsHash
        case (.interfaceNotFound(let lhsId), .interfaceNotFound(let rhsId)):
            return lhsId == rhsId
        case (.noInterfacesAvailable, .noInterfacesAvailable):
            return true
        case (.destinationNotRegistered(let lhsHash), .destinationNotRegistered(let rhsHash)):
            return lhsHash == rhsHash
        case (.sendFailed(let lhsId, let lhsErr), .sendFailed(let rhsId, let rhsErr)):
            return lhsId == rhsId && lhsErr == rhsErr
        case (.invalidPacket(let lhsReason), .invalidPacket(let rhsReason)):
            return lhsReason == rhsReason
        default:
            return false
        }
    }
}

// MARK: - LocalizedError

extension TransportError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notConnected:
            return "Transport is not connected"
        case .noPathAvailable(let hash):
            let hexPrefix = hash.prefix(4).map { String(format: "%02x", $0) }.joined()
            return "No path available to destination \(hexPrefix)..."
        case .interfaceNotFound(let id):
            return "Interface not found: \(id)"
        case .noInterfacesAvailable:
            return "No interfaces available for sending"
        case .destinationNotRegistered(let hash):
            let hexPrefix = hash.prefix(4).map { String(format: "%02x", $0) }.joined()
            return "Destination not registered: \(hexPrefix)..."
        case .sendFailed(let interfaceId, let underlying):
            return "Send failed on interface \(interfaceId): \(underlying)"
        case .invalidPacket(let reason):
            return "Invalid packet: \(reason)"
        }
    }
}
