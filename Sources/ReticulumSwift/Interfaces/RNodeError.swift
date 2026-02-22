//
//  RNodeError.swift
//  ReticulumSwift
//
//  Error types for RNode interface communication.
//

import Foundation

/// Errors that can occur during RNode interface operations.
public enum RNodeError: Error, Sendable {

    // MARK: - Hardware Errors (from CMD_ERROR)

    /// Radio initialization failed (ERROR_INITRADIO = 0x01).
    ///
    /// The RNode firmware could not initialize the radio hardware.
    /// This may indicate a hardware fault or incompatible radio module.
    case radioInitFailed

    /// Transmission failed (ERROR_TXFAILED = 0x02).
    ///
    /// The radio could not transmit the packet. This may be due to
    /// channel congestion, hardware issues, or CSMA backoff failure.
    case transmitFailed

    /// RNode packet queue is full (ERROR_QUEUE_FULL = 0x04).
    ///
    /// The firmware's internal packet queue is full. The sender
    /// must wait before sending more packets.
    case queueFull

    /// RNode memory is low (ERROR_MEMORY_LOW = 0x05).
    ///
    /// The firmware is running low on RAM. This may prevent
    /// new packets from being queued or processed.
    case memoryLow

    /// Modem timeout (ERROR_MODEM_TIMEOUT = 0x06).
    ///
    /// The radio modem did not respond in time. This may indicate
    /// a hardware fault or firmware bug.
    case modemTimeout

    /// Invalid configuration (ERROR_INVALID_CONFIG = 0x40).
    ///
    /// The RNode rejected the radio configuration. Most commonly caused
    /// by TX power exceeding device limits (SX1262=22dBm, SX1276=17dBm).
    case invalidConfig

    /// Unknown hardware error code received.
    ///
    /// The firmware sent an error code not recognized by this
    /// implementation. The raw error code is included.
    case unknownHardwareError(UInt8)

    // MARK: - Firmware Version Errors

    /// Firmware version is too old.
    ///
    /// The connected RNode has firmware older than the required
    /// version (1.52). Upgrade the RNode firmware.
    case firmwareVersionTooOld(major: UInt8, minor: UInt8)

    // MARK: - Configuration Errors

    /// RNode detect handshake failed.
    ///
    /// The RNode did not respond to the detect sequence within
    /// the timeout period. Check BLE connection.
    case detectFailed

    /// Radio configuration validation failed.
    ///
    /// The RNode did not echo back the expected configuration
    /// values, or the configuration was rejected as invalid.
    case radioConfigFailed(String)

    /// Interface is not configured.
    ///
    /// Attempted to send a packet before the radio was configured.
    /// Call configure() first.
    case notConfigured

    // MARK: - Queue Errors

    /// Local interface packet queue is full.
    ///
    /// The iOS-side packet queue has reached its maximum depth (32).
    /// Wait for packets to be transmitted before sending more.
    case interfaceQueueFull
}

// MARK: - LocalizedError

extension RNodeError: LocalizedError {

    public var errorDescription: String? {
        switch self {
        case .radioInitFailed:
            return "RNode radio initialization failed. Check hardware."

        case .transmitFailed:
            return "RNode transmission failed. Channel may be congested."

        case .queueFull:
            return "RNode packet queue is full. Wait before sending more packets."

        case .memoryLow:
            return "RNode memory is low. Reduce packet rate."

        case .modemTimeout:
            return "RNode modem timeout. Hardware may be faulty."

        case .invalidConfig:
            return "RNode rejected configuration — TX power may exceed device limits. Try reducing TX power."

        case .unknownHardwareError(let code):
            return "RNode hardware error: unknown error code 0x\(String(format: "%02X", code))."

        case .firmwareVersionTooOld(let major, let minor):
            return "RNode firmware \(major).\(minor) is too old. Requires 1.52 or newer."

        case .detectFailed:
            return "RNode detect handshake failed. Check BLE connection."

        case .radioConfigFailed(let reason):
            return "RNode radio configuration failed: \(reason)"

        case .notConfigured:
            return "RNode interface is not configured. Call configure() first."

        case .interfaceQueueFull:
            return "RNode interface queue is full (32 packets). Wait for transmission."
        }
    }
}
