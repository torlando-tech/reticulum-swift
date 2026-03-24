// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  KISSFramedTransport.swift
//  ReticulumSwift
//
//  KISS-framed transport layer for RNode BLE communication.
//  Wraps BLETransport with KISS framing and command routing.
//

#if canImport(CoreBluetooth)
import Foundation

/// Transport wrapper that adds KISS framing to an underlying BLE transport.
///
/// Unlike FramedTransport (HDLC), KISSFramedTransport uses KISS protocol
/// with FEND delimiters (0xC0) and transposed escape sequences.
///
/// Key features:
/// - Separates CMD_DATA frames (delivered to onDataReceived) from command
///   frames like CMD_READY, CMD_FREQUENCY echoes, CMD_ERROR (onCommandReceived)
/// - Provides sendCommand() for RNode control commands
/// - Provides sendRaw() for pre-built KISS frames (detect handshake)
///
/// Usage:
/// ```swift
/// let ble = BLETransport(deviceName: "RNode_A9")
/// let framed = KISSFramedTransport(transport: ble)
/// framed.onDataReceived = { data in
///     // Receives data packets (CMD_DATA)
/// }
/// framed.onCommandReceived = { command, payload in
///     // Receives control commands (CMD_READY, CMD_FREQUENCY, etc.)
/// }
/// framed.connect()
/// framed.sendCommand(RNodeConstants.CMD_FREQUENCY, payload: frequencyBytes)
/// ```
public class KISSFramedTransport: Transport {

    // MARK: - Properties

    /// Underlying transport (BLETransport).
    private let underlying: Transport

    /// Buffer for accumulating incoming data until complete frames.
    private var receiveBuffer = Data()

    /// Lock for thread-safe buffer access.
    private let bufferLock = NSLock()

    // MARK: - Transport Protocol

    public var state: TransportState {
        underlying.state
    }

    public var onStateChange: ((TransportState) -> Void)? {
        get { underlying.onStateChange }
        set { underlying.onStateChange = newValue }
    }

    /// Callback for received data frames (CMD_DATA = 0x00).
    ///
    /// Called once per complete KISS data frame extracted from the BLE stream.
    /// The payload is unescaped and unframed.
    public var onDataReceived: ((Data) -> Void)?

    /// Callback for received command frames (non-data KISS commands).
    ///
    /// RNode firmware sends commands like:
    /// - CMD_READY (0x0F) when initialization completes
    /// - CMD_FREQUENCY (0x01) echoing back configured frequency
    /// - CMD_ERROR (0x90) when errors occur
    /// - CMD_DETECT (0x08) response during handshake
    ///
    /// Parameters:
    /// - command: KISS command byte (first byte after FEND)
    /// - payload: Unescaped command payload
    public var onCommandReceived: ((UInt8, Data) -> Void)?

    // MARK: - Initialization

    /// Create a KISS-framed transport wrapping an underlying transport.
    ///
    /// - Parameter transport: The underlying transport (typically BLETransport).
    public init(transport: Transport) {
        self.underlying = transport

        // Hook into underlying transport's data callback
        underlying.onDataReceived = { [weak self] data in
            self?.handleReceivedData(data)
        }
    }

    /// Convenience initializer for BLE transport.
    ///
    /// - Parameter bleTransport: BLE transport instance.
    public convenience init(bleTransport: BLETransport) {
        self.init(transport: bleTransport as Transport)
    }

    // MARK: - Transport Methods

    public func connect() {
        underlying.connect()
    }

    /// Send data through the transport with KISS framing.
    ///
    /// Data is automatically wrapped with FEND delimiters, CMD_DATA command
    /// byte, and escape sequences before transmission.
    ///
    /// - Parameters:
    ///   - data: Raw packet data to send (will be KISS-framed as CMD_DATA)
    ///   - completion: Optional callback with error on failure
    public func send(_ data: Data, completion: ((Error?) -> Void)? = nil) {
        let framed = KISS.frame(data, command: KISS.CMD_DATA)
        underlying.send(framed, completion: completion)
    }

    /// Send a KISS command with optional payload.
    ///
    /// Used by RNodeInterface to send configuration commands like:
    /// - CMD_FREQUENCY with 4-byte frequency value
    /// - CMD_BANDWIDTH with 4-byte bandwidth value
    /// - CMD_DETECT for handshake
    ///
    /// Frame format: [FEND] [command] [escaped_payload] [FEND]
    ///
    /// - Parameters:
    ///   - command: KISS command byte (e.g., RNodeConstants.CMD_FREQUENCY)
    ///   - payload: Command payload (will be escaped)
    ///   - completion: Optional callback with error on failure
    public func sendCommand(_ command: UInt8, payload: Data = Data(), completion: ((Error?) -> Void)? = nil) {
        let framed = KISS.frame(payload, command: command)
        underlying.send(framed, completion: completion)
    }

    /// Send pre-built raw KISS frame bytes.
    ///
    /// Used for the detect handshake which bundles multiple commands in one write.
    /// The data should already include FEND delimiters and escape sequences.
    ///
    /// - Parameters:
    ///   - data: Pre-built KISS frame bytes (no framing added)
    ///   - completion: Optional callback with error on failure
    public func sendRaw(_ data: Data, completion: ((Error?) -> Void)? = nil) {
        underlying.send(data, completion: completion)
    }

    public func disconnect() {
        underlying.disconnect()

        // Clear buffer on disconnect
        bufferLock.lock()
        receiveBuffer.removeAll()
        bufferLock.unlock()
    }

    // MARK: - Private Methods

    /// Handle data received from underlying transport.
    ///
    /// Accumulates data in buffer and extracts complete KISS frames.
    /// Routes CMD_DATA frames to onDataReceived, all other commands to onCommandReceived.
    private func handleReceivedData(_ data: Data) {
        bufferLock.lock()
        receiveBuffer.append(data)

        // Extract all complete frames from buffer
        let frames = extractKISSFrames(from: &receiveBuffer)
        bufferLock.unlock()

        // Deliver each frame to appropriate callback
        for (command, payload) in frames {
            if command == KISS.CMD_DATA {
                // Data frame -> onDataReceived
                onDataReceived?(payload)
            } else {
                // Command frame -> onCommandReceived
                onCommandReceived?(command, payload)
            }
        }
    }

    /// Extract KISS frames from buffer, preserving command byte.
    ///
    /// Unlike KISS.extractFrames() which strips the command byte, this
    /// method returns both the command and payload for routing.
    ///
    /// Frame format: [FEND] [command] [escaped_payload] [FEND]
    ///
    /// - Parameter buffer: Mutable buffer of received data
    /// - Returns: Array of (command, unescaped_payload) tuples
    private func extractKISSFrames(from buffer: inout Data) -> [(UInt8, Data)] {
        var frames: [(UInt8, Data)] = []

        while true {
            // Find start FEND
            guard let startIdx = buffer.firstIndex(of: KISS.FEND) else {
                break
            }

            // Find end FEND (must be after start)
            let searchStart = buffer.index(after: startIdx)
            guard searchStart < buffer.endIndex,
                  let endIdx = buffer[searchStart...].firstIndex(of: KISS.FEND) else {
                break
            }

            // Extract frame content (between FENDs)
            let frameContent = buffer[(buffer.index(after: startIdx))..<endIdx]

            // Remove processed data including end FEND
            buffer.removeSubrange(buffer.startIndex...endIdx)

            // Skip empty frames (consecutive FENDs)
            if frameContent.isEmpty {
                continue
            }

            // First byte is command, remaining bytes are escaped payload
            let commandAndPayload = Data(frameContent)
            guard !commandAndPayload.isEmpty else {
                continue
            }

            let command = commandAndPayload[0]

            // Extract payload (bytes after command)
            let escapedPayload = commandAndPayload.dropFirst()

            // Unescape payload
            // Silently skip malformed frames (truncated escape)
            if let unescaped = try? KISS.unescape(Data(escapedPayload)) {
                frames.append((command, unescaped))
            }
        }

        return frames
    }
}

// MARK: - CustomStringConvertible

extension KISSFramedTransport: CustomStringConvertible {
    public var description: String {
        return "KISSFramedTransport(\(underlying))"
    }
}

#endif // canImport(CoreBluetooth)
