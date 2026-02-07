//
//  FramedTransport.swift
//  ReticulumSwift
//
//  HDLC-framed transport layer for Reticulum protocol.
//

import Foundation

/// Transport wrapper that adds HDLC framing to an underlying transport.
///
/// FramedTransport handles the complexities of TCP streaming:
/// - Frames outgoing data with HDLC flag bytes and escape sequences
/// - Buffers incoming data until complete frames are received
/// - Extracts multiple frames from single TCP reads
/// - Delivers complete, unframed packets to the callback
///
/// Usage:
/// ```swift
/// let tcp = TCPTransport(host: "relay.example.com", port: 4242)
/// let framed = FramedTransport(transport: tcp)
/// framed.onDataReceived = { packet in
///     // Receives complete Reticulum packets (unframed)
/// }
/// framed.connect()
/// framed.send(packetData) // Automatically HDLC-framed
/// ```
public class FramedTransport: Transport {

    // MARK: - Properties

    /// Underlying transport (TCP, etc.)
    private let underlying: Transport

    /// Buffer for accumulating incoming data until complete frames
    private var receiveBuffer = Data()

    /// Lock for thread-safe buffer access
    private let bufferLock = NSLock()

    // MARK: - Transport Protocol

    public var state: TransportState {
        underlying.state
    }

    public var onStateChange: ((TransportState) -> Void)? {
        get { underlying.onStateChange }
        set { underlying.onStateChange = newValue }
    }

    /// Callback for received frames (unframed data).
    /// Called once per complete frame extracted from the TCP stream.
    public var onDataReceived: ((Data) -> Void)?

    // MARK: - Initialization

    /// Create a framed transport wrapping an underlying transport.
    ///
    /// - Parameter transport: The underlying transport (e.g., TCPTransport)
    public init(transport: Transport) {
        self.underlying = transport

        // Hook into underlying transport's data callback
        underlying.onDataReceived = { [weak self] data in
            self?.handleReceivedData(data)
        }
    }

    /// Convenience initializer for TCP transport.
    ///
    /// - Parameters:
    ///   - host: Remote host address
    ///   - port: Remote port number
    public convenience init(host: String, port: UInt16) {
        let tcp = TCPTransport(host: host, port: port)
        self.init(transport: tcp)
    }

    // MARK: - Transport Methods

    public func connect() {
        underlying.connect()
    }

    /// Send data through the transport with HDLC framing.
    ///
    /// The data is automatically wrapped with HDLC flag bytes and
    /// special bytes are escaped before transmission.
    ///
    /// - Parameters:
    ///   - data: Raw packet data to send (will be framed)
    ///   - completion: Optional callback with error on failure
    public func send(_ data: Data, completion: ((Error?) -> Void)? = nil) {
        let framed = HDLC.frame(data)
        underlying.send(framed, completion: completion)
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
    /// Accumulates data in buffer and extracts complete HDLC frames.
    /// Each complete frame is delivered via onDataReceived callback.
    private func handleReceivedData(_ data: Data) {
        let hexDump = data.prefix(40).map { String(format: "%02x", $0) }.joined()
        print("[FRAMEDTRANSPORT] Raw TCP data: \(data.count) bytes: \(hexDump)")

        bufferLock.lock()
        receiveBuffer.append(data)

        // Extract all complete frames from buffer
        let frames = HDLC.extractFrames(from: &receiveBuffer)
        bufferLock.unlock()

        print("[FRAMEDTRANSPORT] Extracted \(frames.count) frame(s), buffer remaining: \(receiveBuffer.count) bytes")

        // Deliver each frame to callback
        for frame in frames {
            let frameHex = frame.prefix(20).map { String(format: "%02x", $0) }.joined()
            print("[FRAMEDTRANSPORT] Delivering frame: \(frame.count) bytes: \(frameHex)")
            onDataReceived?(frame)
        }
    }
}

// MARK: - CustomStringConvertible

extension FramedTransport: CustomStringConvertible {
    public var description: String {
        return "FramedTransport(\(underlying))"
    }
}
