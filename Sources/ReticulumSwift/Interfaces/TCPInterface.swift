//
//  TCPInterface.swift
//  ReticulumSwift
//
//  Actor-based TCP interface with automatic reconnection.
//  Wraps FramedTransport with connection lifecycle management.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "net.reticulum", category: "TCPInterface")

// MARK: - TCPInterface

/// Actor-based TCP interface with automatic reconnection.
///
/// TCPInterface wraps FramedTransport with connection lifecycle management,
/// exponential backoff reconnection, and delegate notifications. This is the
/// primary interface type for TCP relay connections.
///
/// Features:
/// - Automatic reconnection on disconnect with exponential backoff
/// - Never gives up reconnection attempts (unlimited retries)
/// - State notifications via delegate pattern
/// - Packet reception with HDLC framing handled automatically
/// - Thread-safe statistics tracking (bytes sent/received)
///
/// Example usage:
/// ```swift
/// let config = InterfaceConfig(
///     id: "relay1",
///     name: "Primary Relay",
///     type: .tcp,
///     enabled: true,
///     mode: .full,
///     host: "relay.example.com",
///     port: 4242
/// )
/// let interface = TCPInterface(config: config)
/// interface.delegate = myHandler
/// await interface.connect()
/// try await interface.send(packetData)
/// ```
public actor TCPInterface: @preconcurrency NetworkInterface {

    // MARK: - Properties

    /// Unique identifier for this interface
    public let id: String

    /// Configuration used to create this interface
    public let config: InterfaceConfig

    /// Interface mode controlling announce propagation
    public let mode: InterfaceMode

    /// Current connection state
    public private(set) var state: InterfaceState = .disconnected

    /// Hardware MTU — TCP has no practical limit, matches Python TCPInterface.HW_MTU
    public var hwMtu: Int { 262144 }

    /// Underlying framed transport
    private var transport: FramedTransport?

    /// Exponential backoff calculator for reconnection
    private let backoff: ExponentialBackoff

    /// Current reconnection task
    private var reconnectTask: Task<Void, Never>?

    /// Whether automatic reconnection is enabled
    private var autoReconnect: Bool = true

    /// Current reconnection attempt (0 when not reconnecting)
    private var reconnectAttempt: Int = 0

    /// Total bytes sent through this interface
    public private(set) var bytesSent: UInt64 = 0

    /// Total bytes received through this interface
    public private(set) var bytesReceived: UInt64 = 0

    /// Description of the last connection error (for UI display).
    public private(set) var lastErrorDescription: String?

    // MARK: - Delegate

    /// Weak reference wrapper for delegate to work within actor
    private var delegateRef: WeakDelegate?

    /// Delegate for interface events.
    ///
    /// Set this before calling connect() to receive state change
    /// and packet notifications.
    public var delegate: InterfaceDelegate? {
        get { delegateRef?.delegate }
        set { delegateRef = newValue.map { WeakDelegate($0) } }
    }

    /// Set the delegate for receiving interface events.
    ///
    /// This method satisfies the NetworkInterface protocol requirement
    /// and is equivalent to setting the delegate property directly.
    ///
    /// - Parameter delegate: Delegate to receive events
    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self.delegate = delegate
    }

    // MARK: - Initialization

    /// Create a new TCP interface.
    ///
    /// - Parameter config: Interface configuration (must be type .tcp)
    /// - Throws: InterfaceError.invalidConfig if config.type is not .tcp
    public init(config: InterfaceConfig) throws {
        guard config.type == .tcp else {
            throw InterfaceError.invalidConfig(reason: "TCPInterface requires config type .tcp, got \(config.type)")
        }

        self.id = config.id
        self.config = config
        self.mode = config.mode
        self.backoff = ExponentialBackoff()
    }

    // MARK: - Connection Methods

    /// Connect to the remote endpoint.
    ///
    /// Starts the connection process. State transitions from disconnected
    /// to connecting, then to connected on success. If connection fails,
    /// automatic reconnection begins.
    public func connect() async throws {
        guard state == .disconnected else { return }

        autoReconnect = true
        await transitionState(to: .connecting)
        await setupTransport()
    }

    /// Disconnect from the remote endpoint.
    ///
    /// Stops any ongoing reconnection attempts and disconnects the transport.
    /// State transitions to disconnected.
    public func disconnect() async {
        autoReconnect = false

        // Cancel any ongoing reconnection
        reconnectTask?.cancel()
        reconnectTask = nil
        reconnectAttempt = 0

        // Disconnect transport
        transport?.disconnect()
        transport = nil

        state = .disconnected
        notifyStateChange()
    }

    /// Send data through the interface.
    ///
    /// - Parameter data: Raw packet data to send (will be HDLC framed)
    /// - Throws: InterfaceError.notConnected if not in connected state
    /// - Throws: InterfaceError.sendFailed if transmission fails
    public func send(_ data: Data) async throws {
        guard state == .connected, let transport = transport else {
            throw InterfaceError.notConnected
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            transport.send(data) { [weak self] error in
                if let error = error {
                    continuation.resume(throwing: InterfaceError.sendFailed(underlying: error.localizedDescription))
                } else {
                    Task { [weak self] in
                        await self?.updateBytesSent(data.count)
                    }
                    continuation.resume()
                }
            }
        }
    }

    // MARK: - Private Methods

    /// Set up the framed transport and wire callbacks.
    private func setupTransport() async {
        let newTransport = FramedTransport(host: config.host, port: config.port)

        // Wire state change callback
        newTransport.onStateChange = { [weak self] transportState in
            Task { [weak self] in
                await self?.handleTransportStateChange(transportState)
            }
        }

        // Wire data received callback
        newTransport.onDataReceived = { [weak self] data in
            Task { [weak self] in
                await self?.handleDataReceived(data)
            }
        }

        self.transport = newTransport

        // Start connection
        newTransport.connect()
    }

    /// Handle transport state changes.
    private func handleTransportStateChange(_ transportState: TransportState) async {
        switch transportState {
        case .disconnected:
            // Transport disconnected - trigger reconnection if we were connected
            if state == .connected || state == .connecting {
                await startReconnectLoop()
            }

        case .connecting:
            // Already in connecting state from our side
            break

        case .connected:
            // Successfully connected!
            reconnectAttempt = 0
            lastErrorDescription = nil
            await transitionState(to: .connected)

        case .failed(let error):
            // Capture error description for UI display
            lastErrorDescription = error.localizedDescription
            // Connection failed - notify delegate and start reconnection
            notifyError(error)
            await startReconnectLoop()
        }
    }

    /// Handle received data from transport.
    private func handleDataReceived(_ data: Data) {
        let hexDump = data.prefix(20).map { String(format: "%02x", $0) }.joined()
        logger.debug("handleDataReceived: \(data.count, privacy: .public) bytes: \(hexDump, privacy: .public)")

        bytesReceived += UInt64(data.count)
        notifyPacketReceived(data)
    }

    /// Update bytes sent counter.
    private func updateBytesSent(_ count: Int) {
        bytesSent += UInt64(count)
    }

    /// Transition to a new state and notify delegate.
    private func transitionState(to newState: InterfaceState) async {
        guard state != newState else { return }
        state = newState
        notifyStateChange()
    }

    // MARK: - Reconnection Logic

    /// Start the reconnection loop.
    ///
    /// This runs until reconnection succeeds or disconnect() is called.
    /// Never gives up - unlimited retries per CONTEXT.md requirement.
    private func startReconnectLoop() async {
        guard autoReconnect else { return }
        guard reconnectTask == nil else { return } // Already reconnecting

        reconnectAttempt = 1
        await transitionState(to: .reconnecting(attempt: reconnectAttempt))

        reconnectTask = Task { [weak self] in
            guard let self = self else { return }

            while !Task.isCancelled {
                let attempt = await self.getReconnectAttempt()
                let delay = await self.calculateDelay(forAttempt: attempt)

                // Wait before attempting
                do {
                    try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                } catch {
                    // Task cancelled
                    return
                }

                // Check if cancelled during sleep
                if Task.isCancelled { return }

                // Attempt reconnection
                await self.attemptReconnect()

                // Check if we connected successfully
                let currentState = await self.state
                if currentState == .connected {
                    await self.clearReconnectTask()
                    return // Success!
                }

                // Increment attempt and continue
                await self.incrementReconnectAttempt()
            }
        }
    }

    /// Get current reconnection attempt number.
    private func getReconnectAttempt() -> Int {
        return reconnectAttempt
    }

    /// Calculate delay for a given attempt.
    private func calculateDelay(forAttempt attempt: Int) -> TimeInterval {
        return backoff.nextDelay(attempt: attempt - 1) // Backoff uses 0-based attempts
    }

    /// Attempt a single reconnection.
    private func attemptReconnect() async {
        // Clean up old transport
        transport?.disconnect()
        transport = nil

        // Create new transport
        await setupTransport()
    }

    /// Increment reconnection attempt counter.
    private func incrementReconnectAttempt() {
        reconnectAttempt += 1
        state = .reconnecting(attempt: reconnectAttempt)
        notifyStateChange()
    }

    /// Clear the reconnection task reference.
    private func clearReconnectTask() {
        reconnectTask = nil
        reconnectAttempt = 0
    }

    // MARK: - Delegate Notifications

    /// Notify delegate of state change.
    private func notifyStateChange() {
        let currentState = state
        let interfaceId = id
        guard let delegate = delegateRef?.delegate else { return }
        delegate.interface(id: interfaceId, didChangeState: currentState)
    }

    /// Notify delegate of received packet.
    private func notifyPacketReceived(_ data: Data) {
        let interfaceId = id
        guard let delegate = delegateRef?.delegate else { return }
        delegate.interface(id: interfaceId, didReceivePacket: data)
    }

    /// Notify delegate of error.
    private func notifyError(_ error: Error) {
        let interfaceId = id
        guard let delegate = delegateRef?.delegate else { return }
        delegate.interface(id: interfaceId, didFailWithError: error)
    }
}

// MARK: - WeakDelegate

/// Wrapper for weak delegate reference within actor.
///
/// Uses @unchecked Sendable because weak references are inherently thread-safe
/// (they become nil atomically when the referent is deallocated).
private final class WeakDelegate: @unchecked Sendable {
    weak var delegate: InterfaceDelegate?

    init(_ delegate: InterfaceDelegate) {
        self.delegate = delegate
    }
}

// MARK: - CustomStringConvertible

extension TCPInterface: CustomStringConvertible {
    nonisolated public var description: String {
        "TCPInterface<\(id)>"
    }
}
