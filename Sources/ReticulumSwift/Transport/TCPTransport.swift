//
//  TCPTransport.swift
//  ReticulumSwift
//
//  NWConnection-based TCP transport implementing the Transport protocol.
//

import Foundation
import Network
import OSLog

/// TCP transport using Network.framework NWConnection.
/// Handles connection lifecycle, state changes, data receive loop, and send operations.
public final class TCPTransport: Transport {
    // MARK: - Properties

    /// The underlying NWConnection instance.
    private var connection: NWConnection?

    /// Server hostname or IP address.
    private let host: String

    /// Server port number.
    private let port: UInt16

    /// Logger for TCP connection events.
    private let logger: Logger

    /// Queue for connection operations.
    private let connectionQueue = DispatchQueue(label: "com.columba.tcptransport", qos: .userInitiated)

    /// Current connection state.
    public private(set) var state: TransportState = .disconnected

    /// Connection timeout work item (cancelled on success or disconnect).
    private var connectionTimeoutWork: DispatchWorkItem?

    /// Connection timeout in seconds.
    private let connectionTimeout: TimeInterval = 15.0

    /// Callback invoked when connection state changes.
    public var onStateChange: ((TransportState) -> Void)?

    /// Callback invoked when data is received from the server.
    public var onDataReceived: ((Data) -> Void)?

    // MARK: - Initialization

    /// Initialize a new TCP transport.
    /// - Parameters:
    ///   - host: Server hostname or IP address.
    ///   - port: Server port number.
    ///   - subsystem: Logger subsystem (default: "com.columba.core").
    public init(host: String, port: UInt16, subsystem: String = "com.columba.core") {
        self.host = host
        self.port = port
        self.logger = Logger(subsystem: subsystem, category: "TCPTransport")
        logger.info("TCPTransport initialized for \(host, privacy: .public):\(port, privacy: .public)")
    }

    // MARK: - Transport Protocol

    /// Establish TCP connection to the configured server.
    public func connect() {
        guard state == .disconnected || state != .connecting else {
            logger.warning("Connect called but already connecting/connected")
            return
        }

        updateState(.connecting)
        logger.info("Connecting to \(self.host, privacy: .public):\(self.port, privacy: .public)...")

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: port)
        )

        connection = NWConnection(to: endpoint, using: .tcp)

        connection?.stateUpdateHandler = { [weak self] nwState in
            guard let self = self else { return }
            self.handleNWState(nwState)
        }

        connection?.viabilityUpdateHandler = { [weak self] isViable in
            self?.logger.info("Connection viability: \(isViable, privacy: .public)")
        }

        connection?.betterPathUpdateHandler = { [weak self] betterPathAvailable in
            if betterPathAvailable {
                self?.logger.info("Better network path available")
            }
        }

        connection?.start(queue: connectionQueue)

        // Start connection timeout
        startConnectionTimeout()
    }

    /// Start a timeout that fires if connection isn't established in time.
    private func startConnectionTimeout() {
        connectionTimeoutWork?.cancel()

        let work = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            guard self.state == .connecting else { return }

            self.logger.error("Connection timed out after \(self.connectionTimeout)s to \(self.host, privacy: .public):\(self.port, privacy: .public)")
            self.connection?.cancel()
            self.connection = nil
            let error = TransportError.connectionTimedOut(host: self.host, port: self.port)
            self.updateState(.failed(error))
        }

        connectionTimeoutWork = work
        connectionQueue.asyncAfter(
            deadline: .now() + connectionTimeout,
            execute: work
        )
    }

    /// Send data to the server.
    /// - Parameters:
    ///   - data: Data to send.
    ///   - completion: Optional callback with nil on success, Error on failure.
    public func send(_ data: Data, completion: ((Error?) -> Void)? = nil) {
        guard state == .connected else {
            let error = TransportError.notConnected
            logger.error("Send failed: not connected")
            completion?(error)
            return
        }

        connection?.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.logger.error("Send failed: \(error.localizedDescription, privacy: .public)")
                completion?(error)
            } else {
                self?.logger.debug("Sent \(data.count, privacy: .public) bytes")
                completion?(nil)
            }
        })
    }

    /// Disconnect and clean up the connection.
    public func disconnect() {
        logger.info("Disconnecting TCP connection")
        connectionTimeoutWork?.cancel()
        connectionTimeoutWork = nil
        connection?.cancel()
        connection = nil
        updateState(.disconnected)
    }

    // MARK: - Private Methods

    private func handleNWState(_ nwState: NWConnection.State) {
        logger.debug("NWConnection state: \(String(describing: nwState), privacy: .public)")

        switch nwState {
        case .ready:
            logger.info("TCP connection ready to \(self.host, privacy: .public):\(self.port, privacy: .public)")
            connectionTimeoutWork?.cancel()
            connectionTimeoutWork = nil
            updateState(.connected)
            startReceiving()

        case .waiting(let error):
            // Surface this as a failure so the UI gets feedback.
            // TCPInterface's reconnect loop will retry automatically.
            logger.warning("TCP connection waiting (unreachable): \(error.localizedDescription, privacy: .public)")
            connectionTimeoutWork?.cancel()
            connectionTimeoutWork = nil
            connection?.cancel()
            connection = nil
            let wrappedError = TransportError.connectionWaiting(
                host: host, port: port, reason: error.localizedDescription
            )
            updateState(.failed(wrappedError))

        case .failed(let error):
            logger.error("TCP connection failed: \(error.localizedDescription, privacy: .public)")
            connectionTimeoutWork?.cancel()
            connectionTimeoutWork = nil
            updateState(.failed(error))

        case .cancelled:
            logger.info("TCP connection cancelled")
            connectionTimeoutWork?.cancel()
            connectionTimeoutWork = nil
            updateState(.disconnected)

        case .preparing:
            logger.debug("TCP connection preparing...")

        case .setup:
            logger.debug("TCP connection setup...")

        @unknown default:
            logger.warning("Unknown connection state")
        }
    }

    private func updateState(_ newState: TransportState) {
        state = newState
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.onStateChange?(newState)
        }
    }

    /// Start the receive loop to continuously read incoming data.
    private func startReceiving() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }

            if let data = data, !data.isEmpty {
                self.logger.debug("Received \(data.count, privacy: .public) bytes")
                self.onDataReceived?(data)
            }

            if let error = error {
                self.logger.error("Receive error: \(error.localizedDescription, privacy: .public)")
                return
            }

            // Continue receiving if connection is still open
            if !isComplete {
                self.startReceiving()
            } else {
                self.logger.info("Connection completed (isComplete=true)")
                self.updateState(.disconnected)
            }
        }
    }
}
