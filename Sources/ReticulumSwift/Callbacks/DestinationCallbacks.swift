//
//  DestinationCallbacks.swift
//  ReticulumSwift
//
//  Callback manager for packet delivery to destinations.
//  Bridges Python RNS closure pattern to Swift concurrency with both
//  callback and AsyncStream interfaces.
//
//  This is infrastructure for Phase 4 (Transport) when we route
//  incoming packets to destinations.
//

import Foundation

// MARK: - Default Callback Manager Implementation

/// Default implementation of DestinationCallbackManager protocol.
///
/// Provides both closure-based callbacks (matching Python RNS pattern) and
/// AsyncStream-based delivery for modern Swift concurrency.
///
/// Thread safety is ensured via actor isolation.
///
/// Usage (closure-based, matches Python RNS):
/// ```swift
/// callbackManager.register(destinationHash: dest.hash) { data, packet in
///     print("Received: \(data.hexString())")
/// }
/// ```
///
/// Usage (AsyncStream, modern Swift):
/// ```swift
/// Task {
///     for await (data, packet) in callbackManager.createStream(for: dest.hash) {
///         print("Received: \(data.hexString())")
///     }
/// }
/// ```
public actor DefaultCallbackManager: DestinationCallbackManager {

    // MARK: - Properties

    /// Closure callbacks keyed by destination hash
    private var closureCallbacks: [Data: [PacketCallback]] = [:]

    /// AsyncStream continuations keyed by destination hash
    private var streamContinuations: [Data: AsyncStream<(Data, Packet)>.Continuation] = [:]

    // MARK: - Initialization

    /// Create an empty callback manager.
    public init() {}

    // MARK: - DestinationCallbackManager Protocol (nonisolated)

    /// Register a callback for a destination.
    ///
    /// Callbacks are invoked when packets are delivered to the destination.
    /// Multiple callbacks can be registered for the same destination.
    ///
    /// NOTE: This nonisolated version spawns a Task and may not complete
    /// before the next line of code runs. Use `registerAsync()` for guaranteed ordering.
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash
    ///   - callback: Callback to invoke with (decrypted data, original packet)
    nonisolated public func register(destinationHash: Data, callback: @escaping PacketCallback) {
        Task {
            await self.registerInternal(destinationHash: destinationHash, callback: callback)
        }
    }

    /// Register a callback for a destination (async version).
    ///
    /// This awaitable version guarantees the callback is registered before returning.
    /// Use this when you need to ensure the callback is registered before continuing.
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash
    ///   - callback: Callback to invoke with (decrypted data, original packet)
    public func registerAsync(destinationHash: Data, callback: @escaping PacketCallback) async {
        let destHex = destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[LXMF_INBOUND] registerAsync: registering callback for \(destHex)")
        registerInternal(destinationHash: destinationHash, callback: callback)
        let count = closureCallbacks[destinationHash]?.count ?? 0
        print("[LXMF_INBOUND] registerAsync: callback registered, count=\(count)")
    }

    /// Create an AsyncStream for receiving packets to a destination.
    ///
    /// Returns a stream that yields (data, packet) tuples when packets arrive.
    /// Only one stream can be active per destination at a time.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: AsyncStream of (decrypted data, original packet) tuples
    nonisolated public func createStream(for destinationHash: Data) -> AsyncStream<(Data, Packet)> {
        // Create the stream with a stored continuation
        // The continuation is stored via a Task to maintain actor isolation
        return AsyncStream { continuation in
            Task {
                await self.storeStreamContinuation(destinationHash: destinationHash, continuation: continuation)
            }
        }
    }

    // MARK: - Internal Actor-Isolated Methods

    /// Internal method to register callback (actor-isolated).
    private func registerInternal(destinationHash: Data, callback: @escaping PacketCallback) {
        if closureCallbacks[destinationHash] == nil {
            closureCallbacks[destinationHash] = []
        }
        closureCallbacks[destinationHash]?.append(callback)
    }

    /// Store an AsyncStream continuation (actor-isolated).
    private func storeStreamContinuation(
        destinationHash: Data,
        continuation: AsyncStream<(Data, Packet)>.Continuation
    ) {
        // Close existing stream if any
        if let existing = streamContinuations[destinationHash] {
            existing.finish()
        }
        streamContinuations[destinationHash] = continuation
    }

    // MARK: - Delivery

    /// Deliver a packet to a destination.
    ///
    /// Invokes all registered callbacks and yields to the AsyncStream if active.
    ///
    /// - Parameters:
    ///   - data: Decrypted packet data
    ///   - packet: Original packet
    ///   - destinationHash: 16-byte destination hash
    public func deliver(data: Data, packet: Packet, to destinationHash: Data) {
        let destHex = destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        let registeredKeys = closureCallbacks.keys.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() }
        print("[LXMF_INBOUND] DefaultCallbackManager.deliver(): destHash=\(destHex), dataLen=\(data.count)")
        print("[LXMF_INBOUND] Registered callback keys: \(registeredKeys)")

        // Invoke all closure callbacks
        if let callbacks = closureCallbacks[destinationHash] {
            print("[LXMF_INBOUND] Found \(callbacks.count) callback(s) for \(destHex), invoking...")
            for (index, callback) in callbacks.enumerated() {
                print("[LXMF_INBOUND] Invoking callback \(index)")
                callback(data, packet)
                print("[LXMF_INBOUND] Callback \(index) returned")
            }
        } else {
            print("[LXMF_INBOUND] NO callbacks registered for \(destHex)!")
        }

        // Yield to AsyncStream if active
        if let continuation = streamContinuations[destinationHash] {
            print("[LXMF_INBOUND] Yielding to AsyncStream for \(destHex)")
            continuation.yield((data, packet))
        } else {
            print("[LXMF_INBOUND] No AsyncStream for \(destHex)")
        }
    }

    // MARK: - Unregistration

    /// Unregister all callbacks for a destination.
    ///
    /// Removes all closure callbacks and does NOT close the AsyncStream.
    /// Use `closeStream(for:)` to close the stream.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    public func unregisterAllCallbacks(for destinationHash: Data) {
        closureCallbacks.removeValue(forKey: destinationHash)
    }

    /// Close the AsyncStream for a destination.
    ///
    /// After closing, the stream's for-await loop will complete.
    /// A new stream can be created by calling `createStream(for:)` again.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    public func closeStream(for destinationHash: Data) {
        if let continuation = streamContinuations.removeValue(forKey: destinationHash) {
            continuation.finish()
        }
    }

    /// Close all streams and remove all callbacks.
    ///
    /// Call this when shutting down the callback manager.
    public func closeAll() {
        for continuation in streamContinuations.values {
            continuation.finish()
        }
        streamContinuations.removeAll()
        closureCallbacks.removeAll()
    }

    // MARK: - Query

    /// Check if any callbacks or streams are registered for a destination.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: true if any callbacks or streams are registered
    public func hasListeners(for destinationHash: Data) -> Bool {
        let hasCallbacks = closureCallbacks[destinationHash]?.isEmpty == false
        let hasStream = streamContinuations[destinationHash] != nil
        return hasCallbacks || hasStream
    }

    /// Number of registered callback destinations.
    public var callbackCount: Int {
        closureCallbacks.count
    }

    /// Number of active streams.
    public var streamCount: Int {
        streamContinuations.count
    }
}
