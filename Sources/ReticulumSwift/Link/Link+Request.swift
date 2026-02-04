//
//  Link+Request.swift
//  ReticulumSwift
//
//  Link request/response API implementation.
//  Enables applications to send requests over links and receive responses.
//
//  Matches Python RNS Link.py request() semantics.
//

import Foundation

// MARK: - Link Request Extension

extension Link {

    /// Send a request over the link.
    ///
    /// Small requests (under MDU) are sent as DATA packets.
    /// Large requests are sent as Resources.
    ///
    /// The request is packed as a MessagePack array:
    /// `[timestamp, pathHash, data]`
    ///
    /// - Parameters:
    ///   - path: Request path (hashed for routing)
    ///   - data: Optional request data
    ///   - responseCallback: Called when response received
    ///   - failedCallback: Called on failure/timeout
    ///   - progressCallback: Called on progress (large requests)
    ///   - timeout: Custom timeout (default: RTT-based)
    /// - Returns: RequestReceipt for tracking
    /// - Throws: LinkError.notActive if link is not established
    public func request(
        path: String,
        data: Data? = nil,
        responseCallback: ((RequestReceipt) async -> Void)? = nil,
        failedCallback: ((RequestReceipt) async -> Void)? = nil,
        progressCallback: ((RequestReceipt) async -> Void)? = nil,
        timeout: TimeInterval? = nil
    ) async throws -> RequestReceipt {
        guard state.isEstablished else {
            throw LinkError.notActive
        }

        // Calculate timeout based on RTT
        let effectiveTimeout = timeout ?? calculateRequestTimeout()

        // Hash request path
        guard let pathData = path.data(using: .utf8) else {
            throw LinkError.invalidState(expected: "valid UTF-8 path", actual: "invalid encoding")
        }
        let pathHash = Hashing.truncatedHash(pathData)

        // Build request structure [timestamp, pathHash, data]
        let timestamp = Date().timeIntervalSince1970
        let requestData = data ?? Data()

        // Pack request as MessagePack array: [timestamp, pathHash, data]
        let packed = packMsgPack(.array([
            .double(timestamp),
            .binary(pathHash),
            .binary(requestData)
        ]))

        // Generate request ID
        let requestId = Hashing.truncatedHash(packed)

        // Create receipt
        let receipt = RequestReceipt(
            requestId: requestId,
            pathHash: pathHash,
            timeout: effectiveTimeout,
            responseCallback: responseCallback,
            failedCallback: failedCallback,
            progressCallback: progressCallback
        )

        // Track pending request
        addPendingRequest(receipt)

        // Choose send method based on size
        // Link MDU is ~500 bytes, minus encryption overhead (16 for IV)
        let mdu = 500 - 16

        do {
            if packed.count <= mdu {
                // Small request: send as DATA packet
                try await sendRequestPacket(packed, requestId: requestId)
            } else {
                // Large request: send as Resource
                _ = try await sendResource(
                    data: packed,
                    requestId: requestId,
                    isResponse: false
                )
            }

            await receipt.markDelivered()
        } catch {
            await receipt.markFailed(reason: "Send failed: \(error)")
            throw error
        }

        return receipt
    }

    /// Calculate request timeout based on RTT.
    ///
    /// Uses the formula: rtt * trafficTimeoutFactor + RESPONSE_MAX_GRACE_TIME * 1.125
    ///
    /// - Returns: Timeout duration in seconds
    private func calculateRequestTimeout() -> TimeInterval {
        let trafficTimeoutFactor = 5.0
        let graceTime = ResourceConstants.RESPONSE_MAX_GRACE_TIME
        return rtt * trafficTimeoutFactor + graceTime * 1.125
    }

    /// Send request as DATA packet.
    ///
    /// Frames the data with the request context byte, encrypts it,
    /// and sends it over the link.
    ///
    /// - Parameters:
    ///   - data: Request data to send
    ///   - requestId: Request ID for tracking
    /// - Throws: LinkError.notActive if send callback not set
    private func sendRequestPacket(_ data: Data, requestId: Data) async throws {
        guard let send = sendCallback else {
            throw LinkError.notActive
        }

        // Frame: context + data
        var packet = Data([RequestPacketContext.request])
        packet.append(data)

        let encrypted = try encrypt(packet)
        try await send(encrypted)
    }

    /// Send response to a request.
    ///
    /// - Parameters:
    ///   - requestId: Request ID being responded to
    ///   - data: Response data
    /// - Throws: LinkError.notActive if link not established
    public func respond(to requestId: Data, with data: Data) async throws {
        guard state.isEstablished else {
            throw LinkError.notActive
        }

        // Link MDU minus encryption overhead
        let mdu = 500 - 16

        // Account for requestId (16 bytes) + context (1 byte)
        if data.count + 17 <= mdu {
            // Small response: send as DATA packet
            guard let send = sendCallback else {
                throw LinkError.notActive
            }

            var packet = Data([RequestPacketContext.response])
            packet.append(requestId)
            packet.append(data)

            let encrypted = try encrypt(packet)
            try await send(encrypted)
        } else {
            // Large response: send as Resource
            _ = try await sendResource(
                data: data,
                requestId: requestId,
                isResponse: true
            )
        }
    }
}
