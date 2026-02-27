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
    /// **Important**: The `data` parameter is packed as a MessagePack value
    /// within the request array, NOT as pre-encoded binary. This matches
    /// Python RNS where `link.request(path, [None, None])` packs the list
    /// as a nested array, not as binary bytes.
    ///
    /// - Parameters:
    ///   - path: Request path (hashed for routing)
    ///   - data: Optional request data as a MessagePack value (array, map, nil, etc.)
    ///   - responseCallback: Called when response received
    ///   - failedCallback: Called on failure/timeout
    ///   - progressCallback: Called on progress (large requests)
    ///   - timeout: Custom timeout (default: RTT-based)
    /// - Returns: RequestReceipt for tracking
    /// - Throws: LinkError.notActive if link is not established
    public func request(
        path: String,
        data: MessagePackValue? = nil,
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
        // The data value is packed as its native MessagePack type (array, map, nil, etc.)
        // NOT as binary bytes. This matches Python: umsgpack.packb([time, hash, data])
        let timestamp = Date().timeIntervalSince1970
        let requestValue = data ?? .null

        // Pack request as MessagePack array: [timestamp, pathHash, data]
        let packed = packMsgPack(.array([
            .double(timestamp),
            .binary(pathHash),
            requestValue
        ]))

        // Choose send method based on size (use negotiated MDU)
        let linkMdu = self.mdu

        if packed.count <= linkMdu {
            // Small request: send as DATA packet
            // Python: request_id = packet_receipt.truncated_hash (packet hashable part hash)
            // We must compute request_id from the SENT packet, not the plaintext data
            let (requestId, packet) = try buildRequestPacket(packed)

            let receipt = RequestReceipt(
                requestId: requestId,
                pathHash: pathHash,
                timeout: effectiveTimeout,
                responseCallback: responseCallback,
                failedCallback: failedCallback,
                progressCallback: progressCallback
            )

            addPendingRequest(receipt)

            do {
                guard let send = sendCallback else {
                    throw LinkError.notActive
                }
                try await send(packet)
                await receipt.markDelivered()
            } catch {
                await receipt.markFailed(reason: "Send failed: \(error)")
                throw error
            }

            return receipt
        } else {
            // Large request: send as Resource
            // For resource requests, request_id = hash of packed data (matches Python)
            let requestId = Hashing.truncatedHash(packed)

            let receipt = RequestReceipt(
                requestId: requestId,
                pathHash: pathHash,
                timeout: effectiveTimeout,
                responseCallback: responseCallback,
                failedCallback: failedCallback,
                progressCallback: progressCallback
            )

            addPendingRequest(receipt)

            do {
                _ = try await sendResource(
                    data: packed,
                    requestId: requestId,
                    isResponse: false
                )
                await receipt.markDelivered()
            } catch {
                await receipt.markFailed(reason: "Send failed: \(error)")
                throw error
            }

            return receipt
        }
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

    /// Build a request DATA packet and compute its request_id.
    ///
    /// The request_id is the truncated hash of the packet's hashable part,
    /// matching Python's `packet_receipt.truncated_hash`. This is how the
    /// server identifies the request and includes it in the response.
    ///
    /// - Parameter data: Request data to send (msgpack-packed request)
    /// - Returns: Tuple of (requestId, encodedPacketBytes)
    /// - Throws: If encryption fails
    private func buildRequestPacket(_ data: Data) throws -> (Data, Data) {
        // Encrypt the request data (Python: link.encrypt(data))
        let encrypted = try encrypt(data)

        // Build proper link DATA packet with REQUEST context
        let header = PacketHeader(
            headerType: .header1,
            hasContext: true,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .data,
            hopCount: 0
        )

        let packet = Packet(
            header: header,
            destination: linkId,
            context: RequestPacketContext.request,
            data: encrypted
        )

        let encoded = packet.encode()

        // Compute request_id from packet's hashable part (matches Python)
        // Python: request_id = packet.getTruncatedHash()
        let requestId = packet.getTruncatedHash()

        return (requestId, encoded)
    }

    /// Send response to a request.
    ///
    /// Response is packed as msgpack([requestId, responseData]) matching Python:
    ///   packed_response = umsgpack.packb([request_id, response])
    ///   RNS.Packet(self, packed_response, DATA, context=RESPONSE).send()
    ///
    /// - Parameters:
    ///   - requestId: Request ID being responded to
    ///   - data: Response data
    /// - Throws: LinkError.notActive if link not established
    public func respond(to requestId: Data, with data: Data) async throws {
        guard state.isEstablished else {
            throw LinkError.notActive
        }

        // Pack response as msgpack([requestId, responseData]) matching Python
        let packedResponse = packMsgPack(.array([
            .binary(requestId),
            .binary(data)
        ]))

        // Use negotiated link MDU
        let linkMdu = self.mdu

        if packedResponse.count <= linkMdu {
            // Small response: send as DATA packet with RESPONSE context
            guard let send = sendCallback else {
                throw LinkError.notActive
            }

            let encrypted = try encrypt(packedResponse)

            let header = PacketHeader(
                headerType: .header1,
                hasContext: true,
                transportType: .broadcast,
                destinationType: .link,
                packetType: .data,
                hopCount: 0
            )

            let packet = Packet(
                header: header,
                destination: linkId,
                context: RequestPacketContext.response,
                data: encrypted
            )

            try await send(packet.encode())
        } else {
            // Large response: send as Resource
            _ = try await sendResource(
                data: packedResponse,
                requestId: requestId,
                isResponse: true
            )
        }
    }
}
