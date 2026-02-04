//
//  Resource.swift
//  ReticulumSwift
//
//  Actor-based resource transfer management for RNS large data transfers.
//  Manages state machine, data preparation, compression, and part assembly.
//
//  Matches Python RNS Resource.py for interoperability.
//

import Foundation
import CryptoKit

// MARK: - Resource

/// Actor-based resource transfer for large data over links.
///
/// Resource implements the Reticulum resource protocol:
/// - State machine: none -> queued -> advertised -> transferring -> awaitingProof -> complete
/// - Data preparation: compression, random hash, hashmap generation
/// - Part assembly: hash validation, decompression
/// - AsyncStream for state observation
///
/// Example usage (outbound):
/// ```swift
/// let resource = Resource(
///     data: largeData,
///     link: activeLink,
///     requestId: nil,
///     isResponse: false,
///     autoCompress: true
/// )
/// try await resource.prepare(partSize: link.sdu)
/// let advertisement = resource.getAdvertisement(segment: 1, linkMDU: link.mdu)
/// ```
///
/// Example usage (inbound):
/// ```swift
/// let resource = Resource(advertisement: adv, link: activeLink)
/// let partData = ... // received from network
/// try await resource.receivePart(partData, at: partIndex)
/// if await resource.isComplete {
///     let originalData = try await resource.assemble()
/// }
/// ```
public actor Resource {

    // MARK: - Identity

    /// Resource hash (SHA256 of random_hash || data)
    public private(set) var hash: Data?

    /// Random hash (4 bytes, for collision detection)
    public private(set) var randomHash: Data?

    /// Associated request ID (16 bytes) or nil
    public let requestId: Data?

    /// Whether this is a response resource
    public let isResponse: Bool

    // MARK: - Data

    /// Original uncompressed data (outbound only)
    private var originalData: Data?

    /// Original uncompressed size
    public private(set) var originalSize: Int = 0

    /// Prepared data (compressed if beneficial, with random hash prepended)
    private var preparedData: Data?

    /// Transfer size (prepared data size)
    public private(set) var transferSize: Int = 0

    /// Whether data was compressed
    public private(set) var compressed: Bool = false

    // MARK: - Parts

    /// Size of each part (Link SDU)
    public private(set) var partSize: Int = 0

    /// Number of parts
    public private(set) var numParts: Int = 0

    /// Parts array (for inbound resources)
    private var parts: [Data?] = []

    /// Hashmap (4-byte hash per part)
    public private(set) var hashmap: Data?

    // MARK: - State

    /// Current resource state
    public private(set) var state: ResourceState = .none

    /// State observation stream continuation
    private var stateContinuation: AsyncStream<ResourceState>.Continuation?

    // MARK: - Link

    /// Associated link (weak to avoid retain cycles)
    public weak var link: Link?

    /// Send callback for encrypted packet transmission
    private var sendCallback: ((Data) async throws -> Void)?

    // MARK: - Window Management

    /// Window manager for flow control
    private let windowManager: ResourceWindow = ResourceWindow()

    /// Transfer start time (for rate calculation)
    private var transferStartTime: Date?

    /// Last request time (for timeout detection)
    private var lastRequestTime: Date?

    /// Parts received status (true if received)
    private var partsReceived: [Bool] = []

    // MARK: - Initialization (Outbound)

    /// Create outbound resource with data to send.
    ///
    /// - Parameters:
    ///   - data: Original data to transfer
    ///   - link: Associated link for transfer
    ///   - requestId: Associated request ID (16 bytes) or nil
    ///   - isResponse: Whether this is a response resource
    ///   - autoCompress: Whether to attempt bz2 compression
    public init(
        data: Data,
        link: Link,
        requestId: Data? = nil,
        isResponse: Bool = false,
        autoCompress: Bool = true
    ) {
        self.originalData = data
        self.originalSize = data.count
        self.link = link
        self.requestId = requestId
        self.isResponse = isResponse
        self.state = .none
    }

    // MARK: - Initialization (Inbound)

    /// Create inbound resource from advertisement.
    ///
    /// - Parameters:
    ///   - advertisement: Resource advertisement packet
    ///   - link: Associated link for transfer
    public init(advertisement: ResourceAdvertisement, link: Link) {
        self.hash = advertisement.hash
        self.randomHash = advertisement.randomHash
        self.transferSize = advertisement.transferSize
        self.originalSize = advertisement.dataSize
        self.numParts = advertisement.numParts
        self.requestId = advertisement.requestId
        self.isResponse = advertisement.flags.isResponseFlag
        self.compressed = advertisement.flags.isCompressed
        self.link = link
        self.state = .advertised

        // Initialize parts array with nil placeholders
        self.parts = Array(repeating: nil, count: advertisement.numParts)

        // Store hashmap chunk from first segment
        self.hashmap = advertisement.hashmapChunk

        // Initialize parts received tracking
        self.partsReceived = Array(repeating: false, count: advertisement.numParts)

        // Start transfer timer
        self.transferStartTime = Date()
    }

    // MARK: - State Observation

    /// AsyncStream for observing resource state changes.
    ///
    /// Yields the current state immediately upon subscription, then yields
    /// each subsequent state change. The stream finishes when the resource
    /// reaches a terminal state.
    ///
    /// - Returns: AsyncStream that yields ResourceState values
    public var stateUpdates: AsyncStream<ResourceState> {
        AsyncStream { continuation in
            self.stateContinuation = continuation
            continuation.yield(self.state)

            continuation.onTermination = { @Sendable _ in
                // Cleanup if needed
            }
        }
    }

    /// Transition to a new state.
    ///
    /// State transitions are validated to ensure they follow the expected
    /// lifecycle. Terminal states (.complete, .failed, .rejected, .cancelled)
    /// cannot be transitioned from.
    ///
    /// - Parameter newState: Target state
    /// - Throws: ResourceError.invalidState if transition is invalid
    public func transitionState(to newState: ResourceState) throws {
        guard state != newState else { return }

        // Validate transition
        guard ResourceState.canTransition(from: state, to: newState) else {
            throw ResourceError.invalidState(
                expected: "valid transition from \(state)",
                actual: "\(newState)"
            )
        }

        state = newState
        stateContinuation?.yield(newState)
    }

    // MARK: - Send Callback

    /// Set the callback for sending encrypted packets via the link.
    ///
    /// The send callback is invoked when the resource needs to send packets
    /// (advertisement, parts, hashmap updates) over the link. The link handles
    /// encryption and framing.
    ///
    /// - Parameter callback: Async closure that encrypts and sends data
    public func setSendCallback(_ callback: @escaping (Data) async throws -> Void) {
        self.sendCallback = callback
    }

    // MARK: - Outbound Transfer

    /// Send resource advertisement over the link.
    ///
    /// Prepares and sends the advertisement packet for segment 0 (initial segment).
    /// The advertisement contains resource metadata (size, hash, flags) and the
    /// first hashmap chunk. For large resources requiring multiple segments,
    /// additional segments are sent via sendHashmapUpdate().
    ///
    /// Flow:
    /// 1. Check state is queued (after prepare())
    /// 2. Get advertisement for segment 1 (first segment)
    /// 3. Encode with MessagePack
    /// 4. Frame with resourceAdvertisement context (0x01)
    /// 5. Send via callback (link encrypts and sends)
    /// 6. Transition to advertised state
    ///
    /// - Parameter linkMDU: Link MDU for hashmap segmentation
    /// - Throws: ResourceError if state is invalid or send fails
    public func sendAdvertisement(linkMDU: Int) async throws {
        guard state == .queued else {
            throw ResourceError.invalidState(
                expected: "queued",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        // Get advertisement for first segment
        let advertisement = try getAdvertisement(segment: 1, linkMDU: linkMDU)

        // Encode with MessagePack
        let advertisementData = try advertisement.pack()

        // Frame with context byte
        var packet = Data()
        packet.append(ResourcePacketContext.resourceAdvertisement)
        packet.append(advertisementData)

        // Send via link (encrypts and sends)
        try await send(packet)

        // Transition to advertised
        try transitionState(to: .advertised)
    }

    /// Send a resource part over the link.
    ///
    /// Sends a single part with its index. The receiver uses the index to
    /// validate the part hash against the hashmap and store it in the correct
    /// position for assembly.
    ///
    /// Packet format:
    /// - Context byte: 0x03 (resourceData)
    /// - Part index: 2 bytes big-endian
    /// - Part data: variable length
    ///
    /// - Parameter index: Part index (0-based)
    /// - Throws: ResourceError if state is invalid or send fails
    public func sendPart(at index: Int) async throws {
        guard state == .transferring else {
            throw ResourceError.invalidState(
                expected: "transferring",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        // Get part data
        let partData = try getPart(at: index)

        // Frame: context (1) + index (2 BE) + part data
        var packet = Data()
        packet.append(ResourcePacketContext.resourceData)

        // Encode index as 2-byte big-endian
        var indexBE = UInt16(index).bigEndian
        packet.append(Data(bytes: &indexBE, count: 2))

        packet.append(partData)

        // Send via link (encrypts and sends)
        try await send(packet)
    }

    /// Send hashmap update for additional segments.
    ///
    /// For resources requiring multiple hashmap segments (due to size constraints),
    /// this sends the advertisement for subsequent segments. The receiver uses these
    /// to build the complete hashmap for part validation.
    ///
    /// Packet format:
    /// - Context byte: 0x05 (resourceHMU)
    /// - Advertisement data: MessagePack-encoded advertisement
    ///
    /// - Parameters:
    ///   - segment: Segment number (2+) for the hashmap update
    ///   - linkMDU: Link MDU for hashmap segmentation
    /// - Throws: ResourceError if state is invalid or send fails
    public func sendHashmapUpdate(segment: Int, linkMDU: Int) async throws {
        guard state == .transferring else {
            throw ResourceError.invalidState(
                expected: "transferring",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        // Get advertisement for specified segment
        let advertisement = try getAdvertisement(segment: segment, linkMDU: linkMDU)

        // Encode with MessagePack
        let advertisementData = try advertisement.pack()

        // Frame with context byte
        var packet = Data()
        packet.append(ResourcePacketContext.resourceHMU)
        packet.append(advertisementData)

        // Send via link (encrypts and sends)
        try await send(packet)
    }

    /// Append a hashmap segment for large resource transfers.
    ///
    /// Called when receiving RESOURCE_HMU packets containing additional
    /// hashmap segments for resources that exceed HASHMAP_MAX_LEN parts.
    ///
    /// - Parameter segment: Additional hashmap segment data
    public func appendHashmapSegment(_ segment: Data) {
        if var existing = hashmap {
            existing.append(segment)
            hashmap = existing
        } else {
            hashmap = segment
        }
    }

    // MARK: - Data Preparation (Outbound)

    /// Prepare resource for transfer.
    ///
    /// Performs data preparation steps:
    /// 1. Compress data with bz2 (fallback to uncompressed if larger)
    /// 2. Generate 4-byte random hash
    /// 3. Prepend random hash to data
    /// 4. Calculate resource hash (SHA256 of random_hash || data)
    /// 5. Generate hashmap (4-byte hash per part)
    /// 6. Transition to queued state
    ///
    /// - Parameters:
    ///   - partSize: Size of each part (Link SDU)
    ///   - autoCompress: Whether to attempt compression (default true)
    /// - Throws: ResourceError if state is invalid or compression fails
    public func prepare(partSize: Int, autoCompress: Bool = true) throws {
        guard state == .none else {
            throw ResourceError.invalidState(expected: "none", actual: "\(state)")
        }

        guard let data = originalData else {
            throw ResourceError.transferFailed(reason: "No original data to prepare")
        }

        self.partSize = partSize

        // Step 1: Compress data if beneficial
        let compressionResult = try ResourceCompression.compress(
            data,
            autoCompress: autoCompress
        )
        self.compressed = compressionResult.compressed

        // Step 2: Generate random hash (4 bytes)
        var randomBytes = Data(count: ResourceConstants.RANDOM_HASH_SIZE)
        _ = randomBytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, ResourceConstants.RANDOM_HASH_SIZE, buffer.baseAddress!)
        }
        self.randomHash = randomBytes

        // Step 3: Prepend random hash to data
        var dataWithRandomHash = Data()
        dataWithRandomHash.append(randomBytes)
        dataWithRandomHash.append(compressionResult.data)
        self.preparedData = dataWithRandomHash
        self.transferSize = dataWithRandomHash.count

        // Step 4: Calculate resource hash (SHA256 of random_hash || data)
        self.hash = Hashing.fullHash(dataWithRandomHash)

        // Step 5: Generate hashmap for parts
        self.hashmap = ResourceHashmap.generateHashmap(
            data: dataWithRandomHash,
            partSize: partSize
        )

        // Calculate number of parts
        self.numParts = (dataWithRandomHash.count + partSize - 1) / partSize

        // Step 6: Transition to queued
        try transitionState(to: .queued)
    }

    /// Get part data at specified index.
    ///
    /// - Parameter index: Part index (0-based)
    /// - Returns: Part data (may be smaller than partSize for last part)
    /// - Throws: ResourceError if index out of range or data not prepared
    public func getPart(at index: Int) throws -> Data {
        guard let data = preparedData else {
            throw ResourceError.invalidState(
                expected: "queued or later (data prepared)",
                actual: "\(state)"
            )
        }

        guard index >= 0 && index < numParts else {
            throw ResourceError.partMissing(index: index)
        }

        let startOffset = index * partSize
        let endOffset = min(startOffset + partSize, data.count)
        return data[startOffset..<endOffset]
    }

    /// Get advertisement for a specific segment.
    ///
    /// - Parameters:
    ///   - segment: Segment index (1-based)
    ///   - linkMDU: Link MDU for hashmap segmentation
    /// - Returns: ResourceAdvertisement for the specified segment
    /// - Throws: ResourceError if data not prepared
    public func getAdvertisement(segment: Int, linkMDU: Int) throws -> ResourceAdvertisement {
        guard let resourceHash = hash,
              let randomHash = randomHash,
              let hashmap = hashmap else {
            throw ResourceError.invalidState(
                expected: "queued (data prepared)",
                actual: "\(state)"
            )
        }

        // Calculate total segments needed
        let maxLength = ResourceHashmap.hashmapMaxLength(linkMDU: linkMDU)
        let totalSegments = ResourceHashmap.segmentCount(
            totalParts: numParts,
            maxLength: maxLength
        )

        // Create flags
        var flags = ResourceFlags(
            encrypted: true,  // Always encrypted for link-based resources
            compressed: compressed,
            split: totalSegments > 1
        )
        if isResponse {
            flags.insert(.isResponse)
        }

        // Use factory method to create advertisement with proper segmentation
        return ResourceAdvertisement.create(
            transferSize: transferSize,
            dataSize: originalSize,
            numParts: numParts,
            resourceHash: resourceHash,
            randomHash: randomHash,
            hashmap: hashmap,
            segment: segment,
            totalSegments: totalSegments,
            requestId: requestId,
            flags: flags,
            linkMDU: linkMDU
        )
    }

    // MARK: - Inbound Transfer

    /// Accept an advertised resource and begin transfer.
    ///
    /// Called by the receiver after receiving an advertisement to indicate
    /// they want to receive this resource. Transitions to transferring state
    /// and prepares to request parts.
    ///
    /// Flow:
    /// 1. Check state is advertised (after receiving advertisement)
    /// 2. Record transfer start time
    /// 3. Transition to transferring state
    /// 4. Request first batch of parts via requestNextParts()
    ///
    /// - Throws: ResourceError if state is invalid
    public func accept() async throws {
        guard state == .advertised else {
            throw ResourceError.invalidState(
                expected: "advertised",
                actual: "\(state)"
            )
        }

        // Set transfer start time for rate calculation
        transferStartTime = Date()

        // Transition to transferring
        try transitionState(to: .transferring)

        // Request first batch of parts
        try await requestNextParts()
    }

    /// Reject an advertised resource.
    ///
    /// Called by the receiver to indicate they do not want to receive this
    /// resource. Sends a reject packet and transitions to rejected state.
    ///
    /// Packet format:
    /// - Context byte: 0x07 (resourceReject)
    ///
    /// - Throws: ResourceError if state is invalid or send fails
    public func reject() async throws {
        guard state == .advertised else {
            throw ResourceError.invalidState(
                expected: "advertised",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        // Send reject packet
        var packet = Data()
        packet.append(ResourcePacketContext.resourceReject)

        try await send(packet)

        // Transition to rejected
        try transitionState(to: .rejected)
    }

    /// Request next batch of parts from sender.
    ///
    /// Uses window manager to determine which parts should be requested based
    /// on current window size and consecutive completion height. Sends a request
    /// packet containing the 4-byte truncated hashes of the desired parts.
    ///
    /// Packet format:
    /// - Context byte: 0x02 (resourceRequest)
    /// - Part hashes: sequence of 4-byte truncated hashes from hashmap
    ///
    /// - Throws: ResourceError if state is invalid or send fails
    public func requestNextParts() async throws {
        guard state == .transferring else {
            throw ResourceError.invalidState(
                expected: "transferring",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        // Get indices of parts to request
        let indices = getNextPartIndices()

        guard !indices.isEmpty else {
            // No parts to request (all received or window full)
            return
        }

        // Build request data (4-byte hashes)
        var requestData = Data()
        for index in indices {
            let partHash = try getPartHash(at: index)
            requestData.append(partHash)
        }

        // Frame with context byte
        var packet = Data()
        packet.append(ResourcePacketContext.resourceRequest)
        packet.append(requestData)

        // Send via link (encrypts and sends)
        try await send(packet)
    }

    /// Handle received part packet.
    ///
    /// Parses the part index and data from a received DATA packet, validates
    /// the part hash, stores the part, and checks for transfer completion.
    /// If the window allows, requests more parts automatically.
    ///
    /// Packet format:
    /// - Part index: 2 bytes big-endian
    /// - Part data: variable length
    ///
    /// - Parameter data: Part packet data (index + part data)
    /// - Returns: true if transfer is complete (all parts received)
    /// - Throws: ResourceError if parsing or validation fails
    public func handlePartPacket(_ data: Data) async throws -> Bool {
        guard data.count >= 2 else {
            throw ResourceError.transferFailed(
                reason: "Part packet too short for index (need 2 bytes, got \(data.count))"
            )
        }

        // Parse index (2 bytes big-endian)
        let indexBE = data.withUnsafeBytes { $0.load(fromByteOffset: 0, as: UInt16.self) }
        let index = Int(UInt16(bigEndian: indexBE))

        // Extract part data
        let partData = data.dropFirst(2)

        // Store part (validates hash)
        try receivePart(Data(partData), at: index)

        // Check if complete
        if isComplete {
            // All parts received, transition to assembling
            try transitionState(to: .assembling)
            return true
        }

        // Request more parts if window allows
        if windowManager.outstanding < windowManager.currentWindow {
            try await requestNextParts()
        }

        return false
    }

    /// Send proof of successful resource assembly.
    ///
    /// Called by the receiver after successfully assembling all parts.
    /// Sends the complete resource hash as proof to the sender.
    ///
    /// Packet format:
    /// - Context byte: 0x04 (resourceProof)
    /// - Resource hash: complete hash of assembled resource
    ///
    /// - Throws: ResourceError if state is invalid or send fails
    public func sendProof() async throws {
        guard state == .complete else {
            throw ResourceError.invalidState(
                expected: "complete",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        guard let resourceHash = hash else {
            throw ResourceError.transferFailed(reason: "No resource hash available")
        }

        // Frame with context byte
        var packet = Data()
        packet.append(ResourcePacketContext.resourceProof)
        packet.append(resourceHash)

        // Send via link (encrypts and sends)
        try await send(packet)
    }

    // MARK: - Part Reception (Inbound)

    /// Receive a part from the network.
    ///
    /// Validates the part hash against the hashmap, stores the part, and
    /// updates window management tracking. When all parts are received,
    /// calculates transfer rate and adjusts window accordingly.
    ///
    /// - Parameters:
    ///   - partData: Part data received
    ///   - index: Part index (0-based)
    /// - Throws: ResourceError if validation fails
    public func receivePart(_ partData: Data, at index: Int) throws {
        guard index >= 0 && index < numParts else {
            throw ResourceError.partMissing(index: index)
        }

        // Validate part hash if hashmap available
        if let hashmap = hashmap {
            let expectedHash = ResourceHashmap.getPartHash(
                from: hashmap,
                at: index
            )
            let actualHash = ResourceHashmap.partHash(partData)

            guard expectedHash == actualHash else {
                throw ResourceError.hashmapMismatch(partIndex: index)
            }
        }

        // Store part
        parts[index] = partData
        partsReceived[index] = true

        // Update window manager
        windowManager.markReceived(index: index, totalParts: numParts)
        windowManager.updateConsecutiveHeight(parts: partsReceived)

        // Check if all parts received
        if partsReceived.allSatisfy({ $0 }) {
            // Calculate transfer rate and adjust window
            let rate = calculateTransferRate()
            windowManager.onAllPartsReceived(transferRate: rate)

            // Transition to awaiting proof (if outbound) or complete (if inbound)
            try transitionState(to: .awaitingProof)
        }
    }

    /// Calculate current transfer rate in bytes per second.
    ///
    /// - Returns: Transfer rate (bytes/sec), or 0 if timing not available
    private func calculateTransferRate() -> Double {
        guard let startTime = transferStartTime else { return 0.0 }

        let elapsed = Date().timeIntervalSince(startTime)
        guard elapsed > 0 else { return 0.0 }

        return Double(transferSize) / elapsed
    }

    // MARK: - Window Flow Control

    /// Get indices of next parts to request.
    ///
    /// Uses window manager to determine which parts should be requested
    /// based on current window size and consecutive completion height.
    ///
    /// - Returns: Array of part indices to request
    public func getNextPartIndices() -> [Int] {
        lastRequestTime = Date()
        let indices = windowManager.getRequestRange(parts: partsReceived)

        // Mark as requested for outstanding count
        windowManager.markRequested(count: indices.count)

        return indices
    }

    /// Handle timeout for outstanding parts.
    ///
    /// Reduces window size and returns indices of parts to re-request.
    ///
    /// - Returns: Array of part indices to re-request
    public func handleTimeout() -> [Int] {
        windowManager.onTimeout()

        // Return indices of incomplete parts up to new window size
        return windowManager.getRequestRange(parts: partsReceived)
    }

    // MARK: - Window Accessors

    /// Current window size.
    public var windowSize: Int {
        windowManager.currentWindow
    }

    /// Number of parts currently outstanding (requested but not received).
    public var outstandingCount: Int {
        windowManager.outstanding
    }

    /// Highest consecutive completed part index.
    public var consecutiveHeight: Int {
        windowManager.height
    }

    // MARK: - Part Assembly

    /// Get expected hash for a part from hashmap.
    ///
    /// - Parameter index: Part index (0-based)
    /// - Returns: 4-byte expected hash from hashmap
    /// - Throws: ResourceError if hashmap not available or index out of range
    public func getPartHash(at index: Int) throws -> Data {
        guard let hashmap = hashmap else {
            throw ResourceError.invalidState(
                expected: "hashmap available",
                actual: "no hashmap"
            )
        }

        guard index >= 0 && index < numParts else {
            throw ResourceError.partMissing(index: index)
        }

        let startByte = index * ResourceConstants.MAPHASH_LEN
        let endByte = startByte + ResourceConstants.MAPHASH_LEN

        guard endByte <= hashmap.count else {
            throw ResourceError.partMissing(index: index)
        }

        return hashmap[startByte..<endByte]
    }

    /// Check if all parts have been received.
    public var isComplete: Bool {
        get {
            guard state == .assembling || state == .awaitingProof || state == .complete else {
                return false
            }
            return partsReceived.allSatisfy { $0 }
        }
    }

    /// Count of received parts.
    public var receivedCount: Int {
        get {
            return partsReceived.filter { $0 }.count
        }
    }

    /// Assemble received parts into original data.
    ///
    /// Performs final assembly steps:
    /// 1. Concatenate all parts in order
    /// 2. Remove random hash prefix (4 bytes)
    /// 3. Decompress if compressed flag is set
    /// 4. Transition to complete state
    ///
    /// - Returns: Original uncompressed data
    /// - Throws: ResourceError if not all parts received or decompression fails
    public func assemble() throws -> Data {
        guard state == .assembling || state == .awaitingProof else {
            throw ResourceError.invalidState(
                expected: "assembling or awaitingProof",
                actual: "\(state)"
            )
        }

        // Verify all parts received
        guard isComplete else {
            let missing = partsReceived.enumerated()
                .filter { !$0.element }
                .map { $0.offset }
            throw ResourceError.transferFailed(
                reason: "Missing parts: \(missing)"
            )
        }

        // Step 1: Concatenate all parts
        var assembled = Data()
        for part in parts {
            guard let partData = part else {
                throw ResourceError.transferFailed(reason: "Part is nil despite isComplete check")
            }
            assembled.append(partData)
        }

        // Verify assembled data size matches transfer size
        guard assembled.count == transferSize else {
            throw ResourceError.transferFailed(
                reason: "Assembled size \(assembled.count) != transfer size \(transferSize)"
            )
        }

        // Step 2: Remove random hash prefix (4 bytes)
        guard assembled.count >= ResourceConstants.RANDOM_HASH_SIZE else {
            throw ResourceError.transferFailed(
                reason: "Assembled data too short to contain random hash"
            )
        }
        let dataWithoutRandomHash = assembled.dropFirst(ResourceConstants.RANDOM_HASH_SIZE)

        // Step 3: Decompress if needed
        let finalData: Data
        if compressed {
            finalData = try ResourceCompression.decompress(Data(dataWithoutRandomHash))
        } else {
            finalData = Data(dataWithoutRandomHash)
        }

        // Verify final data size matches original size
        guard finalData.count == originalSize else {
            throw ResourceError.transferFailed(
                reason: "Final size \(finalData.count) != original size \(originalSize)"
            )
        }

        // Step 4: Transition to complete
        try transitionState(to: .complete)

        return finalData
    }
}
