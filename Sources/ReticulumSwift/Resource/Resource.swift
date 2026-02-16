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

    /// Assembled data (available after assemble() completes successfully)
    public private(set) var assembledData: Data?

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

    /// Decrypt callback for link decryption of assembled resource data
    private var decryptCallback: ((Data) throws -> Data)?

    // MARK: - Window Management

    /// Window manager for flow control
    private let windowManager: ResourceWindow = ResourceWindow()

    /// Transfer start time (for rate calculation)
    private var transferStartTime: Date?

    /// Last request time (for timeout detection)
    private var lastRequestTime: Date?

    /// Parts received status (true if received)
    private var partsReceived: [Bool] = []

    /// Current hashmap segment (1-based, incremented as HMU requests arrive)
    public private(set) var currentHashmapSegment: Int = 1

    /// Total hashmap segments needed
    public private(set) var totalHashmapSegments: Int = 1

    /// Whether we're waiting for a hashmap update (HMU) from the sender.
    /// When true, no further RESOURCE_REQ should be sent until HMU arrives.
    public private(set) var waitingForHMU: Bool = false

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

    /// Transition from advertised to transferring state.
    ///
    /// Called by the sender when the first RESOURCE_REQ is received from the peer.
    /// This matches Python's behavior where `Resource.request()` transitions to
    /// TRANSFERRING on the first incoming request.
    public func transitionToTransferring() {
        if state == .advertised {
            state = .transferring
            stateContinuation?.yield(.transferring)
        }
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

    /// Set the callback for link-decrypting assembled resource data.
    ///
    /// Called by the receiver to decrypt the assembled encrypted parts
    /// before stripping the random prefix and decompressing.
    public func setDecryptCallback(_ callback: @escaping (Data) throws -> Data) {
        self.decryptCallback = callback
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

        // Frame: context (1) + part data
        // Python identifies parts by hash, NOT by index.
        // Python receive_part(): part_hash = get_map_hash(packet.data)
        // So we send raw part data only (no index prefix).
        var packet = Data()
        packet.append(ResourcePacketContext.resource)
        packet.append(partData)

        // Send via link (encrypts and sends)
        try await send(packet)
    }

    /// Send hashmap update for additional segments.
    ///
    /// For resources requiring multiple hashmap segments (due to size constraints),
    /// this sends raw hashmap bytes for the next segment. The receiver uses these
    /// to build the complete hashmap for part validation.
    ///
    /// Python wire format (Resource.py line 1000):
    ///   `hmu = self.hash + umsgpack.packb([segment, hashmap])`
    /// Python receiver (Resource.py line 442):
    ///   `update = umsgpack.unpackb(plaintext[HASHLENGTH//8:])`
    ///   `self.hashmap_update(update[0], update[1])`
    ///
    /// Packet format:
    /// - Context byte: 0x04 (resourceHMU)
    /// - Resource hash: 32 bytes
    /// - Msgpack([segment_index, raw_hashmap_bytes])
    ///
    /// - Parameters:
    ///   - segment: Segment number (1-based internal, converted to 0-based for wire)
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

        guard let resourceHash = hash, let fullHashmap = hashmap else {
            throw ResourceError.invalidState(
                expected: "prepared (hash/hashmap available)",
                actual: "\(state)"
            )
        }

        // Convert 1-based segment to 0-based for hashmap indexing
        let zeroBasedSegment = segment - 1
        let maxLength = ResourceHashmap.hashmapMaxLength(linkMDU: linkMDU)
        guard let hashmapChunk = ResourceHashmap.getHashmapSegment(
            hashmap: fullHashmap,
            segment: zeroBasedSegment,
            maxLength: maxLength
        ) else {
            throw ResourceError.transferFailed(reason: "Hashmap segment \(segment) out of range")
        }

        // Python wire format: resource_hash(32) + msgpack([segment, hashmap_bytes])
        let hmuPayload = packMsgPack(.array([
            .int(Int64(zeroBasedSegment)),
            .binary(Data(hashmapChunk))
        ]))

        // Frame: context byte + resource hash + msgpack payload
        var packet = Data()
        packet.append(ResourcePacketContext.resourceHMU)
        packet.append(resourceHash)
        packet.append(hmuPayload)

        // Send via link (encrypts and sends)
        try await send(packet)
    }

    /// Send the next hashmap segment when the receiver reports exhaustion.
    ///
    /// Called by the Link when a RESOURCE_REQ arrives with exhausted=true,
    /// meaning the receiver has used all part hashes from the current segment
    /// and needs more.
    ///
    /// - Parameter linkMDU: Link MDU for segmentation calculation
    /// - Returns: True if a new segment was sent, false if all segments already sent
    public func sendNextHashmapSegment(linkMDU: Int) async throws -> Bool {
        let nextSegment = currentHashmapSegment + 1
        guard nextSegment <= totalHashmapSegments else {
            return false
        }
        currentHashmapSegment = nextSegment
        try await sendHashmapUpdate(segment: nextSegment, linkMDU: linkMDU)
        return true
    }

    /// Append a hashmap segment for large resource transfers.
    ///
    /// Called when receiving RESOURCE_HMU packets containing additional
    /// hashmap segments for resources that exceed HASHMAP_MAX_LEN parts.
    ///
    /// - Parameter segment: Additional hashmap segment data
    public func appendHashmapSegment(_ segment: Data) async {
        if var existing = hashmap {
            existing.append(segment)
            hashmap = existing
        } else {
            hashmap = segment
        }
        // Clear HMU wait flag and resume requesting parts
        waitingForHMU = false
        if state == .transferring {
            try? await requestNextParts()
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
    /// Prepare resource for transfer.
    ///
    /// Follows Python RNS Resource.__init__() sequence:
    /// 1. Compress data if beneficial
    /// 2. Prepend random data prefix (4 bytes) to compressed data
    /// 3. Link-encrypt the entire blob (random prefix + compressed data)
    /// 4. Generate SEPARATE random_hash (4 bytes) for hashmap computation
    /// 5. Compute resource hash = SHA256(original_data + random_hash)
    /// 6. Generate hashmap from encrypted data parts + random_hash
    /// 7. Split encrypted data for transfer
    ///
    /// - Parameters:
    ///   - partSize: Maximum part size (Link SDU/MDU)
    ///   - linkEncrypt: Closure to link-encrypt the data blob
    ///   - autoCompress: Whether to auto-compress data
    public func prepare(partSize: Int, linkEncrypt: (Data) throws -> Data, autoCompress: Bool = true) throws {
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

        // Step 2: Generate random data prefix (4 bytes) — prepended before encryption
        // This is NOT the same as self.randomHash (used for hashmap)
        var randomPrefix = Data(count: ResourceConstants.RANDOM_HASH_SIZE)
        _ = randomPrefix.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, ResourceConstants.RANDOM_HASH_SIZE, buffer.baseAddress!)
        }

        // Step 3: Build pre-encryption blob: random_prefix + compressed_data
        var preEncryptionData = Data()
        preEncryptionData.append(randomPrefix)
        preEncryptionData.append(compressionResult.data)

        // Step 4: Link-encrypt the entire blob
        let encryptedData = try linkEncrypt(preEncryptionData)
        self.preparedData = encryptedData
        self.transferSize = encryptedData.count

        // Step 5: Generate SEPARATE random_hash for hashmap (4 bytes)
        var randomBytes = Data(count: ResourceConstants.RANDOM_HASH_SIZE)
        _ = randomBytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, ResourceConstants.RANDOM_HASH_SIZE, buffer.baseAddress!)
        }
        self.randomHash = randomBytes

        // Step 6: Calculate resource hash = SHA256(original_data + random_hash)
        // Python: self.hash = RNS.Identity.full_hash(data + self.random_hash)
        var hashInput = Data(data) // original uncompressed data
        hashInput.append(randomBytes)
        self.hash = Hashing.fullHash(hashInput)

        // Step 7: Generate hashmap from ENCRYPTED data parts + random_hash
        // Python: get_map_hash(encrypted_segment) = SHA256(encrypted_segment + random_hash)[:4]
        self.hashmap = ResourceHashmap.generateHashmap(
            data: encryptedData,
            partSize: partSize,
            randomHash: randomBytes
        )

        // Calculate number of parts from encrypted data size
        self.numParts = (encryptedData.count + partSize - 1) / partSize

        // Step 8: Transition to queued
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

        // Calculate hashmap segments needed for HMU tracking
        // NOTE: hashmap segments != resource segments. Python's "total_segments"
        // in advertisements refers to data segments for >1MB transfers.
        // For normal transfers (under MAX_EFFICIENT_SIZE=1MB), it's always 1.
        let maxLength = ResourceHashmap.hashmapMaxLength(linkMDU: linkMDU)
        let hashmapSegments = ResourceHashmap.segmentCount(
            totalParts: numParts,
            maxLength: maxLength
        )
        // Cache for HMU tracking (number of hashmap chunks, not resource segments)
        self.totalHashmapSegments = hashmapSegments

        // Create flags — "split" refers to resource segments, not hashmap segments
        // Since we send all data in one resource transfer, split is always false
        var flags = ResourceFlags(
            encrypted: true,  // Always encrypted for link-based resources
            compressed: compressed,
            split: false
        )
        if isResponse {
            flags.insert(.isResponse)
        }

        // Use factory method to create advertisement with proper segmentation
        // segment=1, totalSegments=1 because this is a single resource transfer
        // (hashmap segments are handled transparently via HMU packets)
        return ResourceAdvertisement.create(
            transferSize: transferSize,
            dataSize: originalSize,
            numParts: numParts,
            resourceHash: resourceHash,
            randomHash: randomHash,
            hashmap: hashmap,
            segment: 1,
            totalSegments: 1,
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

        // Don't send requests while waiting for a hashmap update
        guard !waitingForHMU else { return }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        guard let resHash = hash else {
            throw ResourceError.transferFailed(reason: "No resource hash available for request")
        }

        // Get indices of parts to request
        let indices = getNextPartIndices()

        guard !indices.isEmpty else {
            // No parts to request (all received or window full)
            return
        }

        // Determine hashmap coverage: how many parts have hashmap entries
        let hashmapCoverage = (hashmap?.count ?? 0) / ResourceConstants.MAPHASH_LEN

        // Separate indices into those we have hashes for and those beyond hashmap
        var requestableIndices: [Int] = []
        var hashmapExhausted = false
        for index in indices {
            if index < hashmapCoverage {
                requestableIndices.append(index)
            } else {
                hashmapExhausted = true
            }
        }

        // Build request data:
        // Python Resource.request_next():
        //   flag = 0x00 (normal) or 0xFF (hashmap exhausted)
        //   If exhausted: flag(0xFF) + last_map_hash(4) + resource_hash(32) + part_hashes
        //   If normal: flag(0x00) + resource_hash(32) + part_hashes
        var requestData = Data()

        // Track how many parts we're actually requesting (for window outstanding count).
        // Only count indices we actually send hashes for — NOT indices beyond hashmap.
        let actualRequestCount: Int

        if hashmapExhausted {
            // Hashmap exhausted: need HMU from sender
            // last_map_hash = hash of the last part we know about in the hashmap
            let lastKnownIndex = hashmapCoverage - 1
            let lastMapHash: Data
            if lastKnownIndex >= 0 {
                lastMapHash = (try? getPartHash(at: lastKnownIndex)) ?? Data(repeating: 0, count: ResourceConstants.MAPHASH_LEN)
            } else {
                lastMapHash = Data(repeating: 0, count: ResourceConstants.MAPHASH_LEN)
            }
            requestData.append(0xFF) // HASHMAP_IS_EXHAUSTED
            requestData.append(lastMapHash) // 4-byte last map hash
            requestData.append(resHash) // 32-byte resource hash
            for index in requestableIndices {
                let partHash = try getPartHash(at: index)
                requestData.append(partHash)
            }
            actualRequestCount = requestableIndices.count
            waitingForHMU = true
        } else {
            // Normal request: all indices have hashmap entries
            requestData.append(0x00) // HASHMAP_IS_NOT_EXHAUSTED
            requestData.append(resHash)
            for index in requestableIndices {
                let partHash = try getPartHash(at: index)
                requestData.append(partHash)
            }
            actualRequestCount = requestableIndices.count
        }

        // Mark only actually-sent parts as outstanding (not beyond-hashmap indices)
        windowManager.markRequested(count: actualRequestCount)

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
        guard data.count > 0 else {
            throw ResourceError.transferFailed(
                reason: "Part packet empty"
            )
        }

        // Python identifies parts by content hash, NOT by index prefix.
        // Compute SHA256(partData + randomHash)[:4] and find matching entry in hashmap.
        guard let rHash = randomHash, let hmap = hashmap else {
            throw ResourceError.transferFailed(
                reason: "No randomHash or hashmap available for part identification"
            )
        }

        let partData = Data(data)
        let contentHash = ResourceHashmap.partHash(partData, randomHash: rHash)

        // Search hashmap for matching 4-byte hash
        let hashLen = ResourceConstants.MAPHASH_LEN
        var index: Int? = nil
        for i in 0..<numParts {
            let start = i * hashLen
            let end = start + hashLen
            guard end <= hmap.count else { break }
            if hmap[start..<end] == contentHash {
                index = i
                break
            }
        }

        guard let foundIndex = index else {
            throw ResourceError.transferFailed(
                reason: "Part hash not found in hashmap"
            )
        }

        // Store part (validates hash)
        try receivePart(partData, at: foundIndex)

        // Check if all parts received (don't use isComplete which has a state guard)
        if partsReceived.allSatisfy({ $0 }) {
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

        // Validate part hash if hashmap and randomHash available
        if let hashmap = hashmap, let randomHash = randomHash {
            let expectedHash = ResourceHashmap.getPartHash(
                from: hashmap,
                at: index
            )
            let actualHash = ResourceHashmap.partHash(partData, randomHash: randomHash)

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
            // State transition is handled by the caller (handlePartPacket for inbound,
            // handleResourceProof for outbound). Don't transition here because
            // inbound goes transferring→assembling→complete while outbound goes
            // transferring→awaitingProof→complete.
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
    /// NOTE: Does NOT call markRequested — the caller (requestNextParts)
    /// must mark only the indices that are actually sent in the request,
    /// since hashmap exhaustion may reduce the set of requestable indices.
    ///
    /// - Returns: Array of part indices to request
    public func getNextPartIndices() -> [Int] {
        lastRequestTime = Date()
        return windowManager.getRequestRange(parts: partsReceived)
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

        // Step 2: Link-decrypt the assembled data
        // Python: if self.encrypted: data = self.link.decrypt(stream)
        // Resource parts are transmitted encrypted; the link does NOT decrypt
        // resource data packets (context 0x01 is passthrough).
        let decrypted: Data
        if let decrypt = decryptCallback {
            decrypted = try decrypt(assembled)
        } else {
            decrypted = assembled
        }

        // Step 3: Remove random hash prefix (4 bytes)
        guard decrypted.count >= ResourceConstants.RANDOM_HASH_SIZE else {
            throw ResourceError.transferFailed(
                reason: "Decrypted data too short to contain random hash prefix"
            )
        }
        let dataWithoutRandomHash = decrypted.dropFirst(ResourceConstants.RANDOM_HASH_SIZE)

        // Step 4: Decompress if needed
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

        // Step 4: Store assembled data and transition to complete
        self.assembledData = finalData
        try transitionState(to: .complete)

        return finalData
    }
}
