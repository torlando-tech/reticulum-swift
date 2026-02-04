//
//  ResourceFlags.swift
//  ReticulumSwift
//
//  Resource flag bitfield encoding matching Python RNS Resource.py
//  Flags encode encrypted/compressed/split/request/response/metadata states
//

import Foundation

/// Resource flags bitfield for advertisement packets.
///
/// Bit layout matches Python RNS Resource.py lines 1286-1287:
/// - Bit 0: encrypted (always true for link-based resources)
/// - Bit 1: compressed (bz2 compression applied)
/// - Bit 2: split (multi-segment resource)
/// - Bit 3: isRequest (request resource)
/// - Bit 4: isResponse (response resource)
/// - Bit 5: hasMetadata (metadata attached)
///
/// Example:
/// ```swift
/// let flags: ResourceFlags = [.encrypted, .compressed]
/// print(flags.rawValue) // 0x03
/// ```
public struct ResourceFlags: OptionSet, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Bit 0: Resource is encrypted (always true for link-based resources)
    public static let encrypted   = ResourceFlags(rawValue: 1 << 0)

    /// Bit 1: Resource data is bz2 compressed
    public static let compressed  = ResourceFlags(rawValue: 1 << 1)

    /// Bit 2: Resource spans multiple segments (requires hashmap)
    public static let split       = ResourceFlags(rawValue: 1 << 2)

    /// Bit 3: Resource is a request (Link.request())
    public static let isRequest   = ResourceFlags(rawValue: 1 << 3)

    /// Bit 4: Resource is a response (Link.response())
    public static let isResponse  = ResourceFlags(rawValue: 1 << 4)

    /// Bit 5: Resource has attached metadata
    public static let hasMetadata = ResourceFlags(rawValue: 1 << 5)
}

// MARK: - Convenience Initializers

extension ResourceFlags {
    /// Create flags for a resource with individual boolean parameters.
    ///
    /// - Parameters:
    ///   - encrypted: Resource is encrypted (default: true for link-based resources)
    ///   - compressed: Resource data is bz2 compressed (default: false)
    ///   - split: Resource spans multiple segments (default: false)
    ///   - isRequest: Resource is a request (default: false)
    ///   - isResponse: Resource is a response (default: false)
    ///   - hasMetadata: Resource has metadata attached (default: false)
    ///
    /// Example:
    /// ```swift
    /// let flags = ResourceFlags(encrypted: true, compressed: true)
    /// // flags.rawValue == 0x03
    /// ```
    public init(
        encrypted: Bool = true,
        compressed: Bool = false,
        split: Bool = false,
        isRequest: Bool = false,
        isResponse: Bool = false,
        hasMetadata: Bool = false
    ) {
        var flags: ResourceFlags = []
        if encrypted { flags.insert(.encrypted) }
        if compressed { flags.insert(.compressed) }
        if split { flags.insert(.split) }
        if isRequest { flags.insert(.isRequest) }
        if isResponse { flags.insert(.isResponse) }
        if hasMetadata { flags.insert(.hasMetadata) }
        self = flags
    }
}

// MARK: - Decoding Helpers

extension ResourceFlags {
    /// Check if the encrypted flag is set.
    public var isEncrypted: Bool {
        contains(.encrypted)
    }

    /// Check if the compressed flag is set.
    public var isCompressed: Bool {
        contains(.compressed)
    }

    /// Check if the split flag is set.
    public var isSplit: Bool {
        contains(.split)
    }

    /// Check if the request flag is set.
    public var isRequestFlag: Bool {
        contains(.isRequest)
    }

    /// Check if the response flag is set.
    public var isResponseFlag: Bool {
        contains(.isResponse)
    }

    /// Check if the metadata flag is set.
    public var hasMetadataFlag: Bool {
        contains(.hasMetadata)
    }
}
