//
//  ResourcePacketContext.swift
//  ReticulumSwift
//
//  Resource packet context values for identifying resource packet types.
//  Values match Python RNS Packet.py exactly for interoperability.
//

import Foundation

// MARK: - Resource Packet Contexts

/// Resource packet context values.
///
/// These context values identify different packet types within the resource
/// transfer protocol. They are used as the wire-format context byte.
///
/// Resource transfer flow:
/// 1. Sender sends ADVERTISEMENT with resource metadata
/// 2. Receiver responds with ACCEPT or REJECT
/// 3. If accepted, receiver sends REQUEST for specific parts
/// 4. Sender responds with DATA packets containing part content
/// 5. On completion, receiver sends PROOF containing resource hash
/// 6. Sender may send HMU (hashmap update) for additional segments
/// 7. Either side may send CANCEL to abort
///
/// Values match Python RNS Packet.py context constants:
/// ```python
/// RESOURCE       = 0x01  # Packet is part of a resource (NOT link-encrypted)
/// RESOURCE_ADV   = 0x02  # Packet is a resource advertisement
/// RESOURCE_REQ   = 0x03  # Packet is a resource part request
/// RESOURCE_HMU   = 0x04  # Packet is a resource hashmap update
/// RESOURCE_PRF   = 0x05  # Packet is a resource proof
/// RESOURCE_ICL   = 0x06  # Packet is a resource initiator cancel message
/// RESOURCE_RCL   = 0x07  # Packet is a resource receiver cancel message
/// ```
public enum ResourcePacketContext {

    // MARK: - Context Values

    /// Resource data part packet (0x01) — Python RESOURCE.
    ///
    /// Contains a segment of the resource transfer data.
    /// IMPORTANT: NOT encrypted by the link (Packet.pack passes through).
    /// The Resource class handles its own segmented encryption.
    /// Format: 2-byte big-endian part index + encrypted part data bytes.
    public static let resource: UInt8 = 0x01

    /// Resource advertisement packet (0x02) — Python RESOURCE_ADV.
    ///
    /// Sent by the sender to advertise availability of a resource.
    /// Contains MessagePack-encoded advertisement data with:
    /// - Transfer size, data size, number of parts
    /// - Resource hash, random hash
    /// - Hashmap chunk (4-byte hash per part)
    /// - Flags (encrypted, compressed, split, etc.)
    /// - Optional request ID for responses
    /// Link-encrypted.
    public static let resourceAdvertisement: UInt8 = 0x02

    /// Resource request packet (0x03) — Python RESOURCE_REQ.
    ///
    /// Sent by the receiver to request specific parts by their hash.
    /// Contains a sequence of 4-byte truncated part hashes from the hashmap.
    /// Link-encrypted.
    public static let resourceRequest: UInt8 = 0x03

    /// Resource hashmap update packet (0x04) — Python RESOURCE_HMU.
    ///
    /// Sent by the sender to provide additional hashmap segments for
    /// resources that are split across multiple advertisements due to
    /// size constraints.
    /// Link-encrypted.
    public static let resourceHMU: UInt8 = 0x04

    /// Resource proof packet (0x05) — Python RESOURCE_PRF.
    ///
    /// Sent by the receiver after successfully receiving all parts.
    /// Contains the complete resource hash to prove successful assembly.
    /// Link-encrypted.
    public static let resourceProof: UInt8 = 0x05

    /// Resource initiator cancel packet (0x06) — Python RESOURCE_ICL.
    ///
    /// Sent by the sender to abort the transfer.
    /// Link-encrypted.
    public static let resourceCancel: UInt8 = 0x06

    /// Resource receiver cancel/reject packet (0x07) — Python RESOURCE_RCL.
    ///
    /// Sent by the receiver to reject or cancel a resource transfer.
    /// Link-encrypted.
    public static let resourceReject: UInt8 = 0x07

    // MARK: - Helpers

    /// Check if a context value is a resource packet context.
    ///
    /// Resource contexts occupy the range 0x01-0x07. Other context values
    /// (like keep-alive 0xFA) are not resource packets.
    ///
    /// - Parameter context: Context byte to check
    /// - Returns: true if context is a resource packet type
    public static func isResourceContext(_ context: UInt8) -> Bool {
        return context >= resource && context <= resourceReject
    }
}
