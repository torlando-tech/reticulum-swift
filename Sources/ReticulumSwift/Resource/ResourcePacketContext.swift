//
//  ResourcePacketContext.swift
//  ReticulumSwift
//
//  Resource packet context values for identifying resource packet types.
//  Values match Python RNS Resource.py and Link.py exactly for interoperability.
//

import Foundation

// MARK: - Resource Packet Contexts

/// Resource packet context values.
///
/// These context values identify different packet types within the resource
/// transfer protocol. They are used in packet framing alongside the packet data.
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
/// Values match Python RNS Link.py resource constants:
/// ```python
/// RESOURCE_ADV = 0x01
/// RESOURCE_REQ = 0x02
/// RESOURCE_HMU = 0x03
/// RESOURCE_PRF = 0x04
/// RESOURCE_ICL = 0x05
/// RESOURCE_RCL = 0x06
/// ```
///
/// Note: Python RNS uses slightly different constant naming (ADV vs ADVERTISEMENT).
/// The numeric values are identical.
public enum ResourcePacketContext {

    // MARK: - Context Values

    /// Resource advertisement packet (0x01).
    ///
    /// Sent by the sender to advertise availability of a resource.
    /// Contains MessagePack-encoded advertisement data with:
    /// - Transfer size, data size, number of parts
    /// - Resource hash, random hash
    /// - Hashmap chunk (4-byte hash per part)
    /// - Flags (encrypted, compressed, split, etc.)
    /// - Optional request ID for responses
    public static let resourceAdvertisement: UInt8 = 0x01

    /// Resource request packet (0x02).
    ///
    /// Sent by the receiver to request specific parts by their hash.
    /// Contains a sequence of 4-byte truncated part hashes from the hashmap.
    /// Each hash identifies which part is being requested.
    public static let resourceRequest: UInt8 = 0x02

    /// Resource data packet (0x03).
    ///
    /// Sent by the sender containing part data.
    /// Format: 2-byte big-endian part index + part data bytes.
    /// The receiver validates the part hash against the hashmap.
    public static let resourceData: UInt8 = 0x03

    /// Resource proof packet (0x04).
    ///
    /// Sent by the receiver after successfully receiving all parts.
    /// Contains the complete resource hash to prove successful assembly.
    /// This signals transfer completion to the sender.
    public static let resourceProof: UInt8 = 0x04

    /// Resource hashmap update packet (0x05).
    ///
    /// Sent by the sender to provide additional hashmap segments for
    /// resources that are split across multiple advertisements due to
    /// size constraints. Contains the next segment's advertisement data.
    public static let resourceHMU: UInt8 = 0x05

    /// Resource cancel packet (0x06).
    ///
    /// Sent by either side to abort the transfer.
    /// After this packet, both sides should discard the resource and
    /// free any allocated buffers.
    public static let resourceCancel: UInt8 = 0x06

    /// Resource reject packet (0x07).
    ///
    /// Sent by the receiver to reject a resource advertisement.
    /// Indicates the receiver does not want to receive this resource.
    /// Sent before transfer begins (in response to advertisement).
    public static let resourceReject: UInt8 = 0x07

    // MARK: - Helpers

    /// Check if a context value is a resource packet context.
    ///
    /// Resource contexts occupy the range 0x01-0x07. Other context values
    /// (like keep-alive 0xFF/0xFE) are not resource packets.
    ///
    /// - Parameter context: Context byte to check
    /// - Returns: true if context is a resource packet type
    public static func isResourceContext(_ context: UInt8) -> Bool {
        return context >= resourceAdvertisement && context <= resourceReject
    }
}
