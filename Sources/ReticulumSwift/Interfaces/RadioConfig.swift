//
//  RadioConfig.swift
//  ReticulumSwift
//
//  Configuration for LoRa radio parameters on RNode devices.
//

import Foundation

/// Configuration for RNode LoRa radio parameters.
///
/// All parameters must be within the valid ranges for the radio hardware.
/// Use `validate()` to check configuration before applying to the radio.
///
/// Example:
/// ```swift
/// var config = RadioConfig(
///     frequency: 915_000_000,  // 915 MHz ISM band
///     bandwidth: 125_000,      // 125 kHz
///     txPower: 17,             // 17 dBm
///     spreadingFactor: 7,      // SF7
///     codingRate: 5            // 4/5
/// )
/// try config.validate()
/// ```
public struct RadioConfig: Sendable, Equatable {

    // MARK: - Properties

    /// Radio frequency in Hz.
    ///
    /// Valid range: 137 MHz to 3 GHz (hardware dependent).
    /// Common ISM bands:
    /// - 433 MHz: 433_050_000 to 434_790_000
    /// - 868 MHz: 863_000_000 to 870_000_000 (EU)
    /// - 915 MHz: 902_000_000 to 928_000_000 (US)
    public var frequency: UInt32

    /// Radio bandwidth in Hz.
    ///
    /// Valid values: 7800, 10400, 15600, 20800, 31250, 41700, 62500, 125000, 250000, 500000.
    /// Lower bandwidth = longer range, lower data rate.
    public var bandwidth: UInt32

    /// Transmit power in dBm.
    ///
    /// Valid range: typically 2-22 dBm (hardware dependent).
    /// Check local regulations for maximum allowed power.
    public var txPower: UInt8

    /// LoRa spreading factor (SF).
    ///
    /// Valid range: 7-12.
    /// Higher SF = longer range, lower data rate, more airtime.
    public var spreadingFactor: UInt8

    /// LoRa coding rate.
    ///
    /// Valid range: 5-8, representing rates 4/5, 4/6, 4/7, 4/8.
    /// Higher coding rate = more error correction, more airtime.
    public var codingRate: UInt8

    /// Short-term airtime lock percentage (0-100%).
    ///
    /// Limits airtime usage over short time windows.
    /// Optional; if nil, no short-term limit is enforced.
    public var stAlock: Float?

    /// Long-term airtime lock percentage (0-100%).
    ///
    /// Limits airtime usage over long time windows.
    /// Optional; if nil, no long-term limit is enforced.
    public var ltAlock: Float?

    // MARK: - Initialization

    public init(
        frequency: UInt32,
        bandwidth: UInt32,
        txPower: UInt8,
        spreadingFactor: UInt8,
        codingRate: UInt8,
        stAlock: Float? = nil,
        ltAlock: Float? = nil
    ) {
        self.frequency = frequency
        self.bandwidth = bandwidth
        self.txPower = txPower
        self.spreadingFactor = spreadingFactor
        self.codingRate = codingRate
        self.stAlock = stAlock
        self.ltAlock = ltAlock
    }

    // MARK: - Validation

    /// Valid bandwidth values in Hz.
    private static let validBandwidths: Set<UInt32> = [
        7_800, 10_400, 15_600, 20_800, 31_250, 41_700,
        62_500, 125_000, 250_000, 500_000
    ]

    /// Validate all radio parameters.
    ///
    /// Checks that frequency, bandwidth, spreading factor, coding rate,
    /// and airtime locks are within valid ranges.
    ///
    /// - Throws: `RNodeError.radioConfigFailed` if any parameter is invalid.
    public func validate() throws {
        // Validate frequency
        if frequency < RNodeConstants.FREQ_MIN || frequency > RNodeConstants.FREQ_MAX {
            throw RNodeError.radioConfigFailed(
                "Frequency \(frequency) Hz is out of range (\(RNodeConstants.FREQ_MIN)-\(RNodeConstants.FREQ_MAX) Hz)"
            )
        }

        // Validate bandwidth
        if !Self.validBandwidths.contains(bandwidth) {
            let validBwList = Self.validBandwidths.sorted().map { "\($0)" }.joined(separator: ", ")
            throw RNodeError.radioConfigFailed(
                "Bandwidth \(bandwidth) Hz is not valid. Must be one of: \(validBwList)"
            )
        }

        // Validate spreading factor
        if spreadingFactor < 7 || spreadingFactor > 12 {
            throw RNodeError.radioConfigFailed(
                "Spreading factor \(spreadingFactor) is out of range (7-12)"
            )
        }

        // Validate coding rate
        if codingRate < 5 || codingRate > 8 {
            throw RNodeError.radioConfigFailed(
                "Coding rate \(codingRate) is out of range (5-8)"
            )
        }

        // Validate short-term airtime lock
        if let st = stAlock {
            if st < 0 || st > 100 {
                throw RNodeError.radioConfigFailed(
                    "Short-term airtime lock \(st)% is out of range (0-100%)"
                )
            }
        }

        // Validate long-term airtime lock
        if let lt = ltAlock {
            if lt < 0 || lt > 100 {
                throw RNodeError.radioConfigFailed(
                    "Long-term airtime lock \(lt)% is out of range (0-100%)"
                )
            }
        }
    }
}

// MARK: - Codable

extension RadioConfig: Codable {}
