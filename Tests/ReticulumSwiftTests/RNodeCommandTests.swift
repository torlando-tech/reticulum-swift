// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  RNodeCommandTests.swift
//  ReticulumSwiftTests
//
//  Unit tests for RNode KISS command encoding and constants.
//

import XCTest
@testable import ReticulumSwift

final class RNodeCommandTests: XCTestCase {

    // MARK: - Constant Value Tests

    func testCommandConstants() {
        // Core commands (Python KISS class lines 40-96)
        XCTAssertEqual(RNodeConstants.CMD_DATA, 0x00)
        XCTAssertEqual(RNodeConstants.CMD_FREQUENCY, 0x01)
        XCTAssertEqual(RNodeConstants.CMD_BANDWIDTH, 0x02)
        XCTAssertEqual(RNodeConstants.CMD_TXPOWER, 0x03)
        XCTAssertEqual(RNodeConstants.CMD_SF, 0x04)
        XCTAssertEqual(RNodeConstants.CMD_CR, 0x05)
        XCTAssertEqual(RNodeConstants.CMD_RADIO_STATE, 0x06)
        XCTAssertEqual(RNodeConstants.CMD_DETECT, 0x08)
        XCTAssertEqual(RNodeConstants.CMD_READY, 0x0F)
    }

    func testErrorCodeConstants() {
        XCTAssertEqual(RNodeConstants.CMD_ERROR, 0x90)
        XCTAssertEqual(RNodeConstants.ERROR_INITRADIO, 0x01)
        XCTAssertEqual(RNodeConstants.ERROR_TXFAILED, 0x02)
        XCTAssertEqual(RNodeConstants.ERROR_QUEUE_FULL, 0x04)
        XCTAssertEqual(RNodeConstants.ERROR_MEMORY_LOW, 0x05)
        XCTAssertEqual(RNodeConstants.ERROR_MODEM_TIMEOUT, 0x06)
        XCTAssertEqual(RNodeConstants.ERROR_INVALID_CONFIG, 0x40)
    }

    func testDetectConstants() {
        XCTAssertEqual(RNodeConstants.DETECT_REQ, 0x73)
        XCTAssertEqual(RNodeConstants.DETECT_RESP, 0x46)
    }

    func testPlatformConstants() {
        XCTAssertEqual(RNodeConstants.PLATFORM_ESP32, 0x80)
        XCTAssertEqual(RNodeConstants.PLATFORM_NRF52, 0x70)
        XCTAssertEqual(RNodeConstants.PLATFORM_AVR, 0x90)
    }

    func testFirmwareRequirements() {
        XCTAssertEqual(RNodeConstants.REQUIRED_FW_VER_MAJ, 1)
        XCTAssertEqual(RNodeConstants.REQUIRED_FW_VER_MIN, 52)
    }

    // MARK: - KISS Command Frame Encoding Tests

    func testFrequencyCommandEncoding() {
        // 915 MHz = 915000000 = 0x36918C40
        let freq: UInt32 = 915_000_000
        let payload = Data([
            UInt8(freq >> 24),           // 0x36
            UInt8((freq >> 16) & 0xFF),  // 0x91
            UInt8((freq >> 8) & 0xFF),   // 0x8C
            UInt8(freq & 0xFF)           // 0x40
        ])
        let frame = KISS.frame(payload, command: RNodeConstants.CMD_FREQUENCY)

        XCTAssertEqual(frame[0], KISS.FEND)
        XCTAssertEqual(frame[1], RNodeConstants.CMD_FREQUENCY)
        XCTAssertEqual(frame.last, KISS.FEND)

        // Verify payload bytes
        let unescaped = try! KISS.unescape(Data(frame[2..<(frame.count-1)]))
        XCTAssertEqual(unescaped, payload)
    }

    func testFrequencyCommandWithEscapedBytes() {
        // Frequency where byte 0 is 0xC0 (FEND) needs escaping
        let payload = Data([0xC0, 0x00, 0x00, 0x00])
        let escaped = KISS.escape(payload)
        // 0xC0 should become [0xDB, 0xDC]
        XCTAssertEqual(escaped[0], KISS.FESC)
        XCTAssertEqual(escaped[1], KISS.TFEND)
    }

    func testBandwidthCommandEncoding() {
        // 125 kHz = 125000 = 0x0001E848
        let bw: UInt32 = 125_000
        let payload = Data([
            UInt8(bw >> 24),
            UInt8((bw >> 16) & 0xFF),
            UInt8((bw >> 8) & 0xFF),
            UInt8(bw & 0xFF)
        ])
        XCTAssertEqual(payload, Data([0x00, 0x01, 0xE8, 0x48]))
    }

    func testSingleByteCommandEncoding() {
        // TX Power = 17 dBm
        let frame = KISS.frame(Data([17]), command: RNodeConstants.CMD_TXPOWER)
        XCTAssertEqual(frame[0], KISS.FEND)
        XCTAssertEqual(frame[1], RNodeConstants.CMD_TXPOWER)
        XCTAssertEqual(frame[2], 17)
        XCTAssertEqual(frame[3], KISS.FEND)

        // Spreading Factor = 10
        let sfFrame = KISS.frame(Data([10]), command: RNodeConstants.CMD_SF)
        XCTAssertEqual(sfFrame[1], RNodeConstants.CMD_SF)
        XCTAssertEqual(sfFrame[2], 10)

        // Coding Rate = 5
        let crFrame = KISS.frame(Data([5]), command: RNodeConstants.CMD_CR)
        XCTAssertEqual(crFrame[1], RNodeConstants.CMD_CR)
        XCTAssertEqual(crFrame[2], 5)
    }

    func testRadioStateCommandEncoding() {
        let onFrame = KISS.frame(Data([RNodeConstants.RADIO_STATE_ON]), command: RNodeConstants.CMD_RADIO_STATE)
        XCTAssertEqual(onFrame[1], RNodeConstants.CMD_RADIO_STATE)
        XCTAssertEqual(onFrame[2], 0x01)

        let offFrame = KISS.frame(Data([RNodeConstants.RADIO_STATE_OFF]), command: RNodeConstants.CMD_RADIO_STATE)
        XCTAssertEqual(offFrame[2], 0x00)
    }

    func testDetectHandshakeBytes() {
        let expected = Data([
            KISS.FEND, RNodeConstants.CMD_DETECT, RNodeConstants.DETECT_REQ, KISS.FEND,
            RNodeConstants.CMD_FW_VERSION, 0x00, KISS.FEND,
            RNodeConstants.CMD_PLATFORM, 0x00, KISS.FEND,
            RNodeConstants.CMD_MCU, 0x00, KISS.FEND
        ])
        XCTAssertEqual(expected.count, 13)
        XCTAssertEqual(expected[0], 0xC0)  // FEND
        XCTAssertEqual(expected[1], 0x08)  // CMD_DETECT
        XCTAssertEqual(expected[2], 0x73)  // DETECT_REQ
        XCTAssertEqual(expected[3], 0xC0)  // FEND
    }

    func testAirtimeLockEncoding() {
        let stAlock: Float = 50.5
        let at = UInt16(stAlock * 100)
        let payload = Data([UInt8(at >> 8), UInt8(at & 0xFF)])
        XCTAssertEqual(payload, Data([0x13, 0xBA]))
    }

    // MARK: - RadioConfig Validation Tests

    func testRadioConfigValid() {
        let valid = RadioConfig(
            frequency: 915_000_000,
            bandwidth: 125_000,
            txPower: 17,
            spreadingFactor: 10,
            codingRate: 5
        )
        XCTAssertNoThrow(try valid.validate())
    }

    func testRadioConfigInvalidFrequencyLow() {
        let lowFreq = RadioConfig(frequency: 100_000_000, bandwidth: 125_000, txPower: 17, spreadingFactor: 10, codingRate: 5)
        XCTAssertThrowsError(try lowFreq.validate())
    }

    func testRadioConfigInvalidSpreadingFactor() {
        let badSF = RadioConfig(frequency: 915_000_000, bandwidth: 125_000, txPower: 17, spreadingFactor: 13, codingRate: 5)
        XCTAssertThrowsError(try badSF.validate())
    }

    func testRadioConfigInvalidCodingRate() {
        let badCR = RadioConfig(frequency: 915_000_000, bandwidth: 125_000, txPower: 17, spreadingFactor: 10, codingRate: 9)
        XCTAssertThrowsError(try badCR.validate())
    }

    func testRadioConfigInvalidBandwidth() {
        let badBW = RadioConfig(frequency: 915_000_000, bandwidth: 99_999, txPower: 17, spreadingFactor: 10, codingRate: 5)
        XCTAssertThrowsError(try badBW.validate())
    }

    // MARK: - SNR Calculation Tests

    func testSnrPositiveValue() {
        // SNR byte 0x14 (20 signed) → 20 / 4.0 = 5.0 dB
        let snrByte: UInt8 = 0x14
        let snr = Double(Int8(bitPattern: snrByte)) / 4.0
        XCTAssertEqual(snr, 5.0)
    }

    func testSnrNegativeValue() {
        // SNR byte 0xEC (-20 signed) → -20 / 4.0 = -5.0 dB
        let negByte: UInt8 = 0xEC
        let negSnr = Double(Int8(bitPattern: negByte)) / 4.0
        XCTAssertEqual(negSnr, -5.0)
    }

    func testSnrZero() {
        let zeroByte: UInt8 = 0x00
        let snr = Double(Int8(bitPattern: zeroByte)) / 4.0
        XCTAssertEqual(snr, 0.0)
    }

    func testSnrQuarterDbResolution() {
        // SNR byte 0x01 (1 signed) → 1 / 4.0 = 0.25 dB
        let snrByte: UInt8 = 0x01
        let snr = Double(Int8(bitPattern: snrByte)) / 4.0
        XCTAssertEqual(snr, 0.25)
    }
}
