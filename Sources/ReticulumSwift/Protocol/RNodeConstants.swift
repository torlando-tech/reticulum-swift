// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  RNodeConstants.swift
//  ReticulumSwift
//
//  KISS command constants and protocol values for RNode firmware.
//  Based on Python RNS RNodeInterface.py lines 40-96.
//

import Foundation

/// RNode KISS protocol command constants and firmware requirements.
///
/// These values match the Python KISS class in RNodeInterface.py exactly.
/// Any deviation will cause firmware communication failures.
public enum RNodeConstants {

    // MARK: - Core KISS Commands

    /// Unknown command marker
    public static let CMD_UNKNOWN: UInt8 = 0xFE

    /// Data frame command (default KISS command)
    public static let CMD_DATA: UInt8 = 0x00

    // MARK: - Radio Configuration Commands

    /// Set radio frequency (Hz, 4 bytes big-endian)
    public static let CMD_FREQUENCY: UInt8 = 0x01

    /// Set radio bandwidth (Hz, 4 bytes big-endian)
    public static let CMD_BANDWIDTH: UInt8 = 0x02

    /// Set transmit power (dBm, 1 byte)
    public static let CMD_TXPOWER: UInt8 = 0x03

    /// Set spreading factor (7-12, 1 byte)
    public static let CMD_SF: UInt8 = 0x04

    /// Set coding rate (5-8, 1 byte)
    public static let CMD_CR: UInt8 = 0x05

    /// Radio state control (ON/OFF/ASK)
    public static let CMD_RADIO_STATE: UInt8 = 0x06

    /// Radio lock control
    public static let CMD_RADIO_LOCK: UInt8 = 0x07

    /// Short-term airtime lock (percentage, 1 byte)
    public static let CMD_ST_ALOCK: UInt8 = 0x0B

    /// Long-term airtime lock (percentage, 1 byte)
    public static let CMD_LT_ALOCK: UInt8 = 0x0C

    // MARK: - Handshake Commands

    /// Detect RNode presence (handshake request)
    public static let CMD_DETECT: UInt8 = 0x08

    /// Leave command mode
    public static let CMD_LEAVE: UInt8 = 0x0A

    /// Ready signal from firmware
    public static let CMD_READY: UInt8 = 0x0F

    // MARK: - Statistics Commands

    /// Request RX statistics
    public static let CMD_STAT_RX: UInt8 = 0x21

    /// Request TX statistics
    public static let CMD_STAT_TX: UInt8 = 0x22

    /// Request RSSI
    public static let CMD_STAT_RSSI: UInt8 = 0x23

    /// Request SNR
    public static let CMD_STAT_SNR: UInt8 = 0x24

    /// Request channel time
    public static let CMD_STAT_CHTM: UInt8 = 0x25

    /// Request physical layer parameters
    public static let CMD_STAT_PHYPRM: UInt8 = 0x26

    /// Request battery voltage
    public static let CMD_STAT_BAT: UInt8 = 0x27

    /// Request CSMA statistics
    public static let CMD_STAT_CSMA: UInt8 = 0x28

    /// Request temperature
    public static let CMD_STAT_TEMP: UInt8 = 0x29

    // MARK: - Utility Commands

    /// Blink LED
    public static let CMD_BLINK: UInt8 = 0x30

    /// Request random data
    public static let CMD_RANDOM: UInt8 = 0x40

    // MARK: - Framebuffer Commands

    /// Framebuffer extended commands
    public static let CMD_FB_EXT: UInt8 = 0x41

    /// Framebuffer read
    public static let CMD_FB_READ: UInt8 = 0x42

    /// Framebuffer write
    public static let CMD_FB_WRITE: UInt8 = 0x43

    // MARK: - Display & Bluetooth Commands

    /// Display read command
    public static let CMD_DISP_READ: UInt8 = 0x66

    /// Bluetooth control
    public static let CMD_BT_CTRL: UInt8 = 0x46

    // MARK: - Device Info Commands

    /// Request platform ID
    public static let CMD_PLATFORM: UInt8 = 0x48

    /// Request MCU type
    public static let CMD_MCU: UInt8 = 0x49

    /// Request firmware version
    public static let CMD_FW_VERSION: UInt8 = 0x50

    /// ROM read command
    public static let CMD_ROM_READ: UInt8 = 0x51

    /// Reset device
    public static let CMD_RESET: UInt8 = 0x55

    // MARK: - Detect Protocol

    /// Detect request byte (sent to RNode)
    public static let DETECT_REQ: UInt8 = 0x73

    /// Detect response byte (received from RNode)
    public static let DETECT_RESP: UInt8 = 0x46

    // MARK: - Radio States

    /// Radio is off
    public static let RADIO_STATE_OFF: UInt8 = 0x00

    /// Radio is on
    public static let RADIO_STATE_ON: UInt8 = 0x01

    /// Request current radio state
    public static let RADIO_STATE_ASK: UInt8 = 0xFF

    // MARK: - Error Codes

    /// Error command marker
    public static let CMD_ERROR: UInt8 = 0x90

    /// Radio initialization failed
    public static let ERROR_INITRADIO: UInt8 = 0x01

    /// Transmission failed
    public static let ERROR_TXFAILED: UInt8 = 0x02

    /// EEPROM is locked
    public static let ERROR_EEPROM_LOCKED: UInt8 = 0x03

    /// Packet queue is full
    public static let ERROR_QUEUE_FULL: UInt8 = 0x04

    /// Memory is low
    public static let ERROR_MEMORY_LOW: UInt8 = 0x05

    /// Modem timeout
    public static let ERROR_MODEM_TIMEOUT: UInt8 = 0x06

    /// Invalid configuration (e.g., TX power exceeds device limits)
    public static let ERROR_INVALID_CONFIG: UInt8 = 0x40

    // MARK: - Platform IDs

    /// AVR platform (Arduino, ATmega)
    public static let PLATFORM_AVR: UInt8 = 0x90

    /// ESP32 platform
    public static let PLATFORM_ESP32: UInt8 = 0x80

    /// nRF52 platform (Nordic)
    public static let PLATFORM_NRF52: UInt8 = 0x70

    // MARK: - Firmware Version Requirements

    /// Required major firmware version
    public static let REQUIRED_FW_VER_MAJ: UInt8 = 1

    /// Required minor firmware version (1.52+)
    public static let REQUIRED_FW_VER_MIN: UInt8 = 52

    // MARK: - Hardware Limits

    /// Hardware MTU (maximum transmission unit)
    public static let HW_MTU: Int = 508

    // MARK: - Frequency Limits

    /// Minimum frequency (137 MHz)
    public static let FREQ_MIN: UInt32 = 137_000_000

    /// Maximum frequency (3 GHz)
    public static let FREQ_MAX: UInt32 = 3_000_000_000
}
