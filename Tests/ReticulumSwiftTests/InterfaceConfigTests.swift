// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  InterfaceConfigTests.swift
//  ReticulumSwift
//
//  Tests for RadioConfig Codable conformance and InterfaceConfig persistence.
//

import XCTest
@testable import ReticulumSwift

final class InterfaceConfigTests: XCTestCase {

    // MARK: - RadioConfig Codable

    func testRadioConfigJSONRoundTrip() throws {
        let config = RadioConfig(
            frequency: 915_000_000,
            bandwidth: 125_000,
            txPower: 17,
            spreadingFactor: 7,
            codingRate: 5,
            stAlock: nil,
            ltAlock: nil
        )

        let data = try JSONEncoder().encode(config)
        let decoded = try JSONDecoder().decode(RadioConfig.self, from: data)

        XCTAssertEqual(decoded.frequency, 915_000_000)
        XCTAssertEqual(decoded.bandwidth, 125_000)
        XCTAssertEqual(decoded.txPower, 17)
        XCTAssertEqual(decoded.spreadingFactor, 7)
        XCTAssertEqual(decoded.codingRate, 5)
        XCTAssertNil(decoded.stAlock)
        XCTAssertNil(decoded.ltAlock)
        XCTAssertEqual(config, decoded)
    }

    func testRadioConfigWithOptionalFields() throws {
        let config = RadioConfig(
            frequency: 868_000_000,
            bandwidth: 250_000,
            txPower: 14,
            spreadingFactor: 12,
            codingRate: 8,
            stAlock: 50.0,
            ltAlock: 25.0
        )

        let data = try JSONEncoder().encode(config)
        let decoded = try JSONDecoder().decode(RadioConfig.self, from: data)

        XCTAssertEqual(decoded.stAlock, 50.0)
        XCTAssertEqual(decoded.ltAlock, 25.0)
        XCTAssertEqual(config, decoded)
    }

    func testRadioConfigPropertyListRoundTrip() throws {
        let config = RadioConfig(
            frequency: 433_050_000,
            bandwidth: 62_500,
            txPower: 10,
            spreadingFactor: 9,
            codingRate: 6,
            stAlock: nil,
            ltAlock: nil
        )

        let data = try PropertyListEncoder().encode(config)
        let decoded = try PropertyListDecoder().decode(RadioConfig.self, from: data)
        XCTAssertEqual(config, decoded)
    }

    // MARK: - InterfaceConfig with RNode Type

    func testInterfaceConfigRNodeType() throws {
        let config = InterfaceConfig(
            id: "rnode1",
            name: "RNode A9",
            type: .rnode,
            enabled: true,
            mode: .full,
            host: "RNode_A9",
            port: 0
        )

        XCTAssertEqual(config.type, .rnode)
        XCTAssertEqual(config.host, "RNode_A9")
        XCTAssertEqual(config.port, 0)

        // Verify PropertyList round-trip
        let data = try PropertyListEncoder().encode(config)
        let decoded = try PropertyListDecoder().decode(InterfaceConfig.self, from: data)
        XCTAssertEqual(config, decoded)
    }

    func testInterfaceConfigTCPStillWorks() throws {
        let config = InterfaceConfig(
            id: "tcp1",
            name: "TCP Server",
            type: .tcp,
            enabled: true,
            mode: .full,
            host: "10.0.0.1",
            port: 4242
        )

        let data = try PropertyListEncoder().encode(config)
        let decoded = try PropertyListDecoder().decode(InterfaceConfig.self, from: data)
        XCTAssertEqual(config, decoded)
        XCTAssertEqual(decoded.type, .tcp)
    }
}
