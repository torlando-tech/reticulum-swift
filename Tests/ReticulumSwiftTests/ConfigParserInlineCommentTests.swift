// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ConfigParserInlineCommentTests.swift
//  ReticulumSwiftTests
//
//  Covers the ConfigObj-style inline-comment stripping in ConfigParser
//  (InterfaceConfigSynthesizer.swift). RNS uses RNS.vendor.configobj, whose
//  value/section regexes end with `\s*(\#.*)?$` — an UNQUOTED `#` begins an inline
//  comment, a `#` inside quotes is literal. Before the fix the parser kept the
//  comment in the value (`bitrate = 9600 # c` -> `9600 # c`), which then failed
//  as_int and silently dropped the field — common in real RNS configs.
//

import XCTest
@testable import ReticulumSwift

final class ConfigParserInlineCommentTests: XCTestCase {

    func testInlineCommentStrippedFromValue() throws {
        let cfg = """
        [interfaces]
          [[Test]]
            type = RNodeInterface
            bitrate = 9600  # uplink radio
            enabled = true # inline
        """
        let iface = ConfigParser.parse(cfg)
            .subsections["interfaces"]?.subsections["Test"]
        XCTAssertNotNil(iface)
        XCTAssertEqual(iface?.string("bitrate"), "9600",
            "Inline comment must be stripped from the value")
        XCTAssertEqual(try iface?.asInt("bitrate"), 9600,
            "The cleaned value must coerce via as_int (the bug Greptile flagged)")
        XCTAssertEqual(iface?.string("type"), "RNodeInterface")
        XCTAssertEqual(try iface?.asBool("enabled"), true)
    }

    func testHashInsideQuotesIsPreserved() {
        // configobj treats `#` inside quotes as literal; only the trailing unquoted
        // `#` is the inline comment. (Quote characters themselves are kept — this
        // narrow port does not strip surrounding quotes, matching prior behaviour.)
        let cfg = """
        [interfaces]
          [[Net]]
            name = "alpha # one"  # real comment
        """
        let iface = ConfigParser.parse(cfg)
            .subsections["interfaces"]?.subsections["Net"]
        XCTAssertEqual(iface?.string("name"), "\"alpha # one\"",
            "A # inside quotes must NOT be treated as a comment")
    }

    func testInlineCommentOnSectionHeaderStillParses() {
        let cfg = """
        [interfaces]  # top-level
          [[Gw]]  # the gateway
            type = TCPClientInterface
        """
        let iface = ConfigParser.parse(cfg)
            .subsections["interfaces"]?.subsections["Gw"]
        XCTAssertNotNil(iface, "A section header with an inline comment must still parse")
        XCTAssertEqual(iface?.string("type"), "TCPClientInterface")
    }

    func testStripInlineCommentQuoteAware() {
        XCTAssertEqual(
            ConfigParser.stripInlineComment("9600  # c").trimmingCharacters(in: .whitespaces),
            "9600")
        XCTAssertEqual(ConfigParser.stripInlineComment("\"a # b\" # c"), "\"a # b\" ")
        XCTAssertEqual(ConfigParser.stripInlineComment("'x # y' rest # z"), "'x # y' rest ")
        XCTAssertEqual(ConfigParser.stripInlineComment("# whole line"), "")
        XCTAssertEqual(ConfigParser.stripInlineComment("plain"), "plain")
    }
}
