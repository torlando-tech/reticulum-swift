// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  InterfaceConfigSynthesizer.swift
//  ReticulumSwift
//
//  A focused port of RNS's vendored ConfigObj INI parser and the config-derived
//  decisions in Reticulum._synthesize_interface (Reticulum/RNS/Reticulum.py:685-1034).
//
//  Python RNS parses its interface configuration from a ConfigObj INI file and
//  then turns each [[interface]] subsection into live interface attributes in
//  Reticulum._synthesize_interface. The handful of config-derived RULES that are
//  security/interop relevant — interface_mode alias selection + precedence, the
//  discoverable->gateway/AP forcing, the bitrate/announce_cap/ifac_size bound
//  checks, the discovery announce-interval floor/default, the ic_* ingress-control
//  knobs, and IFAC networkname/passphrase credential resolution — are reproduced
//  here exactly against the reference site, so the synthesized attributes match
//  RNS byte-for-byte for the keys under conformance.
//
//  This is a deliberately narrow port: it models the config-parse pipeline (parse
//  -> synthesize -> read-back attrs), not the full interface instantiation /
//  Transport.add_interface machinery. The interface type seen in conformance is
//  the no-op ConfigParseProbeInterface (DEFAULT_IFAC_SIZE == 16, AUTOCONFIGURE_MTU
//  == False, seed bitrate 62500); the RNode AP-vs-gateway forcing branch keys off
//  the configured `type`, matching Reticulum.py:843-848.
//

import Foundation

// MARK: - ConfigObj INI parsing

/// A parsed ConfigObj section: scalar key/value pairs plus nested subsections.
///
/// Mirrors the slice of `RNS.vendor.configobj.ConfigObj` semantics the interface
/// synthesizer relies on: nesting by bracket depth (`[interfaces]` -> `[[name]]`),
/// `key = value` scalars (values trimmed, empty allowed), and the `as_int` /
/// `as_float` / `as_bool` coercions. Comment and blank lines are skipped.
public final class ConfigSection {

    /// Scalar key -> raw string value (already whitespace-trimmed).
    public private(set) var scalars: [String: String] = [:]

    /// Nested subsection name -> section.
    public private(set) var subsections: [String: ConfigSection] = [:]

    public init() {}

    /// Whether a scalar key is present (`"key" in c`).
    public func contains(_ key: String) -> Bool { scalars[key] != nil }

    /// Raw scalar value (`c["key"]`), or nil if absent.
    public func string(_ key: String) -> String? { scalars[key] }

    func setScalar(_ key: String, _ value: String) { scalars[key] = value }

    /// Get-or-create a nested subsection.
    func subsection(_ name: String) -> ConfigSection {
        if let existing = subsections[name] { return existing }
        let created = ConfigSection()
        subsections[name] = created
        return created
    }

    // ConfigObj coercions. These mirror ConfigObj.as_int / as_float / as_bool:
    // int()/float() of the string, and a fixed truthy/falsy token table.

    /// `c.as_int(key)` — Python `int(value)`. Throws on a non-integer token.
    public func asInt(_ key: String) throws -> Int {
        guard let raw = scalars[key] else {
            throw InterfaceConfigSynthesizer.SynthesisError.keyError(key)
        }
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard let value = Int(trimmed) else {
            throw InterfaceConfigSynthesizer.SynthesisError.valueError(
                "invalid literal for as_int(\(key)): '\(raw)'")
        }
        return value
    }

    /// `c.as_float(key)` — Python `float(value)`. Throws on a non-numeric token.
    public func asFloat(_ key: String) throws -> Double {
        guard let raw = scalars[key] else {
            throw InterfaceConfigSynthesizer.SynthesisError.keyError(key)
        }
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard let value = Double(trimmed) else {
            throw InterfaceConfigSynthesizer.SynthesisError.valueError(
                "could not convert string to float for as_float(\(key)): '\(raw)'")
        }
        return value
    }

    /// `c.as_bool(key)` — ConfigObj's truthy/falsy token table (case-insensitive:
    /// true/yes/on/1 vs false/no/off/0). Throws on an unrecognized token.
    public func asBool(_ key: String) throws -> Bool {
        guard let raw = scalars[key] else {
            throw InterfaceConfigSynthesizer.SynthesisError.keyError(key)
        }
        switch raw.trimmingCharacters(in: .whitespaces).lowercased() {
        case "true", "yes", "on", "1": return true
        case "false", "no", "off", "0": return false
        default:
            throw InterfaceConfigSynthesizer.SynthesisError.valueError(
                "Value '\(raw)' is neither True nor False for as_bool(\(key))")
        }
    }
}

/// Minimal ConfigObj-compatible INI parser.
///
/// Supports exactly the structure RNS interface config uses: section headers
/// nested by bracket depth (`[x]`, `[[y]]`, `[[[z]]]`) and `key = value` scalars.
/// Indentation is cosmetic — nesting is determined solely by bracket count, as in
/// ConfigObj. Blank lines and `#`-prefixed comment lines are skipped.
public enum ConfigParser {

    public static func parse(_ text: String) -> ConfigSection {
        let root = ConfigSection()
        // Ancestor stack: (depth, section). Root is depth 0.
        var stack: [(depth: Int, section: ConfigSection)] = [(0, root)]

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }

            if line.hasPrefix("[") {
                // Section header: depth == number of leading '[' brackets.
                var depth = 0
                for ch in line {
                    if ch == "[" { depth += 1 } else { break }
                }
                // Name sits between the `depth` opening and `depth` closing brackets.
                let inner = line.dropFirst(depth).dropLast(depth)
                let name = inner.trimmingCharacters(in: .whitespaces)
                // A header at depth d nests under the section at depth d-1: drop
                // any deeper-or-equal ancestors, then attach to the new parent.
                while let top = stack.last, top.depth >= depth { stack.removeLast() }
                let parent = stack.last?.section ?? root
                let child = parent.subsection(name)
                stack.append((depth, child))
            } else if let eq = line.firstIndex(of: "=") {
                let key = line[line.startIndex..<eq].trimmingCharacters(in: .whitespaces)
                let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
                stack.last?.section.setScalar(key, value)
            }
            // Lines without '=' or a section header are ignored (as ConfigObj
            // would for our inputs — there are none in conformance configs).
        }

        return root
    }
}

// MARK: - Interface synthesis

/// A focused port of `Reticulum._synthesize_interface` (Reticulum.py:685-1034):
/// parse a single interface config section and compute the attributes RNS would
/// store onto the live interface object.
public enum InterfaceConfigSynthesizer {

    // Interface.MODE_* spec literals (Interfaces/Interface.py:45-50). Carried as
    // raw bytes here because the wire-visible mode is the byte, not the Swift enum.
    public static let MODE_FULL = 0x01
    public static let MODE_POINT_TO_POINT = 0x02
    public static let MODE_ACCESS_POINT = 0x03
    public static let MODE_ROAMING = 0x04
    public static let MODE_BOUNDARY = 0x05
    public static let MODE_GATEWAY = 0x06

    // Reticulum config bound constants (Reticulum.py:113,133,148).
    static let ANNOUNCE_CAP_PERCENT = 2.0          // Reticulum.ANNOUNCE_CAP
    static let MINIMUM_BITRATE = 5                  // Reticulum.MINIMUM_BITRATE
    static let IFAC_MIN_SIZE = 1                    // Reticulum.IFAC_MIN_SIZE

    // Interface ingress-control class-constant defaults (Interface.py:70-82),
    // seeded onto every interface in Interface.__init__ and overridden per-config.
    static let IC_MAX_HELD_ANNOUNCES = 256
    static let IC_BURST_FREQ_NEW: Double = 3
    static let IC_BURST_FREQ: Double = 10
    static let IC_BURST_HOLD: Double = 15
    static let IC_BURST_PENALTY: Double = 15
    static let IC_HELD_RELEASE_INTERVAL: Double = 5
    static let IC_NEW_TIME: Double = 2 * 60 * 60   // 7200

    /// The no-op probe interface's class constants (bridge ConfigParseProbeInterface).
    static let PROBE_DEFAULT_IFAC_SIZE = 16        // ConfigParseProbeInterface.DEFAULT_IFAC_SIZE
    static let PROBE_SEED_BITRATE = 62500          // probe __init__ seed bitrate

    public enum SynthesisError: Error, CustomStringConvertible {
        /// `[interfaces]` / `[[name]]` not found in the parsed config.
        case missingSection(String)
        /// Faithful reproduction of the upstream KeyError quirk
        /// (Reticulum.py:701: the gateway arm reads c["mode"], not c["interface_mode"]).
        case keyError(String)
        /// A ConfigObj as_int/as_float/as_bool coercion failed.
        case valueError(String)

        public var description: String {
            switch self {
            case .missingSection(let s): return "missingSection: \(s)"
            case .keyError(let k): return "KeyError: '\(k)'"
            case .valueError(let m): return "ValueError: \(m)"
            }
        }
    }

    /// The synthesized interface attributes RNS would store (read straight back by
    /// the bridge). Optionals carry RNS's None where a value is unset/rejected.
    public struct Synthesized {
        public var interfaceEnabled: Bool
        public var selectedInterfaceMode: Int
        public var configuredBitrate: Int?
        public var bitrate: Int
        public var announceCap: Double
        public var ifacSize: Int
        public var defaultIfacSize: Int
        public var discoverable: Bool
        public var discoveryAnnounceInterval: Int?
        public var ifacNetname: String?
        public var ifacNetkey: String?
        public var ifacActive: Bool
        public var icMaxHeldAnnounces: Int?
        public var icBurstHold: Double?
        public var icBurstFreqNew: Double?
        public var icBurstFreq: Double?
        public var icNewTime: Double?
        public var icBurstPenalty: Double?
        public var icHeldReleaseInterval: Double?

        public var modeName: String? {
            switch selectedInterfaceMode {
            case MODE_FULL: return "full"
            case MODE_POINT_TO_POINT: return "pointtopoint"
            case MODE_ACCESS_POINT: return "access_point"
            case MODE_ROAMING: return "roaming"
            case MODE_BOUNDARY: return "boundary"
            case MODE_GATEWAY: return "gateway"
            default: return nil
            }
        }
    }

    /// Parse raw config text, locate `[interfaces][[name]]`, and synthesize.
    public static func parseAndSynthesize(configText: String, interfaceName: String) throws -> Synthesized {
        let root = ConfigParser.parse(configText)
        guard let interfaces = root.subsections["interfaces"],
              let section = interfaces.subsections[interfaceName] else {
            throw SynthesisError.missingSection(
                "config_text has no [[\(interfaceName)]] under [interfaces]")
        }
        return try synthesize(section)
    }

    /// Compute interface attributes from a single interface config section,
    /// mirroring Reticulum._synthesize_interface (Reticulum.py:685-1034).
    public static func synthesize(_ c: ConfigSection) throws -> Synthesized {
        // --- interface_mode selection + precedence (Reticulum.py:687-717) ---
        // interface_mode takes precedence over the legacy `mode` key. The gateway
        // arm of the interface_mode branch reads c["mode"] (upstream quirk:701).
        var interfaceMode = MODE_FULL
        if c.contains("interface_mode") {
            let im = (c.string("interface_mode") ?? "").lowercased()
            switch im {
            case "full": interfaceMode = MODE_FULL
            case "access_point", "accesspoint", "ap": interfaceMode = MODE_ACCESS_POINT
            case "pointtopoint", "ptp": interfaceMode = MODE_POINT_TO_POINT
            case "roaming": interfaceMode = MODE_ROAMING
            case "boundary": interfaceMode = MODE_BOUNDARY
            default:
                // elif c["mode"] == "gateway" or c["mode"] == "gw": ...
                // c["mode"] is read RAW (not lowercased) here, and raises KeyError
                // when "mode" is absent — reproduce both behaviours faithfully.
                guard let modeVal = c.string("mode") else {
                    throw SynthesisError.keyError("mode")
                }
                if modeVal == "gateway" || modeVal == "gw" {
                    interfaceMode = MODE_GATEWAY
                }
                // any other value leaves interfaceMode at the default (FULL)
            }
        } else if c.contains("mode") {
            let m = (c.string("mode") ?? "").lowercased()
            switch m {
            case "full": interfaceMode = MODE_FULL
            case "access_point", "accesspoint", "ap": interfaceMode = MODE_ACCESS_POINT
            case "pointtopoint", "ptp": interfaceMode = MODE_POINT_TO_POINT
            case "roaming": interfaceMode = MODE_ROAMING
            case "boundary": interfaceMode = MODE_BOUNDARY
            case "gateway", "gw": interfaceMode = MODE_GATEWAY
            default: interfaceMode = MODE_FULL
            }
        }

        // --- ifac_size bound (Reticulum.py:719-722) ---
        var ifacSize: Int? = nil
        if c.contains("ifac_size") {
            if try c.asInt("ifac_size") >= IFAC_MIN_SIZE * 8 {
                ifacSize = try c.asInt("ifac_size") / 8
            }
        }

        // --- IFAC credential resolution (Reticulum.py:724-738) ---
        // networkname/network_name -> ifac_netname; passphrase/pass_phrase ->
        // ifac_netkey. The later alias wins; an empty-string value means UNSET.
        var ifacNetname: String? = nil
        if let v = c.string("networkname"), v != "" { ifacNetname = v }
        if let v = c.string("network_name"), v != "" { ifacNetname = v }

        var ifacNetkey: String? = nil
        if let v = c.string("passphrase"), v != "" { ifacNetkey = v }
        if let v = c.string("pass_phrase"), v != "" { ifacNetkey = v }

        // --- ingress-control knobs (Reticulum.py:744-763) ---
        // Seeded to the Interface class-constant defaults (Interface.__init__),
        // overridden when the config provides the key.
        var icMaxHeldAnnounces: Int? = IC_MAX_HELD_ANNOUNCES
        var icBurstHold: Double? = IC_BURST_HOLD
        var icBurstFreqNew: Double? = IC_BURST_FREQ_NEW
        var icBurstFreq: Double? = IC_BURST_FREQ
        var icNewTime: Double? = IC_NEW_TIME
        var icBurstPenalty: Double? = IC_BURST_PENALTY
        var icHeldReleaseInterval: Double? = IC_HELD_RELEASE_INTERVAL
        if c.contains("ic_max_held_announces") { icMaxHeldAnnounces = try c.asInt("ic_max_held_announces") }
        if c.contains("ic_burst_hold") { icBurstHold = try c.asFloat("ic_burst_hold") }
        if c.contains("ic_burst_freq_new") { icBurstFreqNew = try c.asFloat("ic_burst_freq_new") }
        if c.contains("ic_burst_freq") { icBurstFreq = try c.asFloat("ic_burst_freq") }
        if c.contains("ic_new_time") { icNewTime = try c.asFloat("ic_new_time") }
        if c.contains("ic_burst_penalty") { icBurstPenalty = try c.asFloat("ic_burst_penalty") }
        if c.contains("ic_held_release_interval") { icHeldReleaseInterval = try c.asFloat("ic_held_release_interval") }

        // --- bitrate bound (Reticulum.py:765-768) ---
        var configuredBitrate: Int? = nil
        if c.contains("bitrate") {
            if try c.asInt("bitrate") >= MINIMUM_BITRATE {
                configuredBitrate = try c.asInt("bitrate")
            }
        }

        // --- announce_cap bound (Reticulum.py:791-794) ---
        var announceCap = ANNOUNCE_CAP_PERCENT / 100.0
        if c.contains("announce_cap") {
            let v = try c.asFloat("announce_cap")
            if v > 0 && v <= 100 { announceCap = v / 100.0 }
        }

        let ignoreConfigWarnings = c.contains("ignore_config_warnings")
            ? (try c.asBool("ignore_config_warnings")) : false

        // --- discoverable + discovery announce-interval (Reticulum.py:807-848) ---
        var discoverable = false
        var discoveryAnnounceInterval: Int? = nil
        if c.contains("discoverable") {
            discoverable = try c.asBool("discoverable")
            if discoverable {
                if c.contains("announce_interval") {
                    var v = try c.asInt("announce_interval") * 60
                    if v < 5 * 60 { v = 5 * 60 }        // 5-minute floor
                    discoveryAnnounceInterval = v
                }
                if discoveryAnnounceInterval == nil { discoveryAnnounceInterval = 6 * 60 * 60 } // 6h default

                // discoverable without a relay-capable mode is auto-promoted:
                // RNode types -> AP, everything else -> GATEWAY (Reticulum.py:841-848).
                if interfaceMode != MODE_GATEWAY && interfaceMode != MODE_ACCESS_POINT {
                    if !ignoreConfigWarnings {
                        let type = c.string("type") ?? ""
                        if type == "RNodeInterface" || type == "RNodeMultiInterface" {
                            interfaceMode = MODE_ACCESS_POINT
                        } else {
                            interfaceMode = MODE_GATEWAY
                        }
                    }
                }
            }
        }

        // --- interface_post_init: store attrs onto the interface (Reticulum.py:850-919) ---
        let interfaceEnabled =
            (c.contains("interface_enabled") && ((try? c.asBool("interface_enabled")) ?? false))
            || (c.contains("enabled") && ((try? c.asBool("enabled")) ?? false))

        // interface.bitrate: probe seed (62500) unless a valid configured_bitrate
        // overrides it; AUTOCONFIGURE_MTU is False on the probe, so optimise_mtu()
        // leaves the bitrate untouched.
        let bitrate = configuredBitrate ?? PROBE_SEED_BITRATE
        // interface.ifac_size: configured value, else DEFAULT_IFAC_SIZE.
        let storedIfacSize = ifacSize ?? PROBE_DEFAULT_IFAC_SIZE
        // ifac_identity is derived iff netname or netkey is non-None (Reticulum.py:898).
        let ifacActive = (ifacNetname != nil) || (ifacNetkey != nil)

        return Synthesized(
            interfaceEnabled: interfaceEnabled,
            selectedInterfaceMode: interfaceMode,
            configuredBitrate: configuredBitrate,
            bitrate: bitrate,
            announceCap: announceCap,
            ifacSize: storedIfacSize,
            defaultIfacSize: PROBE_DEFAULT_IFAC_SIZE,
            discoverable: discoverable,
            discoveryAnnounceInterval: discoveryAnnounceInterval,
            ifacNetname: ifacNetname,
            ifacNetkey: ifacNetkey,
            ifacActive: ifacActive,
            icMaxHeldAnnounces: icMaxHeldAnnounces,
            icBurstHold: icBurstHold,
            icBurstFreqNew: icBurstFreqNew,
            icBurstFreq: icBurstFreq,
            icNewTime: icNewTime,
            icBurstPenalty: icBurstPenalty,
            icHeldReleaseInterval: icHeldReleaseInterval
        )
    }
}
