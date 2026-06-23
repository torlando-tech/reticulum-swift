// Ext+Interface.swift — conformance bridge extension cluster: M-IFACE
//   interface_hw_mtu            — class-level HW_MTU per interface type
//   interface_default_ifac_size — per-class DEFAULT_IFAC_SIZE constants
//   interface_optimise_mtu      — Interface.optimise_mtu bitrate->HW_MTU tier table
//   config_parse_interface      — RNS ConfigObj + _synthesize_interface (LIBRARY GAP)
//
// Ports from reticulum-conformance reference/bridge_server.py
// (cmd_interface_hw_mtu :1645, cmd_config_parse_interface :3744,
//  cmd_interface_default_ifac_size :3833, cmd_interface_optimise_mtu :3875).
// Returns nil for any command it does not own (dispatch chain: Ext+Dispatch.swift).
//
// LIBRARY GAPS (reported in libraryGaps; see also the per-site // LIBRARY-GAP
// comments below):
//   * reticulum-swift declares HW_MTU only as per-instance computed properties
//     (TCPInterface.hwMtu == 262144, AutoInterface.hwMtu == 1196) — there is no
//     static class constant readable without constructing an interface, and no
//     BackboneInterface class at all (RNS BackboneInterface.HW_MTU == 1048576).
//     interface_hw_mtu reproduces the documented RNS 1.3.1 spec literals so the
//     cross-impl output is byte-faithful, sourcing AutoInterface from the one
//     static the library does expose (AutoInterfaceConstants.hwMTU).
//   * the library carries no per-class DEFAULT_IFAC_SIZE constants for the
//     serial/framed-media classes (Serial/KISS/AX25KISS/RNode/Pipe == 8) — only
//     the packet-class default exists (TransportConstants.DEFAULT_IFAC_SIZE == 16,
//     IFAC_MIN_SIZE == 1). interface_default_ifac_size pins the 8-byte serial tag
//     as a spec literal and reads the 16-byte packet default + min size from the
//     library.
//   * the library has no Interface.optimise_mtu; interface_optimise_mtu reproduces
//     the RNS 1.3.1 bitrate->HW_MTU tier table (Interface.py:198-221) inline.
//   * config_parse_interface delegates entirely to RNS's vendored ConfigObj INI
//     parser + Reticulum._synthesize_interface, neither of which reticulum-swift
//     provides (InterfaceConfig is a Codable struct, not an INI config pipeline).
//     The command cannot be serviced without that machinery and is reported as a
//     library gap rather than reimplementing the whole RNS config pipeline in the
//     bridge (a bridge-side reimplementation would test the bridge, not the lib).
import Foundation
import ReticulumSwift

func handleInterfaceExtCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // Class-level HW_MTU per interface type. Python reads cls.HW_MTU off the live
    // class for {TCPInterface, AutoInterface, BackboneInterface}; any other type
    // returns a (non-raising) {'error': ...} dict. (cmd_interface_hw_mtu :1645)
    case "interface_hw_mtu":
        let itype = try getString(p, "type")
        // LIBRARY-GAP: reticulum-swift has no static HW_MTU class constants and no
        // BackboneInterface; values are the RNS 1.3.1 spec literals (AutoInterface
        // sourced from the one library static, AutoInterfaceConstants.hwMTU).
        let classHwMtu: [String: Int] = [
            "TCPInterface": 262144,                  // == TCPInterface.hwMtu (instance-only in lib)
            "AutoInterface": AutoInterfaceConstants.hwMTU, // 1196 (library static)
            "BackboneInterface": 1048576,            // no BackboneInterface class in lib
        ]
        guard let mtu = classHwMtu[itype] else {
            // Python: {'error': f"unsupported interface type {itype!r} "
            //          f"(class-level HW_MTU only: {sorted(_CLASS_HW_MTU_INTERFACES)})"}
            // sorted(keys) == ['AutoInterface', 'BackboneInterface', 'TCPInterface'].
            return ["error": str("unsupported interface type '\(itype)' "
                + "(class-level HW_MTU only: ['AutoInterface', 'BackboneInterface', 'TCPInterface'])")]
        }
        return ["hw_mtu": num(mtu)]

    // Per-class DEFAULT_IFAC_SIZE: serial/framed media default to an 8-byte IFAC
    // tag, packet/IP media to 16; IFAC_MIN_SIZE is 1 byte. Python reads each off
    // the class attribute. (cmd_interface_default_ifac_size :3833)
    case "interface_default_ifac_size":
        // LIBRARY-GAP: no Serial/KISS/AX25KISS/RNode/Pipe DEFAULT_IFAC_SIZE==8
        // constant exists in reticulum-swift; the 8-byte serial-class tag is the
        // RNS 1.3.1 spec literal. The 16-byte packet default and the min size are
        // read from the library.
        let serialIfac = num(8)
        let packetIfac = num(TransportConstants.DEFAULT_IFAC_SIZE) // 16
        let sizes: [String: JSONValue] = [
            "SerialInterface": serialIfac,
            "KISSInterface": serialIfac,
            "AX25KISSInterface": serialIfac,
            "RNodeInterface": serialIfac,
            "PipeInterface": serialIfac,
            "TCPServerInterface": packetIfac,
            "TCPClientInterface": packetIfac,
            "UDPInterface": packetIfac,
        ]
        return [
            "default_ifac_size": .dict(sizes),
            "ifac_min_size": num(TransportConstants.IFAC_MIN_SIZE), // 1
        ]

    // RNS Interface.optimise_mtu bitrate->HW_MTU tier mapping (Interface.py:198-221).
    // The whole tier table is gated on AUTOCONFIGURE_MTU: when off, HW_MTU is left
    // at the pre-seeded sentinel (-1) and `unchanged` is True. When on, HW_MTU is
    // always (re)assigned — to a tier literal, or to None below the lowest tier —
    // so `unchanged` is always False. (cmd_interface_optimise_mtu :3875)
    case "interface_optimise_mtu":
        let bitrate = try getInt(p, "bitrate")
        let autoconfigure = getBoolOptional(p, "autoconfigure") ?? true
        // Sentinel HW_MTU so a no-op (autoconfigure off) is observable as unchanged.
        let sentinel = -1
        var hwMtu: JSONValue = num(sentinel)
        var assigned = false
        // LIBRARY-GAP: reticulum-swift has no Interface.optimise_mtu — the RNS
        // 1.3.1 tier table is reproduced inline. Comparisons are strict > except
        // the top tier (>=).
        if autoconfigure {
            assigned = true
            if bitrate >= 1_000_000_000 {
                hwMtu = num(524288)
            } else if bitrate > 750_000_000 {
                hwMtu = num(262144)
            } else if bitrate > 400_000_000 {
                hwMtu = num(131072)
            } else if bitrate > 200_000_000 {
                hwMtu = num(65536)
            } else if bitrate > 100_000_000 {
                hwMtu = num(32768)
            } else if bitrate > 10_000_000 {
                hwMtu = num(16384)
            } else if bitrate > 5_000_000 {
                hwMtu = num(8192)
            } else if bitrate > 2_000_000 {
                hwMtu = num(4096)
            } else if bitrate > 1_000_000 {
                hwMtu = num(2048)
            } else if bitrate > 62_500 {
                hwMtu = num(1024)
            } else {
                hwMtu = .null // RNS assigns HW_MTU = None below the lowest tier
            }
        }
        // unchanged == (HW_MTU still equals the sentinel). After an autoconfigure
        // pass HW_MTU is always reassigned (even to None), so it can only remain
        // the sentinel when autoconfigure was off.
        return ["hw_mtu": hwMtu, "unchanged": boolean(!assigned)]

    // Push raw RNS config text through the ReticulumSwift ConfigObj INI parser +
    // InterfaceConfigSynthesizer (a focused port of Reticulum._synthesize_interface,
    // Reticulum.py:685-1034) and read back the stored interface attrs.
    // (cmd_config_parse_interface :3744)
    case "config_parse_interface":
        let interfaceName = try getString(p, "interface_name")
        let configText = try getString(p, "config_text")
        let syn: InterfaceConfigSynthesizer.Synthesized
        do {
            syn = try InterfaceConfigSynthesizer.parseAndSynthesize(
                configText: configText, interfaceName: interfaceName)
        } catch let e as InterfaceConfigSynthesizer.SynthesisError {
            // Faithfully surface the upstream KeyError quirk (Reticulum.py:701) and
            // ConfigObj coercion failures as bridge errors so the harness raises
            // BridgeError, exactly as real RNS propagates the exception out of
            // _synthesize_interface (the mode-selection runs BEFORE RNS's
            // try/except, so the KeyError is not swallowed).
            throw BridgeError.invalidData("\(e)")
        }
        // Mirror cmd_config_parse_interface's read-back (bridge_server.py:3830-3875):
        // selected_interface_mode + configured_bitrate come from the config section;
        // the rest are read straight off the synthesized interface attrs.
        func optInt(_ v: Int?) -> JSONValue { v.map { num($0) } ?? .null }
        func optDouble(_ v: Double?) -> JSONValue { v.map { num($0) } ?? .null }
        func optStr(_ v: String?) -> JSONValue { v.map { str($0) } ?? .null }
        return [
            "selected_interface_mode": num(syn.selectedInterfaceMode),
            "configured_bitrate": optInt(syn.configuredBitrate),
            "mode": num(syn.selectedInterfaceMode),
            "mode_name": optStr(syn.modeName),
            "bitrate": num(syn.bitrate),
            "announce_cap": num(syn.announceCap),
            "ifac_size": num(syn.ifacSize),
            "default_ifac_size": num(syn.defaultIfacSize),
            "discoverable": boolean(syn.discoverable),
            "discovery_announce_interval": optInt(syn.discoveryAnnounceInterval),
            "ifac_netname": optStr(syn.ifacNetname),
            "ifac_netkey": optStr(syn.ifacNetkey),
            "ifac_active": boolean(syn.ifacActive),
            "ic_max_held_announces": optInt(syn.icMaxHeldAnnounces),
            "ic_burst_hold": optDouble(syn.icBurstHold),
            "ic_burst_freq_new": optDouble(syn.icBurstFreqNew),
            "ic_burst_freq": optDouble(syn.icBurstFreq),
            "ic_new_time": optDouble(syn.icNewTime),
            "ic_burst_penalty": optDouble(syn.icBurstPenalty),
            "ic_held_release_interval": optDouble(syn.icHeldReleaseInterval),
        ]

    default:
        return nil
    }
}
