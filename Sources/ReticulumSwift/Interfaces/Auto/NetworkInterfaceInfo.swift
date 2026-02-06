//
//  NetworkInterfaceInfo.swift
//  ReticulumSwift
//
//  Enumerates system network interfaces using getifaddrs() to find
//  IPv6 link-local addresses for AutoInterface multicast discovery.
//

import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// MARK: - Network Interface Info

/// Information about a local network interface with an IPv6 link-local address.
public struct NetworkInterfaceInfo: Sendable {
    /// Interface name (e.g., "en0", "en1")
    public let name: String

    /// Interface index from if_nametoindex()
    public let index: UInt32

    /// IPv6 link-local address without scope suffix (e.g., "fe80::1")
    public let linkLocalAddress: String
}

// MARK: - Enumeration

extension NetworkInterfaceInfo {
    /// Default ignore list for Darwin platforms.
    /// Matches Python AutoInterface: awdl (Apple Wireless Direct Link),
    /// llw (Low Latency WLAN), lo (loopback), en5 (Thunderbolt bridge).
    public static let darwinIgnoredInterfaces: Set<String> = [
        "awdl0", "llw0", "lo0", "en5"
    ]

    /// Enumerate all network interfaces with IPv6 link-local addresses.
    ///
    /// Uses POSIX `getifaddrs()` to iterate all interfaces, filtering for
    /// AF_INET6 addresses in the fe80::/10 range. Ignored interfaces
    /// (loopback, AWDL, etc.) are excluded.
    ///
    /// - Parameter ignoredInterfaces: Set of interface names to skip.
    ///   Defaults to `darwinIgnoredInterfaces`.
    /// - Returns: Array of interfaces with link-local addresses.
    public static func enumerateInterfaces(
        ignoredInterfaces: Set<String> = darwinIgnoredInterfaces
    ) -> [NetworkInterfaceInfo] {
        var results: [NetworkInterfaceInfo] = []
        var ifaddrsPtr: UnsafeMutablePointer<ifaddrs>?

        guard getifaddrs(&ifaddrsPtr) == 0, let firstAddr = ifaddrsPtr else {
            return results
        }
        defer { freeifaddrs(firstAddr) }

        var current: UnsafeMutablePointer<ifaddrs>? = firstAddr
        // Track seen interface names to avoid duplicates (multiple addrs per if)
        var seen = Set<String>()

        while let ifa = current {
            defer { current = ifa.pointee.ifa_next }

            guard let addr = ifa.pointee.ifa_addr else { continue }
            guard addr.pointee.sa_family == UInt8(AF_INET6) else { continue }

            let name = String(cString: ifa.pointee.ifa_name)
            guard !ignoredInterfaces.contains(name) else { continue }
            guard !seen.contains(name) else { continue }

            // Extract IPv6 address
            let ipv6Addr = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { ptr in
                ptr.pointee
            }

            // Check for link-local (fe80::/10)
            let bytes = withUnsafeBytes(of: ipv6Addr.sin6_addr) { Array($0) }
            guard bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 else { continue }

            // Convert to string
            var addrString = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            var sin6 = ipv6Addr
            inet_ntop(AF_INET6, &sin6.sin6_addr, &addrString, socklen_t(INET6_ADDRSTRLEN))
            var address = String(cString: addrString)

            // Strip scope suffix (e.g., "%en0") — equivalent to Python descope_linklocal
            if let percentIndex = address.firstIndex(of: "%") {
                address = String(address[address.startIndex..<percentIndex])
            }

            let index = if_nametoindex(name)
            guard index != 0 else { continue }

            seen.insert(name)
            results.append(NetworkInterfaceInfo(
                name: name,
                index: index,
                linkLocalAddress: address
            ))
        }

        return results
    }
}
