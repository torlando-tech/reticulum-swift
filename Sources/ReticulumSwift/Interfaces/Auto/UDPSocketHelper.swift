//
//  UDPSocketHelper.swift
//  ReticulumSwift
//
//  Thin wrappers around BSD socket calls for IPv6 UDP multicast.
//  Used by AutoInterface for discovery and data transfer.
//

import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// MARK: - Socket Errors

public enum SocketError: Error, LocalizedError {
    case creationFailed(Int32)
    case bindFailed(Int32)
    case joinGroupFailed(Int32)
    case sendFailed(Int32)
    case receiveFailed(Int32)
    case setOptionFailed(Int32)
    case addressResolutionFailed(String)

    public var errorDescription: String? {
        switch self {
        case .creationFailed(let errno):
            return "Socket creation failed: \(String(cString: strerror(errno)))"
        case .bindFailed(let errno):
            return "Socket bind failed: \(String(cString: strerror(errno)))"
        case .joinGroupFailed(let errno):
            return "Join multicast group failed: \(String(cString: strerror(errno)))"
        case .sendFailed(let errno):
            return "Socket send failed: \(String(cString: strerror(errno)))"
        case .receiveFailed(let errno):
            return "Socket receive failed: \(String(cString: strerror(errno)))"
        case .setOptionFailed(let errno):
            return "Socket option failed: \(String(cString: strerror(errno)))"
        case .addressResolutionFailed(let addr):
            return "Address resolution failed for: \(addr)"
        }
    }
}

// MARK: - UDPSocketHelper

public enum UDPSocketHelper {

    /// Create an IPv6 UDP socket with SO_REUSEADDR and SO_REUSEPORT.
    ///
    /// - Returns: File descriptor for the new socket
    /// - Throws: SocketError.creationFailed or .setOptionFailed
    public static func createIPv6Socket() throws -> Int32 {
        let fd = socket(AF_INET6, SOCK_DGRAM, 0)
        guard fd >= 0 else {
            throw SocketError.creationFailed(errno)
        }

        var yes: Int32 = 1

        guard setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            Darwin.close(fd)
            throw SocketError.setOptionFailed(errno)
        }

        guard setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            Darwin.close(fd)
            throw SocketError.setOptionFailed(errno)
        }

        return fd
    }

    /// Join an IPv6 multicast group on a specific interface.
    ///
    /// Uses `IPV6_JOIN_GROUP` with `ipv6_mreq` struct containing
    /// the 16-byte group address and 4-byte interface index.
    ///
    /// - Parameters:
    ///   - socket: File descriptor
    ///   - group: Multicast group address string (e.g., "ff12:0:...")
    ///   - interfaceIndex: Interface index from if_nametoindex()
    /// - Throws: SocketError if join fails
    public static func joinMulticastGroup(_ socket: Int32, group: String, interfaceIndex: UInt32) throws {
        var groupAddr = in6_addr()
        guard inet_pton(AF_INET6, group, &groupAddr) == 1 else {
            throw SocketError.addressResolutionFailed(group)
        }

        var mreq = ipv6_mreq()
        mreq.ipv6mr_multiaddr = groupAddr
        mreq.ipv6mr_interface = interfaceIndex

        guard setsockopt(socket, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, socklen_t(MemoryLayout<ipv6_mreq>.size)) == 0 else {
            throw SocketError.joinGroupFailed(errno)
        }
    }

    /// Set the multicast output interface for a socket.
    ///
    /// - Parameters:
    ///   - socket: File descriptor
    ///   - interfaceIndex: Interface index to send multicast from
    /// - Throws: SocketError if setting fails
    public static func setMulticastInterface(_ socket: Int32, interfaceIndex: UInt32) throws {
        var idx = interfaceIndex
        guard setsockopt(socket, IPPROTO_IPV6, IPV6_MULTICAST_IF, &idx, socklen_t(MemoryLayout<UInt32>.size)) == 0 else {
            throw SocketError.setOptionFailed(errno)
        }
    }

    /// Enable receiving multicast loopback (to detect own beacons for carrier detection).
    ///
    /// - Parameters:
    ///   - socket: File descriptor
    ///   - enabled: Whether loopback is enabled
    /// - Throws: SocketError
    public static func setMulticastLoopback(_ socket: Int32, enabled: Bool) throws {
        var val: UInt32 = enabled ? 1 : 0
        guard setsockopt(socket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val, socklen_t(MemoryLayout<UInt32>.size)) == 0 else {
            throw SocketError.setOptionFailed(errno)
        }
    }

    /// Bind socket to an IPv6 address and port.
    ///
    /// For link-local addresses, `sin6_scope_id` is set to the interface index.
    /// For multicast addresses (ff::/8), the address is bound as-is.
    ///
    /// - Parameters:
    ///   - socket: File descriptor
    ///   - address: IPv6 address string (link-local or multicast)
    ///   - port: Port number
    ///   - interfaceIndex: Interface index for scope ID
    /// - Throws: SocketError.bindFailed
    public static func bind(_ socket: Int32, address: String, port: UInt16, interfaceIndex: UInt32) throws {
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = port.bigEndian
        addr.sin6_scope_id = interfaceIndex

        guard inet_pton(AF_INET6, address, &addr.sin6_addr) == 1 else {
            throw SocketError.addressResolutionFailed(address)
        }

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(socket, sockPtr, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }

        guard result == 0 else {
            throw SocketError.bindFailed(errno)
        }
    }

    /// Bind socket to in6addr_any on a port (for multicast receive).
    ///
    /// - Parameters:
    ///   - socket: File descriptor
    ///   - port: Port number
    /// - Throws: SocketError.bindFailed
    public static func bindAny(_ socket: Int32, port: UInt16) throws {
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = port.bigEndian
        addr.sin6_addr = in6addr_any

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(socket, sockPtr, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }

        guard result == 0 else {
            throw SocketError.bindFailed(errno)
        }
    }

    /// Send data to an IPv6 address and port.
    ///
    /// - Parameters:
    ///   - socket: File descriptor
    ///   - data: Data to send
    ///   - address: Destination IPv6 address string
    ///   - port: Destination port
    ///   - interfaceIndex: Interface index for scope ID (needed for link-local)
    /// - Throws: SocketError.sendFailed
    public static func sendTo(_ socket: Int32, data: Data, address: String, port: UInt16, interfaceIndex: UInt32) throws {
        var destAddr = sockaddr_in6()
        destAddr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        destAddr.sin6_family = sa_family_t(AF_INET6)
        destAddr.sin6_port = port.bigEndian

        // Only set scope_id for link-local unicast (fe80::).
        // For multicast (ff__::), the outgoing interface is already set via
        // IPV6_MULTICAST_IF socket option — setting scope_id on multicast
        // destinations causes EHOSTUNREACH on iOS.
        if address.hasPrefix("fe80") {
            destAddr.sin6_scope_id = interfaceIndex
        }

        guard inet_pton(AF_INET6, address, &destAddr.sin6_addr) == 1 else {
            throw SocketError.addressResolutionFailed(address)
        }

        let sent = data.withUnsafeBytes { rawBuffer -> Int in
            guard let ptr = rawBuffer.baseAddress else { return -1 }
            return withUnsafePointer(to: &destAddr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    Darwin.sendto(socket, ptr, data.count, 0, sockPtr, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        }

        guard sent >= 0 else {
            throw SocketError.sendFailed(errno)
        }
    }

    /// Receive data from a socket with source address.
    ///
    /// This call blocks until data is available or the socket is closed.
    ///
    /// - Parameters:
    ///   - socket: File descriptor
    ///   - maxLength: Maximum bytes to receive
    /// - Returns: Tuple of received data and source IPv6 address (without scope suffix)
    /// - Throws: SocketError.receiveFailed
    public static func receiveFrom(_ socket: Int32, maxLength: Int = 2048) throws -> (data: Data, address: String, interfaceIndex: UInt32) {
        var buffer = [UInt8](repeating: 0, count: maxLength)
        var srcAddr = sockaddr_in6()
        var srcLen = socklen_t(MemoryLayout<sockaddr_in6>.size)

        let bytesRead = withUnsafeMutablePointer(to: &srcAddr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                recvfrom(socket, &buffer, maxLength, 0, sockPtr, &srcLen)
            }
        }

        guard bytesRead > 0 else {
            throw SocketError.receiveFailed(errno)
        }

        // Convert source address to string
        var addrString = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        var sin6Addr = srcAddr.sin6_addr
        inet_ntop(AF_INET6, &sin6Addr, &addrString, socklen_t(INET6_ADDRSTRLEN))
        var address = String(cString: addrString)

        // Strip scope suffix
        if let percentIndex = address.firstIndex(of: "%") {
            address = String(address[address.startIndex..<percentIndex])
        }

        return (Data(buffer[0..<bytesRead]), address, srcAddr.sin6_scope_id)
    }

    /// Close a socket file descriptor.
    ///
    /// - Parameter socket: File descriptor to close. -1 is a no-op.
    public static func close(_ socket: Int32) {
        if socket >= 0 {
            Darwin.close(socket)
        }
    }

    /// Make a socket non-blocking.
    ///
    /// - Parameter socket: File descriptor
    /// - Throws: SocketError.setOptionFailed
    public static func setNonBlocking(_ socket: Int32) throws {
        let flags = fcntl(socket, F_GETFL)
        guard flags >= 0 else {
            throw SocketError.setOptionFailed(errno)
        }
        guard fcntl(socket, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            throw SocketError.setOptionFailed(errno)
        }
    }
}
