import XCTest
import CryptoKit
@testable import ReticulumSwift

final class LinkMtuTests: XCTestCase {

    // MARK: - Signaling Encoding/Decoding

    func testEncodeDecodeSignaling_defaultMtu() {
        let signaling = IncomingLinkRequest.encodeSignaling(mtu: 500, mode: LinkConstants.MODE_DEFAULT)
        XCTAssertEqual(signaling.count, 3)
        XCTAssertEqual(signaling, LinkConstants.DEFAULT_MTU_SIGNALING)

        let (mtu, mode) = IncomingLinkRequest.decodeSignaling(signaling)
        XCTAssertEqual(mtu, 500)
        XCTAssertEqual(mode, LinkConstants.MODE_DEFAULT)
    }

    func testEncodeDecodeSignaling_tcpMtu() {
        let tcpMtu: UInt32 = 262144
        let signaling = IncomingLinkRequest.encodeSignaling(mtu: tcpMtu, mode: LinkConstants.MODE_DEFAULT)
        XCTAssertEqual(signaling.count, 3)

        let (mtu, mode) = IncomingLinkRequest.decodeSignaling(signaling)
        XCTAssertEqual(mtu, tcpMtu)
        XCTAssertEqual(mode, LinkConstants.MODE_DEFAULT)
    }

    func testEncodeDecodeSignaling_rnodeMtu() {
        let rnodeMtu: UInt32 = 508
        let signaling = IncomingLinkRequest.encodeSignaling(mtu: rnodeMtu, mode: LinkConstants.MODE_DEFAULT)

        let (mtu, mode) = IncomingLinkRequest.decodeSignaling(signaling)
        XCTAssertEqual(mtu, rnodeMtu)
        XCTAssertEqual(mode, LinkConstants.MODE_DEFAULT)
    }

    // MARK: - MDU Calculation

    func testMduCalculation_defaultMtu() {
        // Python: floor((500 - 1 - 19 - 48) / 16) * 16 - 1 = 431
        let mtu = 500
        let mdu = ((mtu - 1 - 19 - 48) / 16) * 16 - 1
        XCTAssertEqual(mdu, 431)
        XCTAssertEqual(mdu, LinkConstants.LINK_MDU)
    }

    func testMduCalculation_tcpMtu() {
        // Python: floor((262144 - 1 - 19 - 48) / 16) * 16 - 1 = 262063
        let mtu = 262144
        let mdu = ((mtu - 1 - 19 - 48) / 16) * 16 - 1
        XCTAssertEqual(mdu, 262063)
    }

    // MARK: - Link Initiator MTU Signaling

    func testInitiatorLink_defaultMtu() async {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["mtu"])
        let link = Link(destination: dest, identity: identity)

        let mtu = await link.mtu
        let mdu = await link.mdu
        XCTAssertEqual(mtu, 500)
        XCTAssertEqual(mdu, 431)
    }

    func testInitiatorLink_tcpMtu() async {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["mtu"])
        let link = Link(destination: dest, identity: identity, hwMtu: 262144)

        // Verify the request data encodes the TCP MTU
        let requestData = await link.requestData
        XCTAssertEqual(requestData.count, 67) // 32 + 32 + 3

        // Extract signaling from last 3 bytes
        let signaling = Data(requestData.suffix(3))
        let (mtu, mode) = IncomingLinkRequest.decodeSignaling(signaling)
        XCTAssertEqual(mtu, 262144)
        XCTAssertEqual(mode, LinkConstants.MODE_DEFAULT)
    }

    // MARK: - Link Responder MTU

    func testEncodeDecodeSignaling_autoInterfaceMtu() {
        let autoMtu: UInt32 = 1196
        let signaling = IncomingLinkRequest.encodeSignaling(mtu: autoMtu, mode: LinkConstants.MODE_DEFAULT)

        let (mtu, mode) = IncomingLinkRequest.decodeSignaling(signaling)
        XCTAssertEqual(mtu, autoMtu)
        XCTAssertEqual(mode, LinkConstants.MODE_DEFAULT)
    }

    func testMduCalculation_autoInterfaceMtu() {
        // Python: floor((1196 - 1 - 19 - 48) / 16) * 16 - 1 = 1119
        let mtu = 1196
        let mdu = ((mtu - 1 - 19 - 48) / 16) * 16 - 1
        XCTAssertEqual(mdu, 1119)
    }

    func testInitiatorLink_autoInterfaceMtu() async {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["mtu"])
        let link = Link(destination: dest, identity: identity, hwMtu: 1196)

        let requestData = await link.requestData
        XCTAssertEqual(requestData.count, 67)

        let signaling = Data(requestData.suffix(3))
        let (mtu, _) = IncomingLinkRequest.decodeSignaling(signaling)
        XCTAssertEqual(mtu, 1196)
    }

    // MARK: - Transport nextHopInterfaceHwMtu

    func testNextHopInterfaceHwMtu_autoInterfacePeer() async throws {
        // Simulate: announce arrives via AutoInterfacePeer, path is stored,
        // then nextHopInterfaceHwMtu resolves to 1196.
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("mtu_test_\(ProcessInfo.processInfo.processIdentifier)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let pathTable = try PathTable(databasePath: tmpDir.appendingPathComponent("paths.db").path)
        let transport = ReticulumTransport(pathTable: pathTable)

        // Create and register an AutoInterfacePeer (simulating what addAutoInterface does)
        let peer = AutoInterfacePeer(
            parentId: "auto0",
            peerAddress: "fe80::1",
            interfaceName: "en0",
            interfaceIndex: 1,
            dataSocket: -1,
            dataPort: 42671
        )
        // The peer ID will be "auto-auto0-fe80::1"
        let peerId = await peer.id

        // Register peer directly in transport (normally done by addAutoInterface callback)
        try await transport.addInterface(peer)

        // Store a path entry with this peer's interface ID
        let destHash = Data(repeating: 0xAB, count: 16)
        let pubKeys = Data(repeating: 0xCD, count: 64)
        let randomBlob = Data(repeating: 0xEF, count: 10)
        await pathTable.record(
            destinationHash: destHash,
            publicKeys: pubKeys,
            randomBlob: randomBlob,
            interfaceId: peerId,
            hopCount: 1
        )

        // Verify the lookup
        let hwMtu = await transport.nextHopInterfaceHwMtu(for: destHash)
        XCTAssertNotNil(hwMtu, "nextHopInterfaceHwMtu should find the AutoInterfacePeer")
        XCTAssertEqual(hwMtu, 1196, "AutoInterfacePeer.hwMtu should be 1196")
    }

    func testNextHopInterfaceHwMtu_tcpInterface() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("mtu_test_tcp_\(ProcessInfo.processInfo.processIdentifier)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let pathTable = try PathTable(databasePath: tmpDir.appendingPathComponent("paths.db").path)
        let transport = ReticulumTransport(pathTable: pathTable)

        // Create a TCP interface (won't actually connect)
        let config = InterfaceConfig(
            id: "tcp-test",
            name: "TCP Test",
            type: .tcp,
            enabled: true,
            mode: .full,
            host: "127.0.0.1",
            port: 9999
        )
        let tcpIface = try TCPInterface(config: config)
        try await transport.addInterface(tcpIface)

        // Store a path entry with this interface ID
        let destHash = Data(repeating: 0xBB, count: 16)
        let pubKeys = Data(repeating: 0xCC, count: 64)
        let randomBlob = Data(repeating: 0xDD, count: 10)
        await pathTable.record(
            destinationHash: destHash,
            publicKeys: pubKeys,
            randomBlob: randomBlob,
            interfaceId: "tcp-test",
            hopCount: 1
        )

        let hwMtu = await transport.nextHopInterfaceHwMtu(for: destHash)
        XCTAssertNotNil(hwMtu)
        XCTAssertEqual(hwMtu, 262144)
    }

    func testNextHopInterfaceHwMtu_missingInterface() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("mtu_test_miss_\(ProcessInfo.processInfo.processIdentifier)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let pathTable = try PathTable(databasePath: tmpDir.appendingPathComponent("paths.db").path)
        let transport = ReticulumTransport(pathTable: pathTable)

        // Store a path with an interface ID that doesn't exist in transport
        let destHash = Data(repeating: 0xCC, count: 16)
        await pathTable.record(
            destinationHash: destHash,
            publicKeys: Data(repeating: 0xDD, count: 64),
            randomBlob: Data(repeating: 0xEE, count: 10),
            interfaceId: "nonexistent-interface",
            hopCount: 1
        )

        let hwMtu = await transport.nextHopInterfaceHwMtu(for: destHash)
        XCTAssertNil(hwMtu, "Should return nil for unregistered interface")
    }

    // MARK: - Link Responder MTU

    func testResponderLink_storesMtu() async {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["mtu"], direction: .in)

        // Build a fake LINKREQUEST with TCP MTU signaling
        let encKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let sigKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let signaling = IncomingLinkRequest.encodeSignaling(mtu: 262144, mode: LinkConstants.MODE_DEFAULT)
        var requestData = Data()
        requestData.append(encKey)
        requestData.append(sigKey)
        requestData.append(signaling)

        // Build packet for IncomingLinkRequest
        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .linkRequest,
            hopCount: 0
        )
        let packet = Packet(
            header: header,
            destination: dest.hash,
            context: 0x00,
            data: requestData
        )

        let incomingRequest = try! IncomingLinkRequest(data: requestData, packet: packet)
        XCTAssertEqual(incomingRequest.mtu, 262144)

        let link = Link(incomingRequest: incomingRequest, destination: dest, identity: identity)

        let linkMtu = await link.mtu
        let linkMdu = await link.mdu
        XCTAssertEqual(linkMtu, 262144)
        XCTAssertEqual(linkMdu, 262063)
    }
}
