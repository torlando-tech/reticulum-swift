//
//  CoreBluetoothBLEDriver.swift
//  ReticulumSwift
//
//  iOS CoreBluetooth implementation of BLEDriver for BLE mesh networking.
//  Operates dual-mode: CBCentralManager (client) + CBPeripheralManager (server).
//
//  GATT server exposes: RX (write), TX (notify), Identity (read)
//  GATT client: scans for service UUID, connects, discovers, enables notifications
//

#if canImport(CoreBluetooth)
import Foundation
import CoreBluetooth
import OSLog

// BLE diagnostic log — uses os_log Logger at error level for guaranteed unredacted syslog output
private let bleDiagLogger = Logger(subsystem: "net.reticulum", category: "BLEDiag")
private func bleDiag(_ message: String) {
    bleDiagLogger.error("[BLE_DRV] \(message, privacy: .public)")
}

// MARK: - CoreBluetooth BLE Driver

/// iOS CoreBluetooth implementation of the BLE mesh driver.
///
/// Runs both as a GATT server (peripheral manager) and GATT client (central manager)
/// simultaneously. The server advertises the mesh service and handles incoming
/// connections from remote centrals. The client scans for and connects to
/// remote peripherals advertising the same service.
public final class CoreBluetoothBLEDriver: NSObject, BLEDriver, @unchecked Sendable {

    // MARK: - Properties

    private let identityHash: Data  // 16-byte local identity
    private var centralManager: CBCentralManager!
    private var peripheralManager: CBPeripheralManager!

    // GATT service and characteristics (peripheral side)
    private var meshService: CBMutableService?
    private var txCharacteristic: CBMutableCharacteristic?
    private var rxCharacteristic: CBMutableCharacteristic?
    private var identityCharacteristic: CBMutableCharacteristic?

    // Connected peripherals (central side)
    private var discoveredPeripherals: [String: CBPeripheral] = [:]
    private var connectedPeripherals: [String: CBPeripheral] = [:]
    private var peripheralConnections: [String: CoreBluetoothPeerConnection] = [:]

    // Connected centrals (peripheral side)
    private var subscribedCentrals: [String: CBCentral] = [:]
    private var centralConnections: [String: CoreBluetoothPeerConnection] = [:]

    // Async stream continuations
    private var discoveredPeersContinuation: AsyncStream<DiscoveredPeer>.Continuation?
    private var incomingConnectionsContinuation: AsyncStream<any BLEPeerConnection>.Continuation?
    private var connectionLostContinuation: AsyncStream<String>.Continuation?

    // State
    private let lock = NSLock()
    private var centralReady = false
    private var peripheralReady = false
    private var _isRunning = false
    private var pendingConnect: [String: CheckedContinuation<any BLEPeerConnection, Error>] = [:]
    private var pendingRssi: [String: CheckedContinuation<Int, Error>] = [:]

    private let logger = Logger(subsystem: "net.reticulum", category: "CoreBluetoothBLEDriver")

    // Dispatch queue for CoreBluetooth delegates
    private let bleQueue = DispatchQueue(label: "net.reticulum.ble.driver", qos: .userInitiated)

    // MARK: - Init

    /// Create a new CoreBluetooth BLE driver.
    ///
    /// - Parameter identityHash: Our 16-byte transport identity hash (exposed via Identity characteristic)
    public init(identityHash: Data) {
        precondition(identityHash.count == 16, "Identity hash must be 16 bytes")
        self.identityHash = identityHash
        super.init()

        centralManager = CBCentralManager(
            delegate: self,
            queue: bleQueue,
            options: [CBCentralManagerOptionRestoreIdentifierKey: "com.columba.bleMeshCentral"]
        )
        peripheralManager = CBPeripheralManager(delegate: self, queue: bleQueue)
    }

    // MARK: - BLEDriver Protocol

    public var localAddress: String? {
        lock.lock()
        defer { lock.unlock() }
        // iOS doesn't expose the local BLE address; use a stable identifier
        return identityHash.map { String(format: "%02x", $0) }.joined()
    }

    public var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _isRunning
    }

    public private(set) lazy var discoveredPeers: AsyncStream<DiscoveredPeer> = {
        AsyncStream { [weak self] continuation in
            self?.discoveredPeersContinuation = continuation
        }
    }()

    public private(set) lazy var incomingConnections: AsyncStream<any BLEPeerConnection> = {
        AsyncStream { [weak self] continuation in
            self?.incomingConnectionsContinuation = continuation
        }
    }()

    public private(set) lazy var connectionLost: AsyncStream<String> = {
        AsyncStream { [weak self] continuation in
            self?.connectionLostContinuation = continuation
        }
    }()

    public func startAdvertising() async throws {
        bleDiag("startAdvertising() called, peripheralReady=\(peripheralReady)")
        if !peripheralReady {
            bleDiag("Waiting up to 3s for peripheral manager...")
            for i in 1...6 {
                try await Task.sleep(for: .milliseconds(500))
                if peripheralReady {
                    bleDiag("Peripheral ready after \(i * 500)ms")
                    break
                }
            }
            bleDiag("After wait, peripheralReady=\(peripheralReady)")
        }
        guard peripheralReady else {
            bleDiag("ERROR: Peripheral NOT ready — cannot advertise")
            throw InterfaceError.connectionFailed(underlying: "Bluetooth peripheral not ready")
        }

        setupGATTService()
        bleDiag("GATT service set up")

        peripheralManager.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [BLEMeshConstants.serviceUUID],
        ])

        lock.withLock { _isRunning = true }

        bleDiag("Advertising started for service \(BLEMeshConstants.serviceUUIDString)")
    }

    public func stopAdvertising() async {
        peripheralManager.stopAdvertising()
        logger.info("BLE advertising stopped")
    }

    public func startScanning() async throws {
        bleDiag("startScanning() called, centralReady=\(centralReady)")
        if !centralReady {
            bleDiag("Waiting up to 3s for central manager...")
            for i in 1...6 {
                try await Task.sleep(for: .milliseconds(500))
                if centralReady {
                    bleDiag("Central ready after \(i * 500)ms")
                    break
                }
            }
            bleDiag("After wait, centralReady=\(centralReady)")
        }
        guard centralReady else {
            bleDiag("ERROR: Central NOT ready — cannot scan")
            throw InterfaceError.connectionFailed(underlying: "Bluetooth central not ready")
        }

        centralManager.scanForPeripherals(
            withServices: [BLEMeshConstants.serviceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        )

        bleDiag("Scanning started for service \(BLEMeshConstants.serviceUUIDString)")
    }

    public func stopScanning() async {
        centralManager.stopScan()
        logger.info("BLE scanning stopped")
    }

    public func connect(address: String) async throws -> any BLEPeerConnection {
        // Must synchronize with bleQueue — didDiscover writes discoveredPeripherals on bleQueue,
        // but connect() is called from BLEInterface actor (Swift concurrency thread).
        // Unsynchronized concurrent read+write corrupts the dictionary (CVE: __NSTaggedDate objectForKey:).
        let peripheral: CBPeripheral? = bleQueue.sync { discoveredPeripherals[address] }
        guard let peripheral else {
            throw InterfaceError.connectionFailed(underlying: "Peripheral not found: \(address)")
        }

        return try await withCheckedThrowingContinuation { [weak self] continuation in
            guard let self = self else {
                continuation.resume(throwing: InterfaceError.connectionFailed(underlying: "Driver deallocated"))
                return
            }

            self.lock.lock()
            self.pendingConnect[address] = continuation
            self.lock.unlock()

            self.centralManager.connect(peripheral, options: nil)

            // Timeout
            Task {
                try? await Task.sleep(for: .seconds(BLEMeshConstants.connectionTimeout))
                let cont = self.lock.withLock {
                    self.pendingConnect.removeValue(forKey: address)
                }
                if let cont {
                    cont.resume(throwing: InterfaceError.connectionFailed(underlying: "Connection timed out"))
                    self.centralManager.cancelPeripheralConnection(peripheral)
                }
            }
        }
    }

    public func disconnect(address: String) async {
        // Synchronize with bleQueue (these dictionaries are written on bleQueue from CB callbacks)
        bleQueue.sync {
            if let peripheral = connectedPeripherals[address] {
                centralManager.cancelPeripheralConnection(peripheral)
            }
            peripheralConnections.removeValue(forKey: address)
            connectedPeripherals.removeValue(forKey: address)
        }
    }

    public func shutdown() {
        // Synchronize dictionary cleanup with bleQueue to avoid races with CB callbacks
        bleQueue.sync {
            centralManager.stopScan()
            peripheralManager.stopAdvertising()

            for (_, peripheral) in connectedPeripherals {
                centralManager.cancelPeripheralConnection(peripheral)
            }

            connectedPeripherals.removeAll()
            peripheralConnections.removeAll()
            discoveredPeripherals.removeAll()
            subscribedCentrals.removeAll()
            centralConnections.removeAll()

            // Remove service so the next driver can add it fresh
            peripheralManager.removeAllServices()
        }

        discoveredPeersContinuation?.finish()
        incomingConnectionsContinuation?.finish()
        connectionLostContinuation?.finish()

        // Release managers so CoreBluetooth can clean up before a new driver
        // creates fresh ones. Without this, the new driver's CBCentralManager
        // sees a "resetting" state while the old one is still being torn down.
        centralManager.delegate = nil
        peripheralManager.delegate = nil

        lock.lock()
        centralReady = false
        peripheralReady = false
        _isRunning = false
        lock.unlock()

        logger.info("CoreBluetoothBLEDriver shut down")
    }

    // MARK: - GATT Service Setup

    private func setupGATTService() {
        // TX: notify (peripheral sends data to central)
        let tx = CBMutableCharacteristic(
            type: BLEMeshConstants.txCharUUID,
            properties: [.read, .notify],
            value: nil,
            permissions: [.readable]
        )
        self.txCharacteristic = tx

        // RX: write (central sends data to peripheral)
        let rx = CBMutableCharacteristic(
            type: BLEMeshConstants.rxCharUUID,
            properties: [.write, .writeWithoutResponse],
            value: nil,
            permissions: [.writeable]
        )
        self.rxCharacteristic = rx

        // Identity: read (16-byte identity hash)
        let identity = CBMutableCharacteristic(
            type: BLEMeshConstants.identityCharUUID,
            properties: [.read],
            value: identityHash,
            permissions: [.readable]
        )
        self.identityCharacteristic = identity

        let service = CBMutableService(type: BLEMeshConstants.serviceUUID, primary: true)
        service.characteristics = [tx, rx, identity]
        self.meshService = service

        peripheralManager.add(service)
    }
}

// MARK: - CBCentralManagerDelegate

extension CoreBluetoothBLEDriver: CBCentralManagerDelegate {

    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        lock.lock()
        centralReady = central.state == .poweredOn
        lock.unlock()

        let stateStr: String
        switch central.state {
        case .poweredOn: stateStr = "poweredOn"
        case .poweredOff: stateStr = "poweredOff"
        case .unauthorized: stateStr = "unauthorized"
        case .unsupported: stateStr = "unsupported"
        case .resetting: stateStr = "resetting"
        case .unknown: stateStr = "unknown"
        @unknown default: stateStr = "rawValue=\(central.state.rawValue)"
        }
        bleDiag("Central manager state: \(stateStr)")
        logger.info("[BLE_DIAG] Central manager state: \(stateStr, privacy: .public)")
    }

    public func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        guard let peripherals = dict[CBCentralManagerRestoredStatePeripheralsKey]
                as? [CBPeripheral] else { return }
        for peripheral in peripherals {
            // Re-register delegate so we get callbacks
            peripheral.delegate = self
            // Attempt reconnect — if already connected, CBCentralManager calls didConnect immediately
            central.connect(peripheral, options: nil)
        }
    }

    public func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let address = peripheral.identifier.uuidString
        let name = peripheral.name ?? advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? "unknown"
        let isNew = discoveredPeripherals[address] == nil
        discoveredPeripherals[address] = peripheral

        // Only log first sighting of each peer (fires ~10x/s per peer with allowDuplicates)
        if isNew {
            bleDiag("Discovered NEW peer: \(name) addr=\(address.prefix(8)) rssi=\(RSSI.intValue)")
        }

        let peer = DiscoveredPeer(
            address: address,
            rssi: RSSI.intValue,
            lastSeen: Date()
        )

        discoveredPeersContinuation?.yield(peer)
    }

    public func centralManager(
        _ central: CBCentralManager,
        didConnect peripheral: CBPeripheral
    ) {
        let address = peripheral.identifier.uuidString
        bleDiag("didConnect peripheral \(address.prefix(8))")
        connectedPeripherals[address] = peripheral
        peripheral.delegate = self

        // Discover the mesh service
        peripheral.discoverServices([BLEMeshConstants.serviceUUID])
    }

    public func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: Error?
    ) {
        let address = peripheral.identifier.uuidString
        let errorMsg = error?.localizedDescription ?? "Unknown error"
        bleDiag("didFailToConnect \(address.prefix(8)): \(errorMsg)")

        lock.lock()
        if let continuation = pendingConnect.removeValue(forKey: address) {
            lock.unlock()
            continuation.resume(throwing: InterfaceError.connectionFailed(underlying: errorMsg))
        } else {
            lock.unlock()
        }
    }

    public func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: Error?
    ) {
        let address = peripheral.identifier.uuidString
        bleDiag("didDisconnect peripheral \(address.prefix(8)), error=\(error?.localizedDescription ?? "none")")
        connectedPeripherals.removeValue(forKey: address)

        if let conn = peripheralConnections.removeValue(forKey: address) {
            conn.handleDisconnection()
        }

        connectionLostContinuation?.yield(address)
    }
}

// MARK: - CBPeripheralDelegate

extension CoreBluetoothBLEDriver: CBPeripheralDelegate {

    public func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverServices error: Error?
    ) {
        let address = peripheral.identifier.uuidString
        bleDiag("didDiscoverServices for \(address.prefix(8)), error=\(error?.localizedDescription ?? "none"), services=\(peripheral.services?.map { $0.uuid.uuidString } ?? [])")
        guard error == nil,
              let service = peripheral.services?.first(where: { $0.uuid == BLEMeshConstants.serviceUUID }) else {
            let address = peripheral.identifier.uuidString
            lock.lock()
            if let cont = pendingConnect.removeValue(forKey: address) {
                lock.unlock()
                cont.resume(throwing: InterfaceError.connectionFailed(underlying: "Service not found"))
            } else {
                lock.unlock()
            }
            return
        }

        peripheral.discoverCharacteristics(
            [BLEMeshConstants.txCharUUID, BLEMeshConstants.rxCharUUID, BLEMeshConstants.identityCharUUID],
            for: service
        )
    }

    public func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: Error?
    ) {
        let address = peripheral.identifier.uuidString
        bleDiag("didDiscoverCharacteristics for \(address.prefix(8)), error=\(error?.localizedDescription ?? "none"), chars=\(service.characteristics?.map { $0.uuid.uuidString } ?? [])")

        guard error == nil, let chars = service.characteristics else {
            lock.lock()
            if let cont = pendingConnect.removeValue(forKey: address) {
                lock.unlock()
                cont.resume(throwing: InterfaceError.connectionFailed(underlying: "Characteristics not found"))
            } else {
                lock.unlock()
            }
            return
        }

        var txChar: CBCharacteristic?
        var rxChar: CBCharacteristic?
        var identityChar: CBCharacteristic?

        for char in chars {
            switch char.uuid {
            case BLEMeshConstants.txCharUUID: txChar = char
            case BLEMeshConstants.rxCharUUID: rxChar = char
            case BLEMeshConstants.identityCharUUID: identityChar = char
            default: break
            }
        }

        guard let tx = txChar, let rx = rxChar, let ident = identityChar else {
            lock.lock()
            if let cont = pendingConnect.removeValue(forKey: address) {
                lock.unlock()
                cont.resume(throwing: InterfaceError.connectionFailed(underlying: "Missing required characteristics"))
            } else {
                lock.unlock()
            }
            return
        }

        // Enable TX notifications
        peripheral.setNotifyValue(true, for: tx)

        // Get negotiated MTU
        let mtu = peripheral.maximumWriteValueLength(for: .withoutResponse) + BLEMeshConstants.headerSize

        // Create connection object
        let connection = CoreBluetoothPeerConnection(
            address: address,
            peripheral: peripheral,
            txCharacteristic: tx,
            rxCharacteristic: rx,
            identityCharacteristic: ident,
            mtu: min(mtu, BLEMeshConstants.maxMTU)
        )

        // Eagerly initialize receivedFragments to set continuation before any data arrives
        _ = connection.receivedFragments

        peripheralConnections[address] = connection

        // Resume pending connect
        lock.lock()
        if let cont = pendingConnect.removeValue(forKey: address) {
            lock.unlock()
            cont.resume(returning: connection)
        } else {
            lock.unlock()
        }
    }

    public func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard error == nil, let data = characteristic.value else {
            // If identity read failed, resume with error
            if characteristic.uuid == BLEMeshConstants.identityCharUUID {
                let address = peripheral.identifier.uuidString
                if let conn = peripheralConnections[address] {
                    bleDiag("Identity read failed for \(address.prefix(8)): \(error?.localizedDescription ?? "no data")")
                    conn.handleIdentityReadError(error ?? InterfaceError.connectionFailed(underlying: "No identity data"))
                }
            }
            return
        }
        let address = peripheral.identifier.uuidString

        if let conn = peripheralConnections[address] {
            if characteristic.uuid == BLEMeshConstants.identityCharUUID {
                // Identity characteristic read response — route to identity handler
                bleDiag("Identity read response from \(address.prefix(8)): \(data.count) bytes")
                conn.handleIdentityRead(data)
            } else {
                // TX notification — route to data handler
                conn.handleReceivedData(data)
            }
        }
    }

    public func peripheral(
        _ peripheral: CBPeripheral,
        didReadRSSI RSSI: NSNumber,
        error: Error?
    ) {
        let address = peripheral.identifier.uuidString

        lock.lock()
        if let cont = pendingRssi.removeValue(forKey: address) {
            lock.unlock()
            if let error = error {
                cont.resume(throwing: error)
            } else {
                cont.resume(returning: RSSI.intValue)
            }
        } else {
            lock.unlock()
        }
    }
}

// MARK: - CBPeripheralManagerDelegate

extension CoreBluetoothBLEDriver: CBPeripheralManagerDelegate {

    public func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        lock.lock()
        peripheralReady = peripheral.state == .poweredOn
        lock.unlock()

        let stateStr: String
        switch peripheral.state {
        case .poweredOn: stateStr = "poweredOn"
        case .poweredOff: stateStr = "poweredOff"
        case .unauthorized: stateStr = "unauthorized"
        case .unsupported: stateStr = "unsupported"
        case .resetting: stateStr = "resetting"
        case .unknown: stateStr = "unknown"
        @unknown default: stateStr = "rawValue=\(peripheral.state.rawValue)"
        }
        bleDiag("Peripheral manager state: \(stateStr)")
        logger.info("[BLE_DIAG] Peripheral manager state: \(stateStr, privacy: .public)")
    }

    public func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didReceiveWrite requests: [CBATTRequest]
    ) {
        for request in requests {
            guard let data = request.value else {
                peripheral.respond(to: request, withResult: .invalidAttributeValueLength)
                continue
            }

            if request.characteristic.uuid == BLEMeshConstants.rxCharUUID {
                let centralId = request.central.identifier.uuidString
                bleDiag("didReceiveWrite from \(centralId.prefix(8)), \(data.count) bytes, existing=\(centralConnections[centralId] != nil), hex=\(data.prefix(32).map { String(format: "%02x", $0) }.joined())")

                // Route to appropriate connection
                if let conn = centralConnections[centralId] {
                    conn.handleReceivedData(data)
                } else {
                    // New central writing to us — create connection for handshake
                    bleDiag("New incoming central \(centralId.prefix(8)) — creating connection")
                    let conn = CoreBluetoothPeerConnection(
                        address: centralId,
                        central: request.central,
                        peripheralManager: peripheralManager,
                        txCharacteristic: txCharacteristic,
                        mtu: min(request.central.maximumUpdateValueLength + BLEMeshConstants.headerSize, BLEMeshConstants.maxMTU)
                    )
                    centralConnections[centralId] = conn

                    // IMPORTANT: Eagerly initialize the receivedFragments lazy var
                    // BEFORE calling handleReceivedData. Otherwise the fragmentContinuation
                    // is nil and the first data (identity) is silently dropped.
                    _ = conn.receivedFragments

                    conn.handleReceivedData(data)

                    // Emit as incoming connection
                    incomingConnectionsContinuation?.yield(conn)
                }
            }

            peripheral.respond(to: request, withResult: .success)
        }
    }

    public func peripheralManager(
        _ peripheral: CBPeripheralManager,
        central: CBCentral,
        didSubscribeTo characteristic: CBCharacteristic
    ) {
        let centralId = central.identifier.uuidString
        subscribedCentrals[centralId] = central
        bleDiag("Central \(centralId.prefix(8)) subscribed to TX (char=\(characteristic.uuid.uuidString))")
    }

    public func peripheralManager(
        _ peripheral: CBPeripheralManager,
        central: CBCentral,
        didUnsubscribeFrom characteristic: CBCharacteristic
    ) {
        let centralId = central.identifier.uuidString
        bleDiag("Central \(centralId.prefix(8)) unsubscribed from TX — tearing down connection")
        subscribedCentrals.removeValue(forKey: centralId)

        if let conn = centralConnections.removeValue(forKey: centralId) {
            conn.handleDisconnection()
        }

        connectionLostContinuation?.yield(centralId)
    }
}

// MARK: - RSSI Reading Support

extension CoreBluetoothBLEDriver {

    /// Read RSSI for a connected peripheral.
    func readRssi(address: String) async throws -> Int {
        let peripheral: CBPeripheral? = bleQueue.sync { connectedPeripherals[address] }
        guard let peripheral else {
            throw InterfaceError.notConnected
        }

        return try await withCheckedThrowingContinuation { [weak self] continuation in
            guard let self = self else {
                continuation.resume(throwing: InterfaceError.notConnected)
                return
            }
            self.lock.lock()
            self.pendingRssi[address] = continuation
            self.lock.unlock()
            peripheral.readRSSI()
        }
    }
}

// MARK: - CoreBluetooth Peer Connection

/// A BLE connection backed by CoreBluetooth.
///
/// Can represent either a central-side connection (we connected to a peripheral)
/// or a peripheral-side connection (a central connected to us).
final class CoreBluetoothPeerConnection: BLEPeerConnection, @unchecked Sendable {

    let address: String
    let mtu: Int
    private(set) var identity: Data?

    // Central-side properties (we are the GATT client)
    private var peripheral: CBPeripheral?
    private var remoteTxChar: CBCharacteristic?
    private var remoteRxChar: CBCharacteristic?
    private var remoteIdentityChar: CBCharacteristic?

    // Peripheral-side properties (we are the GATT server)
    private var central: CBCentral?
    private var peripheralMgr: CBPeripheralManager?
    private var localTxChar: CBMutableCharacteristic?

    // Fragment stream
    private var fragmentContinuation: AsyncStream<Data>.Continuation?
    private(set) lazy var receivedFragments: AsyncStream<Data> = {
        AsyncStream { [weak self] continuation in
            self?.fragmentContinuation = continuation
        }
    }()

    private let lock = NSLock()
    private var pendingIdentityRead: CheckedContinuation<Data, Error>?
    private var pendingIdentityWrite: CheckedContinuation<Void, Error>?

    /// Central-side init (we connected to a remote peripheral).
    init(
        address: String,
        peripheral: CBPeripheral,
        txCharacteristic: CBCharacteristic,
        rxCharacteristic: CBCharacteristic,
        identityCharacteristic: CBCharacteristic,
        mtu: Int
    ) {
        self.address = address
        self.peripheral = peripheral
        self.remoteTxChar = txCharacteristic
        self.remoteRxChar = rxCharacteristic
        self.remoteIdentityChar = identityCharacteristic
        self.mtu = mtu
    }

    /// Peripheral-side init (a remote central connected to us).
    init(
        address: String,
        central: CBCentral,
        peripheralManager: CBPeripheralManager,
        txCharacteristic: CBMutableCharacteristic?,
        mtu: Int
    ) {
        self.address = address
        self.central = central
        self.peripheralMgr = peripheralManager
        self.localTxChar = txCharacteristic
        self.mtu = mtu
    }

    func sendFragment(_ data: Data) async throws {
        if let peripheral = peripheral, let rxChar = remoteRxChar {
            // Central side: write to remote RX characteristic
            peripheral.writeValue(data, for: rxChar, type: .withoutResponse)
        } else if let central = central, let peripheralMgr = peripheralMgr, let txChar = localTxChar {
            // Peripheral side: send notification via TX characteristic
            let sent = peripheralMgr.updateValue(data, for: txChar, onSubscribedCentrals: [central])
            if !sent {
                // Queue was full — wait briefly and retry
                try await Task.sleep(for: .milliseconds(10))
                peripheralMgr.updateValue(data, for: txChar, onSubscribedCentrals: [central])
            }
        } else {
            throw InterfaceError.notConnected
        }
    }

    func readIdentity() async throws -> Data {
        guard let peripheral = peripheral, let identityChar = remoteIdentityChar else {
            throw InterfaceError.connectionFailed(underlying: "No identity characteristic (peripheral-side)")
        }

        return try await withCheckedThrowingContinuation { [weak self] continuation in
            self?.lock.lock()
            self?.pendingIdentityRead = continuation
            self?.lock.unlock()
            peripheral.readValue(for: identityChar)
        }
    }

    func writeIdentity(_ identity: Data) async throws {
        if let peripheral = peripheral, let rxChar = remoteRxChar {
            peripheral.writeValue(identity, for: rxChar, type: .withResponse)
        } else {
            throw InterfaceError.connectionFailed(underlying: "Cannot write identity (peripheral-side)")
        }
    }

    func readRemoteRssi() async throws -> Int {
        guard let peripheral = peripheral else {
            throw InterfaceError.notConnected
        }
        // This needs to be routed through the driver
        peripheral.readRSSI()
        return 0 // Actual value comes through delegate
    }

    func close() {
        fragmentContinuation?.finish()
    }

    // MARK: - Internal Callbacks

    func handleReceivedData(_ data: Data) {
        fragmentContinuation?.yield(data)
    }

    func handleIdentityRead(_ data: Data) {
        lock.lock()
        let cont = pendingIdentityRead
        pendingIdentityRead = nil
        lock.unlock()

        identity = data
        cont?.resume(returning: data)
    }

    func handleIdentityReadError(_ error: Error) {
        lock.lock()
        let cont = pendingIdentityRead
        pendingIdentityRead = nil
        lock.unlock()

        cont?.resume(throwing: error)
    }

    func handleDisconnection() {
        fragmentContinuation?.finish()
    }
}

#endif // canImport(CoreBluetooth)
