// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  BLETransport.swift
//  ReticulumSwift
//
//  CoreBluetooth transport implementing the Transport protocol.
//  Provides BLE connectivity to RNode devices via Nordic UART Service.
//

#if canImport(CoreBluetooth)
import Foundation
import CoreBluetooth
import OSLog

/// Bluetooth Low Energy transport for RNode devices.
///
/// Scans for RNode peripherals advertising Nordic UART Service (NUS),
/// connects, discovers TX/RX characteristics, and enables bidirectional
/// data transfer. Implements connection timeout, exponential backoff,
/// MTU chunking, and state preservation for background mode.
///
/// Usage:
/// ```swift
/// let ble = BLETransport(deviceName: "RNode_A9")
/// ble.onStateChange = { state in print("BLE state: \(state)") }
/// ble.onDataReceived = { data in print("Received: \(data)") }
/// ble.connect()
/// ```
public final class BLETransport: Transport {

    // MARK: - Properties

    /// CoreBluetooth central manager for scanning and connections.
    private var centralManager: CBCentralManager?

    /// Currently connected peripheral (RNode device).
    private var peripheral: CBPeripheral?

    /// TX characteristic (RNode -> iOS, notifications enabled).
    private var txCharacteristic: CBCharacteristic?

    /// RX characteristic (iOS -> RNode, write without response).
    private var rxCharacteristic: CBCharacteristic?

    /// Optional target device name for filtered connection.
    ///
    /// If nil, connects to first RNode discovered with NUS service.
    /// If set, only connects to peripherals matching this name.
    private let targetDeviceName: String?

    /// Logger for BLE transport events.
    fileprivate let logger: Logger

    /// Queue for BLE operations (scanning, connection, discovery).
    private let bleQueue = DispatchQueue(label: "com.columba.bletransport", qos: .userInitiated)

    /// Current connection state.
    public private(set) var state: TransportState = .disconnected

    /// Callback invoked when connection state changes.
    public var onStateChange: ((TransportState) -> Void)?

    /// Callback invoked when data is received from the peripheral.
    public var onDataReceived: ((Data) -> Void)?

    /// Callback invoked when a peripheral is discovered during scanning.
    ///
    /// Useful for UI to display available RNode devices.
    /// Parameters: (peripheral, RSSI)
    public var onPeripheralDiscovered: ((CBPeripheral, NSNumber) -> Void)?

    /// Connection timeout work item (cancelled on success or disconnect).
    private var connectionTimeoutWork: DispatchWorkItem?

    /// Exponential backoff calculator for reconnection delays.
    private let backoff = ExponentialBackoff(baseDelay: 2.0, maxDelay: 30.0)

    /// Current reconnection attempt number (reset to 0 on successful connect).
    private var reconnectAttempt: Int = 0

    /// True when connect() was called before Bluetooth was ready.
    /// Deferred until centralManagerDidUpdateState(.poweredOn).
    private var pendingConnect: Bool = false

    /// Delegate wrapper for CoreBluetooth callbacks.
    private lazy var delegateWrapper = BLEDelegateWrapper(transport: self)

    // MARK: - Initialization

    /// Initialize a new BLE transport.
    ///
    /// - Parameters:
    ///   - deviceName: Optional target device name for filtered connection.
    ///   - subsystem: Logger subsystem (default: "com.columba.core").
    public init(deviceName: String? = nil, subsystem: String = "com.columba.core") {
        self.targetDeviceName = deviceName
        self.logger = Logger(subsystem: subsystem, category: "BLETransport")

        if let name = deviceName {
            logger.info("BLETransport initialized for device: \(name, privacy: .public)")
        } else {
            logger.info("BLETransport initialized (no device filter)")
        }

        // Initialize CBCentralManager with state preservation
        bleQueue.async { [weak self] in
            guard let self = self else { return }
            self.centralManager = CBCentralManager(
                delegate: self.delegateWrapper,
                queue: self.bleQueue,
                options: [CBCentralManagerOptionRestoreIdentifierKey: BLEConstants.RESTORE_IDENTIFIER_KEY]
            )
        }
    }

    // MARK: - Transport Protocol

    /// Establish BLE connection to an RNode device.
    ///
    /// Scans for peripherals advertising Nordic UART Service (NUS).
    /// If `targetDeviceName` is set, only connects to matching peripherals.
    /// Times out after 15 seconds if no peripheral is found or connection fails.
    public func connect() {
        bleQueue.async { [weak self] in
            guard let self = self else { return }

            // Prevent re-connection while already connecting or connected
            switch self.state {
            case .disconnected, .failed:
                break // OK to connect
            case .connecting, .connected:
                self.logger.warning("Connect called but already connecting/connected")
                return
            }

            // Check if Bluetooth is ready
            guard let manager = self.centralManager, manager.state == .poweredOn else {
                // Bluetooth not ready yet — defer scan until poweredOn callback
                self.logger.info("Bluetooth not ready yet, deferring scan until powered on")
                self.pendingConnect = true
                self.updateState(.connecting)
                return
            }

            self.updateState(.connecting)

            let isScanOnly = (self.targetDeviceName == nil)

            if isScanOnly {
                // Scan-only mode (device picker): scan ALL devices so RNodes that
                // don't advertise NUS service UUID still appear. User selects by name.
                self.logger.error("[BLETRANS] Scanning all peripherals (discovery mode)")
                manager.scanForPeripherals(
                    withServices: nil,
                    options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
                )
            } else {
                // Targeted mode: scan without service filter because many RNodes
                // don't advertise the NUS service UUID in BLE advertisement packets.
                // We filter by peripheral name instead (in handleDiscoveredPeripheral).
                self.logger.error("[BLETRANS] Scanning for peripheral named '\(self.targetDeviceName ?? "", privacy: .public)'")
                manager.scanForPeripherals(
                    withServices: nil,
                    options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
                )
            }

            // Start connection timeout (only for targeted connections, not scan-only)
            if self.targetDeviceName != nil {
                self.startConnectionTimeout()
            }
        }
    }

    /// Send data to the connected RNode peripheral.
    ///
    /// Data is chunked to respect the peripheral's MTU. The write type is
    /// determined by the RX characteristic's supported properties:
    /// - `.writeWithoutResponse` preferred for lowest latency
    /// - `.write` (with response) used as fallback
    ///
    /// - Parameters:
    ///   - data: Data to send.
    ///   - completion: Optional callback with nil on success, Error on failure.
    public func send(_ data: Data, completion: ((Error?) -> Void)? = nil) {
        bleQueue.async { [weak self] in
            guard let self = self else {
                completion?(BLEError.notConnected)
                return
            }

            // Check if connected
            guard self.state == .connected else {
                self.logger.error("Send failed: not connected")
                completion?(BLEError.notConnected)
                return
            }

            // Check if peripheral and RX characteristic exist
            guard let peripheral = self.peripheral,
                  let rxChar = self.rxCharacteristic else {
                self.logger.error("Send failed: peripheral or RX characteristic missing")
                completion?(BLEError.notConnected)
                return
            }

            // Determine write type based on characteristic properties
            let writeType: CBCharacteristicWriteType
            if rxChar.properties.contains(.writeWithoutResponse) {
                // Check if buffer is available for write-without-response
                guard peripheral.canSendWriteWithoutResponse else {
                    self.logger.warning("Write buffer full, falling back to writeWithResponse")
                    // Fall back to write-with-response instead of failing
                    if rxChar.properties.contains(.write) {
                        self.doWrite(data, to: peripheral, char: rxChar, type: .withResponse, completion: completion)
                    } else {
                        completion?(BLEError.bufferFull)
                    }
                    return
                }
                writeType = .withoutResponse
            } else if rxChar.properties.contains(.write) {
                writeType = .withResponse
            } else {
                self.logger.error("[BLETRANS] RX characteristic supports neither write nor writeWithoutResponse! props=\(rxChar.properties.rawValue, privacy: .public)")
                completion?(BLEError.notConnected)
                return
            }

            self.doWrite(data, to: peripheral, char: rxChar, type: writeType, completion: completion)
        }
    }

    /// Perform the actual BLE write with chunking.
    private func doWrite(_ data: Data, to peripheral: CBPeripheral, char rxChar: CBCharacteristic, type writeType: CBCharacteristicWriteType, completion: ((Error?) -> Void)?) {
        // Query MTU for the selected write type
        let mtu = peripheral.maximumWriteValueLength(for: writeType)
        let safeMtu = max(mtu, BLEConstants.DEFAULT_MTU)

        self.logger.error("[BLETRANS] TX \(data.count, privacy: .public) bytes (MTU: \(safeMtu, privacy: .public), type: \(writeType == .withResponse ? "withResp" : "noResp", privacy: .public)): \(data.prefix(20).map { String(format: "%02x", $0) }.joined(separator: " "), privacy: .public)")

        // Send data (chunk if necessary)
        if data.count <= safeMtu {
            peripheral.writeValue(data, for: rxChar, type: writeType)
            completion?(nil)
        } else {
            let chunks = data.chunked(into: safeMtu)
            for chunk in chunks {
                peripheral.writeValue(chunk, for: rxChar, type: writeType)
            }
            completion?(nil)
        }
    }

    /// Resume scanning after a connection attempt (successful or failed).
    ///
    /// Cancels any pending reconnect, disconnects any peripheral, clears
    /// connection state, and restarts the BLE scan. Used by wizard/picker UI
    /// to go back to discovery mode without creating a new CBCentralManager.
    public func resumeScan() {
        bleQueue.async { [weak self] in
            guard let self = self else { return }

            // Cancel connection timeout
            self.connectionTimeoutWork?.cancel()
            self.connectionTimeoutWork = nil

            // Disconnect peripheral if any
            if let peripheral = self.peripheral {
                self.centralManager?.cancelPeripheralConnection(peripheral)
            }
            self.peripheral = nil
            self.txCharacteristic = nil
            self.rxCharacteristic = nil
            self.reconnectAttempt = 0

            // Restart scanning
            guard let manager = self.centralManager, manager.state == .poweredOn else {
                self.updateState(.disconnected)
                return
            }

            manager.stopScan()

            let isScanOnly = (self.targetDeviceName == nil)
            if isScanOnly {
                manager.scanForPeripherals(
                    withServices: nil,
                    options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
                )
            } else {
                let serviceUUID = CBUUID(string: BLEConstants.NUS_SERVICE_UUID)
                manager.scanForPeripherals(
                    withServices: [serviceUUID],
                    options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
                )
            }
            self.updateState(.connecting)
        }
    }

    /// Connect to a specific already-discovered peripheral.
    ///
    /// Used to trigger BLE pairing by connecting to a peripheral that was
    /// discovered during a scan-only session (targetDeviceName == nil).
    /// Stops scanning before connecting.
    ///
    /// - Parameter peripheral: The peripheral to connect to (must have been
    ///   discovered by THIS transport's CBCentralManager).
    public func connectToPeripheral(_ peripheral: CBPeripheral) {
        bleQueue.async { [weak self] in
            guard let self = self else {
                Logger(subsystem: "com.columba.core", category: "BLETransport")
                    .error("[PROBE] connectToPeripheral: self is nil")
                return
            }
            let name = peripheral.name ?? "Unknown"
            self.logger.error("[PROBE] connectToPeripheral called for \(name, privacy: .public), peripheral.state=\(String(describing: peripheral.state.rawValue), privacy: .public)")
            guard let manager = self.centralManager, manager.state == .poweredOn else {
                self.logger.error("[PROBE] manager not powered on, state=\(String(describing: self.centralManager?.state.rawValue ?? -1), privacy: .public)")
                self.updateState(.failed(BLEError.bluetoothNotReady))
                return
            }

            // Stop scanning
            manager.stopScan()

            // Store peripheral and connect
            self.peripheral = peripheral
            self.updateState(.connecting)
            self.startConnectionTimeout()
            self.logger.error("[PROBE] calling manager.connect for \(name, privacy: .public)")
            manager.connect(peripheral, options: nil)
        }
    }

    /// Disconnect and clean up the BLE connection.
    public func disconnect() {
        bleQueue.async { [weak self] in
            guard let self = self else { return }

            self.logger.info("Disconnecting BLE connection")

            // Cancel timeout
            self.connectionTimeoutWork?.cancel()
            self.connectionTimeoutWork = nil

            // Stop scanning if active
            self.centralManager?.stopScan()

            // Disconnect peripheral if connected
            if let peripheral = self.peripheral {
                self.centralManager?.cancelPeripheralConnection(peripheral)
            }

            // Clear references
            self.peripheral = nil
            self.txCharacteristic = nil
            self.rxCharacteristic = nil

            // Reset reconnect attempt counter
            self.reconnectAttempt = 0
            self.pendingConnect = false

            self.updateState(.disconnected)
        }
    }

    // MARK: - Internal Handler Methods

    /// Handle CBCentralManager state changes.
    ///
    /// Called by BLEDelegateWrapper when Bluetooth state changes.
    func handleCentralStateChange(_ cbState: CBManagerState) {
        logger.debug("CBCentralManager state: \(String(describing: cbState), privacy: .public)")

        switch cbState {
        case .poweredOn:
            logger.info("Bluetooth powered on")
            // If connect() was called before Bluetooth was ready, start scanning now
            if pendingConnect {
                pendingConnect = false
                logger.info("Starting deferred BLE scan")
                let isScanOnly = (targetDeviceName == nil)
                if isScanOnly {
                    centralManager?.scanForPeripherals(
                        withServices: nil,
                        options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
                    )
                } else {
                    // Scan without service UUID filter — RNodes don't advertise NUS in their
                    // advertisement packets. We filter by peripheral name in handleDiscoveredPeripheral.
                    centralManager?.scanForPeripherals(
                        withServices: nil,
                        options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
                    )
                    startConnectionTimeout()
                }
            }

        case .poweredOff:
            logger.warning("Bluetooth powered off")
            if state == .connecting || state == .connected {
                updateState(.failed(BLEError.bluetoothNotReady))
            }

        case .unauthorized:
            logger.error("Bluetooth unauthorized")
            updateState(.failed(BLEError.bluetoothUnauthorized))

        case .unsupported:
            logger.error("Bluetooth unsupported")
            updateState(.failed(BLEError.bluetoothUnsupported))

        case .resetting:
            logger.warning("Bluetooth resetting")

        case .unknown:
            logger.warning("Bluetooth state unknown")

        @unknown default:
            logger.warning("Unknown Bluetooth state")
        }
    }

    /// Handle discovered peripheral during scan.
    ///
    /// Called by BLEDelegateWrapper when a peripheral is discovered.
    func handleDiscoveredPeripheral(_ peripheral: CBPeripheral, advertisementData: [String: Any], rssi: NSNumber) {
        let name = peripheral.name ?? "Unknown"
        logger.error("[BLETRANS] Discovered: '\(name, privacy: .public)' RSSI=\(rssi, privacy: .public)")

        // Notify UI callback (if set)
        DispatchQueue.main.async { [weak self] in
            self?.onPeripheralDiscovered?(peripheral, rssi)
        }

        // If no target device name, we're in scan-only mode — don't auto-connect
        guard let targetName = targetDeviceName else {
            return
        }

        // Filter by device name
        guard peripheral.name == targetName else {
            return
        }

        // Stop scanning and connect
        logger.error("[BLETRANS] Name match! Connecting to '\(name, privacy: .public)'")
        centralManager?.stopScan()
        self.peripheral = peripheral
        centralManager?.connect(peripheral, options: nil)
    }

    /// Handle successful peripheral connection.
    ///
    /// Called by BLEDelegateWrapper when peripheral connects.
    func handleConnectedPeripheral(_ peripheral: CBPeripheral) {
        let name = peripheral.name ?? "Unknown"
        logger.error("[PROBE] Connected to peripheral: \(name, privacy: .public)")

        // Discover Nordic UART Service
        let serviceUUID = CBUUID(string: BLEConstants.NUS_SERVICE_UUID)
        peripheral.discoverServices([serviceUUID])
    }

    /// Handle failed peripheral connection.
    ///
    /// Called by BLEDelegateWrapper when connection fails.
    func handleFailedToConnect(_ peripheral: CBPeripheral, error: Error?) {
        let name = peripheral.name ?? "Unknown"
        let errorDesc = error?.localizedDescription ?? "Unknown error"
        logger.error("[PROBE] Failed to connect to \(name, privacy: .public): \(errorDesc, privacy: .public)")

        connectionTimeoutWork?.cancel()
        connectionTimeoutWork = nil

        let wrappedError = error ?? BLEError.connectionTimedOut
        updateState(.failed(wrappedError))

        // Schedule reconnect with exponential backoff
        scheduleReconnect()
    }

    /// Handle peripheral disconnection.
    ///
    /// Called by BLEDelegateWrapper when peripheral disconnects.
    func handleDisconnectedPeripheral(_ peripheral: CBPeripheral, error: Error?) {
        let name = peripheral.name ?? "Unknown"

        if let error = error {
            logger.error("[PROBE] Disconnected from \(name, privacy: .public): \(error.localizedDescription, privacy: .public)")
            updateState(.failed(error))
            // Schedule reconnect with exponential backoff
            scheduleReconnect()
        } else {
            logger.error("[PROBE] Disconnected from \(name, privacy: .public) (clean disconnect)")
            updateState(.disconnected)
        }

        // Clear peripheral references
        self.peripheral = nil
        self.txCharacteristic = nil
        self.rxCharacteristic = nil
    }

    /// Handle discovered services on peripheral.
    ///
    /// Called by BLEDelegateWrapper when services are discovered.
    func handleDiscoveredServices(_ peripheral: CBPeripheral, error: Error?) {
        if let error = error {
            logger.error("Service discovery failed: \(error.localizedDescription, privacy: .public)")
            updateState(.failed(BLEError.serviceDiscoveryFailed))
            return
        }

        guard let services = peripheral.services else {
            logger.error("No services found")
            updateState(.failed(BLEError.serviceDiscoveryFailed))
            return
        }

        // Find Nordic UART Service
        let serviceUUID = CBUUID(string: BLEConstants.NUS_SERVICE_UUID)
        guard let nusService = services.first(where: { $0.uuid == serviceUUID }) else {
            logger.error("Nordic UART Service not found")
            updateState(.failed(BLEError.serviceDiscoveryFailed))
            return
        }

        logger.error("[BLETRANS] Found NUS service, discovering characteristics...")

        // Discover TX and RX characteristics
        let txUUID = CBUUID(string: BLEConstants.NUS_TX_CHAR_UUID)
        let rxUUID = CBUUID(string: BLEConstants.NUS_RX_CHAR_UUID)
        peripheral.discoverCharacteristics([txUUID, rxUUID], for: nusService)
    }

    /// Handle discovered characteristics on service.
    ///
    /// Called by BLEDelegateWrapper when characteristics are discovered.
    func handleDiscoveredCharacteristics(_ peripheral: CBPeripheral, service: CBService, error: Error?) {
        if let error = error {
            logger.error("Characteristic discovery failed: \(error.localizedDescription, privacy: .public)")
            updateState(.failed(BLEError.characteristicDiscoveryFailed))
            return
        }

        guard let characteristics = service.characteristics else {
            logger.error("No characteristics found")
            updateState(.failed(BLEError.characteristicDiscoveryFailed))
            return
        }

        // Find TX characteristic (RNode -> iOS, notifications)
        let txUUID = CBUUID(string: BLEConstants.NUS_TX_CHAR_UUID)
        if let tx = characteristics.first(where: { $0.uuid == txUUID }) {
            txCharacteristic = tx
            logger.error("[BLETRANS] Found TX char, enabling notifications...")
            peripheral.setNotifyValue(true, for: tx)
        }

        // Find RX characteristic (iOS -> RNode, write)
        let rxUUID = CBUUID(string: BLEConstants.NUS_RX_CHAR_UUID)
        if let rx = characteristics.first(where: { $0.uuid == rxUUID }) {
            rxCharacteristic = rx
            logger.error("[BLETRANS] Found RX char")
        }

        // Check if both characteristics are present
        guard txCharacteristic != nil && rxCharacteristic != nil else {
            logger.error("Missing TX or RX characteristic")
            updateState(.failed(BLEError.characteristicDiscoveryFailed))
            return
        }

        // Connection fully established
        logger.error("[BLETRANS] BLE connection ready — NUS TX+RX found")
        connectionTimeoutWork?.cancel()
        connectionTimeoutWork = nil
        reconnectAttempt = 0
        updateState(.connected)
    }

    /// Handle received data from TX characteristic.
    ///
    /// Called by BLEDelegateWrapper when notifications arrive.
    func handleReceivedData(_ data: Data) {
        logger.error("[BLETRANS] RX \(data.count, privacy: .public) bytes: \(data.prefix(20).map { String(format: "%02x", $0) }.joined(separator: " "), privacy: .public)")

        DispatchQueue.main.async { [weak self] in
            self?.onDataReceived?(data)
        }
    }

    /// Handle restored state from system (state preservation).
    ///
    /// Called by BLEDelegateWrapper when app is restored from background.
    func handleRestoredState(_ dict: [String: Any]) {
        logger.info("Restoring BLE state from system")

        // Restore peripherals
        if let peripherals = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral],
           let restoredPeripheral = peripherals.first {
            logger.info("Restored peripheral: \(restoredPeripheral.name ?? "Unknown", privacy: .public)")
            peripheral = restoredPeripheral
            restoredPeripheral.delegate = delegateWrapper

            // Re-discover services and characteristics if connected
            if restoredPeripheral.state == .connected {
                let serviceUUID = CBUUID(string: BLEConstants.NUS_SERVICE_UUID)
                restoredPeripheral.discoverServices([serviceUUID])
            }
        }

        // Restore scan state
        if let scanServices = dict[CBCentralManagerRestoredStateScanServicesKey] as? [CBUUID] {
            logger.info("Restored scan for services: \(scanServices, privacy: .public)")
            // Optionally resume scanning
        }
    }

    // MARK: - Private Helpers

    /// Start a timeout that fires if connection isn't established in time.
    private func startConnectionTimeout() {
        connectionTimeoutWork?.cancel()

        let work = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            guard self.state == .connecting else { return }

            self.logger.error("Connection timed out after \(BLEConstants.CONNECTION_TIMEOUT, privacy: .public)s")
            self.centralManager?.stopScan()

            if let peripheral = self.peripheral {
                self.centralManager?.cancelPeripheralConnection(peripheral)
            }

            self.peripheral = nil
            self.updateState(.failed(BLEError.connectionTimedOut))

            // Schedule reconnect with exponential backoff
            self.scheduleReconnect()
        }

        connectionTimeoutWork = work
        bleQueue.asyncAfter(
            deadline: .now() + BLEConstants.CONNECTION_TIMEOUT,
            execute: work
        )
    }

    /// Schedule a reconnection attempt with exponential backoff.
    private func scheduleReconnect() {
        let delay = backoff.nextDelay(attempt: reconnectAttempt)
        reconnectAttempt += 1

        logger.info("Scheduling reconnect in \(delay, privacy: .public)s (attempt \(self.reconnectAttempt, privacy: .public))")

        bleQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self = self else { return }
            // Only reconnect if still in failed state
            if case .failed = self.state {
                self.connect()
            }
        }
    }

    /// Update state and notify callback on main queue.
    private func updateState(_ newState: TransportState) {
        logger.error("[PROBE] state -> \(String(describing: newState), privacy: .public)")
        state = newState
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.onStateChange?(newState)
        }
    }
}

// MARK: - BLE Delegate Wrapper

/// Wrapper class to bridge CoreBluetooth delegate callbacks to BLETransport.
///
/// CoreBluetooth requires delegate to be NSObject, but Transport is a protocol.
/// This wrapper translates delegate methods into internal handler calls.
final class BLEDelegateWrapper: NSObject {

    /// Weak reference to parent transport (prevents retain cycle).
    private weak var transport: BLETransport?

    /// Initialize with parent transport.
    init(transport: BLETransport) {
        self.transport = transport
        super.init()
    }
}

// MARK: - CBCentralManagerDelegate

extension BLEDelegateWrapper: CBCentralManagerDelegate {

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        transport?.handleCentralStateChange(central.state)
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        transport?.handleDiscoveredPeripheral(peripheral, advertisementData: advertisementData, rssi: RSSI)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        // Set delegate to wrapper
        peripheral.delegate = self
        transport?.handleConnectedPeripheral(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        transport?.handleFailedToConnect(peripheral, error: error)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        transport?.handleDisconnectedPeripheral(peripheral, error: error)
    }

    func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        transport?.handleRestoredState(dict)
    }
}

// MARK: - CBPeripheralDelegate

extension BLEDelegateWrapper: CBPeripheralDelegate {

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        transport?.handleDiscoveredServices(peripheral, error: error)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        transport?.handleDiscoveredCharacteristics(peripheral, service: service, error: error)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error = error {
            transport?.logger.error("Characteristic update error: \(error.localizedDescription, privacy: .public)")
            return
        }

        guard let data = characteristic.value, !data.isEmpty else {
            return
        }

        transport?.handleReceivedData(data)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if let error = error {
            transport?.logger.error("Notification state update error: \(error.localizedDescription, privacy: .public)")
            return
        }

        if characteristic.isNotifying {
            transport?.logger.info("Notifications enabled for characteristic \(characteristic.uuid, privacy: .public)")
        } else {
            transport?.logger.info("Notifications disabled for characteristic \(characteristic.uuid, privacy: .public)")
        }
    }
}

// MARK: - Data Chunking Extension

/// Private extension for chunking data into MTU-sized pieces.
private extension Data {
    /// Split data into chunks of specified size.
    ///
    /// - Parameter size: Maximum chunk size in bytes.
    /// - Returns: Array of data chunks, each <= size bytes.
    func chunked(into size: Int) -> [Data] {
        guard size > 0 else { return [self] }
        return stride(from: 0, to: count, by: size).map {
            self[$0..<Swift.min($0 + size, count)]
        }
    }
}

#endif // canImport(CoreBluetooth)
