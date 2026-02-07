//
//  RNodeInterface.swift
//  ReticulumSwift
//
//  Actor-based RNode BLE interface with firmware detection and radio configuration.
//  Wraps KISSFramedTransport with RNode device lifecycle management.
//

#if canImport(CoreBluetooth)
import Foundation

// MARK: - RNodeInterface

/// Actor-based RNode BLE interface with firmware detection and radio configuration.
///
/// RNodeInterface manages the complete RNode device lifecycle:
/// - Firmware detect handshake (CMD_DETECT, CMD_FW_VERSION, CMD_PLATFORM, CMD_MCU)
/// - Radio configuration sequence (frequency, bandwidth, spreading factor, etc.)
/// - Configuration validation via echoed parameters
/// - Command parsing for all RNode responses
/// - Automatic reconnection with exponential backoff
///
/// Features:
/// - Automatic firmware version validation (requires 1.52+)
/// - Radio parameter echo validation with frequency tolerance
/// - Queue-based flow control with CMD_READY signaling
/// - Error handling matching Python severity levels
/// - Thread-safe statistics tracking (bytes sent/received, RSSI, SNR)
///
/// Example usage:
/// ```swift
/// let config = InterfaceConfig(
///     id: "rnode1",
///     name: "RNode A9",
///     type: .rnode,
///     enabled: true,
///     mode: .full,
///     host: "RNode_A9",  // BLE device name
///     port: 0
/// )
/// let interface = try RNodeInterface(config: config)
///
/// var radioConfig = RadioConfig(
///     frequency: 915_000_000,
///     bandwidth: 125_000,
///     txPower: 17,
///     spreadingFactor: 7,
///     codingRate: 5
/// )
/// try await interface.configureRadio(radioConfig)
/// try await interface.connect()
/// try await interface.send(packetData)
/// ```
public actor RNodeInterface: @preconcurrency NetworkInterface {

    // MARK: - Properties

    /// Unique identifier for this interface
    public let id: String

    /// Configuration used to create this interface
    public let config: InterfaceConfig

    /// Interface mode controlling announce propagation
    public let mode: InterfaceMode

    /// Current connection state
    public private(set) var state: InterfaceState = .disconnected

    /// Underlying KISS-framed transport (wraps BLETransport)
    private var transport: KISSFramedTransport?

    /// Exponential backoff calculator for reconnection (BLE-specific: 2s-30s)
    private let backoff: ExponentialBackoff

    /// Current reconnection task
    private var reconnectTask: Task<Void, Never>?

    /// Whether automatic reconnection is enabled
    private var autoReconnect: Bool = true

    /// Current reconnection attempt (0 when not reconnecting)
    private var reconnectAttempt: Int = 0

    /// Total bytes sent through this interface
    public private(set) var bytesSent: UInt64 = 0

    /// Total bytes received through this interface
    public private(set) var bytesReceived: UInt64 = 0

    /// Description of the last connection error (for UI display)
    public private(set) var lastErrorDescription: String?

    // MARK: - RNode-Specific State

    /// Radio configuration (set via configureRadio before connect)
    public private(set) var radioConfig: RadioConfig?

    /// Whether RNode was detected via handshake
    public private(set) var detected: Bool = false

    /// Whether firmware version is acceptable
    public private(set) var firmwareOk: Bool = false

    /// Firmware major version
    public private(set) var majVersion: UInt8 = 0

    /// Firmware minor version
    public private(set) var minVersion: UInt8 = 0

    /// Platform ID (AVR, ESP32, nRF52)
    public private(set) var platform: UInt8 = 0

    /// MCU type
    public private(set) var mcu: UInt8 = 0

    /// Whether interface is online (detected + configured + validated)
    public private(set) var online: Bool = false

    /// Whether interface is ready to send (all setup complete)
    private var interfaceReady: Bool = false

    /// Packet queue for flow control (max 32 packets)
    private var packetQueue: [Data] = []

    /// Maximum queue depth
    private let maxQueueDepth: Int = 32

    // MARK: - Radio Echo State (for validation)

    /// Echoed frequency from RNode
    private var rFrequency: UInt32?

    /// Echoed bandwidth from RNode
    private var rBandwidth: UInt32?

    /// Echoed TX power from RNode
    private var rTxPower: UInt8?

    /// Echoed spreading factor from RNode
    private var rSf: UInt8?

    /// Echoed coding rate from RNode
    private var rCr: UInt8?

    /// Echoed radio state from RNode
    private var rState: UInt8?

    /// Echoed radio lock from RNode
    private var rLock: UInt8?

    /// Last packet RSSI (dBm)
    private var rStatRssi: Int?

    /// Last packet SNR (dB)
    private var rStatSnr: Int?

    /// Battery state
    private var rBatteryState: UInt8?

    /// Battery percentage (0-100)
    private var rBatteryPercent: UInt8?

    // MARK: - Delegate

    /// Weak reference wrapper for delegate to work within actor
    private var delegateRef: WeakDelegate?

    /// Delegate for interface events
    public var delegate: InterfaceDelegate? {
        get { delegateRef?.delegate }
        set { delegateRef = newValue.map { WeakDelegate($0) } }
    }

    /// Set the delegate for receiving interface events.
    ///
    /// This method satisfies the NetworkInterface protocol requirement
    /// and is equivalent to setting the delegate property directly.
    ///
    /// - Parameter delegate: Delegate to receive events
    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self.delegate = delegate
    }

    // MARK: - Initialization

    /// Create a new RNode BLE interface.
    ///
    /// - Parameter config: Interface configuration (must be type .rnode)
    /// - Throws: InterfaceError.invalidConfig if config.type is not .rnode
    public init(config: InterfaceConfig) throws {
        guard config.type == .rnode else {
            throw InterfaceError.invalidConfig(reason: "RNodeInterface requires config type .rnode, got \(config.type)")
        }

        self.id = config.id
        self.config = config
        self.mode = config.mode
        self.backoff = ExponentialBackoff(baseDelay: 2.0, maxDelay: 30.0)
    }

    // MARK: - Public API

    /// Configure radio parameters.
    ///
    /// Must be called before connect() to set radio configuration.
    /// Configuration is validated immediately.
    ///
    /// - Parameter config: Radio configuration to apply
    /// - Throws: RNodeError.radioConfigFailed if configuration is invalid
    public func configureRadio(_ config: RadioConfig) async throws {
        try config.validate()
        self.radioConfig = config
    }

    /// Connect to the RNode device.
    ///
    /// Starts the connection process. State transitions from disconnected
    /// to connecting, then to connected on success. If connection fails,
    /// automatic reconnection begins.
    public func connect() async throws {
        guard state == .disconnected else { return }

        autoReconnect = true
        await transitionState(to: .connecting)
        await setupTransport()
    }

    /// Disconnect from the RNode device.
    ///
    /// Stops any ongoing reconnection attempts and disconnects the transport.
    /// State transitions to disconnected.
    public func disconnect() async {
        autoReconnect = false

        // Cancel any ongoing reconnection
        reconnectTask?.cancel()
        reconnectTask = nil
        reconnectAttempt = 0

        // Disconnect transport
        transport?.disconnect()
        transport = nil

        state = .disconnected
        notifyStateChange()
    }

    /// Send data through the interface.
    ///
    /// - Parameter data: Raw packet data to send (will be KISS framed)
    /// - Throws: InterfaceError.notConnected if not in connected state
    /// - Throws: InterfaceError.sendFailed if transmission fails
    public func send(_ data: Data) async throws {
        // Stub for now - Plan 03 fills in flow control logic
        guard state == .connected else {
            throw InterfaceError.notConnected
        }
        throw InterfaceError.sendFailed(underlying: "Flow control not yet implemented (Plan 03)")
    }

    // MARK: - Private Methods - Transport Setup

    /// Set up the KISS-framed BLE transport and wire callbacks.
    private func setupTransport() async {
        // Create BLE transport targeting device name from config.host
        let bleTransport = BLETransport(deviceName: config.host)

        // Wrap in KISS framing layer
        let kissTransport = KISSFramedTransport(transport: bleTransport)

        // Wire state change callback
        kissTransport.onStateChange = { [weak self] transportState in
            Task { [weak self] in
                await self?.handleTransportStateChange(transportState)
            }
        }

        // Wire data received callback (CMD_DATA frames)
        kissTransport.onDataReceived = { [weak self] data in
            Task { [weak self] in
                await self?.handleDataReceived(data)
            }
        }

        // Wire command received callback (all other KISS commands)
        kissTransport.onCommandReceived = { [weak self] command, payload in
            Task { [weak self] in
                await self?.handleCommand(command, payload)
            }
        }

        self.transport = kissTransport

        // Start connection
        kissTransport.connect()
    }

    /// Handle transport state changes.
    private func handleTransportStateChange(_ transportState: TransportState) async {
        switch transportState {
        case .disconnected:
            // Transport disconnected - trigger reconnection if we were connected
            if state == .connected || state == .connecting {
                await startReconnectLoop()
            }

        case .connecting:
            // Already in connecting state from our side
            break

        case .connected:
            // BLE connected - now run firmware detect and config
            reconnectAttempt = 0
            lastErrorDescription = nil
            await configureDevice()

        case .failed(let error):
            // Capture error description for UI display
            lastErrorDescription = error.localizedDescription
            // Connection failed - notify delegate and start reconnection
            notifyError(error)
            await startReconnectLoop()
        }
    }

    // MARK: - Device Configuration

    /// Configure the RNode device after BLE connection.
    ///
    /// Follows Python configure_device sequence (lines 424-467):
    /// 1. Reset radio state
    /// 2. Send detect handshake
    /// 3. Wait for detect response (5s timeout)
    /// 4. Validate firmware version (>= 1.52)
    /// 5. If radioConfig set: initialize radio and validate
    /// 6. Transition to connected state
    private func configureDevice() async {
        // Reset radio state
        resetRadioState()

        // Send detect handshake
        do {
            try await detect()
        } catch {
            lastErrorDescription = "Detect handshake failed: \(error.localizedDescription)"
            notifyError(RNodeError.detectFailed)
            await disconnect()
            return
        }

        // Wait up to 5 seconds for detected flag
        let startTime = Date()
        while !detected && Date().timeIntervalSince(startTime) < 5.0 {
            try? await Task.sleep(nanoseconds: 100_000_000) // 100ms
        }

        if !detected {
            lastErrorDescription = "RNode did not respond to detect handshake"
            notifyError(RNodeError.detectFailed)
            await disconnect()
            return
        }

        // Validate firmware version
        if majVersion < RNodeConstants.REQUIRED_FW_VER_MAJ ||
           (majVersion == RNodeConstants.REQUIRED_FW_VER_MAJ && minVersion < RNodeConstants.REQUIRED_FW_VER_MIN) {
            let error = RNodeError.firmwareVersionTooOld(major: majVersion, minor: minVersion)
            lastErrorDescription = error.localizedDescription
            notifyError(error)
            await disconnect()
            return
        }

        firmwareOk = true

        // If radio config is set, initialize radio
        if radioConfig != nil {
            do {
                try await initRadio()
                try await validateRadioState()
                interfaceReady = true
                online = true
            } catch {
                lastErrorDescription = "Radio configuration failed: \(error.localizedDescription)"
                notifyError(error)
                await disconnect()
                return
            }
        }

        // Success!
        await transitionState(to: .connected)
    }

    /// Reset all radio echo state variables.
    private func resetRadioState() {
        rFrequency = nil
        rBandwidth = nil
        rTxPower = nil
        rSf = nil
        rCr = nil
        rState = nil
        rLock = nil
        rStatRssi = nil
        rStatSnr = nil
        rBatteryState = nil
        rBatteryPercent = nil
        detected = false
        firmwareOk = false
        online = false
        interfaceReady = false
    }

    /// Send detect handshake to RNode.
    ///
    /// Matches Python detect() (lines 483-487).
    /// Sends all four commands in one raw write:
    /// - CMD_DETECT with DETECT_REQ
    /// - CMD_FW_VERSION query
    /// - CMD_PLATFORM query
    /// - CMD_MCU query
    private func detect() async throws {
        // Build detect command sequence
        // Note: trailing FEND of one command IS the leading FEND of the next
        let detectCommand = Data([
            KISS.FEND, RNodeConstants.CMD_DETECT, RNodeConstants.DETECT_REQ, KISS.FEND,
            RNodeConstants.CMD_FW_VERSION, 0x00, KISS.FEND,
            RNodeConstants.CMD_PLATFORM, 0x00, KISS.FEND,
            RNodeConstants.CMD_MCU, 0x00, KISS.FEND
        ])

        guard let transport = transport else {
            throw InterfaceError.notConnected
        }

        // Use sendRaw since this is pre-built KISS frames
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            transport.sendRaw(detectCommand) { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    /// Initialize radio with configured parameters.
    ///
    /// Matches Python initRadio() (lines 470-481).
    /// Sends configuration commands in order:
    /// 1. Frequency (4 bytes big-endian)
    /// 2. Bandwidth (4 bytes big-endian)
    /// 3. TX Power (1 byte)
    /// 4. Spreading Factor (1 byte)
    /// 5. Coding Rate (1 byte)
    /// 6. Short-term airtime lock (optional, 2 bytes big-endian)
    /// 7. Long-term airtime lock (optional, 2 bytes big-endian)
    /// 8. Radio state ON (1 byte)
    ///
    /// Then waits 2 seconds for BLE settling.
    private func initRadio() async throws {
        guard let config = radioConfig else {
            throw RNodeError.notConfigured
        }

        // Send config commands in order
        try await setFrequency(config.frequency)
        try await setBandwidth(config.bandwidth)
        try await setTXPower(config.txPower)
        try await setSpreadingFactor(config.spreadingFactor)
        try await setCodingRate(config.codingRate)

        // Optional airtime locks
        if let stAlock = config.stAlock {
            try await setSTALock(stAlock)
        }
        if let ltAlock = config.ltAlock {
            try await setLTALock(ltAlock)
        }

        // Turn radio on
        try await setRadioState(RNodeConstants.RADIO_STATE_ON)

        // BLE settling time (Python line 481)
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
    }

    /// Validate radio state by comparing echoed values to requested values.
    ///
    /// Matches Python validateRadioState() (lines 660-690).
    /// Checks:
    /// - Frequency within 100 Hz tolerance
    /// - Bandwidth exact match
    /// - TX power exact match
    /// - Spreading factor exact match
    /// - Radio state is ON
    private func validateRadioState() async throws {
        guard let config = radioConfig else {
            throw RNodeError.notConfigured
        }

        // BLE settling time (Python line 662)
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second

        // Validate frequency (100 Hz tolerance)
        if let rFreq = rFrequency {
            let freqDiff = abs(Int64(config.frequency) - Int64(rFreq))
            if freqDiff > 100 {
                throw RNodeError.radioConfigFailed("Frequency mismatch: expected \(config.frequency) Hz, got \(rFreq) Hz (diff: \(freqDiff) Hz)")
            }
        } else {
            throw RNodeError.radioConfigFailed("No frequency echo received from RNode")
        }

        // Validate bandwidth (exact match)
        if let rBw = rBandwidth {
            if config.bandwidth != rBw {
                throw RNodeError.radioConfigFailed("Bandwidth mismatch: expected \(config.bandwidth) Hz, got \(rBw) Hz")
            }
        } else {
            throw RNodeError.radioConfigFailed("No bandwidth echo received from RNode")
        }

        // Validate TX power (exact match)
        if let rTx = rTxPower {
            if config.txPower != rTx {
                throw RNodeError.radioConfigFailed("TX power mismatch: expected \(config.txPower) dBm, got \(rTx) dBm")
            }
        } else {
            throw RNodeError.radioConfigFailed("No TX power echo received from RNode")
        }

        // Validate spreading factor (exact match)
        if let rSpread = rSf {
            if config.spreadingFactor != rSpread {
                throw RNodeError.radioConfigFailed("Spreading factor mismatch: expected \(config.spreadingFactor), got \(rSpread)")
            }
        } else {
            throw RNodeError.radioConfigFailed("No spreading factor echo received from RNode")
        }

        // Validate radio state is ON
        if let rSt = rState {
            if rSt != RNodeConstants.RADIO_STATE_ON {
                throw RNodeError.radioConfigFailed("Radio state is not ON: got state \(rSt)")
            }
        } else {
            throw RNodeError.radioConfigFailed("No radio state echo received from RNode")
        }

        // All validation passed
    }

    // MARK: - Radio Configuration Setters

    /// Send KISS command and wait for completion.
    private func sendKISSCommand(_ command: UInt8, payload: Data) async throws {
        guard let transport = transport else {
            throw InterfaceError.notConnected
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            transport.sendCommand(command, payload: payload) { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    /// Set radio frequency (4 bytes big-endian).
    private func setFrequency(_ freq: UInt32) async throws {
        let payload = Data([
            UInt8(freq >> 24),
            UInt8((freq >> 16) & 0xFF),
            UInt8((freq >> 8) & 0xFF),
            UInt8(freq & 0xFF)
        ])
        try await sendKISSCommand(RNodeConstants.CMD_FREQUENCY, payload: payload)
    }

    /// Set radio bandwidth (4 bytes big-endian).
    private func setBandwidth(_ bw: UInt32) async throws {
        let payload = Data([
            UInt8(bw >> 24),
            UInt8((bw >> 16) & 0xFF),
            UInt8((bw >> 8) & 0xFF),
            UInt8(bw & 0xFF)
        ])
        try await sendKISSCommand(RNodeConstants.CMD_BANDWIDTH, payload: payload)
    }

    /// Set transmit power (1 byte).
    private func setTXPower(_ power: UInt8) async throws {
        let payload = Data([power])
        try await sendKISSCommand(RNodeConstants.CMD_TXPOWER, payload: payload)
    }

    /// Set spreading factor (1 byte).
    private func setSpreadingFactor(_ sf: UInt8) async throws {
        let payload = Data([sf])
        try await sendKISSCommand(RNodeConstants.CMD_SF, payload: payload)
    }

    /// Set coding rate (1 byte).
    private func setCodingRate(_ cr: UInt8) async throws {
        let payload = Data([cr])
        try await sendKISSCommand(RNodeConstants.CMD_CR, payload: payload)
    }

    /// Set short-term airtime lock (2 bytes big-endian, percentage * 100).
    private func setSTALock(_ percentage: Float) async throws {
        let value = UInt16(percentage * 100)
        let payload = Data([
            UInt8(value >> 8),
            UInt8(value & 0xFF)
        ])
        try await sendKISSCommand(RNodeConstants.CMD_ST_ALOCK, payload: payload)
    }

    /// Set long-term airtime lock (2 bytes big-endian, percentage * 100).
    private func setLTALock(_ percentage: Float) async throws {
        let value = UInt16(percentage * 100)
        let payload = Data([
            UInt8(value >> 8),
            UInt8(value & 0xFF)
        ])
        try await sendKISSCommand(RNodeConstants.CMD_LT_ALOCK, payload: payload)
    }

    /// Set radio state (1 byte).
    private func setRadioState(_ state: UInt8) async throws {
        let payload = Data([state])
        try await sendKISSCommand(RNodeConstants.CMD_RADIO_STATE, payload: payload)
    }

    // MARK: - Data & Command Handling

    /// Handle received data frame (CMD_DATA).
    private func handleDataReceived(_ data: Data) {
        bytesReceived += UInt64(data.count)

        // Clear per-packet stats (Python process_incoming line 704)
        rStatRssi = nil
        rStatSnr = nil

        notifyPacketReceived(data)
    }

    /// Handle received KISS command.
    ///
    /// Dispatches based on command byte to appropriate handler.
    /// Matches Python readLoop command dispatch (lines 781-1131).
    private func handleCommand(_ command: UInt8, _ payload: Data) {
        // Guard all payload access with bounds checks
        switch command {
        case RNodeConstants.CMD_DETECT:
            handleCmdDetect(payload)

        case RNodeConstants.CMD_FW_VERSION:
            handleCmdFwVersion(payload)

        case RNodeConstants.CMD_PLATFORM:
            handleCmdPlatform(payload)

        case RNodeConstants.CMD_MCU:
            handleCmdMcu(payload)

        case RNodeConstants.CMD_FREQUENCY:
            handleCmdFrequency(payload)

        case RNodeConstants.CMD_BANDWIDTH:
            handleCmdBandwidth(payload)

        case RNodeConstants.CMD_TXPOWER:
            handleCmdTxPower(payload)

        case RNodeConstants.CMD_SF:
            handleCmdSf(payload)

        case RNodeConstants.CMD_CR:
            handleCmdCr(payload)

        case RNodeConstants.CMD_RADIO_STATE:
            handleCmdRadioState(payload)

        case RNodeConstants.CMD_RADIO_LOCK:
            handleCmdRadioLock(payload)

        case RNodeConstants.CMD_STAT_RSSI:
            handleCmdStatRssi(payload)

        case RNodeConstants.CMD_STAT_SNR:
            handleCmdStatSnr(payload)

        case RNodeConstants.CMD_STAT_BAT:
            handleCmdStatBat(payload)

        case RNodeConstants.CMD_READY:
            handleCmdReady()

        case RNodeConstants.CMD_ERROR:
            handleCmdError(payload)

        case RNodeConstants.CMD_RESET:
            handleCmdReset(payload)

        // Commands not relevant to v1.1 (log and ignore)
        case RNodeConstants.CMD_STAT_CHTM,
             RNodeConstants.CMD_STAT_PHYPRM,
             RNodeConstants.CMD_STAT_CSMA,
             RNodeConstants.CMD_STAT_TEMP,
             RNodeConstants.CMD_FB_READ,
             RNodeConstants.CMD_DISP_READ,
             RNodeConstants.CMD_RANDOM:
            // Log and ignore
            break

        default:
            // Unknown command
            print("[RNodeInterface] Unknown command: 0x\(String(format: "%02X", command))")
        }
    }

    // MARK: - Command Handlers

    private func handleCmdDetect(_ payload: Data) {
        guard !payload.isEmpty else { return }
        if payload[0] == RNodeConstants.DETECT_RESP {
            detected = true
        } else {
            detected = false
        }
    }

    private func handleCmdFwVersion(_ payload: Data) {
        guard payload.count >= 2 else { return }
        majVersion = payload[0]
        minVersion = payload[1]
        print("[RNodeInterface] Firmware version: \(majVersion).\(minVersion)")
    }

    private func handleCmdPlatform(_ payload: Data) {
        guard !payload.isEmpty else { return }
        platform = payload[0]
    }

    private func handleCmdMcu(_ payload: Data) {
        guard !payload.isEmpty else { return }
        mcu = payload[0]
    }

    private func handleCmdFrequency(_ payload: Data) {
        guard payload.count >= 4 else { return }
        rFrequency = UInt32(payload[0]) << 24 |
                     UInt32(payload[1]) << 16 |
                     UInt32(payload[2]) << 8 |
                     UInt32(payload[3])
    }

    private func handleCmdBandwidth(_ payload: Data) {
        guard payload.count >= 4 else { return }
        rBandwidth = UInt32(payload[0]) << 24 |
                     UInt32(payload[1]) << 16 |
                     UInt32(payload[2]) << 8 |
                     UInt32(payload[3])
    }

    private func handleCmdTxPower(_ payload: Data) {
        guard !payload.isEmpty else { return }
        rTxPower = payload[0]
    }

    private func handleCmdSf(_ payload: Data) {
        guard !payload.isEmpty else { return }
        rSf = payload[0]
    }

    private func handleCmdCr(_ payload: Data) {
        guard !payload.isEmpty else { return }
        rCr = payload[0]
    }

    private func handleCmdRadioState(_ payload: Data) {
        guard !payload.isEmpty else { return }
        rState = payload[0]
    }

    private func handleCmdRadioLock(_ payload: Data) {
        guard !payload.isEmpty else { return }
        rLock = payload[0]
    }

    private func handleCmdStatRssi(_ payload: Data) {
        guard !payload.isEmpty else { return }
        // RSSI_OFFSET = 157 (Python line 115)
        rStatRssi = Int(payload[0]) - 157
    }

    private func handleCmdStatSnr(_ payload: Data) {
        guard !payload.isEmpty else { return }
        // SNR is signed byte
        rStatSnr = Int(Int8(bitPattern: payload[0]))
    }

    private func handleCmdStatBat(_ payload: Data) {
        guard payload.count >= 2 else { return }
        rBatteryState = payload[0]
        rBatteryPercent = min(payload[1], 100)
    }

    private func handleCmdReady() {
        // Flow control - Plan 03 implements processQueue()
        processQueue()
    }

    private func handleCmdError(_ payload: Data) {
        guard !payload.isEmpty else { return }
        let errorCode = payload[0]

        switch errorCode {
        case RNodeConstants.ERROR_INITRADIO:
            // Disconnect on radio init failure
            lastErrorDescription = "Radio initialization failed"
            notifyError(RNodeError.radioInitFailed)
            Task { await disconnect() }

        case RNodeConstants.ERROR_TXFAILED:
            // Log but stay connected
            notifyError(RNodeError.transmitFailed)

        case RNodeConstants.ERROR_QUEUE_FULL:
            // Log but stay connected
            notifyError(RNodeError.queueFull)

        case RNodeConstants.ERROR_MEMORY_LOW:
            // Log only
            print("[RNodeInterface] Warning: RNode memory low")

        case RNodeConstants.ERROR_MODEM_TIMEOUT:
            // Log only
            print("[RNodeInterface] Warning: RNode modem timeout")

        default:
            // Unknown error
            notifyError(RNodeError.unknownHardwareError(errorCode))
        }
    }

    private func handleCmdReset(_ payload: Data) {
        guard !payload.isEmpty else { return }
        // ESP32 reset detection (Python line 1127-1131)
        if payload[0] == 0xF8 && platform == RNodeConstants.PLATFORM_ESP32 && online {
            print("[RNodeInterface] ESP32 reset detected, triggering reconnection")
            Task { await startReconnectLoop() }
        }
    }

    /// Stub for flow control - Plan 03 implements this.
    private func processQueue() {
        // Plan 03: process packet queue when CMD_READY received
    }

    // MARK: - Reconnection Logic

    /// Start the reconnection loop.
    ///
    /// This runs until reconnection succeeds or disconnect() is called.
    /// Never gives up - unlimited retries.
    private func startReconnectLoop() async {
        guard autoReconnect else { return }
        guard reconnectTask == nil else { return } // Already reconnecting

        reconnectAttempt = 1
        await transitionState(to: .reconnecting(attempt: reconnectAttempt))

        reconnectTask = Task { [weak self] in
            guard let self = self else { return }

            while !Task.isCancelled {
                let attempt = await self.getReconnectAttempt()
                let delay = await self.calculateDelay(forAttempt: attempt)

                // Wait before attempting
                do {
                    try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                } catch {
                    // Task cancelled
                    return
                }

                // Check if cancelled during sleep
                if Task.isCancelled { return }

                // Attempt reconnection
                await self.attemptReconnect()

                // Check if we connected successfully
                let currentState = await self.state
                if currentState == .connected {
                    await self.clearReconnectTask()
                    return // Success!
                }

                // Increment attempt and continue
                await self.incrementReconnectAttempt()
            }
        }
    }

    /// Get current reconnection attempt number.
    private func getReconnectAttempt() -> Int {
        return reconnectAttempt
    }

    /// Calculate delay for a given attempt.
    private func calculateDelay(forAttempt attempt: Int) -> TimeInterval {
        return backoff.nextDelay(attempt: attempt - 1) // Backoff uses 0-based attempts
    }

    /// Attempt a single reconnection.
    private func attemptReconnect() async {
        // Clean up old transport
        transport?.disconnect()
        transport = nil

        // Create new transport
        await setupTransport()
    }

    /// Increment reconnection attempt counter.
    private func incrementReconnectAttempt() {
        reconnectAttempt += 1
        state = .reconnecting(attempt: reconnectAttempt)
        notifyStateChange()
    }

    /// Clear the reconnection task reference.
    private func clearReconnectTask() {
        reconnectTask = nil
        reconnectAttempt = 0
    }

    // MARK: - State Transition

    /// Transition to a new state and notify delegate.
    private func transitionState(to newState: InterfaceState) async {
        guard state != newState else { return }
        state = newState
        notifyStateChange()
    }

    // MARK: - Delegate Notifications

    /// Notify delegate of state change.
    private func notifyStateChange() {
        let currentState = state
        let interfaceId = id
        guard let delegate = delegateRef?.delegate else { return }
        delegate.interface(id: interfaceId, didChangeState: currentState)
    }

    /// Notify delegate of received packet.
    private func notifyPacketReceived(_ data: Data) {
        let interfaceId = id
        guard let delegate = delegateRef?.delegate else { return }
        delegate.interface(id: interfaceId, didReceivePacket: data)
    }

    /// Notify delegate of error.
    private func notifyError(_ error: Error) {
        let interfaceId = id
        guard let delegate = delegateRef?.delegate else { return }
        delegate.interface(id: interfaceId, didFailWithError: error)
    }
}

// MARK: - WeakDelegate

/// Wrapper for weak delegate reference within actor.
///
/// Uses @unchecked Sendable because weak references are inherently thread-safe
/// (they become nil atomically when the referent is deallocated).
private final class WeakDelegate: @unchecked Sendable {
    weak var delegate: InterfaceDelegate?

    init(_ delegate: InterfaceDelegate) {
        self.delegate = delegate
    }
}

// MARK: - CustomStringConvertible

extension RNodeInterface: CustomStringConvertible {
    nonisolated public var description: String {
        "RNodeInterface<\(id)>"
    }
}

#endif // canImport(CoreBluetooth)
