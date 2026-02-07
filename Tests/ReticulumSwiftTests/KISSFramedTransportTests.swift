//
//  KISSFramedTransportTests.swift
//  ReticulumSwiftTests
//
//  Unit tests for KISSFramedTransport command routing.
//

#if canImport(CoreBluetooth)
import XCTest
@testable import ReticulumSwift

// MARK: - MockTransport

class MockTransport: Transport {
    var state: TransportState = .disconnected
    var onStateChange: ((TransportState) -> Void)?
    var onDataReceived: ((Data) -> Void)?
    var sentData: [Data] = []

    func connect() {
        state = .connected
        onStateChange?(.connected)
    }

    func send(_ data: Data, completion: ((Error?) -> Void)? = nil) {
        sentData.append(data)
        completion?(nil)
    }

    func disconnect() {
        state = .disconnected
        onStateChange?(.disconnected)
    }

    func simulateReceive(_ data: Data) {
        onDataReceived?(data)
    }
}

// MARK: - Tests

final class KISSFramedTransportTests: XCTestCase {

    func testDataFrameRoutedToOnDataReceived() {
        let mockTransport = MockTransport()
        let kissTransport = KISSFramedTransport(transport: mockTransport)

        var receivedData: Data?
        kissTransport.onDataReceived = { data in
            receivedData = data
        }

        let payload = Data([0x01, 0x02, 0x03, 0x04])
        let frame = KISS.frame(payload, command: KISS.CMD_DATA)
        mockTransport.simulateReceive(frame)

        XCTAssertEqual(receivedData, payload)
    }

    func testCommandFrameRoutedToOnCommandReceived() {
        let mockTransport = MockTransport()
        let kissTransport = KISSFramedTransport(transport: mockTransport)

        var receivedCommand: UInt8?
        var receivedPayload: Data?
        kissTransport.onCommandReceived = { cmd, payload in
            receivedCommand = cmd
            receivedPayload = payload
        }

        let frame = Data([KISS.FEND, RNodeConstants.CMD_DETECT, RNodeConstants.DETECT_RESP, KISS.FEND])
        mockTransport.simulateReceive(frame)

        XCTAssertEqual(receivedCommand, RNodeConstants.CMD_DETECT)
        XCTAssertEqual(receivedPayload, Data([RNodeConstants.DETECT_RESP]))
    }

    func testFrequencyEchoRoutedAsCommand() {
        let mockTransport = MockTransport()
        let kissTransport = KISSFramedTransport(transport: mockTransport)

        var receivedCommand: UInt8?
        var receivedPayload: Data?
        kissTransport.onCommandReceived = { cmd, payload in
            receivedCommand = cmd
            receivedPayload = payload
        }

        let freqBytes = Data([0x36, 0x91, 0x8C, 0x40]) // 915 MHz
        let frame = Data([KISS.FEND, RNodeConstants.CMD_FREQUENCY]) + freqBytes + Data([KISS.FEND])
        mockTransport.simulateReceive(frame)

        XCTAssertEqual(receivedCommand, RNodeConstants.CMD_FREQUENCY)
        XCTAssertEqual(receivedPayload, freqBytes)
    }

    func testSendFramesDataWithKISS() {
        let mockTransport = MockTransport()
        let kissTransport = KISSFramedTransport(transport: mockTransport)

        let payload = Data([0x01, 0x02, 0x03])
        kissTransport.send(payload, completion: nil)

        XCTAssertEqual(mockTransport.sentData.count, 1)
        let sent = mockTransport.sentData[0]
        XCTAssertEqual(sent.first, KISS.FEND)
        XCTAssertEqual(sent.last, KISS.FEND)
        XCTAssertEqual(sent[1], KISS.CMD_DATA)
    }

    func testSendCommandFrames() {
        let mockTransport = MockTransport()
        let kissTransport = KISSFramedTransport(transport: mockTransport)

        kissTransport.sendCommand(RNodeConstants.CMD_RADIO_STATE, payload: Data([RNodeConstants.RADIO_STATE_ON]))

        XCTAssertEqual(mockTransport.sentData.count, 1)
        let sent = mockTransport.sentData[0]
        XCTAssertEqual(sent[0], KISS.FEND)
        XCTAssertEqual(sent[1], RNodeConstants.CMD_RADIO_STATE)
        XCTAssertEqual(sent[2], RNodeConstants.RADIO_STATE_ON)
        XCTAssertEqual(sent[3], KISS.FEND)
    }

    func testMultipleFramesInOneReceive() {
        let mockTransport = MockTransport()
        let kissTransport = KISSFramedTransport(transport: mockTransport)

        var dataCount = 0
        var commandCount = 0
        kissTransport.onDataReceived = { _ in dataCount += 1 }
        kissTransport.onCommandReceived = { _, _ in commandCount += 1 }

        let dataFrame = KISS.frame(Data([0xAA, 0xBB]), command: KISS.CMD_DATA)
        let cmdFrame = Data([KISS.FEND, RNodeConstants.CMD_READY, 0x01, KISS.FEND])
        mockTransport.simulateReceive(dataFrame + cmdFrame)

        XCTAssertEqual(dataCount, 1)
        XCTAssertEqual(commandCount, 1)
    }

    func testEscapedPayloadInCommandResponse() {
        let mockTransport = MockTransport()
        let kissTransport = KISSFramedTransport(transport: mockTransport)

        var receivedPayload: Data?
        kissTransport.onCommandReceived = { _, payload in
            receivedPayload = payload
        }

        // Frequency where byte is 0xC0 (FEND) needs escape
        let frame = Data([KISS.FEND, RNodeConstants.CMD_FREQUENCY, KISS.FESC, KISS.TFEND, 0x00, 0x00, 0x00, KISS.FEND])
        mockTransport.simulateReceive(frame)

        XCTAssertEqual(receivedPayload, Data([0xC0, 0x00, 0x00, 0x00]))
    }

    func testPartialFrameBuffering() {
        let mockTransport = MockTransport()
        let kissTransport = KISSFramedTransport(transport: mockTransport)

        var receivedData: Data?
        kissTransport.onDataReceived = { data in receivedData = data }

        let fullFrame = KISS.frame(Data([0x01, 0x02, 0x03]), command: KISS.CMD_DATA)
        let mid = fullFrame.count / 2
        mockTransport.simulateReceive(Data(fullFrame[0..<mid]))

        XCTAssertNil(receivedData, "Should not deliver partial frame")

        mockTransport.simulateReceive(Data(fullFrame[mid...]))

        XCTAssertEqual(receivedData, Data([0x01, 0x02, 0x03]))
    }
}

#endif // canImport(CoreBluetooth)
