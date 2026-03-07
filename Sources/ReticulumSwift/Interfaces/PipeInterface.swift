//
//  PipeInterface.swift
//  ReticulumSwift
//
//  HDLC-framed interface over stdin/stdout (or arbitrary file handles).
//  Used for conformance testing via subprocess pipe protocol.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "net.reticulum", category: "PipeInterface")

public actor PipeInterface: @preconcurrency NetworkInterface {

    public let id: String
    public let config: InterfaceConfig
    public let mode: InterfaceMode
    public private(set) var state: InterfaceState = .disconnected
    public var hwMtu: Int { 1064 }
    public private(set) var bytesSent: UInt64 = 0
    public private(set) var bytesReceived: UInt64 = 0

    private let inputHandle: FileHandle
    private let outputHandle: FileHandle
    private var readTask: Task<Void, Never>?
    private var buffer = Data()
    nonisolated(unsafe) private weak var _delegate: InterfaceDelegate?

    public var delegate: InterfaceDelegate? { _delegate }

    public init(
        id: String = "pipe",
        name: String = "PipeInterface",
        mode: InterfaceMode = .full,
        inputHandle: FileHandle = .standardInput,
        outputHandle: FileHandle = .standardOutput,
        ifacSize: Int = 0,
        ifacKey: Data? = nil
    ) {
        self.id = id
        self.config = InterfaceConfig(
            id: id,
            name: name,
            type: .tcp,
            enabled: true,
            mode: mode,
            host: "pipe",
            port: 0,
            ifacSize: ifacSize,
            ifacKey: ifacKey
        )
        self.mode = mode
        self.inputHandle = inputHandle
        self.outputHandle = outputHandle
    }

    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self._delegate = delegate
    }

    public func connect() async throws {
        state = .connected
        _delegate?.interface(id: id, didChangeState: .connected)
        startReadLoop()
    }

    public func disconnect() async {
        readTask?.cancel()
        readTask = nil
        state = .disconnected
        _delegate?.interface(id: id, didChangeState: .disconnected)
    }

    public func send(_ data: Data) async throws {
        let framed = HDLC.frame(data)
        outputHandle.write(framed)
        bytesSent += UInt64(data.count)
    }

    private func startReadLoop() {
        let handle = self.inputHandle
        readTask = Task.detached { [weak self] in
            while !Task.isCancelled {
                let chunk: Data
                do {
                    chunk = try await withCheckedThrowingContinuation { continuation in
                        let data = handle.availableData
                        if data.isEmpty {
                            continuation.resume(throwing: CancellationError())
                        } else {
                            continuation.resume(returning: data)
                        }
                    }
                } catch {
                    break
                }
                guard let self else { break }
                await self.processChunk(chunk)
            }
            await self?.disconnect()
        }
    }

    private func processChunk(_ chunk: Data) {
        buffer.append(chunk)
        let frames = HDLC.extractFrames(from: &buffer)
        for frame in frames {
            bytesReceived += UInt64(frame.count)
            _delegate?.interface(id: id, didReceivePacket: frame)
        }
    }
}
