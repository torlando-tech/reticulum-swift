//
//  PythonBridge.swift
//  ReticulumSwiftTests
//
//  Bridge to Python RNS implementation for interop testing.
//  Communicates with bridge_server.py via JSON over stdin/stdout.
//
//  Mirrors: reticulum-kt/rns-test/.../interop/PythonBridge.kt
//

import Foundation

/// Bridge to Python RNS reference implementation for interop testing.
///
/// Communicates with bridge_server.py via JSON over stdin/stdout.
/// The bridge script is language-agnostic — same one used by Kotlin tests.
public final class PythonBridge {

    private let process: Process
    private let stdin: FileHandle
    private let stdout: FileHandle
    private var requestCounter = 0
    private let lock = NSLock()

    /// Check whether the Python bridge is available.
    ///
    /// Checks: python3 on PATH, bridge_server.py exists,
    /// PYTHON_RNS_PATH or ~/repos/Reticulum exists.
    public static var isAvailable: Bool {
        // Check python3
        let which = Process()
        which.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        which.arguments = ["python3"]
        which.standardOutput = FileHandle.nullDevice
        which.standardError = FileHandle.nullDevice
        do {
            try which.run()
            which.waitUntilExit()
            guard which.terminationStatus == 0 else { return false }
        } catch {
            return false
        }

        // Check bridge script
        guard findBridgeScript() != nil else { return false }

        // Check RNS path
        guard findRNSPath() != nil else { return false }

        return true
    }

    /// Start a new Python bridge subprocess.
    public static func start() throws -> PythonBridge {
        guard let scriptPath = findBridgeScript() else {
            throw BridgeError.scriptNotFound
        }
        guard let rnsPath = findRNSPath() else {
            throw BridgeError.rnsNotFound
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [scriptPath]
        process.currentDirectoryURL = URL(fileURLWithPath: scriptPath)
            .deletingLastPathComponent().deletingLastPathComponent()

        var env = ProcessInfo.processInfo.environment
        env["PYTHON_RNS_PATH"] = rnsPath
        process.environment = env

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()

        let stdinHandle = stdinPipe.fileHandleForWriting
        let stdoutHandle = stdoutPipe.fileHandleForReading

        // Wait for READY signal
        guard let readyLine = stdoutHandle.readLine(), readyLine == "READY" else {
            let stderr = String(data: stderrPipe.fileHandleForReading.availableData, encoding: .utf8) ?? ""
            process.terminate()
            throw BridgeError.startupFailed(stderr: stderr)
        }

        return PythonBridge(process: process, stdin: stdinHandle, stdout: stdoutHandle)
    }

    private init(process: Process, stdin: FileHandle, stdout: FileHandle) {
        self.process = process
        self.stdin = stdin
        self.stdout = stdout
    }

    /// Execute a command on the Python bridge and expect success.
    ///
    /// - Parameters:
    ///   - command: Command name (e.g., "sha256", "x25519_generate")
    ///   - params: Parameters as key-value pairs. Data values are auto hex-encoded.
    /// - Returns: Result dictionary from Python
    /// - Throws: `BridgeError.commandFailed` if Python returns an error
    @discardableResult
    public func execute(_ command: String, _ params: (String, Any?)...) throws -> [String: Any] {
        let paramPairs = params.compactMap { (key, value) -> (String, Any)? in
            guard let v = value else { return nil }
            switch v {
            case let data as Data:
                return (key, data.map { String(format: "%02x", $0) }.joined())
            case let bytes as [UInt8]:
                return (key, Data(bytes).map { String(format: "%02x", $0) }.joined())
            default:
                return (key, v)
            }
        }
        return try executeRaw(command, params: Dictionary(uniqueKeysWithValues: paramPairs))
    }

    /// Execute with an array of param pairs (for forwarding from non-variadic callers).
    @discardableResult
    public func executeArray(_ command: String, _ params: [(String, Any?)]) throws -> [String: Any] {
        let paramPairs = params.compactMap { (key, value) -> (String, Any)? in
            guard let v = value else { return nil }
            switch v {
            case let data as Data:
                return (key, data.map { String(format: "%02x", $0) }.joined())
            case let bytes as [UInt8]:
                return (key, Data(bytes).map { String(format: "%02x", $0) }.joined())
            default:
                return (key, v)
            }
        }
        return try executeRaw(command, params: Dictionary(uniqueKeysWithValues: paramPairs))
    }

    /// Execute with a pre-built params dictionary.
    public func executeRaw(_ command: String, params: [String: Any] = [:]) throws -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }

        requestCounter += 1
        let id = "req-\(requestCounter)"

        // Build JSON request manually (avoid JSONSerialization quirks with hex strings)
        var json = "{\"id\":\"\(id)\",\"command\":\"\(command)\",\"params\":{"
        var first = true
        for (key, value) in params {
            if !first { json += "," }
            first = false
            json += "\"\(key)\":"
            switch value {
            case let s as String:
                json += "\"\(s)\""
            case let n as Int:
                json += "\(n)"
            case let n as Double:
                json += "\(n)"
            case let b as Bool:
                json += b ? "true" : "false"
            case let arr as [String]:
                json += "[" + arr.map { "\"\($0)\"" }.joined(separator: ",") + "]"
            default:
                json += "\"\(value)\""
            }
        }
        json += "}}\n"

        // Send request
        guard let requestData = json.data(using: .utf8) else {
            throw BridgeError.encodingError
        }
        stdin.write(requestData)

        // Read response
        guard let responseLine = stdout.readLine() else {
            throw BridgeError.unexpectedClose
        }

        guard let responseData = responseLine.data(using: .utf8),
              let responseObj = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
            throw BridgeError.invalidResponse(responseLine)
        }

        let success = responseObj["success"] as? Bool ?? false
        if success {
            return responseObj["result"] as? [String: Any] ?? [:]
        } else {
            let error = responseObj["error"] as? String ?? "Unknown error"
            let traceback = responseObj["traceback"] as? String
            throw BridgeError.commandFailed(command: command, error: error, traceback: traceback)
        }
    }

    /// Close the bridge subprocess.
    public func close() {
        try? stdin.close()
        try? stdout.close()
        process.terminate()
        process.waitUntilExit()
    }

    deinit {
        close()
    }

    // MARK: - Path Discovery

    private static func findBridgeScript() -> String? {
        if let envPath = ProcessInfo.processInfo.environment["BRIDGE_SCRIPT_PATH"],
           FileManager.default.fileExists(atPath: envPath) {
            return envPath
        }

        let candidates = [
            // From test bundle (symlink)
            URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .appendingPathComponent("bridge_server.py").path,
            // Sibling repo
            NSHomeDirectory() + "/repos/reticulum-kt/python-bridge/bridge_server.py",
        ]

        return candidates.first { FileManager.default.fileExists(atPath: $0) }
    }

    private static func findRNSPath() -> String? {
        if let envPath = ProcessInfo.processInfo.environment["PYTHON_RNS_PATH"],
           FileManager.default.fileExists(atPath: envPath) {
            return envPath
        }

        let candidates = [
            NSHomeDirectory() + "/repos/Reticulum",
            NSHomeDirectory() + "/repos/public/Reticulum",
        ]

        return candidates.first { path in
            FileManager.default.fileExists(atPath: path) &&
            FileManager.default.fileExists(atPath: path + "/RNS")
        }
    }
}

// MARK: - Error Types

public enum BridgeError: Error, CustomStringConvertible {
    case scriptNotFound
    case rnsNotFound
    case startupFailed(stderr: String)
    case encodingError
    case unexpectedClose
    case invalidResponse(String)
    case commandFailed(command: String, error: String, traceback: String?)

    public var description: String {
        switch self {
        case .scriptNotFound:
            return "bridge_server.py not found"
        case .rnsNotFound:
            return "Python Reticulum not found. Set PYTHON_RNS_PATH."
        case .startupFailed(let stderr):
            return "Python bridge failed to start: \(stderr)"
        case .encodingError:
            return "Failed to encode request"
        case .unexpectedClose:
            return "Python bridge closed unexpectedly"
        case .invalidResponse(let line):
            return "Invalid response from bridge: \(line)"
        case .commandFailed(let cmd, let error, let traceback):
            return "Python command '\(cmd)' failed: \(error)\n\(traceback ?? "")"
        }
    }
}

// MARK: - FileHandle Line Reading

extension FileHandle {
    /// Read a single line (terminated by newline) from the file handle.
    func readLine() -> String? {
        var buffer = Data()
        while true {
            let byte = readData(ofLength: 1)
            if byte.isEmpty { return buffer.isEmpty ? nil : String(data: buffer, encoding: .utf8) }
            if byte[0] == UInt8(ascii: "\n") {
                return String(data: buffer, encoding: .utf8)
            }
            buffer.append(byte)
        }
    }
}

// MARK: - Hex Helpers

extension Data {
    /// Initialize Data from a hex string.
    public init?(hex: String) {
        let len = hex.count
        guard len % 2 == 0 else { return nil }

        var data = Data(capacity: len / 2)
        var index = hex.startIndex
        for _ in 0..<len / 2 {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}

// MARK: - Result Helpers

extension Dictionary where Key == String, Value == Any {
    /// Get a hex-encoded byte array from the result.
    public func getBytes(_ key: String) -> Data {
        guard let hex = self[key] as? String, let data = Data(hex: hex) else {
            fatalError("Missing or invalid hex field: \(key)")
        }
        return data
    }

    /// Get a string field from the result.
    public func getString(_ key: String) -> String {
        guard let value = self[key] as? String else {
            fatalError("Missing string field: \(key)")
        }
        return value
    }

    /// Get a boolean field from the result.
    public func getBool(_ key: String) -> Bool {
        guard let value = self[key] as? Bool else {
            // Try numeric (JSON sometimes encodes bool as 0/1)
            if let num = self[key] as? Int { return num != 0 }
            fatalError("Missing bool field: \(key)")
        }
        return value
    }

    /// Get an integer field from the result.
    public func getInt(_ key: String) -> Int {
        if let value = self[key] as? Int { return value }
        if let value = self[key] as? Double { return Int(value) }
        if let value = self[key] as? String, let i = Int(value) { return i }
        fatalError("Missing int field: \(key)")
    }
}
