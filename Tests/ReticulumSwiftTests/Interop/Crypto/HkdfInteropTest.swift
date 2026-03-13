//
//  HkdfInteropTest.swift
//  ReticulumSwiftTests
//
//  HKDF interoperability tests with Python RNS.
//

import XCTest
@testable import ReticulumSwift

final class HkdfInteropTest: InteropTestBase {

    func testHkdfWithSaltAndInfo() throws {
        let ikm = Data(0..<32)
        let salt = Data((100..<132).map { UInt8($0) })
        let info = "context".data(using: .utf8)!
        let length = 64

        let swiftDerived = KeyDerivation.deriveKey(
            length: length, inputKeyMaterial: ikm, salt: salt, context: info
        )

        let pyResult = try bridge.execute(
            "hkdf",
            ("length", length),
            ("ikm", ikm),
            ("salt", salt),
            ("info", info)
        )

        assertBytesEqual(pyResult.getBytes("derived_key"), swiftDerived, "HKDF with salt and info")
    }

    func testHkdfWithNullSalt() throws {
        let ikm = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 2) })
        let info = "test".data(using: .utf8)!
        let length = 64

        let swiftDerived = KeyDerivation.deriveKey(
            length: length, inputKeyMaterial: ikm, salt: nil, context: info
        )

        let pyResult = try bridge.execute(
            "hkdf",
            ("length", length),
            ("ikm", ikm),
            ("info", info)
        )

        assertBytesEqual(pyResult.getBytes("derived_key"), swiftDerived, "HKDF with null salt")
    }

    func testHkdfWithNullInfo() throws {
        let ikm = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 3) })
        let salt = Data((50..<82).map { UInt8($0) })
        let length = 32

        let swiftDerived = KeyDerivation.deriveKey(
            length: length, inputKeyMaterial: ikm, salt: salt, context: nil
        )

        let pyResult = try bridge.execute(
            "hkdf",
            ("length", length),
            ("ikm", ikm),
            ("salt", salt)
        )

        assertBytesEqual(pyResult.getBytes("derived_key"), swiftDerived, "HKDF with null info")
    }

    func testHkdf64BytesForIdentity() throws {
        let sharedSecret = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 5) })
        let identityHash = Data((0..<16).map { UInt8(truncatingIfNeeded: $0 &* 7) })
        let length = 64

        let swiftDerived = KeyDerivation.deriveKey(
            length: length, inputKeyMaterial: sharedSecret, salt: identityHash, context: nil
        )

        let pyResult = try bridge.execute(
            "hkdf",
            ("length", length),
            ("ikm", sharedSecret),
            ("salt", identityHash)
        )

        XCTAssertEqual(swiftDerived.count, 64)
        assertBytesEqual(pyResult.getBytes("derived_key"), swiftDerived, "HKDF for Identity (64 bytes)")
    }

    func testHkdfWithVariousOutputLengths() throws {
        let ikm = Data(0..<32)
        let salt = Data((10..<42).map { UInt8($0) })
        let info = "test".data(using: .utf8)!

        for length in [16, 32, 48, 64, 96, 128] {
            let swiftDerived = KeyDerivation.deriveKey(
                length: length, inputKeyMaterial: ikm, salt: salt, context: info
            )

            let pyResult = try bridge.execute(
                "hkdf",
                ("length", length),
                ("ikm", ikm),
                ("salt", salt),
                ("info", info)
            )

            XCTAssertEqual(swiftDerived.count, length)
            assertBytesEqual(pyResult.getBytes("derived_key"), swiftDerived, "HKDF with length \(length)")
        }
    }
}
