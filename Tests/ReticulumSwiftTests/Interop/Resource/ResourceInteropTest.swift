//
//  ResourceInteropTest.swift
//  ReticulumSwiftTests
//
//  Resource interoperability tests with Python RNS.
//

import XCTest
@testable import ReticulumSwift

final class ResourceInteropTest: InteropTestBase {

    // MARK: - Part Hash

    func testPartHashMatchesPython() throws {
        let testParts: [Data] = [
            "Part 0 data".data(using: .utf8)!,
            "Part 1 data".data(using: .utf8)!,
            Data((0..<100).map { UInt8($0) }),
            Data(),
        ]
        let randomHash = Data([0xDE, 0xAD, 0xBE, 0xEF])

        for part in testParts {
            let swiftHash = ResourceHashmap.partHash(part, randomHash: randomHash)

            let pyResult = try bridge.execute(
                "resource_map_hash",
                ("part_data", part),
                ("random_hash", randomHash)
            )

            assertBytesEqual(pyResult.getBytes("map_hash"), swiftHash,
                "Part hash for \(part.count) bytes")
            XCTAssertEqual(swiftHash.count, ResourceConstants.MAPHASH_LEN)
        }
    }

    // MARK: - Hashmap Generation

    func testHashmapGenerationMatchesPython() throws {
        let randomHash = Data([0x01, 0x02, 0x03, 0x04])
        let partSize = 464

        // Create data and split into parts manually for the Python bridge
        let data = Data((0..<2000).map { UInt8($0 % 256) })

        let swiftHashmap = ResourceHashmap.generateHashmap(
            data: data, partSize: partSize, randomHash: randomHash
        )

        // Split data into parts and hex-encode for Python
        let totalParts = (data.count + partSize - 1) / partSize
        var partHexStrings: [String] = []
        for i in 0..<totalParts {
            let start = i * partSize
            let end = min(start + partSize, data.count)
            let partData = data[start..<end]
            partHexStrings.append(Data(partData).map { String(format: "%02x", $0) }.joined())
        }

        let pyResult = try bridge.execute(
            "resource_build_hashmap",
            ("parts", partHexStrings),
            ("random_hash", randomHash)
        )

        assertBytesEqual(pyResult.getBytes("hashmap"), swiftHashmap, "Hashmap")
        XCTAssertEqual(pyResult.getInt("num_parts"), totalParts)
    }

    // MARK: - Advertisement Unpack

    func testAdvertisementUnpackMatchesPython() throws {
        let resourceHash = Data((0..<16).map { UInt8($0) })
        let randomHash = Data([0x11, 0x22, 0x33, 0x44])
        let originalHash = Data((30..<46).map { UInt8($0) })
        let hashmap = Data((0..<20).map { UInt8($0) }) // 5 parts

        // Pack with Python
        let pyResult = try bridge.execute(
            "resource_adv_pack",
            ("transfer_size", 10240),
            ("data_size", 20480),
            ("num_parts", 5),
            ("resource_hash", resourceHash),
            ("random_hash", randomHash),
            ("original_hash", originalHash),
            ("segment_index", 1),
            ("total_segments", 1),
            ("flags", 0x03),
            ("hashmap", hashmap),
            ("segment", 0)
        )

        let packed = pyResult.getBytes("packed")

        // Unpack with Swift
        let adv = try ResourceAdvertisement.unpack(packed)

        // Verify fields match
        XCTAssertEqual(adv.transferSize, 10240)
        XCTAssertEqual(adv.dataSize, 20480)
        XCTAssertEqual(adv.numParts, 5)
        assertBytesEqual(resourceHash, adv.hash, "Resource hash")
        assertBytesEqual(randomHash, adv.randomHash, "Random hash")
        assertBytesEqual(originalHash, adv.originalHash, "Original hash")
        XCTAssertEqual(adv.segmentIndex, 1)
        XCTAssertEqual(adv.totalSegments, 1)
        XCTAssertNil(adv.requestId)
        XCTAssertTrue(adv.flags.isEncrypted)
        XCTAssertTrue(adv.flags.isCompressed)
        assertBytesEqual(hashmap, adv.hashmapChunk, "Hashmap chunk")
    }

    func testAdvertisementRoundTripPreservesFields() throws {
        let resourceHash = Data((10..<26).map { UInt8($0) })
        let randomHash = Data([0xFF, 0xEE, 0xDD, 0xCC])
        let originalHash = Data((40..<56).map { UInt8($0) })
        let requestId = Data((60..<76).map { UInt8($0) })
        let hashmap = Data((0..<100).map { UInt8($0) }) // 25 parts

        // Pack with Python
        let pyPack = try bridge.execute(
            "resource_adv_pack",
            ("transfer_size", 204800),
            ("data_size", 409600),
            ("num_parts", 25),
            ("resource_hash", resourceHash),
            ("random_hash", randomHash),
            ("original_hash", originalHash),
            ("segment_index", 2),
            ("total_segments", 3),
            ("request_id", requestId),
            ("flags", 0x3F),
            ("hashmap", hashmap),
            ("segment", 0)
        )

        let packed = pyPack.getBytes("packed")

        // Unpack with Swift
        let adv = try ResourceAdvertisement.unpack(packed)

        // Verify all fields preserved
        XCTAssertEqual(adv.transferSize, 204800)
        XCTAssertEqual(adv.dataSize, 409600)
        XCTAssertEqual(adv.numParts, 25)
        assertBytesEqual(resourceHash, adv.hash, "Resource hash")
        assertBytesEqual(randomHash, adv.randomHash, "Random hash")
        assertBytesEqual(originalHash, adv.originalHash, "Original hash")
        XCTAssertEqual(adv.segmentIndex, 2)
        XCTAssertEqual(adv.totalSegments, 3)
        assertBytesEqual(requestId, adv.requestId!, "Request ID")
        XCTAssertEqual(adv.flags.rawValue, 0x3F)

        // Re-pack with Swift, unpack with Python, verify fields match
        let repacked = try adv.pack()
        let pyUnpack = try bridge.execute(
            "resource_adv_unpack",
            ("packed", repacked)
        )

        XCTAssertEqual(pyUnpack.getInt("transfer_size"), 204800)
        XCTAssertEqual(pyUnpack.getInt("data_size"), 409600)
        XCTAssertEqual(pyUnpack.getInt("num_parts"), 25)
        XCTAssertEqual(pyUnpack.getInt("segment_index"), 2)
        XCTAssertEqual(pyUnpack.getInt("total_segments"), 3)
        XCTAssertEqual(pyUnpack.getInt("flags"), 0x3F)
    }

    // MARK: - Flag Encoding

    func testFlagEncodingMatchesPython() throws {
        let testCases: [(Bool, Bool, Bool, Bool, Bool, Bool)] = [
            (true, false, false, false, false, false),
            (false, true, false, false, false, false),
            (true, true, true, false, false, false),
            (false, false, false, true, false, false),
            (false, false, false, false, true, false),
            (false, false, false, false, false, true),
            (true, true, true, true, true, true),
        ]

        for (enc, comp, split, req, resp, meta) in testCases {
            let swiftFlags = ResourceFlags(
                encrypted: enc, compressed: comp, split: split,
                isRequest: req, isResponse: resp, hasMetadata: meta
            )

            let pyResult = try bridge.execute(
                "resource_flags",
                ("mode", "encode"),
                ("encrypted", enc),
                ("compressed", comp),
                ("split", split),
                ("is_request", req),
                ("is_response", resp),
                ("has_metadata", meta)
            )

            XCTAssertEqual(Int(swiftFlags.rawValue), pyResult.getInt("flags"),
                "Flags for enc=\(enc) comp=\(comp) split=\(split)")
        }
    }

    func testFlagDecodingMatchesPython() throws {
        let testFlags: [UInt8] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x3F]

        for flagsByte in testFlags {
            let flags = ResourceFlags(rawValue: flagsByte)

            let pyResult = try bridge.execute(
                "resource_flags",
                ("mode", "decode"),
                ("flags", Int(flagsByte))
            )

            XCTAssertEqual(flags.isEncrypted, pyResult.getBool("encrypted"),
                "encrypted for 0x\(String(format: "%02x", flagsByte))")
            XCTAssertEqual(flags.isCompressed, pyResult.getBool("compressed"),
                "compressed for 0x\(String(format: "%02x", flagsByte))")
            XCTAssertEqual(flags.isSplit, pyResult.getBool("split"),
                "split for 0x\(String(format: "%02x", flagsByte))")
            XCTAssertEqual(flags.isRequestFlag, pyResult.getBool("is_request"),
                "is_request for 0x\(String(format: "%02x", flagsByte))")
            XCTAssertEqual(flags.isResponseFlag, pyResult.getBool("is_response"),
                "is_response for 0x\(String(format: "%02x", flagsByte))")
            XCTAssertEqual(flags.hasMetadataFlag, pyResult.getBool("has_metadata"),
                "has_metadata for 0x\(String(format: "%02x", flagsByte))")
        }
    }
}
