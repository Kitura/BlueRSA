//
//  CryptorRSATests.swift
//  CryptorRSA
//
//  Created by Bill Abt on 1/17/17.
//
//  Copyright © 2017 IBM. All rights reserved.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

import XCTest
@testable import CryptorRSA

@available(macOS 10.12, iOS 10.0, *)
class CryptorRSATests: XCTestCase {
	
	// MARK: Public Key Tests
	
	static let bundle = Bundle(for: CryptorRSATests.self)
	
	func test_public_initWithData() throws {
		
		guard let path = CryptorRSATests.bundle.path(forResource: "public", ofType: "der") else {
			
			return XCTFail()
		}
		
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		let publicKey = try? CryptorRSA.Key(with: data, isPublic: true)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.isPublic)
	}
	
	func test_public_initWithBase64String() throws {
		
		guard let path = CryptorRSATests.bundle.path(forResource: "public-base64", ofType: "txt") else {
			
			return XCTFail()
		}
		
		let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
		let publicKey = try? CryptorRSA.Key(withBase64: str, isPublic: true)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.isPublic)
	}
	

	func test_public_initWithBase64StringWhichContainsNewLines() throws {
		
		guard let path = CryptorRSATests.bundle.path(forResource: "public-base64-newlines", ofType: "txt") else {
			
			return XCTFail()
		}
		let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
		let publicKey = try? CryptorRSA.Key(withBase64: str, isPublic: true)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.isPublic)
	}
	
	func test_public_initWithPEMString() throws {
		
		guard let path = CryptorRSATests.bundle.path(forResource: "public", ofType: "pem") else {
			
			return XCTFail()
		}
		
		let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
		let publicKey = try? CryptorRSA.Key(withPEM: str, isPublic: true)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.isPublic)
	}
	
	func test_public_initWithPEMName() throws {
		
		let message = try? CryptorRSA.Key(withPEMNamed: "public", in: CryptorRSATests.bundle, isPublic: true)
		XCTAssertNotNil(message)
	}
	
	func test_public_initWithDERName() throws {
		
		//let message = try? CryptorRSA.Key(pemNamed: "public", in: CryptorRSATests.bundle)
		//XCTAssertNotNil(message)
	}
	
	func test_public_initWithPEMStringHeaderless() throws {
		
		guard let path = CryptorRSATests.bundle.path(forResource: "public-headerless", ofType: "pem") else {
			
			return XCTFail()
		}
		
		let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
		let publicKey = try? CryptorRSA.Key(withPEM: str, isPublic: true)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.isPublic)
	}
	
	func test_publicKeysFromComplexPEMFileWorksCorrectly() {
		
		let input = CryptorRSATests.pemKeyString(name: "multiple-keys-testcase")
		let keys = CryptorRSA.Key.publicKeys(withPEM: input)
		XCTAssertEqual(keys.count, 9)
	}
	
	func test_publicKeysFromEmptyPEMFileReturnsEmptyArray() {
		
		let keys = CryptorRSA.Key.publicKeys(withPEM: "")
		XCTAssertEqual(keys.count, 0)
	}
	
	
	// MARK: Private Key Tests
	
	func test_private_initWithPEMString() throws {
		
		guard let path = CryptorRSATests.bundle.path(forResource: "private", ofType: "pem") else {
			
			return XCTFail()
		}
		
		let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
		let privateKey = try? CryptorRSA.Key(withPEM: str, isPublic: false)
		XCTAssertNotNil(privateKey)
		XCTAssertFalse(privateKey!.isPublic)
	}
	
	func test_private_initWithPEMStringHeaderless() throws {
		
		guard let path = CryptorRSATests.bundle.path(forResource: "private-headerless", ofType: "pem") else {
			
			return XCTFail()
		}
		
		let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
		let privateKey = try? CryptorRSA.Key(withPEM: str, isPublic: false)
		XCTAssertNotNil(privateKey)
		XCTAssertFalse(privateKey!.isPublic)
	}
	
	func test_private_initWithPEMName() throws {
		
		let message = try? CryptorRSA.Key(withPEMNamed: "private", in: CryptorRSATests.bundle, isPublic: false)
		XCTAssertNotNil(message)
	}
	
	func test_private_initWithDERName() throws {
		
		//let message = try? CryptorRSA.Key(pemNamed: "private", in: CryptorRSATests.bundle)
		//XCTAssertNotNil(message)
	}
	
	// MARK: Test Utilities
	
	struct TestError: Error {
		let description: String
	}
	
	static public func pemKeyString(name: String) -> String {
		
		let pubPath = bundle.path(forResource: name, ofType: "pem")!
		return (try! NSString(contentsOfFile: pubPath, encoding: String.Encoding.utf8.rawValue)) as String
	}
	
	static public func derKeyData(name: String) -> Data {
		
		let pubPath  = bundle.path(forResource: name, ofType: "der")!
		return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))
	}
	
	static public func publicKey(name: String) throws -> CryptorRSA.Key {
		
		guard let path = bundle.path(forResource: name, ofType: "pem") else {
			
			throw TestError(description: "Couldn't load key for provided path")
		}
		
		let pemString = try String(contentsOf: URL(fileURLWithPath: path))
		return try CryptorRSA.Key(withPEM: pemString, isPublic: true)
	}
	
	static public func privateKey(name: String) throws -> CryptorRSA.Key {
		
		guard let path = bundle.path(forResource: name, ofType: "pem") else {
			
			throw TestError(description: "Couldn't load key for provided path")
		}
		
		let pemString = try String(contentsOf: URL(fileURLWithPath: path))
		return try CryptorRSA.Key(withPEM: pemString, isPublic: true)
	}
	
	static public func randomData(count: Int) -> Data {
		
		var data = Data(capacity: count)
		data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> Void in
			
			_ = SecRandomCopyBytes(kSecRandomDefault, count, bytes)
		}
		return data
	}


	static var allTests : [(String, (CryptorRSATests) -> () throws -> Void)] {
        return [
            ("test_public_initWithData", test_public_initWithData),
            ("test_public_initWithBase64String", test_public_initWithBase64String),
            ("test_public_initWithBase64StringWhichContainsNewLines", test_public_initWithBase64StringWhichContainsNewLines),
            ("test_public_initWithPEMString", test_public_initWithPEMString),
            ("test_public_initWithPEMName", test_public_initWithPEMName),
            ("test_public_initWithDERName", test_public_initWithDERName),
            ("test_public_initWithPEMStringHeaderless", test_public_initWithPEMStringHeaderless),
            ("test_publicKeysFromComplexPEMFileWorksCorrectly", test_publicKeysFromComplexPEMFileWorksCorrectly),
            ("test_publicKeysFromEmptyPEMFileReturnsEmptyArray", test_publicKeysFromEmptyPEMFileReturnsEmptyArray),
            ("test_private_initWithPEMString", test_private_initWithPEMString),
            ("test_private_initWithPEMStringHeaderless", test_private_initWithPEMStringHeaderless),
            ("test_private_initWithPEMName", test_private_initWithPEMName),
            ("test_private_initWithDERName", test_private_initWithDERName),
        ]
    }
}
