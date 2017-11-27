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
	
	static var useBundles: Bool {
		
		let path = CryptorRSATests.bundle.path(forResource: "public", ofType: "der")
		return path != nil
	}
	
	// MARK: Public Key Tests
	
	static let bundle = Bundle(for: CryptorRSATests.self)
	
	func test_public_initWithData() throws {
		
        let path: URL
		if CryptorRSATests.useBundles {
			guard let bPath = CryptorRSATests.bundle.path(forResource: "public", ofType: "der") else {
			
				return XCTFail()
			}
            path = URL(fileURLWithPath: bPath)
			
		} else {
			
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/public.der").standardized
		}
        
        let data = try Data(contentsOf: path)
		let publicKey = try? CryptorRSA.createPublicKey(with: data)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.type == .publicType)
	}
	
	func test_public_initWithCertData() throws {
		
		var path: URL
		if CryptorRSATests.useBundles {
			guard let bPath = CryptorRSATests.bundle.path(forResource: "staging", ofType: "cer") else {
				
				return XCTFail()
			}
			path = URL(fileURLWithPath: bPath)
			
		} else {
			
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/staging.cer").standardized
		}
		
		let data = try Data(contentsOf: path)
		let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: data)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.type == .publicType)
	}
	
	func test_public_initWithCertData2() throws {
		
		var path: URL
		if CryptorRSATests.useBundles {
			guard let bPath = CryptorRSATests.bundle.path(forResource: "staging2", ofType: "cer") else {
				
				return XCTFail()
			}
			path = URL(fileURLWithPath: bPath)
			
		} else {
			
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/staging2.cer").standardized
		}
		
		let data = try Data(contentsOf: path)
		let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: data)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.type == .publicType)
	}
	
	func test_public_initWithBase64String() throws {
		
		var path: URL
		if CryptorRSATests.useBundles {
			guard let bPath = CryptorRSATests.bundle.path(forResource: "public-base64", ofType: "txt") else {
				
				return XCTFail()
			}
            path = URL(fileURLWithPath: bPath)

		} else {
			
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/public-base64.txt").standardized
		}
		
		let str = try String(contentsOf: path, encoding: .utf8)
		let publicKey = try? CryptorRSA.createPublicKey(withBase64: str)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.type == .publicType)
	}
	

	func test_public_initWithBase64StringWhichContainsNewLines() throws {
		
		var path: URL
		if CryptorRSATests.useBundles {
			guard let bPath = CryptorRSATests.bundle.path(forResource: "public-base64-newlines", ofType: "txt") else {
				
				return XCTFail()
			}
            path = URL(fileURLWithPath: bPath)

		} else {
			
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/public-base64-newlines.txt").standardized
		}
		
		let str = try String(contentsOf: path, encoding: .utf8)
		let publicKey = try? CryptorRSA.createPublicKey(withBase64: str)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.type == .publicType)
	}
	
	func test_public_initWithPEMString() throws {
		
		var path: URL
		if CryptorRSATests.useBundles {
			guard let bPath = CryptorRSATests.bundle.path(forResource: "public", ofType: "pem") else {
				
				return XCTFail()
			}
            path = URL(fileURLWithPath: bPath)

		} else {
			
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/public.pem").standardized
		}
		
		let str = try String(contentsOf: path, encoding: .utf8)
		let publicKey = try? CryptorRSA.createPublicKey(withPEM: str)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.type == .publicType)
	}
	
	func test_public_initWithPEMName() throws {
		
		if CryptorRSATests.useBundles {
			
			let publicKey = try? CryptorRSA.createPublicKey(withPEMNamed: "public", in: CryptorRSATests.bundle)
			XCTAssertNotNil(publicKey)
		
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(withPEMNamed: "public", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
	}
	
	func test_public_initWithDERName() throws {
		
		if CryptorRSATests.useBundles {
			
			let publicKey = try? CryptorRSA.createPublicKey(withDERNamed: "public", in: CryptorRSATests.bundle)
			XCTAssertNotNil(publicKey)
			
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(withDERNamed: "public", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
		
	}
	
	func test_public_initWithPEMStringHeaderless() throws {
		
		var path: URL
		if CryptorRSATests.useBundles {
			guard let bPath = CryptorRSATests.bundle.path(forResource: "public-headerless", ofType: "pem") else {
				
				return XCTFail()
			}
            path = URL(fileURLWithPath: bPath)

		} else {
			
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/public-headerless.pem").standardized
		}
		
		let str = try String(contentsOf: path, encoding: .utf8)
		let publicKey = try? CryptorRSA.createPublicKey(withPEM: str)
		XCTAssertNotNil(publicKey)
		XCTAssertTrue(publicKey!.type == .publicType)
	}
	
	func test_publicKeysFromComplexPEMFileWorksCorrectly() {
		
		let input = CryptorRSATests.pemKeyString(name: "multiple-keys-testcase")
		let keys = CryptorRSA.PublicKey.publicKeys(withPEM: input)
		XCTAssertEqual(keys.count, 9)
		
		for publicKey in keys {
			XCTAssertTrue(publicKey.type == .publicType)
		}
	}
	
	func test_publicKeysFromEmptyPEMFileReturnsEmptyArray() {
		
		let keys = CryptorRSA.PublicKey.publicKeys(withPEM: "")
		XCTAssertEqual(keys.count, 0)
	}
	
	func test_public_initWithCertificateName() throws {
		
		if CryptorRSATests.useBundles {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging", in: CryptorRSATests.bundle)
			XCTAssertNotNil(publicKey)
			
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
		
	}
	
	func test_public_initWithCertificateName2() throws {
		
		if CryptorRSATests.useBundles {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging2", in: CryptorRSATests.bundle)
			XCTAssertNotNil(publicKey)
			
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging2", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
		
	}
	
	
	// MARK: Private Key Tests
	
	func test_private_initWithPEMString() throws {
		
		var path: URL
		if CryptorRSATests.useBundles {
			guard let bPath = CryptorRSATests.bundle.path(forResource: "private", ofType: "pem") else {
				
				return XCTFail()
			}
            path = URL(fileURLWithPath: bPath)

		} else {
			
			//path = "./Tests/CryptorRSATests/Keys/private.pem"
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/private.pem").standardized
		}
		
		let str = try String(contentsOf: path, encoding: .utf8)
		let privateKey = try? CryptorRSA.createPrivateKey(withPEM: str)
		XCTAssertNotNil(privateKey)
		XCTAssertTrue(privateKey!.type == .privateType)
	}
	
	func test_private_initWithPEMStringHeaderless() throws {
		
		var path: URL
		if CryptorRSATests.useBundles {
			guard let bPath = CryptorRSATests.bundle.path(forResource: "private-headerless", ofType: "pem") else {
				
				return XCTFail()
			}
            path = URL(fileURLWithPath: bPath)

		} else {
			
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/private-headerless.pem").standardized
		}
		
		let str = try String(contentsOf: path, encoding: .utf8)
		let privateKey = try? CryptorRSA.createPrivateKey(withPEM: str)
		XCTAssertNotNil(privateKey)
		XCTAssertTrue(privateKey!.type == .privateType)
	}
	
	func test_private_initWithPEMName() throws {
		
		if CryptorRSATests.useBundles {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withPEMNamed: "private", in: CryptorRSATests.bundle)
			XCTAssertNotNil(privateKey)
			
		} else {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withPEMNamed: "private", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(privateKey)
		}
		
	}
	
	func test_private_initWithDERName() throws {
		
		if CryptorRSATests.useBundles {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withDERNamed: "private", in: CryptorRSATests.bundle)
			XCTAssertNotNil(privateKey)
			
		} else {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withDERNamed: "private", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(privateKey)
		}
		
	}
	
	// MARK: Encyption/Decryption Tests
	
	let publicKey: CryptorRSA.PublicKey = try! CryptorRSATests.publicKey(name: "public")
	let privateKey: CryptorRSA.PrivateKey = try! CryptorRSATests.privateKey(name: "private")
	
	func test_simpleEncryption() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
		                                              (.sha224, ".sha224"),
		                                              (.sha256, ".sha256"),
		                                              (.sha384, ".sha384"),
		                                              /*(.sha512, ".sha512")*/]
		// Test all the algorithms available...
		//	Note: .sha512 appears to be broken internally on Apple platforms.
		for (algorithm, name) in algorithms {
		
			print("Testing algorithm: \(name)")
			let str = "Plain Text"
			let plainText = try CryptorRSA.createPlaintext(with: str, using: .utf8)
		
			let encrypted = try plainText.encrypted(with: publicKey, algorithm: algorithm)
			XCTAssertNotNil(encrypted)
			let decrypted = try encrypted!.decrypted(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(decrypted)
			let decryptedString = try decrypted!.string(using: .utf8)
			XCTAssertEqual(decryptedString, str)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	func test_longStringEncryption() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
		                                              (.sha224, ".sha224"),
		                                              (.sha256, ".sha256"),
		                                              (.sha384, ".sha384"),
		                                              /*(.sha512, ".sha512")*/]
		// Test all the algorithms available...
		//	Note: .sha512 appears to be broken internally on Apple platforms.
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let str = [String](repeating: "a", count: 9999).joined(separator: "")
			let plainText = try CryptorRSA.createPlaintext(with: str, using: .utf8)
		
			let encrypted = try plainText.encrypted(with: publicKey, algorithm: algorithm)
			XCTAssertNotNil(encrypted)
			let decrypted = try encrypted!.decrypted(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(decrypted)
			let decryptedString = try decrypted!.string(using: .utf8)
			XCTAssertEqual(decryptedString, str)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	func test_randomByteEncryption() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
		                                              (.sha224, ".sha224"),
		                                              (.sha256, ".sha256"),
		                                              (.sha384, ".sha384"),
		                                              /*(.sha512, ".sha512")*/]
		// Test all the algorithms available...
		//	Note: .sha512 appears to be broken internally on Apple platforms.
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let data = CryptorRSATests.randomData(count: 2048)
			let plainData = CryptorRSA.createPlaintext(with: data)
		
			let encrypted = try plainData.encrypted(with: publicKey, algorithm: algorithm)
			XCTAssertNotNil(encrypted)
			let decrypted = try encrypted!.decrypted(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(decrypted)
			XCTAssertEqual(decrypted!.data, data)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	// MARK: Signing/Verification Tests
	
	func test_signVerifyAllDigestTypes() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
		                                              (.sha224, ".sha224"),
		                                              (.sha256, ".sha256"),
		                                              (.sha384, ".sha384"),
		                                              (.sha512, ".sha512")]
		// Test all the algorithms available...
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let data = CryptorRSATests.randomData(count: 8192)
			let message = CryptorRSA.createPlaintext(with: data)
			let signature = try message.signed(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(signature)
			let verificationResult = try message.verify(with: publicKey, signature: signature!, algorithm: algorithm)
			XCTAssertTrue(verificationResult)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	func test_signVerifyBase64() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
		                                              (.sha224, ".sha224"),
		                                              (.sha256, ".sha256"),
		                                              (.sha384, ".sha384"),
		                                              (.sha512, ".sha512")]
		// Test all the algorithms available...
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let data = CryptorRSATests.randomData(count: 8192)
			let message = CryptorRSA.createPlaintext(with: data)
			let signature = try message.signed(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(signature)
			XCTAssertEqual(signature!.base64String, signature!.data.base64EncodedString())
			let verificationResult = try message.verify(with: publicKey, signature: signature!, algorithm: algorithm)
			XCTAssertTrue(verificationResult)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	// MARK: Test Utilities
	
	struct TestError: Error {
		let description: String
	}
	
	static public func pemKeyString(name: String) -> String {
		
		if useBundles {
			
			let pubPath = bundle.path(forResource: name, ofType: "pem")!
			return (try! NSString(contentsOfFile: pubPath, encoding: String.Encoding.utf8.rawValue)) as String
		
		} else {
			
			let pubPath = "../../CryptorRSATests/Keys/".appending(name.appending(".pem"))
            let fullPath = URL(fileURLWithPath: #file).appendingPathComponent( pubPath ).standardized
            print ("fullPath = \(fullPath.path) ")
            
			return (try! NSString(contentsOfFile: fullPath.path, encoding: String.Encoding.utf8.rawValue )) as String
		}
	}
	
	static public func derKeyData(name: String) -> Data {
		
		if useBundles {
			
			let pubPath  = bundle.path(forResource: name, ofType: "der")!
			return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))
		
		} else {
			
			let pubPath = "../../Tests/CryptorRSATests/Keys/".appending(name.appending(".der"))
			return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))
		}
	}
	
	static public func publicKey(name: String) throws -> CryptorRSA.PublicKey {
		
        let path: URL
		if useBundles {
			guard let bPath = bundle.path(forResource: name, ofType: "pem") else {
				
				throw TestError(description: "Couldn't load key for provided path")
			}
			path = URL(fileURLWithPath: bPath)

		} else {
			
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/"+name.appending(".pem")).standardized
		}
        let pemString = try String(contentsOf: path, encoding: String.Encoding.ascii)
		return try CryptorRSA.createPublicKey(withPEM: pemString)
	}
	
	static public func privateKey(name: String) throws -> CryptorRSA.PrivateKey {
		
        let path: URL
		if useBundles {
			guard let bPath = bundle.path(forResource: name, ofType: "pem") else {
				
				throw TestError(description: "Couldn't load key for provided path")
			}
			path = URL(fileURLWithPath: bPath)
            
		} else {
			
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/"+name.appending(".pem")).standardized
		}
        let pemString = try String(contentsOf: path, encoding: String.Encoding.ascii)
        return try CryptorRSA.createPrivateKey(withPEM: pemString)
	}
	
	static public func randomData(count: Int) -> Data {
		
		var data = Data(capacity: count)
		data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> Void in
			
			_ = SecRandomCopyBytes(kSecRandomDefault, count, bytes)
		}
		return data
	}
	
	// MARK: Test Lists
	

	static var allTests : [(String, (CryptorRSATests) -> () throws -> Void)] {
        return [
            ("test_public_initWithData", test_public_initWithData),
            ("test_public_initWithCertData", test_public_initWithCertData),
            ("test_public_initWithCertData2", test_public_initWithCertData2),
            ("test_public_initWithBase64String", test_public_initWithBase64String),
            ("test_public_initWithBase64StringWhichContainsNewLines", test_public_initWithBase64StringWhichContainsNewLines),
            ("test_public_initWithPEMString", test_public_initWithPEMString),
            ("test_public_initWithPEMName", test_public_initWithPEMName),
            ("test_public_initWithDERName", test_public_initWithDERName),
            ("test_public_initWithPEMStringHeaderless", test_public_initWithPEMStringHeaderless),
            ("test_publicKeysFromComplexPEMFileWorksCorrectly", test_publicKeysFromComplexPEMFileWorksCorrectly),
            ("test_publicKeysFromEmptyPEMFileReturnsEmptyArray", test_publicKeysFromEmptyPEMFileReturnsEmptyArray),
            ("test_public_initWithCertificateName", test_public_initWithCertificateName),
            ("test_public_initWithCertificateName2", test_public_initWithCertificateName2),
            ("test_private_initWithPEMString", test_private_initWithPEMString),
            ("test_private_initWithPEMStringHeaderless", test_private_initWithPEMStringHeaderless),
            ("test_private_initWithPEMName", test_private_initWithPEMName),
            ("test_private_initWithDERName", test_private_initWithDERName),
            ("test_simpleEncryption", test_simpleEncryption),
            ("test_longStringEncryption", test_longStringEncryption),
            ("test_randomByteEncryption", test_randomByteEncryption),
            ("test_signVerifyAllDigestTypes", test_signVerifyAllDigestTypes),
            ("test_signVerifyBase64", test_signVerifyBase64),
        ]
    }
}
