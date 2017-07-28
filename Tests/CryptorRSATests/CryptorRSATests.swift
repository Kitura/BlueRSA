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

#if os(Linux)
import OpenSSL
#endif
import XCTest
@testable import CryptorRSA

@available(macOS 10.12, iOS 10.0, *)
class CryptorRSATests: XCTestCase {

	// Ideally, we would use Bundles... but on Linux, they are not fully implemented yet.
	// For instance, this constructor is not yet implemented:
	// fatal error: init(for:) is not yet implemented: file Foundation/NSBundle.swift, line 56
	// static let bundle = Bundle(for: CryptorRSATests.self)
	// Also tried using a different constructor... that worked but then ran into another problem with Foundation...
	//static let keysURL: URL = URL(fileURLWithPath: #file).appendingPathComponent("../keys").standardized

	#if !os(Linux)
	static let bundle =  Bundle(for: CryptorRSATests.self)
	static var useBundles: Bool {
		let path = CryptorRSATests.bundle.path(forResource: "public", ofType: "der")
		return path != nil
	}
	#endif

	static func getPath(forResource resource: String, ofType type: String) -> String? {
		var path = "./Tests/CryptorRSATests/keys/\(resource).\(type)"
		#if !os(Linux)
		if useBundles {
			guard let bPath = CryptorRSATests.bundle.path(forResource: resource, ofType: type) else {
				XCTFail("Could not load test resource!")
				return nil
			}
			path = bPath
		}
		#endif
		return path
	}

	// MARK: Public Key Tests

    /*
	//////////////
	func test_public_initWithDataRO() throws {
		if let path: String = CryptorRSATests.getPath(forResource: "public", ofType: "pem") {
            let dataIn = try Data(contentsOf: URL(fileURLWithPath: path))
            // So... it looks like OpenSSL expects PEM as input while Apple's library expects DER?????
            #if os(Linux)
                let data = dataIn
            #else
                let data = dataIn
            #endif

			guard let publicKey = try? CryptorRSA.createPublicKey(with: data) else {
				XCTFail("publicKey was nil!")
				return
			}
			XCTAssertNotNil(publicKey)
			XCTAssertTrue(publicKey.type == .publicType)
		}
	}
	//////////////
     */

	func test_public_initWithData() throws {
		if let path: String = CryptorRSATests.getPath(forResource: "public", ofType: "der") {
            let dataIn = try Data(contentsOf: URL(fileURLWithPath: path))
            // I could only get this to work by making this data conversion from DER to PEM
            // before calling the createPublicKey() method...
            // but is this expected? Do we need to make this transformation from DER to PEM?
            // https://support.ssl.com/Knowledgebase/Article/View/19/0/der-vs-crt-vs-cer-vs-pem-certificates-and-how-to-convert-them
            // https://stackoverflow.com/questions/25366887/openssl-api-read-private-key-in-der-format-instead-of-pem
            // https://search.thawte.com/support/ssl-digital-certificates/index?page=content&actp=CROSSLINK&id=SO26449
            // Is OpenSSL expecting data in PEM format? And Apple expects DER format?
            // http://gagravarr.org/writing/openssl-certs/general.shtml
            // http://fm4dd.com/openssl/certpubkey.htm
            // http://openssl.6102.n7.nabble.com/Converting-RSA-to-EVP-pkey-td12798.html
            #if os(Linux)
                let data = CryptorRSA.convertDerToPem(from: dataIn, type: .publicType)
            #else
                let data = dataIn
            #endif

			guard let publicKey = try? CryptorRSA.createPublicKey(with: data) else {
				XCTFail("publicKey was nil!")
				return
			}
			XCTAssertNotNil(publicKey)
			XCTAssertTrue(publicKey.type == .publicType)
		}
	}

	func test_public_initWithCertData() throws {
		if let path: String = CryptorRSATests.getPath(forResource: "staging", ofType: "cer") {
			let data = try Data(contentsOf: URL(fileURLWithPath: path))
			guard let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: data) else {
				XCTFail("publicKey was nil!")
				return
			}
			XCTAssertNotNil(publicKey)
			XCTAssertTrue(publicKey.type == .publicType)
		}
	}

	func test_public_initWithCertData2() throws {
		if let path: String = CryptorRSATests.getPath(forResource: "staging2", ofType: "cer") {
			let data = try Data(contentsOf: URL(fileURLWithPath: path))
			guard let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: data) else {
				XCTFail("publicKey was nil!")
				return
			}
			XCTAssertNotNil(publicKey)
			XCTAssertTrue(publicKey.type == .publicType)
		}
	}

	func test_public_initWithBase64String() throws {
		if let path: String = CryptorRSATests.getPath(forResource: "public-base64", ofType: "txt") {
			//let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
			let str = try String(contentsOfFile: path, encoding: .utf8)
			guard let publicKey = try? CryptorRSA.createPublicKey(withBase64: str) else {
				XCTFail("publicKey was nil!")
				return
			}
			XCTAssertNotNil(publicKey)
			XCTAssertTrue(publicKey.type == .publicType)
		}
	}

	func test_public_initWithBase64StringWhichContainsNewLines() throws {
		if let path: String = CryptorRSATests.getPath(forResource: "public-base64-newlines", ofType: "txt") {
			//let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
			let str = try String(contentsOfFile: path, encoding: .utf8)
			guard let publicKey = try? CryptorRSA.createPublicKey(withBase64: str) else {
				XCTFail("publicKey was nil!")
				return
			}
			XCTAssertNotNil(publicKey)
			XCTAssertTrue(publicKey.type == .publicType)
		}
	}

	func test_public_initWithPEMString() throws {
		if let path: String = CryptorRSATests.getPath(forResource: "public", ofType: "pem") {
			//let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
			let str = try String(contentsOfFile: path, encoding: .utf8)
			guard let publicKey = try? CryptorRSA.createPublicKey(withPEM: str) else {
				XCTFail("publicKey was nil!")
				return
			}
			XCTAssertNotNil(publicKey)
			XCTAssertTrue(publicKey.type == .publicType)
		}
	}


	func test_public_initWithPEMName() throws {

        setbuf(stdout, nil)

        print("start: test_public_initWithPEMName")

		#if !os(Linux)

		if CryptorRSATests.useBundles {
			let publicKey = try? CryptorRSA.createPublicKey(withPEMNamed: "public", in: CryptorRSATests.bundle)
			XCTAssertNotNil(publicKey)
		} else {
			let publicKey = try? CryptorRSA.createPublicKey(withPEMNamed: "public", onPath: "./Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}

		#else

		let publicKey = try? CryptorRSA.createPublicKey(withPEMNamed: "public", onPath: "./Tests/CryptorRSATests/keys/")
		XCTAssertNotNil(publicKey)

		#endif
	}


	func test_public_initWithDERName() throws {
		#if !os(Linux)

		if CryptorRSATests.useBundles {
			let publicKey = try? CryptorRSA.createPublicKey(withDERNamed: "public", in: CryptorRSATests.bundle)
			XCTAssertNotNil(publicKey)
		} else {
			let publicKey = try? CryptorRSA.createPublicKey(withDERNamed: "public", onPath: "./Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}

		#else

		let publicKey = try? CryptorRSA.createPublicKey(withDERNamed: "public", onPath: "./Tests/CryptorRSATests/keys/")
		XCTAssertNotNil(publicKey)

		#endif
	}

	func test_public_initWithPEMStringHeaderless() throws {
		if let path: String = CryptorRSATests.getPath(forResource: "public-headerless", ofType: "pem") {
        //if let path: String = CryptorRSATests.getPath(forResource: "public", ofType: "pem") {
			//let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
			let str = try String(contentsOfFile: path, encoding: .utf8)
			guard let publicKey = try? CryptorRSA.createPublicKey(withPEM: str) else {
				XCTFail("publicKey was nil!")
				return
			}
			XCTAssertNotNil(publicKey)
			XCTAssertTrue(publicKey.type == .publicType)
		}
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
		#if !os(Linux)

		if CryptorRSATests.useBundles {
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging", in: CryptorRSATests.bundle)
			XCTAssertNotNil(publicKey)
		} else {
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging", onPath: "./Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}

		#else
		let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging", onPath: "./Tests/CryptorRSATests/keys/")
		XCTAssertNotNil(publicKey)
		#endif
	}

	func test_public_initWithCertificateName2() throws {
		#if !os(Linux)

		if CryptorRSATests.useBundles {
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging2", in: CryptorRSATests.bundle)
			XCTAssertNotNil(publicKey)
		} else {
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging2", onPath: "./Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}

		#else
		let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging2", onPath: "./Tests/CryptorRSATests/keys/")
		XCTAssertNotNil(publicKey)
		#endif
	}

	// MARK: Private Key Tests

	func test_private_initWithPEMString() throws {
		if let path: String = CryptorRSATests.getPath(forResource: "private", ofType: "pem") {
			let str = try String(contentsOfFile: path, encoding: .utf8)
			guard let privateKey = try? CryptorRSA.createPrivateKey(withPEM: str) else {
				XCTFail("privateKey was nil!")
				return
			}
			XCTAssertNotNil(privateKey)
			XCTAssertTrue(privateKey.type == .privateType)
		}
	}

	func test_private_initWithPEMStringHeaderless() throws {
		if let path: String = CryptorRSATests.getPath(forResource: "private-headerless", ofType: "pem") {
			//let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
			let str = try String(contentsOfFile: path, encoding: .utf8)
			guard let privateKey = try? CryptorRSA.createPrivateKey(withPEM: str) else {
				XCTFail("privateKey was nil!")
				return
			}
			XCTAssertNotNil(privateKey)
			XCTAssertTrue(privateKey.type == .privateType)
		}
	}

	func test_private_initWithPEMName() throws {
		#if !os(Linux)

		if CryptorRSATests.useBundles {
			let privateKey = try? CryptorRSA.createPrivateKey(withPEMNamed: "private", in: CryptorRSATests.bundle)
			XCTAssertNotNil(privateKey)
		} else {
			let privateKey = try? CryptorRSA.createPrivateKey(withPEMNamed: "private", onPath: "./Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(privateKey)
		}

		#else

		let privateKey = try? CryptorRSA.createPrivateKey(withPEMNamed: "private", onPath: "./Tests/CryptorRSATests/keys/")
		XCTAssertNotNil(privateKey)

		#endif
	}

	func test_private_initWithDERName() throws {
		#if !os(Linux)

		if CryptorRSATests.useBundles {
			let privateKey = try? CryptorRSA.createPrivateKey(withDERNamed: "private", in: CryptorRSATests.bundle)
			XCTAssertNotNil(privateKey)
		} else {
			let privateKey = try? CryptorRSA.createPrivateKey(withDERNamed: "private", onPath: "./Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(privateKey)
		}

		#else
		let privateKey = try? CryptorRSA.createPrivateKey(withDERNamed: "private", onPath: "./Tests/CryptorRSATests/keys/")
		XCTAssertNotNil(privateKey)
		#endif
	}

	// MARK: Encyption/Decryption Tests

	func test_simpleEncryption() throws {

		guard let publicKey: CryptorRSA.PublicKey = try? CryptorRSATests.publicKey(name: "public") else {
			XCTFail("publicKey was nil!")
			return
		}
		guard let privateKey: CryptorRSA.PrivateKey = try? CryptorRSATests.privateKey(name: "private") else {
			return
		}

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
			print("HELLLLLLLOOOOOO1")
			guard let encrypted = try plainText.encrypted(with: publicKey, algorithm: algorithm) else {
				XCTFail("Fail to encrypt text!")
				return
			}
			print("HELLLLLLLOOOOOO2")
			XCTAssertNotNil(encrypted)
			print("HELLLLLLLOOOOOO3")
			let decrypted = try encrypted.decrypted(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(decrypted)
			let decryptedString = try decrypted!.string(using: .utf8)
			XCTAssertEqual(decryptedString, str)
			print("Test of algorithm: \(name) succeeded")
		}
	}

	func test_longStringEncryption() throws {

		guard let publicKey: CryptorRSA.PublicKey = try? CryptorRSATests.publicKey(name: "public") else {
			XCTFail("publicKey was nil!")
			return
		}
		guard let privateKey: CryptorRSA.PrivateKey = try? CryptorRSATests.privateKey(name: "private") else {
			XCTFail("privateKey was nil!")
			return
		}

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

		guard let publicKey: CryptorRSA.PublicKey = try? CryptorRSATests.publicKey(name: "public") else {
			XCTFail("publicKey was nil!")
			return
		}
		guard let privateKey: CryptorRSA.PrivateKey = try? CryptorRSATests.privateKey(name: "private") else {
			XCTFail("privateKey was nil!")
			return
		}

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

		guard let publicKey: CryptorRSA.PublicKey = try? CryptorRSATests.publicKey(name: "public") else {
			XCTFail("publicKey was nil!")
			return
		}
		guard let privateKey: CryptorRSA.PrivateKey = try? CryptorRSATests.privateKey(name: "private") else {
			XCTFail("privateKey was nil!")
			return
		}

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

		guard let publicKey: CryptorRSA.PublicKey = try? CryptorRSATests.publicKey(name: "public") else {
			XCTFail("publicKey was nil!")
			return
		}
		guard let privateKey: CryptorRSA.PrivateKey = try? CryptorRSATests.privateKey(name: "private") else {
			XCTFail("privateKey was nil!")
			return
		}

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
		#if !os(Linux)

		if useBundles {
			let pubPath = bundle.path(forResource: name, ofType: "pem")!
			return (try! String(contentsOfFile: pubPath, encoding: String.Encoding.utf8))
		} else {
			let pubPath = "./Tests/CryptorRSATests/keys/".appending(name.appending(".pem"))
			return (try! String(contentsOfFile: pubPath, encoding: String.Encoding.utf8))
		}

		#else

		let pubPath = "./Tests/CryptorRSATests/keys/".appending(name.appending(".pem"))
		return (try! String(contentsOfFile: pubPath, encoding: String.Encoding.utf8))

		#endif
	}

	static public func derKeyData(name: String) -> Data {
		#if !os(Linux)

		if useBundles {
			let pubPath  = bundle.path(forResource: name, ofType: "der")!
			return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))
		} else {
			let pubPath = "./Tests/CryptorRSATests/keys/".appending(name.appending(".der"))
			return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))
		}

		#else

		let pubPath = "./Tests/CryptorRSATests/keys/".appending(name.appending(".der"))
		return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))

		#endif
	}

	static public func publicKey(name: String) throws -> CryptorRSA.PublicKey {

		var path: String

		#if !os(Linux)

		if useBundles {
			guard let bPath = bundle.path(forResource: name, ofType: "pem") else {
				throw TestError(description: "Couldn't load key for provided path")
			}
			path = bPath
		} else {
			path = "./Tests/CryptorRSATests/keys/".appending(name.appending(".pem"))
		}

		#else

		path = "./Tests/CryptorRSATests/keys/".appending(name.appending(".pem"))
		print("PATH IS: \(path)")

		#endif

		//let pemString = try String(contentsOf: URL(fileURLWithPath: path))
		let pemString = try String(contentsOfFile: path, encoding: .utf8)
		return try CryptorRSA.createPublicKey(withPEM: pemString)
	}

	static public func privateKey(name: String) throws -> CryptorRSA.PrivateKey {

		var path: String

		#if !os(Linux)

		if useBundles {
			guard let bPath = bundle.path(forResource: name, ofType: "pem") else {

				throw TestError(description: "Couldn't load key for provided path")
			}
			path = bPath
		} else {
			path = "./Tests/CryptorRSATests/keys/".appending(name.appending(".pem"))
		}

		#else
		path = "./Tests/CryptorRSATests/keys/".appending(name.appending(".pem"))
		#endif

		let pemString = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
		return try CryptorRSA.createPrivateKey(withPEM: pemString)
	}

	static public func randomData(count: Int) -> Data {

		//https://www.openssl.org/docs/man1.0.2/crypto/RAND_pseudo_bytes.html
		//https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?preferredLanguage=occ

		var data = Data(capacity: count)
		data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> Void in

			#if os(Linux)
			RAND_bytes(bytes, Int32(count))
			#else
			_ = SecRandomCopyBytes(kSecRandomDefault, count, bytes)
			#endif
		}

		return data
	}

	// MARK: Test Lists

	static var allTests : [(String, (CryptorRSATests) -> () throws -> Void)] {
		return [
		//	("test_public_initWithDataRO", test_public_initWithDataRO),
			("test_public_initWithData", test_public_initWithData),
			("test_public_initWithCertData", test_public_initWithCertData),
			("test_public_initWithCertData2", test_public_initWithCertData2),
			("test_public_initWithBase64String", test_public_initWithBase64String),
			("test_public_initWithBase64StringWhichContainsNewLines", test_public_initWithBase64StringWhichContainsNewLines),
			("test_public_initWithPEMString", test_public_initWithPEMString),
			("test_public_initWithPEMName", test_public_initWithPEMName),
			("test_public_initWithDERName", test_public_initWithDERName),
			//("test_public_initWithPEMStringHeaderless", test_public_initWithPEMStringHeaderless), // is this a valid test???
			("test_publicKeysFromComplexPEMFileWorksCorrectly", test_publicKeysFromComplexPEMFileWorksCorrectly),
			("test_publicKeysFromEmptyPEMFileReturnsEmptyArray", test_publicKeysFromEmptyPEMFileReturnsEmptyArray),
			("test_public_initWithCertificateName", test_public_initWithCertificateName),
			("test_public_initWithCertificateName2", test_public_initWithCertificateName2),
			("test_private_initWithPEMString", test_private_initWithPEMString),
			("test_private_initWithPEMStringHeaderless", test_private_initWithPEMStringHeaderless),
			("test_private_initWithPEMName", test_private_initWithPEMName),
			("test_private_initWithDERName", test_private_initWithDERName),
			("test_simpleEncryption", test_simpleEncryption),/*
			("test_longStringEncryption", test_longStringEncryption),
			("test_randomByteEncryption", test_randomByteEncryption),
			("test_signVerifyAllDigestTypes", test_signVerifyAllDigestTypes),
			("test_signVerifyBase64", test_signVerifyBase64),*/
		]
	}
}
