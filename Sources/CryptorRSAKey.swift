//
//  CryptorRSAKey.swift
//  CryptorRSA
//
//  Created by Bill Abt on 1/18/17.
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

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
	import CommonCrypto
#elseif os(Linux)
	import OpenSSL
#endif

import Foundation

// MARK: -

@available(macOS 10.12, iOS 10.0, *)
public extension CryptorRSA {

	// MARK: Type Aliases

	#if os(Linux)

		typealias NativeKey = UnsafeMutablePointer<RSA>

	#else

		typealias NativeKey = SecKey

	#endif

	// MARK: Class Functions

	// MARK: -- Public Key Creation

	///
	/// Creates a public key with data.
	///
	/// - Parameters:
	///		- data: 			Key data
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(with data: Data) throws -> PublicKey {
		return try PublicKey(with: data)
	}

	///
	/// Creates a public key by extracting it from a certificate.
	///
	/// - Parameters:
	/// 	- data:				`Data` representing the certificate.
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(extractingFrom data: Data) throws -> PublicKey {

		// Extact the data as a base64 string...
		guard let str = String(data: data, encoding: .utf8) else {
			throw Error(code: ERR_CREATE_CERT_FAILED, reason: "Unable to create certificate from certificate data, incorrect format.")
		}

		let base64 = try CryptorRSA.base64String(for: str)
		guard let data = Data(base64Encoded: base64) else {
			throw Error(code: ERR_CREATE_CERT_FAILED, reason: "Unable to create certificate from certificate data, incorrect format.")
		}

		// Call the internal function to finish up...
		return try CryptorRSA.createPublicKey(data: data)
	}

	///
	/// Creates a key with a base64-encoded string.
	///
	/// - Parameters:
	///		- base64String: 	Base64-encoded key data
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(withBase64 base64String: String) throws -> PublicKey {

		guard let data = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {
			throw Error(code: ERR_INIT_PK, reason: "Couldn't decode base64 string.")
		}
        
        print("createPublicKey(withBase64): \(data)")

		return try PublicKey(with: data)
	}

	///
	/// Creates a key with a PEM string.
	///
	/// - Parameters:
	///		- pemString: 		PEM-encoded key string
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(withPEM pemString: String) throws -> PublicKey {
		let base64String = try CryptorRSA.base64String(for: pemString)
		return try createPublicKey(withBase64: base64String)
	}

	///
	/// Creates a key with a PEM file.
	///
	/// - Parameters:
	/// 	- pemName: 			Name of the PEM file
	/// 	- path: 			Path where the file is located.
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(withPEMNamed pemName: String, onPath path: String) throws -> PublicKey {
        
        print("createPublicKey start")

		var fullPath = path.appending(pemName)
		if !path.hasSuffix(PEM_SUFFIX) {
			fullPath = fullPath.appending(PEM_SUFFIX)
		}
        
        //testing - RO
		let keyString = try String(contentsOf: URL(fileURLWithPath: fullPath), encoding: .utf8)
        //print("keyString: \(keyString)")
        return try createPublicKey(withPEM: keyString)
        
        //print("right before creating data...")
        //let data = keyString.data(using: .utf8)
        // OR
        //let data = try Data(contentsOf: URL(fileURLWithPath: fullPath))
        //print("right after creating data...")
        //print("createPublicKey")
        //print("data: \(data!)")
        //return try PublicKey(with: data!)
        //testing - RO
	}

	///
	/// Creates a key with a DER file.
	///
	/// - Parameters:
	/// 	- derName: 			Name of the DER file
	/// 	- path: 			Path where the file is located.
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(withDERNamed derName: String, onPath path: String) throws -> PublicKey {

		var fullPath = path.appending(derName)
		if !path.hasSuffix(DER_SUFFIX) {
			fullPath = fullPath.appending(DER_SUFFIX)
		}

		let dataIn = try Data(contentsOf: URL(fileURLWithPath: fullPath))

		#if os(Linux)
			let data = CryptorRSA.convertDerToPem(from: dataIn, type: .publicType)
		#else
			let data = dataIn
		#endif

		return try PublicKey(with: data)
	}

	///
	/// Creates a public key by extracting it from a certificate.
	///
	/// - Parameters:
	/// 	- certName:			Name of the certificate file.
	/// 	- path: 			Path where the file is located.
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(extractingFrom certName: String, onPath path: String) throws -> PublicKey {

		var fullPath = path.appending(certName)
		if !path.hasSuffix(CER_SUFFIX) {

			fullPath = fullPath.appending(CER_SUFFIX)
		}

		// Import the data from the file...
		let tmp = try String(contentsOf: URL(fileURLWithPath: fullPath))
		//let tmp = try String(contentsOfFile: fullPath)
		let base64 = try CryptorRSA.base64String(for: tmp)
		let data = Data(base64Encoded: base64)!

		// Call the internal function to finish up...
		return try CryptorRSA.createPublicKey(data: data)
	}

	///
	/// Creates a key with a PEM file.
	///
	/// - Parameters:
	/// 	- pemName: 			Name of the PEM file
	/// 	- bundle: 			Bundle in which to look for the PEM file. Defaults to the main bundle.
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(withPEMNamed pemName: String, in bundle: Bundle = Bundle.main) throws -> PublicKey {

		guard let path = bundle.path(forResource: pemName, ofType: PEM_SUFFIX) else {
			throw Error(code: ERR_INIT_PK, reason: "Couldn't find a PEM file named '\(pemName)'")
		}

		let keyString = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
		//let keyString = try String(contentsOfFile: path, encoding: .utf8)
		return try createPublicKey(withPEM: keyString)
	}

	///
	/// Creates a key with a DER file.
	///
	/// - Parameters:
	/// 	- derName: 			Name of the DER file
	/// 	- bundle: 			Bundle in which to look for the DER file. Defaults to the main bundle.
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(withDERNamed derName: String, in bundle: Bundle = Bundle.main) throws -> PublicKey {

		guard let path = bundle.path(forResource: derName, ofType: DER_SUFFIX) else {

			throw Error(code: ERR_INIT_PK, reason: "Couldn't find a DER file named '\(derName)'")
		}

		let dataIn = try Data(contentsOf: URL(fileURLWithPath: path))

		#if os(Linux)
			let data = CryptorRSA.convertDerToPem(from: dataIn, type: .publicType)
		#else
			let data = dataIn
		#endif

		return try PublicKey(with: data)
	}

	///
	/// Creates a public key by extracting it from a certificate.
	///
	/// - Parameters:
	/// 	- certName:			Name of the certificate file.
	/// 	- bundle: 			Bundle in which to look for the DER file. Defaults to the main bundle.
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(extractingFrom certName: String, in bundle: Bundle = Bundle.main) throws -> PublicKey {

		guard let path = bundle.path(forResource: certName, ofType: CER_SUFFIX) else {

			throw Error(code: ERR_INIT_PK, reason: "Couldn't find a certificate file named '\(certName)'")
		}

		// Import the data from the file...
		let tmp = try String(contentsOf: URL(fileURLWithPath: path))
		let base64 = try CryptorRSA.base64String(for: tmp)
		let data = Data(base64Encoded: base64)!

		// Call the internal function to finish up...
		return try CryptorRSA.createPublicKey(data: data)
	}

	///
	/// Creates a public key by extracting it certificate data.
	///
	/// - Parameters:
	/// 	- data:				`Data` representing the certificate.
	///
	/// - Returns:				New `PublicKey` instance.
	///
	internal class func createPublicKey(data: Data) throws -> PublicKey {

		#if os(Linux)

			throw Error(code: ERR_NOT_IMPLEMENTED, reason: "Not implemented yet.")

		#else

			// Create a certificate from the data...
			let certificateData = SecCertificateCreateWithData(nil, data as CFData)
			guard let certData = certificateData else {

				throw Error(code: ERR_CREATE_CERT_FAILED, reason: "Unable to create certificate from certificate data.")
			}

			// Now extract the public key from it...
			var key: SecKey? = nil
			let status: OSStatus = withUnsafeMutablePointer(to: &key) { ptr in

				SecCertificateCopyPublicKey(certData, UnsafeMutablePointer(ptr))
			}
			if status != errSecSuccess || key == nil {

				throw Error(code: ERR_EXTRACT_PUBLIC_KEY_FAILED, reason: "Unable to extract public key from data.")
			}

			return PublicKey(with: key!)

		#endif
	}

	// MARK: -- Private Key Creation

	///
	/// Creates a private key with data.
	///
	/// - Parameters:
	///		- data: 			Key data
	///
	/// - Returns:				New `PrivateKey` instance.
	///
	public class func createPrivateKey(with data: Data) throws -> PrivateKey {

		return try PrivateKey(with: data)
	}

	///
	/// Creates a key with a base64-encoded string.
	///
	/// - Parameters:
	///		- base64String: 	Base64-encoded key data
	///
	/// - Returns:				New `PrivateKey` instance.
	///
	public class func createPrivateKey(withBase64 base64String: String) throws -> PrivateKey {

		guard let data = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {

			throw Error(code: ERR_INIT_PK, reason: "Couldn't decode base 64 string")
		}

		return try PrivateKey(with: data)
	}

	///
	/// Creates a key with a PEM string.
	///
	/// - Parameters:
	///		- pemString: 		PEM-encoded key string
	///
	/// - Returns:				New `PrivateKey` instance.
	///
	public class func createPrivateKey(withPEM pemString: String) throws -> PrivateKey {

		let base64String = try CryptorRSA.base64String(for: pemString)

		return try CryptorRSA.createPrivateKey(withBase64: base64String)
	}

	///
	/// Creates a key with a PEM file.
	///
	/// - Parameters:
	/// 	- pemName: 			Name of the PEM file
	/// 	- path: 			Path where the file is located.
	///
	/// - Returns:				New `PrivateKey` instance.
	///
	public class func createPrivateKey(withPEMNamed pemName: String, onPath path: String) throws -> PrivateKey {

		var fullPath = path.appending(pemName)
		if !path.hasSuffix(PEM_SUFFIX) {
			fullPath = fullPath.appending(PEM_SUFFIX)
		}

		let keyString = try String(contentsOf: URL(fileURLWithPath: fullPath), encoding: .utf8)
		//let keyString = try String(contentsOfFile: fullPath, encoding: .utf8)
		return try CryptorRSA.createPrivateKey(withPEM: keyString)
	}

	///
	/// Creates a key with a DER file.
	///
	/// - Parameters:
	/// 	- derName: 			Name of the DER file
	/// 	- path: 			Path where the file is located.
	///
	/// - Returns:				New `PrivateKey` instance.
	///
	public class func createPrivateKey(withDERNamed derName: String, onPath path: String) throws -> PrivateKey {

		var fullPath = path.appending(derName)
		if !path.hasSuffix(DER_SUFFIX) {

			fullPath = fullPath.appending(DER_SUFFIX)
		}

		let dataIn = try Data(contentsOf: URL(fileURLWithPath: fullPath))

		#if os(Linux)
			let data = CryptorRSA.convertDerToPem(from: dataIn, type: .privateType)
		#else
			let data = dataIn
		#endif

		return try PrivateKey(with: data)
	}

	///
	/// Creates a key with a PEM file.
	///
	/// - Parameters:
	/// 	- pemName: 			Name of the PEM file
	/// 	- bundle: 			Bundle in which to look for the PEM file. Defaults to the main bundle.
	///
	/// - Returns:				New `PrivateKey` instance.
	///
	public class func createPrivateKey(withPEMNamed pemName: String, in bundle: Bundle = Bundle.main) throws -> PrivateKey {

		guard let path = bundle.path(forResource: pemName, ofType: PEM_SUFFIX) else {
			throw Error(code: ERR_INIT_PK, reason: "Couldn't find a PEM file named '\(pemName)'")
		}

		let keyString = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
		//let keyString = try String(contentsOfFile: path, encoding: .utf8)
		return try CryptorRSA.createPrivateKey(withPEM: keyString)
	}

	///
	/// Creates a key with a DER file.
	///
	/// - Parameters:
	/// 	- derName: 			Name of the DER file
	/// 	- bundle: 			Bundle in which to look for the DER file. Defaults to the main bundle.
	///
	/// - Returns:				New `PrivateKey` instance.
	///
	public class func createPrivateKey(withDERNamed derName: String, in bundle: Bundle = Bundle.main) throws -> PrivateKey {

		guard let path = bundle.path(forResource: derName, ofType: DER_SUFFIX) else {

			throw Error(code: ERR_INIT_PK, reason: "Couldn't find a DER file named '\(derName)'")
		}

		let dataIn = try Data(contentsOf: URL(fileURLWithPath: path))

		#if os(Linux)
			let data = CryptorRSA.convertDerToPem(from: dataIn, type: .privateType)
		#else
			let data = dataIn
		#endif

		return try PrivateKey(with: data)
	}

	// MARK: -

	///
	/// RSA Key Creation and Handling
	///
	public class RSAKey {

		// MARK: Enums

		/// Denotes the type of key this represents.
		public enum KeyType {

			/// Public
			case publicType

			/// Private
			case privateType
		}

		// MARK: Properties

		/// The stored key
		internal let reference: NativeKey

		/// Represents the type of key data contained.
		public internal(set) var type: KeyType = .publicType

		// MARK: Initializers

		///
		/// Create a key using key data.
		///
		/// - Parameters:
		///		- data: 			Key data.
		///		- type:				Type of key data.
		///
		/// - Returns:				New `RSAKey` instance.
		///
		internal init(with data: Data, type: KeyType) throws {

			self.type = type

			// On macOS, we need to strip off the header...  Not so on Linux...
			#if !os(Linux)
				let data = try CryptorRSA.stripPublicKeyHeader(for: data)
			#endif
			reference = try CryptorRSA.createKey(from: data, type: type)
		}

		///
		/// Create a key using a native key.
		///
		/// - Parameters:
		///		- nativeKey:		Native key representation.
		///		- type:				Type of key.
		///
		/// - Returns:				New `RSAKey` instance.
		///
		internal init(with nativeKey: NativeKey, type: KeyType) {

			self.type = type
			self.reference = nativeKey
		}
	}

	// MARK: -

	///
	/// Public Key - Represents public key data.
	///
	public class PublicKey: RSAKey {

		/// MARK: Statics

		/// Regular expression for the PK using the begin and end markers.
		static let publicKeyRegex: NSRegularExpression? = {

			let publicKeyRegex = "(\(CryptorRSA.PK_BEGIN_MARKER).+?\(CryptorRSA.PK_END_MARKER))"
			return try? NSRegularExpression(pattern: publicKeyRegex, options: .dotMatchesLineSeparators)
		}()

		// MARK: -- Static Functions

		///
		/// Takes an input string, scans for public key sections, and then returns a Key for any valid keys found
		/// - This method scans the file for public key armor - if no keys are found, an empty array is returned
		/// - Each public key block found is "parsed" by `publicKeyFromPEMString()`
		/// - should that method throw, the error is _swallowed_ and not rethrown
		///
		/// - Parameters:
		///		- pemString: 		The string to use to parse out values
		///
		/// - Returns: 				An array of `PublicKey` objects containing just public keys.
		///
		public static func publicKeys(withPEM pemString: String) -> [PublicKey] {

			// If our regexp isn't valid, or the input string is empty, we can't move forward…
			guard let publicKeyRegexp = publicKeyRegex, pemString.characters.count > 0 else {
				return []
			}

			let all = NSRange(
				location: 0,
				length: pemString.characters.count
			)

			#if os(Linux)
				let matches = publicKeyRegexp.matches(
					in: pemString,
					options: NSMatchingOptions(rawValue: 0),
					range: all
				)
			#else
				let matches = publicKeyRegexp.matches(
					in: pemString,
					options: NSRegularExpression.MatchingOptions(rawValue: 0),
					range: all
				)
			#endif

			let keys = matches.flatMap { result -> PublicKey? in

				#if os(Linux)
					let match = result.range(at: 1)
				#else
					let match = result.rangeAt(1)
				#endif
				let start = pemString.characters.index(pemString.startIndex, offsetBy: match.location)
				let end = pemString.characters.index(start, offsetBy: match.length)

				let range = Range<String.Index>(start..<end)

				let thisKey = pemString[range]

				return try? CryptorRSA.createPublicKey(withPEM: thisKey)
			}

			return keys
		}

		// MARK: -- Initializers

		///
		/// Create a public key using key data.
		///
		/// - Parameters:
		///		- data: 			Key data
		///
		/// - Returns:				New `PublicKey` instance.
		///
		public init(with data: Data) throws {

			try super.init(with: data, type: .publicType)
		}

		///
		/// Create a key using a native key.
		///
		/// - Parameters:
		///		- nativeKey:		Native key representation.
		///
		/// - Returns:				New `PublicKey` instance.
		///
		public init(with nativeKey: NativeKey) {

			super.init(with: nativeKey, type: .publicType)
		}
	}

	// MARK: -

	///
	/// Private Key - Represents private key data.
	///
	public class PrivateKey: RSAKey {

		// MARK: -- Initializers

		///
		/// Create a private key using key data.
		///
		/// - Parameters:
		///		- data: 			Key data
		///
		/// - Returns:				New `PrivateKey` instance.
		///
		public init(with data: Data) throws {

			try super.init(with: data, type: .privateType)
		}

		///
		/// Create a key using a native key.
		///
		/// - Parameters:
		///		- nativeKey:		Native key representation.
		///
		/// - Returns:				New `PrivateKey` instance.
		///
		public init(with nativeKey: NativeKey) {

			super.init(with: nativeKey, type: .privateType)
		}
	}
}
