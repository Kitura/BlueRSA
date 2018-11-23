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
	
		#if swift(>=4.2)
	
			typealias NativeKey = OpaquePointer?
	
		#else
	
			typealias NativeKey = UnsafeMutablePointer<RSA>
	
		#endif
	
	#else
	
		typealias NativeKey = SecKey
	
	#endif
	
	// MARK: Class Functions
	
	// MARK: -- Public Key Creation
	
	///
	/// Creates a public key with DER data.
	///
	/// - Parameters:
	///		- data: 			Key data
	///
	/// - Returns:				New `PublicKey` instance.
	///
	public class func createPublicKey(with data: Data) throws -> PublicKey {
		
		#if os(Linux)
		
			let data = CryptorRSA.convertDerToPem(from: data, type: .publicType)
		
		#endif
		
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
		
		#if !os(Linux)
		
			// Extact the data as a base64 string...
			let str = String(data: data, encoding: .utf8)
			guard let tmp = str else {
				
				throw Error(code: ERR_CREATE_CERT_FAILED, reason: "Unable to create certificate from certificate data, incorrect format.")
			}
		
			// Get the Base64 representation of the PEM encoded string after stripping off the PEM markers...
			let base64 = try CryptorRSA.base64String(for: tmp)
			let data = Data(base64Encoded: base64)!
		
		#endif
		
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
		
		guard var data = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {
			
			throw Error(code: ERR_INIT_PK, reason: "Couldn't decode base64 string")
		}
		
		#if os(Linux)
		
			// OpenSSL uses the PEM version when importing key...
			data = CryptorRSA.convertDerToPem(from: data, type: .publicType)
		
		#endif
		
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
		
		#if os(Linux)
		
			// OpenSSL takes the full PEM format...
			let keyData = pemString.data(using: String.Encoding.utf8)!
		
			return try PublicKey(with: keyData)
		
		#else
		
			// Get the Base64 representation of the PEM encoded string after stripping off the PEM markers
			let base64String = try CryptorRSA.base64String(for: pemString)
		
			return try createPublicKey(withBase64: base64String)
		
		#endif
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
		
		var certName = pemName
		if !pemName.hasSuffix(PEM_SUFFIX) {
			
			certName = pemName.appending(PEM_SUFFIX)
		}
		
		let fullPath = URL(fileURLWithPath: #file).appendingPathComponent( path.appending(certName) ).standardized
		
		let keyString = try String(contentsOf: fullPath, encoding: .utf8)
		
		return try createPublicKey(withPEM: keyString)
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
		
		var certName = derName
		if !derName.hasSuffix(DER_SUFFIX) {
			
			certName = derName.appending(DER_SUFFIX)
		}
		
		let fullPath = URL(fileURLWithPath: #file).appendingPathComponent( path.appending(certName) ).standardized
		
		let dataIn = try Data(contentsOf: fullPath)
		
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
		
		var certNameFull = certName
		if !certName.hasSuffix(CER_SUFFIX) {
			
			certNameFull = certName.appending(CER_SUFFIX)
		}
		
		let fullPath = URL(fileURLWithPath: #file).appendingPathComponent( path.appending(certNameFull) ).standardized
		
		// Import the data from the file...
		#if os(Linux)
		
			// In OpenSSL, we can just get the data and don't have to worry about stripping off headers etc.
			let data = try Data(contentsOf: fullPath)
		
		#else
		
			// Get the Base64 representation of the PEM encoded string after stripping off the PEM markers...
			let tmp = try String(contentsOf: fullPath, encoding: .utf8)
			let base64 = try CryptorRSA.base64String(for: tmp)
			let data = Data(base64Encoded: base64)!
		
		#endif
		
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
	/// Creates a public key by extracting it from certificate data.
	///
	/// - Parameters:
	/// 	- data:				`Data` representing the certificate.
	///
	/// - Returns:				New `PublicKey` instance.
	///
	internal class func createPublicKey(data: Data) throws -> PublicKey {
		
		#if os(Linux)
		
			let certbio = BIO_new(BIO_s_mem())
			defer {
				BIO_free(certbio)
			}
		
			// Move the key data to BIO
			try data.withUnsafeBytes() { (buffer: UnsafePointer<UInt8>) in
				
				let len = BIO_write(certbio, buffer, Int32(data.count))
				guard len != 0 else {
					let source = "Couldn't create BIO reference from key data"
					if let reason = CryptorRSA.getLastError(source: source) {
						
						throw Error(code: ERR_ADD_KEY, reason: reason)
					}
					throw Error(code: ERR_ADD_KEY, reason: source + ": No OpenSSL error reported.")
				}
				
				// The below is equivalent of BIO_flush...
				BIO_ctrl(certbio, BIO_CTRL_FLUSH, 0, nil)
			}
			let cert = PEM_read_bio_X509(certbio, nil, nil, nil)
		
			if cert == nil {
				print("Error loading cert into memory\n")
				throw Error(code: ERR_CREATE_CERT_FAILED, reason: "Error loading cert into memory.")
			}
		
			// Extract the certificate's public key data.
			let evp_key = X509_get_pubkey(cert)
			if evp_key == nil {
				throw Error(code: ERR_CREATE_CERT_FAILED, reason: "Error getting public key from certificate")
			}
		
			let key = EVP_PKEY_get1_RSA( evp_key)
			if key == nil {
				throw Error(code: ERR_CREATE_CERT_FAILED, reason: "Error getting public key from certificate")
			}
			defer {
				//	RSA_free(key)
				EVP_PKEY_free(evp_key)
			}
		
			#if swift(>=4.1)
				return PublicKey(with: .make(optional: key!)!)
			#else
				return PublicKey(with: key!)
			#endif
	
		#else
		
			// Create a DER-encoded X.509 certificate object from the DER data...
			let certificateData = SecCertificateCreateWithData(nil, data as CFData)
			guard let certData = certificateData else {
				
				throw Error(code: ERR_CREATE_CERT_FAILED, reason: "Unable to create certificate from certificate data.")
			}
		
			#if os(macOS)
		
				// Now extract the public key from it...
				var key: SecKey? = nil
				let status: OSStatus = withUnsafeMutablePointer(to: &key) { ptr in
					
					// Retrieves the public key from a certificate...
					SecCertificateCopyPublicKey(certData, UnsafeMutablePointer(ptr))
				}
				if status != errSecSuccess || key == nil {
					
					throw Error(code: ERR_EXTRACT_PUBLIC_KEY_FAILED, reason: "Unable to extract public key from data.")
				}
		
			#else
		
				let key = SecCertificateCopyPublicKey(certData)
		
			#endif
		
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
		
		#if os(Linux)
		
			// OpenSSL takes the full PEM format...
			let keyData = pemString.data(using: String.Encoding.utf8)!
		
			return try PrivateKey(with: keyData)
		
		#else
		
			// SecKey needs the PEM format stripped of the header info and converted to base64...
			let base64String = try CryptorRSA.base64String(for: pemString)
		
			return try CryptorRSA.createPrivateKey(withBase64: base64String)
		
		#endif
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
		
		var certName = pemName
		if !pemName.hasSuffix(PEM_SUFFIX) {
			
			certName = pemName.appending(PEM_SUFFIX)
		}
		let fullPath = URL(fileURLWithPath: #file).appendingPathComponent( path.appending(certName) ).standardized
		
		let keyString = try String(contentsOf: fullPath, encoding: .utf8)
		
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
		
		var certName = derName
		if !derName.hasSuffix(DER_SUFFIX) {
			
			certName = derName.appending(DER_SUFFIX)
		}
		let fullPath = URL(fileURLWithPath: #file).appendingPathComponent( path.appending(certName) ).standardized
		
		let dataIn = try Data(contentsOf: fullPath)
		
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
		/// Create a key using key data (in DER format).
		///
		/// - Parameters:
		///		- data: 			Key data.
		///		- type:				Type of key data.
		///
		/// - Returns:				New `RSAKey` instance.
		///
		internal init(with data: Data, type: KeyType) throws {
			
			self.type = type
			
			// On macOS, we need to strip off the X509 header if it exists...
			#if !os(Linux)
			
				let data = try CryptorRSA.stripX509CertificateHeader(for: data)
			
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
			guard let publicKeyRegexp = publicKeyRegex, pemString.count > 0 else {
				return []
			}
			
			let all = NSRange(
				location: 0,
				length: pemString.count
			)
			
			let matches = publicKeyRegexp.matches(
				in: pemString,
				options: NSRegularExpression.MatchingOptions(rawValue: 0),
				range: all
			)
			
			#if swift(>=4.1)
			
				let keys = matches.compactMap { result -> PublicKey? in
				
					let match = result.range(at: 1)
					let start = pemString.index(pemString.startIndex, offsetBy: match.location)
					let end = pemString.index(start, offsetBy: match.length)
					
					let range = start..<end
					
					let thisKey = pemString[range]
					
					return try? CryptorRSA.createPublicKey(withPEM: String(thisKey))
				}
			
			#else
			
				let keys = matches.flatMap { result -> PublicKey? in
			
					let match = result.range(at: 1)
					let start = pemString.index(pemString.startIndex, offsetBy: match.location)
					let end = pemString.index(start, offsetBy: match.length)
			
					let range = start..<end
			
					let thisKey = pemString[range]
			
					return try? CryptorRSA.createPublicKey(withPEM: String(thisKey))
				}
			
			#endif
			
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
