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

import Foundation

public extension CryptorRSA {
	
	/// MARK: -
	
	///
	/// Public Key Handling
	///
	public class PublicKey: RSAKey {
		
		/// MARK: Statics
		
		/// Regular expression for the PK using the begin and end markers.
		static let publicKeyRegex: NSRegularExpression? = {
			let publicKeyRegex = "(\(CryptorRSA.PK_BEGIN_MARKER).+?\(CryptorRSA.PK_END_MARKER)"
			return try? NSRegularExpression(pattern: publicKeyRegex, options: .dotMatchesLineSeparators)
		}()
		
		// MARK: Properties
		
		let reference: SecKey
		let tag: String
		
		// MARK: Static Functions
		
		///
		/// Takes an input string, scans for public key sections, and then returns a PublicKey for any valid keys found
		/// - This method scans the file for public key armor - if no keys are found, an empty array is returned
		/// - Each public key block found is "parsed" by `publicKeyFromPEMString()`
		/// - should that method throw, the error is _swallowed_ and not rethrown
		///
		/// - Parameters:
		///		- pemString: 		The string to use to parse out values
		///
		/// - Returns: 				An array of `PublicKey` objects
		///
		public static func publicKeys(pemEncoded pemString: String) -> [PublicKey] {
			
			// If our regexp isn't valid, or the input string is empty, we can't move forward…
			guard let publicKeyRegexp = publicKeyRegex, pemString.characters.count > 0 else {
				return []
			}
			
			let all = NSRange(
				location: 0,
				length: pemString.characters.count
			)
			
			let matches = publicKeyRegexp.matches(
				in: pemString,
				options: NSRegularExpression.MatchingOptions(rawValue: 0),
				range: all
			)
			
			let keys = matches.flatMap { result -> PublicKey? in
				let match = result.rangeAt(1)
				let start = pemString.characters.index(pemString.startIndex, offsetBy: match.location)
				let end = pemString.characters.index(start, offsetBy: match.length)
				
				let range = Range<String.Index>(start..<end)
				
				let thisKey = pemString[range]
				
				return try? PublicKey(withPEM: thisKey)
			}
			
			return keys
		}
		
		// MARK: Initializers
		
		///
		/// Creates a public with a RSA public key data.
		///
		/// - Parameters:
		///		- data: 			Public key data
		///
		/// - Returns:				New `PublicKey` instance.
		///
		required public init(with data: Data) throws {
			
			tag = UUID().uuidString
			let data = try CryptorRSA.stripPublicKeyHeader(for: data)
			reference = try CryptorRSA.addKey(using: data, isPublic: true, taggedWith: tag)
		}
		
		///
		/// Creates a public key with a base64-encoded string.
		///
		/// - Parameters:
		///		- base64String: 	Base64-encoded public key data
		///
		/// - Returns:				New `PublicKey` instance.
		///
		public convenience init(withBase64 base64String: String) throws {
			
			guard let data = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {
				
				throw CryptorRSA.Error(code: CryptorRSA.ERR_INIT_PK, reason: "Couldn't decode base 64 string")
			}
			
			try self.init(with: data)
		}
		
		///
		/// Creates a public key with a PEM string.
		///
		/// - Parameters:
		///		- pemString: 		PEM-encoded public key string
		///
		/// - Returns:				New `PublicKey` instance.
		///
		public convenience init(withPEM pemString: String) throws {
			
			let base64String = try CryptorRSA.base64String(for: pemString)
			
			try self.init(withBase64: base64String)
		}
		
		///
		/// Creates a public key with a PEM file.
		///
		/// - Parameters:
		///   - pemName: 			Name of the PEM file
		///   - bundle: 			Bundle in which to look for the PEM file. Defaults to the main bundle.
		///
		/// - Returns:				New `PublicKey` instance.
		///
		public convenience init(withPEMNamed pemName: String, in bundle: Bundle = Bundle.main) throws {
			
			guard let path = bundle.path(forResource: pemName, ofType: "pem") else {
				
				throw CryptorRSA.Error(code: CryptorRSA.ERR_INIT_PK, reason: "Couldn't find a PEM file named '\(pemName)'")
			}
			
			let keyString = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
			
			try self.init(withPEM: keyString)
		}
		
		///
		/// Creates a private key with a DER file.
		///
		/// - Parameters:
		///   - derName: 			Name of the DER file
		///   - bundle: 			Bundle in which to look for the DER file. Defaults to the main bundle.
		///
		/// - Returns:				New `PublicKey` instance.
		///
		public convenience init(withDERNamed derName: String, in bundle: Bundle = Bundle.main) throws {
			
			guard let path = bundle.path(forResource: derName, ofType: "der") else {
				
				throw CryptorRSA.Error(code: CryptorRSA.ERR_INIT_PK, reason: "Couldn't find a DER file named '\(derName)'")
			}
			let data = try Data(contentsOf: URL(fileURLWithPath: path))
			try self.init(with: data)
		}

		///
		/// Deinitialize
		///
		deinit {
			try! CryptorRSA.removeKey(with: tag)
		}
		
	}
	
	/// MARK: -
	
	///
	/// Private Key Handling
	///
	public class PrivateKey: NSObject, RSAKey {
		
		// MARK: Properties
		
		let reference: SecKey
		let tag: String
		
		// MARK: Initializers
		
		///
		/// Creates a private key with a RSA public key data.
		///
		/// - Parameters:
		///		- data:		 		Private key data
		///
		/// - Returns:				New `PrivateKey` instance.
		///
		required public init(with data: Data) throws {
			
			tag = UUID().uuidString
			
			reference = try CryptorRSA.addKey(using: data, isPublic: false, taggedWith: tag)
		}
		
		///
		/// Creates a private key with a base64-encoded string.
		///
		/// - Parameters:
		///		- base64String: 	Base64-encoded private key data
		///
		/// - Returns:				New `PrivateKey` instance.
		///
		public convenience init(withBase64 base64String: String) throws {
			
			guard let data = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {
				
				throw CryptorRSA.Error(code: CryptorRSA.ERR_INIT_PK, reason: "Couldn't decode base 64 string")
			}
			
			try self.init(with: data)
		}
		
		///
		/// Creates a private key with a PEM string.
		///
		/// - Parameters:
		///		- pemString: 		PEM-encoded private key string
		///
		/// - Returns:				New `PrivateKey` instance.
		///
		public convenience init(withPEM pemString: String) throws {
			
			let base64String = try CryptorRSA.base64String(for: pemString)
			
			try self.init(withBase64: base64String)
		}
		
		///
		/// Creates a private key with a PEM file.
		///
		/// - Parameters:
		///   - pemName: 			Name of the PEM file
		///   - bundle: 			Bundle in which to look for the PEM file. Defaults to the main bundle.
		///
		/// - Returns:				New `PrivateKey` instance.
		///
		public convenience init(withPEMNamed pemName: String, in bundle: Bundle = Bundle.main) throws {
			
			guard let path = bundle.path(forResource: pemName, ofType: "pem") else {
				
				throw CryptorRSA.Error(code: CryptorRSA.ERR_INIT_PK, reason: "Couldn't find a PEM file named '\(pemName)'")
			}
			
			let keyString = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
			
			try self.init(withPEM: keyString)
		}
		
		///
		/// Creates a private key with a DER file.
		///
		/// - Parameters:
		///   - derName: 			Name of the DER file
		///   - bundle: 			Bundle in which to look for the DER file. Defaults to the main bundle.
		///
		/// - Returns:				New `PrivateKey` instance.
		///
		public convenience init(withDERNamed derName: String, in bundle: Bundle = Bundle.main) throws {
			
			guard let path = bundle.path(forResource: derName, ofType: "der") else {
				
				throw CryptorRSA.Error(code: CryptorRSA.ERR_INIT_PK, reason: "Couldn't find a DER file named '\(derName)'")
			}
			
			let data = try Data(contentsOf: URL(fileURLWithPath: path))
			try self.init(with: data)
		}
		
		///
		/// Deinitialize
		///
		deinit {
			
			try! CryptorRSA.removeKey(with: tag)
		}
	}

}
