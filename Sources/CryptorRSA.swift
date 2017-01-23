//
//  CryptorRSA.swift
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

import Foundation

// MARK: -

// MARK: -

///
/// RSA Encryption/Decryption, Signing/Verification
///
@available(macOS 10.12, iOS 10.0, *)
public class CryptorRSA {
	
	// MARK: Class Functions
	
	///
	/// Create a plaintext data container.
	///
	/// - Parameters:
	///		- data:				`Data` containing the key data.
	///
	/// - Returns:				Newly initialized `PlaintextData`.
	///
	public class func createPlaintext(with data: Data) -> PlaintextData {
		
		return PlaintextData(with: data)
	}
	
	///
	/// Creates a message from a plaintext string, with the specified encoding.
	///
	/// - Parameters:
	///   - string: 			String value of the plaintext message
	///   - encoding: 			Encoding to use to generate the clear data
	///
	/// - Returns:				Newly initialized `PlaintextData`.
	///
	public class func createPlaintext(with string: String, using encoding: String.Encoding) throws -> PlaintextData {
		
		return try PlaintextData(with: string, using: encoding)
	}
	
	///
	/// Create an encrypted data container.
	///
	/// - Parameters:
	///		- data:				`Data` containing the encrypted data.
	///
	/// - Returns:				Newly initialized `EncryptedData`.
	///
	public class func createEncrypted(with data: Data) -> EncryptedData {
		
		return EncryptedData(with: data)
	}
	
	///
	/// Creates a message with a encrypted base64-encoded string.
	///
	/// - Parameters:
	///		- base64String: 	Base64-encoded data of an encrypted message
	///
	/// - Returns:				Newly initialized `EncryptedData`.
	///
	public class func createEncrypted(with base64String: String) throws -> EncryptedData {
		
		return try EncryptedData(withBase64: base64String)
	}
	
	///
	/// Create an signed data container.
	///
	/// - Parameters:
	///		- data:				`Data` containing the signed data.
	///
	/// - Returns:				Newly initialized `SignedData`.
	///
	public class func createSigned(with data: Data) -> SignedData {
		
		return SignedData(with: data)
	}
	
	///
	/// RSA Data Object: Allows for RSA Encryption/Decryption, Signing/Verification and various utility functions.
	///
	public class RSAData {
		
		// MARK: -- Properties
		
		/// Data of the message
		public let data: Data
		
		/// True if constructed with encrypted data
		public internal(set) var isEncrypted: Bool = false
		
		/// Base64-encoded string of the message data
		public var base64String: String {
			
			return data.base64EncodedString()
		}

		// MARK: -- Initializers
		
		///
		/// Initialize a new RSAData object.
		///
		/// - Parameters:
		///		- data:				`Data` containing the data.
		///		- isEncrypted:		True if *data* is encrypted, false if *data* is plaintext.
		///
		/// - Returns:				Newly initialized `RSAData`.
		///
		internal init(with data: Data, isEncrypted: Bool) {
			
			self.data = data
			self.isEncrypted = isEncrypted
		}
		
		///
		/// Creates a RSAData with a encrypted base64-encoded string.
		///
		/// - Parameters:
	 	///		- base64String: 	Base64-encoded data of an encrypted message
		///
		/// - Returns:				Newly initialized `RSAData`.
		///
		internal init(withBase64 base64String: String) throws {
			
			guard let data = Data(base64Encoded: base64String) else {
				
				throw Error(code: CryptorRSA.ERR_BASE64_PEM_DATA, reason: "Couldn't convert base 64 encoded string ")
			}
			
			self.data = data
			self.isEncrypted = true
		}
		
		///
		/// Creates a message from a plaintext string, with the specified encoding.
		///
		/// - Parameters:
		///   - string: 			String value of the plaintext message
		///   - encoding: 			Encoding to use to generate the clear data
		///
		/// - Returns:				Newly initialized `RSAData`.
		///
		internal init(with string: String, using encoding: String.Encoding) throws {
			
			guard let data = string.data(using: encoding) else {
				
				throw Error(code: CryptorRSA.ERR_STRING_ENCODING, reason: "Couldn't convert string to data using specified encoding")
			}
			
			self.data = data
			self.isEncrypted = false
		}
		
		
		// MARK: -- Functions
		
		// MARK: --- Encrypt/Decrypt
		
		///
		/// Encrypt the data.
		///
		/// - Parameters:
		///		- key:				The `PublicKey`
		///		- algorithm:		The algorithm to use (`Data.Algorithm`).
		///
		///	- Returns:				A new optional `EncryptedData` containing the encrypted data.
		///
		public func encrypted(with key: PublicKey, algorithm: Data.Algorithm) throws ->EncryptedData? {
			
			// Must be plaintext...
			guard self.isEncrypted == false else {
				
				throw Error(code: CryptorRSA.ERR_NOT_PLAINTEXT, reason: "Data is not plaintext")
			}
			
			// Key must be public...
			guard key.isPublic else {
				
				throw Error(code: CryptorRSA.ERR_KEY_NOT_PUBLIC, reason: "Supplied key is not public")
			}
			
			var response: Unmanaged<CFError>? = nil
			let eData = SecKeyCreateEncryptedData(key.reference, algorithm.alogrithmForEncryption, self.data as CFData, &response)
			if response != nil {
				
				guard let error = response?.takeRetainedValue() as? Swift.Error else {
					
					throw Error(code: CryptorRSA.ERR_ENCRYPTION_FAILED, reason: "Encryption failed. Unable to determine error.")
				}
				
				throw Error(code: CryptorRSA.ERR_ENCRYPTION_FAILED, reason: "Encryption failed with error: \(error)")
			}
			
			return EncryptedData(with: eData as! Data)
		}
		
		///
		/// Decrypt the data.
		///
		/// - Parameters:
		///		- key:				The `PrivateKey`
		///		- algorithm:		The algorithm to use (`Data.Algorithm`).
		///
		///	- Returns:				A new optional `PlaintextData` containing the decrypted data.
		///
		public func decrypted(with key: PrivateKey, algorithm: Data.Algorithm) throws -> PlaintextData? {
			
			// Must be plaintext...
			guard self.isEncrypted else {
				
				throw Error(code: CryptorRSA.ERR_NOT_ENCRYPTED, reason: "Data is plaintext")
			}
			
			// Key must be private...
			guard key.isPublic == false else {
				
				throw Error(code: CryptorRSA.ERR_KEY_NOT_PUBLIC, reason: "Supplied key is not private")
			}
			
			var response: Unmanaged<CFError>? = nil
			let pData = SecKeyCreateDecryptedData(key.reference, algorithm.alogrithmForEncryption, self.data as CFData, &response)
			if response != nil {
				
				guard let error = response?.takeRetainedValue() as? Swift.Error else {
					
					throw Error(code: CryptorRSA.ERR_DECRYPTION_FAILED, reason: "Decryption failed. Unable to determine error.")
				}
				
				throw Error(code: CryptorRSA.ERR_DECRYPTION_FAILED, reason: "Decryption failed with error: \(error)")
			}
			
			return PlaintextData(with: pData as! Data)
		}
		
		
		// MARK: --- Sign/Verification
		
		///
		/// Sign the data
		///
		/// - Parameters:
		///		- key:				The `PrivateKey`.
		///		- algorithm:		The algorithm to use (`Data.Algorithm`).
		///
		///	- Returns:				A new optional `SignedData` containing the digital signature.
		///
		public func signed(with key: PrivateKey, algorithm: Data.Algorithm) throws -> SignedData? {
			
			// Must be plaintext...
			guard self.isEncrypted == false else {
				
				throw Error(code: CryptorRSA.ERR_NOT_PLAINTEXT, reason: "Data is not plaintext")
			}
			
			// Key must be private...
			guard key.isPublic == false else {
				
				throw Error(code: CryptorRSA.ERR_KEY_NOT_PRIVATE, reason: "Supplied key is not private")
			}
			
			var response: Unmanaged<CFError>? = nil
			let sData = SecKeyCreateSignature(key.reference, algorithm.alogrithmForSignature, self.data as CFData, &response)
			if response != nil {
				
				guard let error = response?.takeRetainedValue() as? Swift.Error else {
					
					throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "Signing failed. Unable to determine error.")
				}
				
				throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "Signing failed with error: \(error)")
			}
			
			return SignedData(with: sData as! Data)
		}
		
		///
		/// Verify the signature
		///
		/// - Parameters:
		///		- key:				The `PublicKey`.
		///		- signature:		The `Data` containing the signature to verify against.
		///		- algorithm:		The algorithm to use (`Data.Algorithm`).
		///
		///	- Returns:				True if verification is successful, false otherwise
		///
		public func verify(with key: PublicKey, signature: Data, algorithm: Data.Algorithm) throws -> Bool {
			
			// Must be plaintext...
			guard self.isEncrypted == false else {
				
				throw Error(code: CryptorRSA.ERR_NOT_PLAINTEXT, reason: "Data is not plaintext")
			}
			
			// Key must be public...
			guard key.isPublic else {
				
				throw Error(code: CryptorRSA.ERR_KEY_NOT_PRIVATE, reason: "Supplied key is not public")
			}
			
			var response: Unmanaged<CFError>? = nil
			let result = SecKeyVerifySignature(key.reference, algorithm.alogrithmForSignature, self.data as CFData, signature as CFData, &response)
			if response != nil {
				
				guard let error = response?.takeRetainedValue() as? Swift.Error else {
					
					throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "Verification failed. Unable to determine error.")
				}
				
				throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "Verification failed with error: \(error)")
			}
			
			return result
		}
		
		// MARK: --- Utility
		
		///
		/// Retrieve a digest of the data using the specified algorithm.
		///
		/// - Parameters:
		///		- algorithm:		Algoririthm to use.
 		///
		///	- Returns:				`Data` containing the digest.
		///
		public func digest(using algorithm: Data.Algorithm) throws -> Data {
			
			return try self.data.digest(using: algorithm)
		}
		
		///
		/// String representation of message in specified string encoding.
		///
		/// - Parameters:
	 	///		- encoding: 		Encoding to use during the string conversion
		///
		/// - Returns: 				String representation of the message
		///
		public func string(using encoding: String.Encoding) throws -> String {
			
			guard let str = String(data: data, encoding: encoding) else {
				
				throw Error(code: CryptorRSA.ERR_STRING_ENCODING, reason: "Couldn't convert data to string representation")
			}
			
			return str
		}
		
	}
	
	// MARK: -
	
	public class PlaintextData: RSAData {
		
		// MARK: Initializers
		
		///
		/// Initialize a new PlaintextData object.
		///
		/// - Parameters:
		///		- data:				`Data` containing the data.
		///
		/// - Returns:				Newly initialized `PlaintextData`.
		///
		internal init(with data: Data) {

			super.init(with: data, isEncrypted: false)
		}
		
		///
		/// Creates a message from a plaintext string, with the specified encoding.
		///
		/// - Parameters:
		///   - string: 			String value of the plaintext message
		///   - encoding: 			Encoding to use to generate the clear data
		///
		/// - Returns:				Newly initialized `RSAData`.
		///
		internal override init(with string: String, using encoding: String.Encoding) throws {
		
			try super.init(with: string, using: encoding)
		}
	}
	
	// MARK: -
	
	public class EncryptedData: RSAData {
		
		// MARK: Initializers
		
		///
		/// Initialize a new EncryptedData object.
		///
		/// - Parameters:
		///		- data:				`Data` containing the data.
		///
		/// - Returns:				Newly initialized EncryptedData`.
		///
		internal init(with data: Data) {
			
			super.init(with: data, isEncrypted: true)
		}
		
		///
		/// Creates a RSAData with a encrypted base64-encoded string.
		///
		/// - Parameters:
		///		- base64String: 	Base64-encoded data of an encrypted message
		///
		/// - Returns:				Newly initialized `RSAData`.
		///
		internal override init(withBase64 base64String: String) throws {
		
			try super.init(withBase64: base64String)
		}
	}
	
	// MARK: -
	
	public class SignedData: RSAData {
		
		// MARK: -- Initializers
		
		///
		/// Initialize a new SignedData object.
		///
		/// - Parameters:
		///		- data:				`Data` containing the data.
		///
		/// - Returns:				Newly initialized `SignedData`.
		///
		internal init(with data: Data) {
			
			super.init(with: data, isEncrypted: true)
		}
		
	}
	
}
