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

///
/// RSA Encryption/Decryption, Signing/Verification
///
@available(macOS 10.12, iOS 10.0, *)
public class CryptorRSA: RSAMessage {
	
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
	/// Initialize an RSAMessage
	///
	/// - Parameters:
	///		- data:				`Data` containing the key data.
	///		- isEncrypted:		True if *data* is encrypted, false if *data* is plaintext.
	///
	/// - Returns:				Newly initialized `CryptorRSA`.
	///
	public required init(with data: Data, isEncrypted: Bool) {
		
		self.data = data
		self.isEncrypted = isEncrypted
	}
	
	///
	/// Creates a message with a encrypted base64-encoded string.
	///
	/// - Parameters:
 	///		- base64String: 	Base64-encoded data of an encrypted message
	///
	/// - Returns:				Newly initialized `CryptorRSA`.
	///
	public convenience init(withBase64 base64String: String) throws {
		
		guard let data = Data(base64Encoded: base64String) else {
			
			throw Error(code: CryptorRSA.ERR_BASE64_PEM_DATA, reason: "Couldn't convert base 64 encoded string ")
		}
		self.init(with: data, isEncrypted: true)
	}
	
	///
	/// Creates a message from a plaintext string, with the specified encoding.
	///
	/// - Parameters:
	///   - string: 			String value of the plaintext message
	///   - encoding: 			Encoding to use to generate the clear data
	///
	/// - Returns:				Newly initialized `CryptorRSA`.
	///
	public convenience init(with string: String, using encoding: String.Encoding) throws {
		
		guard let data = string.data(using: encoding) else {
			
			throw Error(code: CryptorRSA.ERR_STRING_ENCODING, reason: "Couldn't convert string to data using specified encoding")
		}
		
		self.init(with: data, isEncrypted: false)
	}
	
	
	// MARK: -- Functions
	
	// MARK: --- Encrypt/Decrypt
	
	///
	/// Encrypt the data.
	///
	/// - Parameters:
	///		- key:				The `Key` **Note:** Must be a public key.
	///		- algorithm:		The algorithm to use (`Data.Algorithm`).
	///
	///	- Returns:				A new optional `Data` containing the encrypted data.
	///
	public func encrypted(with key: Key, algorithm: Data.Algorithm) throws -> Data? {
		
		// Must be plaintext...
		guard self.isEncrypted == false else {
			
			throw Error(code: CryptorRSA.ERR_NOT_PLAINTEXT, reason: "Data is not plaintext")
		}
		
		// Key must be public...
		guard key.isPublic else {
			
			throw Error(code: CryptorRSA.ERR_KEY_NOT_PUBLIC, reason: "Supplied key is not public")
		}
		
		var response: Unmanaged<CFError>? = nil
		let eData = SecKeyCreateEncryptedData(key.reference, algorithm.alogrithmForMessage, self.data as CFData, &response)
		if response != nil {
			
			guard let error = response?.takeRetainedValue() as? Swift.Error else {
				
				throw Error(code: CryptorRSA.ERR_ENCRYTION_FAILED, reason: "Encryption failed. Unable to determine error.")
			}
			
			throw Error(code: CryptorRSA.ERR_ENCRYTION_FAILED, reason: "Encryption failed with error: \(error)")
		}
		
		return eData as? Data
	}
	
	///
	/// Decrypt the data.
	///
	/// - Parameters:
	///		- key:				The `Key` **Note:** Must be a private key.
	///		- algorithm:		The algorithm to use (`Data.Algorithm`).
	///
	///	- Returns:				A new optional `Data` containing the decrypted data.
	///
	public func decrypted(with key: Key, algorithm: Data.Algorithm) throws -> Data? {
		
		// Must be plaintext...
		guard self.isEncrypted else {
			
			throw Error(code: CryptorRSA.ERR_NOT_ENCRYTPED, reason: "Data is plaintext")
		}
		
		// Key must be private...
		guard key.isPublic == false else {
			
			throw Error(code: CryptorRSA.ERR_KEY_NOT_PUBLIC, reason: "Supplied key is not private")
		}
		
		var response: Unmanaged<CFError>? = nil
		let pData = SecKeyCreateDecryptedData(key.reference, algorithm.alogrithmForMessage, self.data as CFData, &response)
		if response != nil {
			
			guard let error = response?.takeRetainedValue() as? Swift.Error else {
				
				throw Error(code: CryptorRSA.ERR_ENCRYTION_FAILED, reason: "Decryption failed. Unable to determine error.")
			}
			
			throw Error(code: CryptorRSA.ERR_ENCRYTION_FAILED, reason: "Decryption failed with error: \(error)")
		}
		
		return pData as? Data
	}
	

	// MARK: --- Sign/Verification
	
	///
	/// Sign the data
	///
	/// - Parameters:
	///		- key:				The `Key` **Note:** Must be a private key.
	///		- algorithm:		The algorithm to use (`Data.Algorithm`).
	///
	///	- Returns:				A new optional `Data` containing the digital signature.
	///
	public func signed(with key: Key, algorithm: Data.Algorithm) throws -> Data? {
		
		// Must be plaintext...
		guard self.isEncrypted == false else {
			
			throw Error(code: CryptorRSA.ERR_NOT_PLAINTEXT, reason: "Data is not plaintext")
		}
		
		// Key must be private...
		guard key.isPublic == false else {
			
			throw Error(code: CryptorRSA.ERR_KEY_NOT_PRIVATE, reason: "Supplied key is not private")
		}
		
		var response: Unmanaged<CFError>? = nil
		let sData = SecKeyCreateSignature(key.reference, algorithm.alogrithmForDigest, self.data as CFData, &response)
		if response != nil {
			
			guard let error = response?.takeRetainedValue() as? Swift.Error else {
				
				throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "Signing failed. Unable to determine error.")
			}
			
			throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "Signing failed with error: \(error)")
		}
		
		return sData as? Data
	}
	
	///
	/// Sign the data
	///
	/// - Parameters:
	///		- key:				The `Key` **Note:** Must be a public key.
	///		- signature:		The `Data` containing the signature to verify against.
	///		- algorithm:		The algorithm to use (`Data.Algorithm`).
	///
	///	- Returns:				True if verification is successful, false otherwise
	///
	public func verify(with key: Key, signature: Data, algorithm: Data.Algorithm) throws -> Bool {
		
		// Must be plaintext...
		guard self.isEncrypted == false else {
			
			throw Error(code: CryptorRSA.ERR_NOT_PLAINTEXT, reason: "Data is not plaintext")
		}
		
		// Key must be public...
		guard key.isPublic else {
			
			throw Error(code: CryptorRSA.ERR_KEY_NOT_PRIVATE, reason: "Supplied key is not public")
		}
		
		var response: Unmanaged<CFError>? = nil
		let result = SecKeyVerifySignature(key.reference, algorithm.alogrithmForDigest, self.data as CFData, signature as CFData, &response)
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
