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
#if os(Linux)
import OpenSSL
#endif

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

		// MARK: Enums

		/// Denotes the type of data this represents.
		public enum DataType {

			/// Plaintext
			case plaintextType

			/// Encrypted
			case encryptedType

			/// Signed
			case signedType
		}

		// MARK: -- Properties

		/// Data of the message
		public let data: Data

		/// Represents the type of data contained.
		public internal(set) var type: DataType = .plaintextType

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
		///		- type:				Type of data contained.
		///
		/// - Returns:				Newly initialized `RSAData`.
		///
		internal init(with data: Data, type: DataType) {

			self.data = data
			self.type = type
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
			self.type = .encryptedType
		}

		///
		/// Creates a message from a plain text string, with the specified encoding.
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
			self.type = .plaintextType
            
            print("Finished creating data from plain text")
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
		public func encrypted(with key: PublicKey, algorithm: Data.Algorithm) throws -> EncryptedData? {
            // References:
            //http://openssl.6102.n7.nabble.com/How-to-encrypt-a-large-file-by-a-public-key-td2906.html
            //https://unix.stackexchange.com/questions/12260/how-to-encrypt-messages-text-with-rsa-openssl
            //https://stackoverflow.com/questions/22373305/rsa-public-key-encryption-openssl
            
            //It seems that SHA1 is the only algorithm supported in OpenSSL for encryption...
            //Makes me wonder if we should change this API... and/or just use OpenSSL on both platforms?

			// Must be plaintext...
			guard self.type == .plaintextType else {
				throw Error(code: CryptorRSA.ERR_NOT_PLAINTEXT, reason: "Data is not plaintext")
			}

			// Key must be public...
			guard key.type == .publicType else {
				throw Error(code: CryptorRSA.ERR_KEY_NOT_PUBLIC, reason: "Supplied key is not public")
			}

			#if os(Linux)
				let encrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(RSA_size(key.reference)))
				defer {
                    encrypted.deallocate(capacity: Int(RSA_size(key.reference)))
				}
                // Int(RSA_size(key.reference)) -> 128
                
				guard let text = String(data: self.data, encoding: .utf8) else {
					throw Error(code: CryptorRSA.ERR_ENCRYPTION_FAILED, reason: "Failed to create plain text string from Data object")
				}
                
                let encryptedDataLength = RSA_public_encrypt(Int32(text.utf8.count), text, encrypted, key.reference, RSA_PKCS1_OAEP_PADDING)
                if encryptedDataLength == -1 {
                    throw Error(code: CryptorRSA.ERR_ENCRYPTION_FAILED, reason: "Failed to encrypt plain text")
                }
                
                let data = Data(UnsafeBufferPointer(start: encrypted, count: Int(encryptedDataLength)))
                return EncryptedData(with: data)

			#else

				var response: Unmanaged<CFError>? = nil
                guard let eData = SecKeyCreateEncryptedData(key.reference, algorithm.alogrithmForEncryption, self.data as CFData, &response) else {
                    throw Error(code: CryptorRSA.ERR_ENCRYPTION_FAILED, reason: "Encryption failed")
                }
                    
				if response != nil {
					guard let error = response?.takeRetainedValue() else {
						throw Error(code: CryptorRSA.ERR_ENCRYPTION_FAILED, reason: "Encryption failed. Unable to determine error.")
					}

					throw Error(code: CryptorRSA.ERR_ENCRYPTION_FAILED, reason: "Encryption failed with error: \(error)")
                }

				return EncryptedData(with: eData as Data)

			#endif
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

			// Must be encrypted...
			guard self.type == .encryptedType else {
				throw Error(code: CryptorRSA.ERR_NOT_ENCRYPTED, reason: "Data is plaintext")
			}

			// Key must be private...
			guard key.type == .privateType else {
				throw Error(code: CryptorRSA.ERR_KEY_NOT_PUBLIC, reason: "Supplied key is not private")
			}

			#if os(Linux)

			let decrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(self.data.count))
			defer {
				decrypted.deallocate(capacity: Int(self.data.count))
			}
                
            let decryptedDataLength = self.data.withUnsafeBytes { (u8Ptr: UnsafePointer<UInt8>) -> Int in
                let length = RSA_private_decrypt(Int32(self.data.count), u8Ptr, decrypted, key.reference, RSA_PKCS1_OAEP_PADDING)
                // It looks like we must null terminate the string...
                decrypted[Int(length)] = 0
                return Int(length)
            }

            if decryptedDataLength == -1 {
                throw Error(code: CryptorRSA.ERR_DECRYPTION_FAILED, reason: "RSA failed to decrypt data")
            }
                
            let decryptedStr = String(cString: UnsafePointer(decrypted))

			guard let data = decryptedStr.data(using: .utf8) else {
                throw Error(code: CryptorRSA.ERR_DECRYPTION_FAILED, reason: "Failed to generate Data object from decrypted text")
            }

            return PlaintextData(with: data)

			#else

				var response: Unmanaged<CFError>? = nil
                guard let pData = SecKeyCreateDecryptedData(key.reference, algorithm.alogrithmForEncryption, self.data as CFData, &response) else {
                    throw Error(code: CryptorRSA.ERR_DECRYPTION_FAILED, reason: "Decryption failed")
                }
                
				if response != nil {
					guard let error = response?.takeRetainedValue() else {
						throw Error(code: CryptorRSA.ERR_DECRYPTION_FAILED, reason: "Decryption failed. Unable to determine error.")
					}

					throw Error(code: CryptorRSA.ERR_DECRYPTION_FAILED, reason: "Decryption failed with error: \(error)")
				}

				return PlaintextData(with: pData as Data)

			#endif
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
			guard self.type == .plaintextType else {
				throw Error(code: CryptorRSA.ERR_NOT_PLAINTEXT, reason: "Data is not plaintext")
			}

			// Key must be private...
			guard key.type == .privateType else {
				throw Error(code: CryptorRSA.ERR_KEY_NOT_PRIVATE, reason: "Supplied key is not private")
			}

			#if os(Linux)
                // References
                //https://eclipsesource.com/blogs/2016/09/07/tutorial-code-signing-and-verification-with-openssl/
                //https://wiki.openssl.org/index.php/Manual:EVP_DigestInit(3)
                //https://wiki.openssl.org/index.php/EVP_Message_Digests???
                //https://www.raywenderlich.com/148569/unsafe-swift
                //https://stackoverflow.com/questions/42868241/how-to-construct-data-nsdata-from-unsafemutablepointert

                let signingCtx = EVP_MD_CTX_create()
                let evpPrivateKey = EVP_PKEY_new()
                
                // Release created memory
                defer {
                    EVP_PKEY_free(evpPrivateKey)
                    EVP_MD_CTX_destroy(signingCtx)
                }
                
                // For some reasone, EVP_PKEY_assign_RSA() is not defined...
                //EVP_PKEY_assign_RSA(evpPrivateKey, key.reference)
                EVP_PKEY_set1_RSA(evpPrivateKey, key.reference)
                
                //TODO: use specified algorithm
                if EVP_DigestSignInit(signingCtx, nil, algorithm.algorithmForSignature(), nil, evpPrivateKey) != 1 {
                    throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "EVP_DigestSignInit() failed")
                }
                
                // For some reason, EVP_DigestSignUpdate() is not defined...
                // Instead, using EVP_DigestUpdate()
                let digestUpdateResult = self.data.withUnsafeBytes { (u8Ptr: UnsafePointer<UInt8>) -> Int in
                    return Int(EVP_DigestUpdate(signingCtx, u8Ptr, self.data.count))
                }
                
                if digestUpdateResult != 1 {
                    throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "EVP_DigestUpdate() failed")
                }
                
                let encMessageLength = UnsafeMutablePointer<Int>.allocate(capacity: 1)
                encMessageLength.initialize(to: 0, count: 1)
                defer {
                    encMessageLength.deinitialize(count: 1)
                    encMessageLength.deallocate(capacity: 1)
                }
                    
                if EVP_DigestSignFinal(signingCtx, nil, encMessageLength) != 1 {
                    throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "EVP_DigestSignFinal() failed")
                }
                
                let encMsg = UnsafeMutablePointer<UInt8>.allocate(capacity: encMessageLength.pointee)
                defer {
                    encMsg.deinitialize(count: encMessageLength.pointee)
                    encMsg.deallocate(capacity: encMessageLength.pointee)
                }
                
                if EVP_DigestSignFinal(signingCtx, encMsg, encMessageLength) != 1 {
                     throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "EVP_DigestSignFinal() failed")
                }
                
                let signedData = Data(UnsafeBufferPointer(start: encMsg, count: encMessageLength.pointee))
                return SignedData(with: signedData)

			#else

				var response: Unmanaged<CFError>? = nil
				let sData = SecKeyCreateSignature(key.reference, algorithm.algorithmForSignature, self.data as CFData, &response)
				if response != nil {
					guard let error = response?.takeRetainedValue() else {
						throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "Signing failed. Unable to determine error.")
					}
					throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "Signing failed with error: \(error)")
				}

				return SignedData(with: sData! as Data)

			#endif
		}

		///
		/// Verify the signature
		///
		/// - Parameters:
		///		- key:				The `PublicKey`.
		///		- signature:		The `SignedData` containing the signature to verify against.
		///		- algorithm:		The algorithm to use (`Data.Algorithm`).
		///
		///	- Returns:				True if verification is successful, false otherwise
		///
		public func verify(with key: PublicKey, signature: SignedData, algorithm: Data.Algorithm) throws -> Bool {
            // https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
            
			// Must be plaintext...
			guard self.type == .plaintextType else {
				throw Error(code: CryptorRSA.ERR_NOT_PLAINTEXT, reason: "Data is not plaintext")
			}

			// Key must be public...
			guard key.type == .publicType else {
				throw Error(code: CryptorRSA.ERR_KEY_NOT_PUBLIC, reason: "Supplied key is not public")
			}
            
			// Signature must be signed data...
			guard signature.type == .signedType else {
				throw Error(code: CryptorRSA.ERR_NOT_SIGNED_DATA, reason: "Supplied signature is not of signed data type")
			}

			#if os(Linux)
                
                // Create message digest context
                let signingCtx = EVP_MD_CTX_create()
                let evpPublicKey = EVP_PKEY_new()
                
                // Release created memory
                defer {
                    EVP_PKEY_free(evpPublicKey)
                    EVP_MD_CTX_destroy(signingCtx)
                }
                
                // Initialize evpKey with public key
                EVP_PKEY_set1_RSA(evpPublicKey, key.reference)
                if EVP_DigestVerifyInit(signingCtx, nil, algorithm.algorithmForSignature(), nil, evpPublicKey) != 1 {
                    throw Error(code: CryptorRSA.ERR_VERIFICATION_FAILED, reason: "EVP_DigestVerifyInit() failed")
                }
                
                let digestUpdateResult: Int = self.data.withUnsafeBytes { (u8Ptr: UnsafePointer<UInt8>) -> Int in
                    let rawPtr = UnsafeRawPointer(u8Ptr)
                    // For some reason, EVP_DigestVerifyUpdate() is not a defined method... instead using EVP_DigestUpdate()
                    return Int(EVP_DigestUpdate(signingCtx, rawPtr, self.data.count))
                }
                
                if digestUpdateResult != 1 {
                     throw Error(code: CryptorRSA.ERR_VERIFICATION_FAILED, reason: "EVP_DigestUpdate() failed")
                }
                
                let digestVerifyResult: Int = signature.data.withUnsafeBytes { (u8Ptr: UnsafePointer<UInt8>) -> Int in
                    // It seems odd EVP_DigestVerifyFinal() expects a mutable pointer
                    let u8MutablePtr = UnsafeMutablePointer<UInt8>(mutating: u8Ptr)
                    return Int(EVP_DigestVerifyFinal(signingCtx, u8MutablePtr, signature.data.count))
                }
                
                // EVP_DigestVerifyFinal() returns true if signature verification succeeds
                return (digestVerifyResult == 1)

			#else

				var response: Unmanaged<CFError>? = nil
				let result = SecKeyVerifySignature(key.reference, algorithm.algorithmForSignature, self.data as CFData, signature.data as CFData, &response)
				if response != nil {
					guard let error = response?.takeRetainedValue() else {
						throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "Verification failed. Unable to determine error.")
					}
					throw Error(code: CryptorRSA.ERR_SIGNING_FAILED, reason: "Verification failed with error: \(error)")
				}
				return result

			#endif
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

	///
	/// Plaintext Data - Represents data not encrypted or signed.
	///
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
			super.init(with: data, type: .plaintextType)
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

	///
	/// Encrypted Data - Represents data encrypted.
	///
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

			super.init(with: data, type: .encryptedType)
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

	///
	/// Signed Data - Represents data that is signed.
	///
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
			super.init(with: data, type: .signedType)
		}

	}

}
