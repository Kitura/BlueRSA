//
//  Utilities.swift
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

// MARK: -- RSAUtilities

///
/// Various RSA Related Utility Functions
///
@available(macOS 10.12, iOS 10.0, *)
public extension CryptorRSA {
	
	#if !os(Linux)
	
	///
	/// Create a key from key data.
	///
	/// - Parameters:
	///		- keyData:			`Data` representation of the key.
	///		- type:				Type of key data.
	///
	///	- Returns:				`SecKey` representation of the key.
	///
	static func createKey(from keyData: Data, type: CryptorRSA.RSAKey.KeyType) throws ->  SecKey {
		
		var keyData = keyData
		
		let keyClass = type == .publicType ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
		
		let sizeInBits = keyData.count * MemoryLayout<UInt8>.size
		let keyDict: [CFString: Any] = [
			kSecAttrKeyType: kSecAttrKeyTypeRSA,
			kSecAttrKeyClass: keyClass,
			kSecAttrKeySizeInBits: NSNumber(value: sizeInBits)
		]
		
		guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, nil) else {
			
			throw Error(code: ERR_ADD_KEY, reason: "Couldn't create key reference from key data")
		}
		
		return key
		
	}
	
	#endif

	///
	/// Get the Base64 representation of a PEM encoded string after stripping off the PEM markers.
	///
	/// - Parameters:
	///		- pemString:		`String` containing PEM formatted data.
	///
	/// - Returns:				Base64 encoded `String` containing the data.
	///
	static func base64String(for pemString: String) throws -> String {
		
		// Filter looking for new lines...
		var lines = pemString.components(separatedBy: "\n").filter { line in
			return !line.hasPrefix(CryptorRSA.GENERIC_BEGIN_MARKER) && !line.hasPrefix(CryptorRSA.GENERIC_END_MARKER)
		}
		
		// No lines, no data...
		guard lines.count != 0 else {
			throw Error(code: ERR_BASE64_PEM_DATA, reason: "Couldn't get data from PEM key: no data available after stripping headers.")
		}
		
		// Strip off any carriage returns...
		lines = lines.map { $0.replacingOccurrences(of: "\r", with: "") }
		
		return lines.joined(separator: "")
	}
	
	///
	/// This function strips the x509 from a provided ASN.1 DER public key. If the key doesn't contain a header,
	///	the DER data is returned as is.
	///
	/// - Parameters:
	///		- keyData:				`Data` containing the public key with or without the x509 header.
	///
	/// - Returns:					`Data` containing the public with header (if present) removed.
	///
	static func stripPublicKeyHeader(for keyData: Data) throws -> Data {
		
		let count = keyData.count / MemoryLayout<CUnsignedChar>.size
		
		guard count > 0 else {
			
			throw Error(code: ERR_STRIP_PK_HEADER, reason: "Provided public key is empty")
		}
		
		var byteArray = [UInt8](repeating: 0, count: count)
		(keyData as NSData).getBytes(&byteArray, length: keyData.count)
		
		var index = 0
		guard byteArray[index] == 0x30 else {
			
			throw Error(code: ERR_STRIP_PK_HEADER, reason: "Provided key doesn't have a valid ASN.1 structure (first byte should be 0x30 == SEQUENCE)")
		}
		
		index += 1
		if byteArray[index] > 0x80 {
			index += Int(byteArray[index]) - 0x80 + 1
		} else {
			index += 1
		}
		
		// If current byte marks an integer (0x02), it means the key doesn't have a X509 header and just
		// contains its modulo & public exponent. In this case, we can just return the provided DER data as is.
		if Int(byteArray[index]) == 0x02 {
			return keyData
		}
		
		// Now that we've excluded the possibility of headerless key, we're looking for a valid X509 header sequence.
		// It should look like this:
		// 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
		guard Int(byteArray[index]) == 0x30 else {
			
			throw Error(code: ERR_STRIP_PK_HEADER, reason: "Provided key doesn't have a valid X509 header")
		}
		
		index += 15
		if byteArray[index] != 0x03 {
			
			throw Error(code: ERR_STRIP_PK_HEADER, reason: "Invalid byte at index \(index - 1) (\(byteArray[index - 1])) for public key header")
		}
		
		index += 1
		if byteArray[index] > 0x80 {
			index += Int(byteArray[index]) - 0x80 + 1
		} else {
			index += 1
		}
		
		guard byteArray[index] == 0 else {
			
			throw Error(code: ERR_STRIP_PK_HEADER, reason: "Invalid byte at index \(index - 1) (\(byteArray[index - 1])) for public key header")
		}
		
		index += 1
		
		let strippedKeyBytes = [UInt8](byteArray[index...keyData.count - 1])
		let data = Data(bytes: UnsafePointer<UInt8>(strippedKeyBytes), count: keyData.count - index)
		
		return data
	}
}

// MARK: -

#if !os(Linux)

	// MARK: -- CFString Extension for Hashing
	
	///
	/// Extension to CFString to make it hashable.
	///
	extension CFString: Hashable {
		
		/// Return the hash value of a CFString
		public var hashValue: Int {
			return (self as String).hashValue
		}
		
		/// Comparison of CFStrings
		static public func == (lhs: CFString, rhs: CFString) -> Bool {
			return lhs as String == rhs as String
		}
	}
	
#endif
