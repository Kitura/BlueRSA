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

public struct RSAUtilities {
	
	#if !os(Linux)
	
	///
	/// Add a key to the keychain.
	///
	/// - Parameters:
	///		- keyData:			`Data` representation of the key.
	///		- isPublic:			True if the key is to be `public`, false otherwise.
	///		- tag:				The `String` representation of the tag to be used.
	///
	///	- Returns:				`SecKey` representation of the key.
	///
	static func addKey(using keyData: Data, isPublic: Bool, taggedWith tag: String) throws ->  SecKey {
		
		var keyData = keyData
		
		guard let tagData = tag.data(using: .utf8) else {
			
			throw CryptorRSA.Error(code: CryptorRSA.ERR_ADD_KEY, reason: "Couldn't create tag data for key")
		}
		
		let keyClass = isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
		
		// On iOS 10+, we can use SecKeyCreateWithData without going through the keychain
		if #available(macOS 10.12, *), #available(iOS 10.0, *), #available(watchOS 3.0, *), #available(tvOS 10.0, *) {
			
			let sizeInBits = keyData.count * MemoryLayout<UInt8>.size
			let keyDict: [CFString: Any] = [
				kSecAttrKeyType: kSecAttrKeyTypeRSA,
				kSecAttrKeyClass: keyClass,
				kSecAttrKeySizeInBits: NSNumber(value: sizeInBits)
			]
			
			guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, nil) else {
				
				throw CryptorRSA.Error(code: CryptorRSA.ERR_ADD_KEY, reason: "Couldn't create key reference from key data")
			}

			return key
			
			// On iOS 9 and earlier, add a persistent version of the key to the system keychain
		} else {
			
			let persistKey = UnsafeMutablePointer<AnyObject?>(mutating: nil)
			
			let keyAddDict: [CFString: Any] = [
				kSecClass: kSecClassKey,
				kSecAttrApplicationTag: tagData,
				kSecAttrKeyType: kSecAttrKeyTypeRSA,
				kSecValueData: keyData,
				kSecAttrKeyClass: keyClass,
				kSecReturnPersistentRef: NSNumber(value: true),
				kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked
			]
			
			var secStatus = SecItemAdd(keyAddDict as CFDictionary, persistKey)
			if secStatus != noErr && secStatus != errSecDuplicateItem {
				throw CryptorRSA.Error(code: CryptorRSA.ERR_ADD_KEY, reason: "Provided key couldn't be added to the keychain")
			}
			
			let keyCopyDict: [CFString: Any] = [
				kSecClass: kSecClassKey,
				kSecAttrApplicationTag: tagData,
				kSecAttrKeyType: kSecAttrKeyTypeRSA,
				kSecAttrKeyClass: keyClass,
				kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
				kSecReturnRef: NSNumber(value: true),
				]
			
			// Now fetch the SecKeyRef version of the key
			var keyRef: AnyObject? = nil
			secStatus = SecItemCopyMatching(keyCopyDict as CFDictionary, &keyRef)
			
			guard let unwrappedKeyRef = keyRef else {
				
				throw CryptorRSA.Error(code: CryptorRSA.ERR_ADD_KEY, reason: "Couldn't get key reference from the keychain")
			}
			
			return unwrappedKeyRef as! SecKey // swiftlint:disable:this force_cast
		}
	}
	
	///
	/// Remove a key from the keychain.
	///
	/// - Parameters:
	///		- tag:				The `String` containing the tag of the key to be removed.
	///
	static func removeKey(with tag: String) throws {
		
		guard let tagData = tag.data(using: .utf8) else {
			
			return
		}
		
		let keyRemoveDict: [CFString: Any] = [
			kSecClass: kSecClassKey,
			kSecAttrKeyType: kSecAttrKeyTypeRSA,
			kSecAttrApplicationTag: tagData,
			]
		
		let status: OSStatus = SecItemDelete(keyRemoveDict as CFDictionary)
		if status != errSecSuccess {
			
			throw CryptorRSA.Error(code: CryptorRSA.ERR_DELETE_KEY, reason: "Unable to remove key from keychain, code: \(status)")
		}
	}
	
	#endif
}

#if !os(Linux)

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
