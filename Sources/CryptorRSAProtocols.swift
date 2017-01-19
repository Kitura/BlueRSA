//
//  CryptorRSAProtocols.swift
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

// MARK: -

///
/// RSA Message Protocol
///
public protocol RSAMessage {
	
	/// `Data` containing the message.
	var data: Data { get }
	
	/// Base64 representation of the message.
	var base64String: String { get }
	
	///
	/// Create an Message with data.
	///
	/// - Parameters:
	///		- data:				`Data` containing the message data.
	///		- isEncrypted:		True if *data* is encrypted, false if *data* is plaintext.
	///
	init(with data: Data, isEncrypted: Bool)
}

// MARK: -

///
/// RSA Key Protocol
///
public protocol RSAKey {
	
	///
	/// Initialize an RSAKey
	///
	/// - Parameters:
	///		- data:				`Data` containing the key data.
	///		- isPublic:			True the key is public, false otherwise.
	///
	init(with data: Data, isPublic: Bool) throws
}

