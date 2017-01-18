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

public class CryptorRSA {
	
	// MARK: Constants
	
	// MARK: -- Generic
	
	// MARK: -- Errors: Domain and Codes
	
	public static let ERR_DOMAIN						= "com.ibm.oss.CryptorRSA.ErrorDomain"
	
	public static let ERR_ADD_KEY						= -9999	
	public static let ERR_DELETE_KEY					= -9998
	public static let ERR_STRIP_PK_HEADER				= -9997

	// MARK: -- Error
	
	///
	/// `RSA` specific error structure.
	///
	public struct Error: Swift.Error, CustomStringConvertible {
		
		// MARK: -- Public Properties
		
		///
		/// The error domain.
		///
		public let domain: String = ERR_DOMAIN
		
		///
		/// The error code: **see constants above for possible errors** (Readonly)
		///
		public internal(set) var errorCode: Int32
		
		///
		/// The reason for the error **(if available)** (Readonly)
		///
		public internal(set) var errorReason: String?
		
		///
		/// Returns a string description of the error. (Readonly)
		///
		public var description: String {
			
			let reason: String = self.errorReason ?? "Reason: Unavailable"
			return "Error code: \(self.errorCode)(0x\(String(self.errorCode, radix: 16, uppercase: true))), \(reason)"
		}
		
		// MARK: -- Public Functions
		
		///
		/// Initializes an Error Instance
		///
		/// - Parameters:
		///		- code:		Error code
		/// 	- reason:	Optional Error Reason
		///
		/// - Returns: Error instance
		///
		init(code: Int, reason: String?) {
			
			self.errorCode = Int32(code)
			self.errorReason = reason
		}
		
	}}
