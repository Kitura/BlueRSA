//
//  CryptorRSADigest.swift
//  CryptorRSA
//
//  Created by Bill Abt on 1/18/17.
//
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
	typealias CC_LONG = size_t
#endif

import Foundation

// MARK: -- RSA Digest Extension for Data

///
/// Digest Handling Extension
///
public extension Data {
	
	// MARK: Enums
	
	///
	/// Enumerates available Digest algorithms
	///
	public enum Algorithm {
		
		/// Secure Hash Algorithm 1
		case sha1
		
		/// Secure Hash Algorithm 2 224-bit
		case sha224
		
		/// Secure Hash Algorithm 2 256-bit
		case sha256
		
		/// Secure Hash Algorithm 2 384-bit
		case sha384
		
		/// Secure Hash Algorithm 2 512-bit
		case sha512
		
		/// Digest Length
		public var length: CC_LONG {
			
			#if os(Linux)
				
				switch self {
					
				case .sha1:
					return CC_LONG(SHA_DIGEST_LENGTH)
					
				case .sha224:
					return CC_LONG(SHA224_DIGEST_LENGTH)
					
				case .sha356:
					return CC_LONG(SHA256_DIGEST_LENGTH)
					
				case .sha384:
					return CC_LONG(SHA384_DIGEST_LENGTH)
					
				case .sha512:
					return CC_LONG(SHA512_DIGEST_LENGTH)
					
				}
				
			#else

				switch self {
				
				case .sha1:
					return CC_LONG(CC_SHA1_DIGEST_LENGTH)
					
				case .sha224:
					return CC_LONG(CC_SHA224_DIGEST_LENGTH)
					
				case .sha256:
					return CC_LONG(CC_SHA256_DIGEST_LENGTH)
					
				case .sha384:
					return CC_LONG(CC_SHA384_DIGEST_LENGTH)
					
				case .sha512:
					return CC_LONG(CC_SHA512_DIGEST_LENGTH)
					
				}

			#endif
		}
		
		#if !os(Linux)
			
			public var alogrithmForDigest: SecKeyAlgorithm {
					
				switch self {
						
				case .sha1:
					return .rsaSignatureDigestPKCS1v15SHA1
						
				case .sha224:
					return .rsaSignatureDigestPKCS1v15SHA224
					
				case .sha256:
					return .rsaSignatureDigestPKCS1v15SHA256
						
				case .sha384:
					return .rsaSignatureDigestPKCS1v15SHA384
						
				case .sha512:
					return .rsaSignatureDigestPKCS1v15SHA512
						
				}
			}
				
			public var alogrithmForMessage: SecKeyAlgorithm {
			
				switch self {
				
				case .sha1:
					return .rsaSignatureMessagePKCS1v15SHA1
				
				case .sha224:
					return .rsaSignatureMessagePKCS1v15SHA224
				
				case .sha256:
					return .rsaSignatureMessagePKCS1v15SHA256
				
				case .sha384:
					return .rsaSignatureMessagePKCS1v15SHA384
				
				case .sha512:
					return .rsaSignatureMessagePKCS1v15SHA512
				
			}
		}
		
		#endif
		
		/// The platform/alogorithm dependent function to be used.
		public var engine: (_ data: UnsafeRawPointer, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {
			
			#if os(Linux)
				
				switch self {
					
				case .sha1:
					return SHA1
					
				case .sha224:
					return SHA224
					
				case .sha356:
					return SHA256
					
				case .sha384:
					return SHA384
					
				case .sha512:
					return SHA512
					
				}
				
			#else
				
				switch self {
					
				case .sha1:
					return CC_SHA1
					
				case .sha224:
					return CC_SHA224
					
				case .sha256:
					return CC_SHA256
					
				case .sha384:
					return CC_SHA384
					
				case .sha512:
					return CC_SHA512
					
				}
				
			#endif
		}
	}
	
	
	// MARK: Functions
	
	///
	/// Return a digest of the data based on the alogorithm selected.
	///
	/// - Parameters:
	///		- alogorithm:		The digest `Alogorithm` to use.
	///
	/// - Returns:				`Data` containing the data in digest form.
	///
	public func digest(using alogorithm: Algorithm) throws -> Data {

		var hash = [UInt8](repeating: 0, count: Int(alogorithm.length))
		
		self.withUnsafeBytes {
			
			_ = alogorithm.engine($0, CC_LONG(self.count), &hash)
		}
		
		return Data(bytes: hash)
	}
}
