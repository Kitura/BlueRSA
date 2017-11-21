// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

//
//  Package.swift
//  CryptorRSA
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

import PackageDescription

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
	
    let CryptoLibUrl = "https://github.com/IBM-Swift/CommonCrypto.git"
    let CryptoLibVersion: Version = "0.1.0"
	
#elseif os(Linux)
	
	let CryptoLibUrl = "https://github.com/IBM-Swift/OpenSSL.git"
    let CryptoLibVersion: Version = "0.3.0"
	
#else
	
	fatalError("Unsupported OS")
	
#endif

let package = Package(
	name: "CryptorRSA",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "CryptorRSA",
            targets: ["CryptorRSA"]
        )
    ],
	dependencies: [
        .package(url: CryptoLibUrl, from: CryptoLibVersion)
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "CryptorRSA",
            dependencies: []
        ),
        .testTarget(
            name: "CryptorRSATests",
            dependencies: ["CryptorRSA"]
        )
    ]
)
