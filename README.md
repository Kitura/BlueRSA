![macOS](https://img.shields.io/badge/os-macOS-green.svg?style=flat)
![iOS](https://img.shields.io/badge/os-iOS-green.svg?style=flat)
![Linux](https://img.shields.io/badge/os-linux-green.svg?style=flat)
![Apache 2](https://img.shields.io/badge/license-Apache2-blue.svg?style=flat)
![](https://img.shields.io/badge/Swift-3.0-orange.svg?style=flat)
[![Build Status - Master](https://travis-ci.org/IBM-Swift/BlueRSA.svg?branch=master)](https://travis-ci.org/IBM-Swift/BlueRSA)

# BlueRSA

## Overview
RSA public/private key encryption, private key signing and public key verification in Swift using the Swift Package Manager. Works on iOS, macOS, and Linux.

## Contents

* CryptorRSA: Utility functions for RSA encryption and signing.

## Prerequisites

### Swift
* Swift Open Source `swift-3.0.1-RELEASE` toolchain (**Minimum REQUIRED for latest release**)
* Swift Open Source `swift-3.0.2-RELEASE` toolchain (**Recommended**)

### iOS
* iOS 10.0 or higher

### macOS

* macOS 10.12.0 (*Sierra*) or higher
* Xcode Version 8.2 (8C38) or higher using one of the above toolchains (*Recommended*)

### Linux

* Ubuntu 16.04 (or 16.10 but only tested on 16.04)
* One of the Swift Open Source toolchains listed above

## Build

To build CryptorRSA from the command line:

```
% cd <path-to-clone>
% swift build
```

## Testing

To run the supplied unit tests for **CryptorRSA** from the command line:

```
% cd <path-to-clone>
% swift build
% swift test

```

## Using CryptorRSA

### Including in your project

#### Swift Package Manager

To include BlueRSA into a Swift Package Manager package, add it to the `dependencies` attribute defined in your `Package.swift` file. You can select the version using the `majorVersion` and `minor` parameters. For example:
```
	dependencies: [
		.Package(url: "https://github.com/IBM-Swift/BlueRSA", majorVersion: <majorVersion>, minor: <minor>)
	]
```

#### Carthage

To include BlueRSA in a project using Carthage, add a line to your `Cartfile` with the GitHub organization and project names and version. For example:
```
	github "IBM-Swift/BlueRSA" ~> <majorVersion>.<minor>
```

### Before starting

The first you need to do is import the CryptorRSA framework.  This is done by the following:
```
import CryptorRSA
```

### Data Types

BlueRSA supports the following *major* data types:

* Key Handling
	- `CryptorRSA.PublicKey` - Represents an RSA Public Key.
	- `CryptorRSA.PrivateKey` - Represents an RSA Private Key.

* Data Handling
	- `CryptorRSA.EncryptedData` - Represents encrypted data.
	- `CryptorRSA.PlaintextData` - Represents plaintext or decrypted data.
	- `CryptorRSA.SignedData` - Represents signed data.

### Key Handling

* `BlueRSA` provides seven (7) initializers each for creating public and private keys from data. They are as follows (where *createXXXX* is either `createPublicKey` or `createPrivateKey` depending on what you're trying to create:

	- `CryptorRSA.createXXXX(with data: Data) throws` - This creates either a private or public key containing the data provided. *It is assumed that the data being provided is in the proper format.*
	- `CryptorRSA.createXXXX(withBase64 base64String: String) throws` - This creates either a private or public key using the `Base64 encoded String` provided.
	- `CryptorRSA.createXXXX(withPEM pemString: String) throws` - This creates either a private or public key using the `PEM encoded String` provided.
	- `CryptorRSA.createXXXX(withPEMNamed pemName: String, onPath path: String) throws` - This creates either a private or public key using the `PEM encoded file` pointed at by the `pemName` and located on the path specified by `path` provided.
	- `CryptorRSA.createXXXX(withDERNamed derName: String, onPath path: String) throws` - This creates either a private or public key using the `DER encoded file` pointed at by the `derName` and located on the path specified by `path` provided.
	- `CryptorRSA.createXXXX(withPEMNamed pemName: String, in bundle: Bundle = Bundle.main) throws` - This creates either a private or public key using the `PEM encoded file` pointed at by the `pemName` and located in the `Bundle` specified by `bundle` provided. By default this API will look in the `main` bundle.
	- `CryptorRSA.createXXXX(withDERNamed derName: String, in bundle: Bundle = Bundle.main) throws` - This creates either a private or public key using the `DER encoded file` pointed at by the `derName` and located in the `Bundle` specified by `bundle` provided. By default this API will look in the `main` bundle.

* Example

The following example illustrates creating a public key given PEM encoded file located on a certain path. *Note: Exception handling omitted for brevity.

```
import Foundation
import CryptorRSA

...

let keyName = ...
let keyPath = ...

let publicKey = try CryptorRSA.createPublicKey(withPEMNamed: keyName, onPath: keyPath)

...

<Do something with the key...>

```

### Data Encryption and Decryption Handling

TBD

### Signing and Verification Handling

TBD
