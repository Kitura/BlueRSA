#if os(Linux)

//http://stackoverflow.com/questions/9284420/how-to-use-sha1-hashing-in-c-programming
//https://memset.wordpress.com/2010/10/06/using-sha1-function/
//https://www.openssl.org/docs/man1.0.2/crypto/sha.html
//https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man3/CC_SHA1.3cc.html

import OpenSSL

func OPENSSL_SHA1(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {
  let d: UnsafePointer<UInt8> = data.assumingMemoryBound(to: UInt8.self)
  let n: Int = Int(len)
  //'(UnsafePointer<UInt8>!, Int, UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>!'
  return SHA1(d, n, md)
}

func OPENSSL_SHA224(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {
  let d: UnsafePointer<UInt8> = data.assumingMemoryBound(to: UInt8.self)
  let n: Int = Int(len)
  //'(UnsafePointer<UInt8>!, Int, UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>!'
  return SHA224(d, n, md)
}

func OPENSSL_SHA256(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {
  let d: UnsafePointer<UInt8> = data.assumingMemoryBound(to: UInt8.self)
  let n: Int = Int(len)
  //'(UnsafePointer<UInt8>!, Int, UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>!'
  return SHA256(d, n, md)
}

func OPENSSL_SHA384(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {
  let d: UnsafePointer<UInt8> = data.assumingMemoryBound(to: UInt8.self)
  let n: Int = Int(len)
  //'(UnsafePointer<UInt8>!, Int, UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>!'
  return SHA384(d, n, md)
}

func OPENSSL_SHA512(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {
  let d: UnsafePointer<UInt8> = data.assumingMemoryBound(to: UInt8.self)
  let n: Int = Int(len)
  //'(UnsafePointer<UInt8>!, Int, UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>!'
  return SHA512(d, n, md)
}

#endif
