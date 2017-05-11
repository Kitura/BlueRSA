#if os(Linux)

//http://stackoverflow.com/questions/9284420/how-to-use-sha1-hashing-in-c-programming
//https://memset.wordpress.com/2010/10/06/using-sha1-function/

import OpenSSL

func OPENSSL_SHA1(arg1: UnsafeRawPointer, arg2: CC_LONG, arg3: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {
  let param1: UnsafePointer<UInt8> = arg1.assumingMemoryBound(to: UInt8.self)
  let param2: Int = Int(arg2)
  return SHA1(param1, param2, arg3)

  //this is what i need:
  //'(UnsafeRawPointer, CC_LONG, UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>!'

  //this is what it is
  //'(UnsafePointer<UInt8>!, Int, UnsafeMutablePointer<UInt8>!) -> UnsafeMutablePointer<UInt8>!'
}

func OPENSSL_SHA224(arg1: UnsafeRawPointer, arg2: CC_LONG, arg3: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {

}

func OPENSSL_SHA256(arg1: UnsafeRawPointer, arg2: CC_LONG, arg3: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {

}

func OPENSSL_SHA384(arg1: UnsafeRawPointer, arg2: CC_LONG, arg3: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {

}

func OPENSSL_SHA512(arg1: UnsafeRawPointer, arg2: CC_LONG, arg3: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>! {

}

#endif
