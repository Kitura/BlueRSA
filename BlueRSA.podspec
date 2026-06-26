Pod::Spec.new do |s|

  s.name              = "BlueRSA"
  s.module_name       = 'CryptorRSA'
  s.version           = "1.0.203"
  s.cocoapods_version = '~> 1.16'
  s.summary           = "Swift cross-platform RSA crypto library using CommonCrypto/libcrypto via Package Manager."
  s.homepage          = "https://github.com/Kitura/BlueRSA"
  s.license           = {
                          :type => "Apache License, Version 2.0"
                        }
  s.author            = "IBM and the Kitura project authors"

  s.source            = {
                          :git => "https://github.com/Kitura/BlueRSA.git",
                          :tag => s.version
                        }

  s.swift_version = "5.8"

  s.ios.deployment_target = "14.5"
  s.osx.deployment_target = "11.5"
  s.tvos.deployment_target = "14.5"
  s.watchos.deployment_target = "8.0"

  s.source_files = "Sources/CryptorRSA/*.swift"

end
