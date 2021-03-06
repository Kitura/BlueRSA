Pod::Spec.new do |s|
s.name        = "BlueRSA"
s.version     = "1.0.201"
s.summary     = "Swift cross-platform RSA crypto library using CommonCrypto/libcrypto via Package Manager."
s.homepage    = "https://github.com/Kitura/BlueRSA"
s.license     = { :type => "Apache License, Version 2.0" }
s.author     = "IBM and the Kitura project authors"
s.module_name  = 'CryptorRSA'
s.swift_version = "5.0.2"
s.requires_arc = true
s.osx.deployment_target = "10.12"
s.ios.deployment_target = "10.3"
s.tvos.deployment_target = "10.3"
s.watchos.deployment_target = "3.3"
s.source   = { :git => "https://github.com/Kitura/BlueRSA.git", :tag => s.version }
s.source_files = "Sources/CryptorRSA/*.swift"
s.pod_target_xcconfig =  {
'SWIFT_VERSION' => '5.0',
}
end
