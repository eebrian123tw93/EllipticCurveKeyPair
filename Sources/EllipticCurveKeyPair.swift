/**
 *  Copyright (c) 2017 Håvard Fossli.
 *
 *  Licensed under the MIT license, as follows:
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */


import Foundation
import Security
import LocalAuthentication

@available(OSX 10.12.1, iOS 9.0, *)
public enum EllipticCurveKeyPair {
    
    public typealias Logger = (String) -> ()
    public static var logger: Logger?
        
    public struct Config {
        
        // The label used to identify the public key in keychain
        public var publicLabel: String
        
        // The label used to identify the private key on the secure enclave
        public var privateLabel: String
        
        // The text presented to the user about why we need his/her fingerprint / device pin
        // If you are passing an LAContext to sign or decrypt this value will be rejected
        public var operationPrompt: String?
        
        // The access control used to manage the access to the public key
        public var publicKeyAccessControl: AccessControl
        
        // The access control used to manage the access to the private key
        public var privateKeyAccessControl: AccessControl
        
        // The access group e.g. "BBDV3R8HVV.no.agens.demo"
        // Useful for shared keychain items
        public var publicKeyAccessGroup: String?
        
        // The access group e.g. "BBDV3R8HVV.no.agens.demo"
        // Useful for shared keychain items
        public var privateKeyAccessGroup: String?
        
        // Should it be stored on .secureEnclave or in .keychain ?
        public var token: Token
        
        public init(publicLabel: String,
                    privateLabel: String,
                    operationPrompt: String?,
                    publicKeyAccessControl: AccessControl,
                    privateKeyAccessControl: AccessControl,
                    publicKeyAccessGroup: String? = nil,
                    privateKeyAccessGroup: String? = nil,
                    token: Token) {
            self.publicLabel = publicLabel
            self.privateLabel = privateLabel
            self.operationPrompt = operationPrompt
            self.publicKeyAccessControl = publicKeyAccessControl
            self.privateKeyAccessControl = privateKeyAccessControl
            self.publicKeyAccessGroup = publicKeyAccessGroup
            self.privateKeyAccessGroup = privateKeyAccessGroup
            self.token = token
        }
    }
    
    // A stateful and opiniated manager for using the secure enclave and keychain
    // If the private or public key is not found this manager will naively just recreate a new keypair
    // If the device doesn't have a Secure Enclave it will store the private key in keychain just like the public key
    //
    // If you think this manager is "too smart" in that sense you may use this manager as an example
    // and create your own manager
    public final class Manager {
        
        private let config: Config
        private let helper: Helper
        private var cachedPublicKey: PublicKey? = nil
        private var cachedPrivateKey: PrivateKey? = nil
        
        public init(config: Config) {
            self.config = config
            self.helper = Helper(config: config)
        }
        
        /* Gevin added: */
        public func importPrivateKeyB64(_ privateKeyB64: String ) throws{
            try self.helper.importKeyBase64(privateKeyB64: privateKeyB64 )
            try cachedPrivateKey = self.helper.getPrivateKey()
        }
        
        /* Gevin added: */
        public func importPublicKeyB64(_ publicKeyB64: String ) throws{
            try self.helper.importKeyBase64(publicKeyB64: publicKeyB64 )
            try cachedPublicKey = self.helper.getPublicKey()
        }
        
        /* Gevin added: */
        public func privateKeyDER() throws -> Data{
            return try self.helper.exportDER( privateKey: cachedPrivateKey!)
        }
        
        /* Gevin added: */
        public func publicKeyDER() throws -> Data{
            return try self.helper.exportDER( publicKey: cachedPublicKey!)
        }
        
        /* Gevin added */
        public func privateKeyPEM() throws -> String {
            let privateKeyPEM = try self.helper.exportPEM(privateKey: cachedPrivateKey!)
            return privateKeyPEM
        }
        
        /* Gevin added */
        public func publicKeyPEM() throws -> String {
            let publicKeyPEM = try self.helper.exportPEM(publicKey: cachedPublicKey!)
            return publicKeyPEM
        }
        
        /* Gevin added: */
        public func generateKeyPair(context: LAContext? = nil) throws{
            let keys = try helper.generateKeyPair(context: context)
            cachedPublicKey = keys.public
            cachedPrivateKey = keys.private
        }
        
        public func deleteKeyPair() throws {
            clearCache()
            try helper.delete()
        }
        
        public func publicKey() throws -> PublicKey {
            do {
                if let key = cachedPublicKey {
                    return key
                }
                let key = try helper.getPublicKey()
                cachedPublicKey = key
                return key
            }catch EllipticCurveKeyPair.Error.underlying(_, let underlying) where underlying.code == errSecItemNotFound {
                let keys = try self.helper.generateKeyPair()
                cachedPublicKey = keys.public
                cachedPrivateKey = keys.private
                return keys.public
            } catch {
                throw error
            }
        }
        
        public func privateKey(context: LAContext? = nil) throws -> PrivateKey {
            do {
                if cachedPrivateKey?.context !== context {
                    cachedPrivateKey = nil
                }
                if let key = cachedPrivateKey {
                    return key
                }
                let key = try helper.getPrivateKey(context: context)
                cachedPrivateKey = key
                return key
            } catch EllipticCurveKeyPair.Error.underlying(_, let underlying) where underlying.code == errSecItemNotFound {
                if config.publicKeyAccessControl.flags.contains(.privateKeyUsage) == false, (try? helper.getPublicKey()) != nil {
                    throw Error.probablyAuthenticationError(underlying: underlying)
                }
                let keys = try helper.generateKeyPair(context: nil)
                cachedPublicKey = keys.public
                cachedPrivateKey = keys.private
                return keys.private
            } catch {
                throw error
            }
        }
        
        public func keys(context: LAContext? = nil) throws -> (`public`: PublicKey, `private`: PrivateKey) {
            let privateKey = try self.privateKey(context: context)
            let publicKey = try self.publicKey()
            return (public: publicKey, private: privateKey)
        }
        
        public func clearCache() {
            cachedPublicKey = nil
            cachedPrivateKey = nil
        }
        
        @available(iOS 10, *)
        public func sign(_ digest: Data, hash: Hash, context: LAContext? = nil) throws -> Data {
            return try helper.sign(digest, privateKey: privateKey(context: context), hash: hash)
        }
        
        @available(OSX, unavailable)
        @available(iOS, deprecated: 10.0, message: "This method and extra complexity will be removed when 9.0 is obsolete.")
        public func signUsingSha256(_ digest: Data, context: LAContext? = nil) throws -> Data {
            #if os(iOS)
                return try helper.signUsingSha256(digest, privateKey: privateKey(context: context))
            #else
                throw Error.inconcistency(message: "Should be unreachable.")
            #endif
        }
        
        @available(iOS 10, *)
        public func verify(signature: Data, originalDigest: Data, hash: Hash) throws {
            try helper.verify(signature: signature, digest: originalDigest, publicKey: publicKey(), hash: hash)
        }
        
        @available(OSX, unavailable)
        @available(iOS, deprecated: 10.0, message: "This method and extra complexity will be removed when 9.0 is obsolete.")
        public func verifyUsingSha256(signature: Data, originalDigest: Data) throws  {
            #if os(iOS)
                try helper.verifyUsingSha256(signature: signature, digest: originalDigest, publicKey: publicKey())
            #else
                throw Error.inconcistency(message: "Should be unreachable.")
            #endif
        }
        
        @available(iOS 10.3, *) // API available at 10.0, but bugs made it unusable on versions lower than 10.3
        public func encrypt(_ digest: Data, hash: Hash = .sha256) throws -> Data {
            return try helper.encrypt(digest, publicKey: publicKey(), hash: hash)
        }
        
        @available(iOS 10.3, *) // API available at 10.0, but bugs made it unusable on versions lower than 10.3
        public func decrypt(_ encrypted: Data, hash: Hash = .sha256, context: LAContext? = nil) throws -> Data {
            return try helper.decrypt(encrypted, privateKey: privateKey(context: context), hash: hash)
        }
        
    }
    
    // Helper is a stateless class for querying the secure enclave and keychain
    // You may create a small stateful facade around this
    // `Manager` is an example of such an opiniated facade
    public struct Helper {
        
        
        // The open ssl compatible DER format X.509
        //
        // We take the raw key and prepend an ASN.1 headers to it. The end result is an
        // ASN.1 SubjectPublicKeyInfo structure, which is what OpenSSL is looking for.
        //
        // See the following DevForums post for more details on this.
        // https://forums.developer.apple.com/message/84684#84684
        //
        // End result looks like this
        // https://lapo.it/asn1js/#3059301306072A8648CE3D020106082A8648CE3D030107034200041F4E3F6CD8163BCC14505EBEEC9C30971098A7FA9BFD52237A3BCBBC48009162AAAFCFC871AC4579C0A180D5F207316F74088BF01A31F83E9EBDC029A533525B
        //
        // Header 的資料 
        // https://stackoverflow.com/questions/45131935/export-an-elliptic-curve-key-from-ios-to-work-with-openssl
        // 
        // Gevin note: 
        //   java 那 private key 的格式，跟 rfc5915 定義不一樣，但為了讓兩邊相容，這邊的輸出改為像 java 那樣
        //   openssl 則是按照 rfc5915 定義的格式
        //   private key format
        //   https://tools.ietf.org/html/rfc5915
        //   ECPrivateKey ::=
        //   SEQUENCE {
        //   |-> version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        //   |-> privateKey OCTET STRING,
        //   |-> parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        //   |-> publicKey  [1] BIT STRING OPTIONAL
        //   }
        // 
        //   0 116: SEQUENCE {
        //   2   1:   INTEGER 1
        //   5  32:   OCTET STRING
        //   :     ED 03 E5 18 E6 7A CF FD D4 D6 F7 74 76 3D 77 19
        //   :     9B 33 B8 15 7F 19 81 DB E3 95 B8 B9 96 31 B1 97
        //   39   7:   [0] {
        //   41   5:     OBJECT IDENTIFIER secp256k1 (1 3 132 0 10)
        //   :     }
        //   48  68:   [1] {
        //   50  66:     BIT STRING
        //   :       04 81 53 44 BA 2A D4 34 21 15 75 FE E7 2D 20 54
        //   :       81 4D 46 5C BA ED 20 17 A0 94 86 CA E7 8B 3D D4
        //   :       79 56 28 E2 A3 93 80 A4 27 7F C1 C0 60 1F 71 82
        //   :       9A F8 38 09 D8 85 10 48 3D 79 2B 54 FF 82 13 3D
        //   :       79
        //   :     }
        //   :   }
        // tag 的規則， [tag id] [value len] [ value content .... ]
        public let x9_62PrivateECHeader = [UInt8]([
        /* sequence           */ 0x30, 0x81, 0x87,
        /* |-> Integer        */ 0x02, 0x01, 0x00,
        /* |-> sequence       */ 0x30, 0x13,
        /* |---> ecPublicKey  */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // http://oid-info.com/get/1.2.840.10045.2.1 (ANSI X9.62 public key type)
        /* |---> prime256v1   */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // http://oid-info.com/get/1.2.840.10045.3.1.7 (ANSI X9.62 named elliptic curve)
        /* |-> octet string   */ 0x04, 0x6D,
        /* |---> sequence     */ 0x30, 0x6B,
        /* |-----> integer    */ 0x02, 0x01, 0x01,
        /* |-----> oct string */ 0x04, 0x20                              
        ])
        
        public let x9_62PrivateECHeader_Element = [UInt8]([
        /* |-----> sub element */ 0xA1, 0x44,
        /* |-----> bit string  */ 0x03, 0x42, 0x00 ])
        
        
        public let x9_62PublicECHeader = [UInt8]([
        /* sequence          */ 0x30, 0x59,
        /* |-> sequence      */ 0x30, 0x13,
        /* |---> ecPublicKey */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // http://oid-info.com/get/1.2.840.10045.2.1 (ANSI X9.62 public key type)
        /* |---> prime256v1  */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // http://oid-info.com/get/1.2.840.10045.3.1.7 (ANSI X9.62 named elliptic curve)
        /* |-> bit headers   */ 0x03, 0x42, 0x00
        ])
        
        
        // The user visible label in the device's key chain
        public let config: Config
        
        // MARK: - SecKey Manage
        
        /* Gevin added */
        public func importKeyBase64( privateKeyB64: String ) throws{

            let decodedData = Data.init(base64Encoded: privateKeyB64)
            var result = Data()
            let privateKeyStart = x9_62PrivateECHeader.count
            let privateKeyEnd = x9_62PrivateECHeader.count + 32
            let publicKeyStart = privateKeyEnd + 5
            let publicKeyEnd = publicKeyStart + 65
            let private_key_data = decodedData?.subdata(in:privateKeyStart..<privateKeyEnd)
            
            let public_key_data = decodedData?.subdata(in:publicKeyStart..<publicKeyEnd)
            result.append(public_key_data!) 
            result.append(private_key_data!)
            
            // On iOS 10+, we can use SecKeyCreateWithData without going through the keychain
            if #available(iOS 10.0, *), #available(watchOS 3.0, *), #available(tvOS 10.0, *) {
                let keyDict: [CFString: Any] = QueryParam.privateKeyCreate(privateKeyData: result)
                
                var error: Unmanaged<CFError>?
                guard let key = SecKeyCreateWithData(result as CFData, keyDict as CFDictionary, &error) else {
                    let errMsg = "Private key create failed."
                    guard let err = error else {
                        throw Error.inconcistency(message: errMsg)
                    }                    
                    guard let swifterr = err.takeUnretainedValue() as? Error else {
                        throw Error.inconcistency(message: errMsg)
                    }
                    throw Error.underlying(message: errMsg, error: swifterr as NSError )
                }
                try self.forceSaveKey(key, label: config.publicLabel)
                // On iOS 9 and earlier, add a persistent version of the key to the system keychain
            } else {
                
                let persistKey = UnsafeMutablePointer<AnyObject?>(mutating: nil)
                let keyAddDict: [CFString: Any] = QueryParam.privateKeyItemAdd(privateLabel: config.privateLabel, keyData: result)
                let addStatus = SecItemAdd(keyAddDict as CFDictionary, persistKey)
                guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
                    throw Error.osStatus(message: "Private key create failed.", osStatus: addStatus)
                }
                
                let keyCopyDict: [CFString: Any] = QueryParam.privateKeyCopy(privateLabel: config.privateLabel) 
                // Now fetch the SecKeyRef version of the key
                var keyRef: AnyObject? = nil
                let copyStatus = SecItemCopyMatching(keyCopyDict as CFDictionary, &keyRef)
                
                guard keyRef != nil else {
                    throw Error.osStatus(message: "Private key copy failed", osStatus: copyStatus)
                }
            }
                
        }
        
        /* Gevin added */
        public func importKeyBase64( publicKeyB64: String ) throws {
            
            let decodedData = Data.init(base64Encoded: publicKeyB64)
            guard let publicKeyData = decodedData else {
                throw Error.inconcistency(message: "base64 string decode failed.")
            } 
            
            var result = Data()
            let publicKeyStart = x9_62PublicECHeader.count
            let publicKeyEnd = publicKeyData.count
            let public_key_data = decodedData?.subdata(in:publicKeyStart..<publicKeyEnd)
            result.append(public_key_data!) 
            
            // On iOS 10+, we can use SecKeyCreateWithData without going through the keychain
            if #available(iOS 10.0, *), #available(watchOS 3.0, *), #available(tvOS 10.0, *) {
                let keyDict: [CFString: Any] = QueryParam.publicKeyCreate(publicKeyData: result)

                var error: Unmanaged<CFError>?
                guard let key = SecKeyCreateWithData(result as CFData, keyDict as CFDictionary, &error) else {
                    let errMsg = "Public key create failed."
                    guard let err = error else {
                        throw Error.inconcistency(message: errMsg)
                    }                    
                    guard let swifterr = err.takeUnretainedValue() as? Error else {
                        throw Error.inconcistency(message: errMsg)
                    }
                    throw Error.underlying(message: errMsg, error: swifterr as NSError )
                }
                try self.forceSaveKey(key, label: config.publicLabel)
                // On iOS 9 and earlier, add a persistent version of the key to the system keychain
            } else {
                
                let persistKey = UnsafeMutablePointer<AnyObject?>(mutating: nil)
                let keyAddDict: [CFString: Any] = QueryParam.publicKeyItemAdd(publicLabel: config.publicLabel, keyData: result)
                
                let addStatus = SecItemAdd(keyAddDict as CFDictionary, persistKey)
                guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
                    throw Error.osStatus(message: "Public key create failed.", osStatus: addStatus)
                }
                let keyCopyDict: [CFString: Any] = QueryParam.publicKeyCopy(publicLabel: config.publicLabel)
                
                // Now fetch the SecKeyRef version of the key
                var keyRef: AnyObject? = nil
                let copyStatus = SecItemCopyMatching(keyCopyDict as CFDictionary, &keyRef)
                
                guard keyRef != nil else {
                    throw Error.osStatus(message: "Public key copy failed", osStatus: copyStatus)
                }
            }
        }
        
        /* Gevin added */
        public func exportDER( privateKey: PrivateKey ) throws -> Data {
            
            let rawKeyData = try privateKey.exportData()
            var result = Data()
            result.append(Data(x9_62PrivateECHeader))
            // raw data contains private key data(32) + public key data(65) = 97
            let private_key_data = rawKeyData.subdata(in:65..<rawKeyData.count)
            let public_key_data = rawKeyData.subdata(in:0..<65)
            result.append(private_key_data) 
            result.append(Data(x9_62PrivateECHeader_Element))
            result.append(public_key_data)
            
            return result
        }
        
        /* Gevin added */
        public func exportPEM(privateKey: PrivateKey) throws -> String {
            var lines = String()
            lines.append("-----BEGIN PRIVATE KEY-----\n")
            lines.append( try self.exportDER(privateKey: privateKey).base64EncodedString(options: [.lineLength64Characters, .endLineWithCarriageReturn]))
            lines.append("\n-----END PRIVATE KEY-----")
            return lines
            
        }
        
        /* Gevin added */
        public func exportDER( publicKey: PublicKey ) throws -> Data {
            let rawKeyData = try publicKey.exportData()
            var result = Data()
            result.append(Data(x9_62PublicECHeader))
            result.append(rawKeyData)
            return result
        }
        
        /* Gevin added */
        public func exportPEM(publicKey: PublicKey) throws -> String {
            var lines = String()
            lines.append("-----BEGIN PUBLIC KEY-----\n")
            lines.append( try self.exportDER(publicKey: publicKey).base64EncodedString(options: [.lineLength64Characters, .endLineWithCarriageReturn]))
            lines.append("\n-----END PUBLIC KEY-----")
            return lines
        }
        
        public func getPublicKey() throws -> PublicKey {
            let query = QueryParam.publicKeyQuery(labeled: config.publicLabel, 
                                                  accessGroup: config.publicKeyAccessGroup)
            let rawKey: SecKey = try self.fetchSecKey(query) 
            return PublicKey(rawKey)
        }
        
        public func getPrivateKey(context: LAContext? = nil) throws -> PrivateKey {
            let context = context ?? LAContext()
            let query = QueryParam.privateKeyQuery(labeled: config.privateLabel,
                                              accessGroup: config.privateKeyAccessGroup, 
                                              prompt: config.operationPrompt,
                                              context: context)
            let rawKey: SecKey = try self.fetchSecKey(query) 
            return PrivateKey( rawKey, context: context)
        }
        
        func fetchSecKey(_ query: [String: Any]) throws -> SecKey {
            var raw: CFTypeRef?
            logger?("SecItemCopyMatching: \(query)")
            let status = SecItemCopyMatching(query as CFDictionary, &raw)
            guard status == errSecSuccess, let result = raw else {
                throw Error.osStatus(message: "Could not get key for query: \(query)", osStatus: status)
            }
            return result as! SecKey
        }
        
        public func fetchSecKeyPairs(context: LAContext? = nil) throws -> (`public`: PublicKey, `private`: PrivateKey) {
            let privateKey = try getPrivateKey(context: context)
            let publicKey = try getPublicKey()
            return (public: publicKey, private: privateKey)
        }
        
        public func generateKeyPair(context: LAContext? = nil) throws -> (`public`: PublicKey, `private`: PrivateKey) {
            guard config.privateLabel != config.publicLabel else{
                throw Error.inconcistency(message: "Public key and private key can not have same label")
            }
            let context = context ?? LAContext()
            let query = try QueryParam.generateKeyPairQuery(config: config, token: config.token, context: context)
            var publicOptional, privateOptional: SecKey?
            logger?("SecKeyGeneratePair: \(query)")
            let status = SecKeyGeneratePair(query as CFDictionary, &publicOptional, &privateOptional)
            guard status == errSecSuccess else {
                if status == errSecAuthFailed {
                    throw Error.osStatus(message: "Could not generate keypair. Security probably doesn't like the access flags you provided. Specifically if this device doesn't have secure enclave and you pass `.privateKeyUsage`. it will produce this error.", osStatus: status)
                } else {
                    throw Error.osStatus(message: "Could not generate keypair.", osStatus: status)
                }
            }
            guard let publicSec = publicOptional, let privateSec = privateOptional else {
                throw Error.inconcistency(message: "Created private public key pair successfully, but weren't able to retreive it.")
            }
            let publicKey = PublicKey(publicSec)
            let privateKey = PrivateKey(privateSec, context: context)
            try self.forceSaveKey(publicSec, label: config.publicLabel)
            try self.forceSaveKey(privateSec, label: config.privateLabel)
            return (public: publicKey, private: privateKey)
        }
        
        
        func deletePublicKey() throws {
            let query = QueryParam.publicKeyQuery(labeled: config.publicLabel,
                                                  accessGroup: config.publicKeyAccessGroup) as CFDictionary
            logger?("SecItemDelete: \(query)")
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.osStatus(message: "Could not delete public key.", osStatus: status)
            }
        }
        
        func deletePrivateKey() throws {
            let query = QueryParam.privateKeyQuery(labeled: config.privateLabel,
                                                   accessGroup: config.privateKeyAccessGroup,
                                                   prompt: nil,
                                                   context: nil) as CFDictionary
            logger?("SecItemDelete: \(query)")
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.osStatus(message: "Could not delete private key.", osStatus: status)
            }
        }
        
        public func delete() throws {
            try self.deletePublicKey()
            try self.deletePrivateKey()
        }
        
        func forceSaveKey(_ rawKey: SecKey, label: String) throws {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrLabel as String: label,
                kSecValueRef as String: rawKey
            ]
            var raw: CFTypeRef?
            logger?("SecItemAdd: \(query)")
            var status = SecItemAdd(query as CFDictionary, &raw)
            if status == errSecDuplicateItem {
                logger?("SecItemDelete: \(query)")
                status = SecItemDelete(query as CFDictionary)
                logger?("SecItemAdd: \(query)")
                status = SecItemAdd(query as CFDictionary, &raw)
            }
            if status == errSecInvalidRecord {
                throw Error.osStatus(message: "Could not save public key. It is possible that the access control you have provided is not supported on this OS and/or hardware.", osStatus: status)
            } else if status != errSecSuccess {
                throw Error.osStatus(message: "Could not save public key", osStatus: status)
            }
        }
        
        // MARK: - Sign & Verify
        
        @available(iOS 10.0, *)
        public func sign(_ digest: Data, privateKey: PrivateKey, hash: Hash) throws -> Data {
            Helper.logToConsoleIfExecutingOnMainThread()
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateSignature(privateKey.rawKey, hash.signatureMessage, digest as CFData, &error)
            guard let signature = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not create signature.")
            }
            return signature as Data
        }
        
        @available(OSX, unavailable)
        @available(iOS, deprecated: 10.0, message: "This method and extra complexity will be removed when 9.0 is obsolete.")
        public func signUsingSha256(_ digest: Data, privateKey: PrivateKey) throws -> Data {
            #if os(iOS)
                Helper.logToConsoleIfExecutingOnMainThread()
                let digestToSign = digest.sha256()
                
                var digestToSignBytes = [UInt8](repeating: 0, count: digestToSign.count)
                digestToSign.copyBytes(to: &digestToSignBytes, count: digestToSign.count)
                
                var signatureBytes = [UInt8](repeating: 0, count: 128)
                var signatureLength = 128
                
                let signErr = SecKeyRawSign(privateKey.rawKey, .PKCS1, &digestToSignBytes, digestToSignBytes.count, &signatureBytes, &signatureLength)
                guard signErr == errSecSuccess else {
                    throw Error.osStatus(message: "Could not create signature.", osStatus: signErr)
                }
                
                let signature = Data(bytes: &signatureBytes, count: signatureLength)
                return signature
            #else
                throw Error.inconcistency(message: "Should be unreachable.")
            #endif
        }
        
        @available(iOS 10.0, *)
        public func verify(signature: Data, digest: Data, publicKey: PublicKey, hash: Hash) throws {
            var error : Unmanaged<CFError>?
            let valid = SecKeyVerifySignature(publicKey.rawKey, hash.signatureMessage, digest as CFData, signature as CFData, &error)
            if let error = error?.takeRetainedValue() {
                throw Error.fromError(error, message: "Could not verify signature.")
            }
            guard valid == true else {
                throw Error.inconcistency(message: "Signature yielded no error, but still marks itself as unsuccessful")
            }
        }
        
        @available(OSX, unavailable)
        @available(iOS, deprecated: 10.0, message: "This method and extra complexity will be removed when 9.0 is obsolete.")
        public func verifyUsingSha256(signature: Data, digest: Data, publicKey: PublicKey) throws {
            #if os(iOS)
                let sha = digest.sha256()
                var shaBytes = [UInt8](repeating: 0, count: sha.count)
                sha.copyBytes(to: &shaBytes, count: sha.count)
                
                var signatureBytes = [UInt8](repeating: 0, count: signature.count)
                signature.copyBytes(to: &signatureBytes, count: signature.count)
                
                let status = SecKeyRawVerify(publicKey.rawKey, .PKCS1, &shaBytes, shaBytes.count, &signatureBytes, signatureBytes.count)
                guard status == errSecSuccess else {
                    throw Error.osStatus(message: "Could not verify signature.", osStatus: status)
                }
            #else
                throw Error.inconcistency(message: "Should be unreachable.")
            #endif
        }
        
        @available(iOS 10.3, *)
        public func encrypt(_ digest: Data, publicKey: PublicKey, hash: Hash) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateEncryptedData(publicKey.rawKey, hash.encryptionEciesEcdh, digest as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not encrypt.")
            }
            return data as Data
        }
        
        @available(iOS 10.3, *)
        public func decrypt(_ encrypted: Data, privateKey: PrivateKey, hash: Hash) throws -> Data {
            Helper.logToConsoleIfExecutingOnMainThread()
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateDecryptedData(privateKey.rawKey, hash.encryptionEciesEcdh, encrypted as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not decrypt.")
            }
            return data as Data
        }
        
        public static func logToConsoleIfExecutingOnMainThread() {
            if Thread.isMainThread {
                let _ = LogOnce.shouldNotBeMainThread
            }
        }
    }
    
    private struct LogOnce {
        static var shouldNotBeMainThread: Void = {
            print("[WARNING] \(EllipticCurveKeyPair.self): Decryption and signing should be done off main thread because LocalAuthentication may need the thread to show UI. This message is logged only once.")
        }()
    }
    
    private struct QueryParam {
        
        /* Gevin added */
        static func publicKeyCreate( publicKeyData: Data ) -> [CFString:Any] {
            let sizeInBits = publicKeyData.count * 8
            let createParam:[CFString:Any] = [
                kSecAttrKeyType: QueryParam.ECKeyType(),
                kSecAttrKeyClass: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits: NSNumber(value: sizeInBits),
                kSecReturnPersistentRef: true
            ]
            return createParam
        }
        
        /* Gevin added */
        static func privateKeyCreate( privateKeyData: Data ) -> [CFString:Any] {
            let sizeInBits = privateKeyData.count * 8
            let createParam:[CFString:Any] = [
                kSecAttrKeyType: Constants.attrKeyTypeEllipticCurve,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits: NSNumber(value: sizeInBits),
                kSecReturnPersistentRef: true
            ]
            return createParam
        }
        
        /* Gevin added */
        static func publicKeyQuery(labeled: String, accessGroup: String?) -> [String:Any] {
            var params: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrLabel as String: labeled,
                kSecReturnRef as String: true,
            ]
            if let accessGroup = accessGroup {
                params[kSecAttrAccessGroup as String] = accessGroup
            }
            return params
        }
        
        /* Gevin added */
        static func privateKeyCopy( privateLabel: String ) -> [CFString:Any] {
            let keyCopyDict: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: privateLabel,
                kSecAttrKeyType: Constants.attrKeyTypeEllipticCurve,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
                kSecReturnRef: true,
                ]
            return keyCopyDict
        }
        
        /* Gevin added */
        static func privateKeyItemAdd( privateLabel: String, keyData: Data ) -> [CFString:Any] {
            let keyAddDict: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: privateLabel,
                kSecAttrKeyType: Constants.attrKeyTypeEllipticCurve,
                kSecValueData: keyData,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecReturnPersistentRef: true,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked
            ]
            return keyAddDict
        }
        
        /* Gevin added */
        static func publicKeyCopy( publicLabel: String ) -> [CFString:Any] {
            let keyCopyDict: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: publicLabel,
                kSecAttrKeyType: Constants.attrKeyTypeEllipticCurve,
                kSecAttrKeyClass: kSecAttrKeyClassPublic,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
                kSecReturnRef: true,
                ]
            return keyCopyDict
        }
        
        /* Gevin added */
        static func publicKeyItemAdd( publicLabel: String, keyData: Data ) -> [CFString:Any] {
            let keyAddDict: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: publicLabel,
                kSecAttrKeyType: Constants.attrKeyTypeEllipticCurve,
                kSecValueData: keyData,
                kSecAttrKeyClass: kSecAttrKeyClassPublic,
                kSecReturnPersistentRef: true,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked
            ]
            return keyAddDict
        }
        
        
        static func privateKeyQuery(labeled: String, accessGroup: String?, prompt: String?, context: LAContext?) -> [String: Any] {
            var params: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrLabel as String: labeled,
                kSecReturnRef as String: true,
                ]
            if let accessGroup = accessGroup {
                params[kSecAttrAccessGroup as String] = accessGroup
            }
            if let prompt = prompt {
                params[kSecUseOperationPrompt as String] = prompt
            }
            if let context = context {
                params[kSecUseAuthenticationContext as String] = context
            }
            return params
        }
        
        static func generateKeyPairQuery(config: Config, token: Token, context: LAContext? = nil) throws -> [String:Any] {
            
            /* ========= private ========= */
            var privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: config.privateLabel,
                kSecAttrIsPermanent as String: true,
                kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow,
                ]
            if let privateKeyAccessGroup = config.privateKeyAccessGroup {
                privateKeyParams[kSecAttrAccessGroup as String] = privateKeyAccessGroup
            }
            if let context = context {
                privateKeyParams[kSecUseAuthenticationContext as String] = context
            }
            
            // On iOS 11 and lower: access control with empty flags doesn't work
            if !config.privateKeyAccessControl.flags.isEmpty {
                privateKeyParams[kSecAttrAccessControl as String] = try config.privateKeyAccessControl.underlying()
            } else {
                privateKeyParams[kSecAttrAccessible as String] = config.privateKeyAccessControl.protection
            }
            
            /* ========= public ========= */
            var publicKeyParams: [String: Any] = [
                kSecAttrLabel as String: config.publicLabel,
                ]
            if let publicKeyAccessGroup = config.publicKeyAccessGroup {
                publicKeyParams[kSecAttrAccessGroup as String] = publicKeyAccessGroup
            }
            
            // On iOS 11 and lower: access control with empty flags doesn't work
            if !config.publicKeyAccessControl.flags.isEmpty {
                publicKeyParams[kSecAttrAccessControl as String] = try config.publicKeyAccessControl.underlying()
            } else {
                publicKeyParams[kSecAttrAccessible as String] = config.publicKeyAccessControl.protection
            }
            
            /* ========= combined ========= */
            var params: [String: Any] = [
                kSecAttrKeyType as String: Constants.attrKeyTypeEllipticCurve,
                kSecPrivateKeyAttrs as String: privateKeyParams,
                kSecPublicKeyAttrs as String: publicKeyParams,
                kSecAttrKeySizeInBits as String: 256,
                ]
            if token == .secureEnclave {
                params[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            }
            return params
        }
        
        static func ECKeyType() -> String {
            if #available(iOS 10.0, *) {
                return kSecAttrKeyTypeECSECPrimeRandom as String
            } else {
                return kSecAttrKeyTypeEC as String
            }
        }
    }
    
    public struct Constants {        
        public static let noCompression: UInt8 = 4
        public static let attrKeyTypeEllipticCurve: String = {
            if #available(iOS 10.0, *) {
                return kSecAttrKeyTypeECSECPrimeRandom as String
            } else {
                return kSecAttrKeyTypeEC as String
            }
        }()
    }
    
    public class Key {
        
        public let rawKey: SecKey
        
        internal init(_ underlying: SecKey) {
            self.rawKey = underlying
        }
        
        private var cachedAttributes: [String:Any]? = nil
        
        public func attributes() throws -> [String:Any] {
            if let attributes = cachedAttributes {
                return attributes
            } else {
                let attributes = try queryAttributes()
                cachedAttributes = attributes
                return attributes
            }
        }
        
        public func label() throws -> String {
            guard let attribute = try self.attributes()[kSecAttrLabel as String] as? String else {
                throw Error.inconcistency(message: "We've got a private key, but we are missing its label.")
            }
            return attribute
        }
        
        public func accessGroup() throws -> String? {
            return try self.attributes()[kSecAttrAccessGroup as String] as? String
        }
        
        public func accessControl() throws -> SecAccessControl {
            guard let attribute = try self.attributes()[kSecAttrAccessControl as String] else {
                throw Error.inconcistency(message: "We've got a private key, but we are missing its access control.")
            }
            return attribute as! SecAccessControl
        }
        
        private func queryAttributes() throws -> [String:Any] {
            var matchResult: AnyObject? = nil
            let query: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecValueRef as String: rawKey,
                kSecReturnAttributes as String: true
            ]
            logger?("SecItemCopyMatching: \(query)")
            let status = SecItemCopyMatching(query as CFDictionary, &matchResult)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not read attributes for key", osStatus: status)
            }
            guard let attributes = matchResult as? [String:Any] else {
                throw Error.inconcistency(message: "Tried reading key attributes something went wrong. Expected dictionary, but received \(String(describing: matchResult)).")
            }
            return attributes
        }
        
        
        func exportData() throws -> Data {
            if #available(iOS 10.0, *) {
                var error : Unmanaged<CFError>?
                guard let raw = SecKeyCopyExternalRepresentation(rawKey, &error) else {
                    throw EllipticCurveKeyPair.Error.fromError(error?.takeRetainedValue(), message: "Tried reading public key bytes.")
                }
                return raw as Data
            }
            else{
                var matchResult: AnyObject? = nil
                let query: [String:Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecValueRef as String: rawKey,
                    kSecReturnData as String: true
                ]
                logger?("SecItemCopyMatching: \(query)")
                let status = SecItemCopyMatching(query as CFDictionary, &matchResult)
                guard status == errSecSuccess else {
                    throw Error.osStatus(message: "Could not generate keypair", osStatus: status)
                }
                guard let keyRaw = matchResult as? Data else {
                    throw Error.inconcistency(message: "Tried reading public key bytes. Expected data, but received \(String(describing: matchResult)).")
                }
                return keyRaw
            }
        }
    }
    
    public final class PublicKey: Key {

    }
    
    public final class PrivateKey: Key {
        
        public private(set) var context: LAContext?
        
        internal init(_ underlying: SecKey, context: LAContext?) {
            super.init(underlying)
            self.context = context
        }
        
        public func isStoredOnSecureEnclave() throws -> Bool {
            let attribute = try self.attributes()[kSecAttrTokenID as String] as? String
            return attribute == (kSecAttrTokenIDSecureEnclave as String)
        }
    }
    
    public final class AccessControl {
        
        // E.g. kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        public let protection: CFTypeRef
        
        // E.g. [.userPresence, .privateKeyUsage]
        public let flags: SecAccessControlCreateFlags
        
        public init(protection: CFTypeRef, flags: SecAccessControlCreateFlags) {
            self.protection = protection
            self.flags = flags
        }
        
        public func underlying() throws -> SecAccessControl {
            if flags.contains(.privateKeyUsage) {
                let flagsWithOnlyPrivateKeyUsage: SecAccessControlCreateFlags = [.privateKeyUsage]
                guard flags != flagsWithOnlyPrivateKeyUsage else {
                    throw EllipticCurveKeyPair.Error.inconcistency(message: "Couldn't create access control flag. Keychain chokes if you try to create access control with only [.privateKeyUsage] on devices older than iOS 11 and macOS 10.13.x")
                }
            }
            
            var error: Unmanaged<CFError>?
            let result = SecAccessControlCreateWithFlags(kCFAllocatorDefault, protection, flags, &error)
            guard let accessControl = result else {
                throw EllipticCurveKeyPair.Error.fromError(error?.takeRetainedValue(), message: "Tried creating access control object with flags \(flags) and protection \(protection)")
            }
            return accessControl
        }
    }
    
    public enum Error: LocalizedError {
        
        case underlying(message: String, error: NSError)
        case inconcistency(message: String)
        case authentication(error: LAError)
        
        public var errorDescription: String? {
            switch self {
            case let .underlying(message: message, error: error):
                return "\(message) \(error.localizedDescription)"
            case let .authentication(error: error):
                return "Authentication failed. \(error.localizedDescription)"
            case let .inconcistency(message: message):
                return "Inconcistency in setup, configuration or keychain. \(message)"
            }
        }
        
        internal static func osStatus(message: String, osStatus: OSStatus) -> Error {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(osStatus), userInfo: [
                NSLocalizedDescriptionKey: message,
                NSLocalizedRecoverySuggestionErrorKey: "See https://www.osstatus.com/search/results?platform=all&framework=all&search=\(osStatus)"
                ])
            return .underlying(message: message, error: error)
        }
        
        internal static func probablyAuthenticationError(underlying: NSError) -> Error {
            return Error.authentication(error: .init(_nsError: NSError(domain: LAErrorDomain, code: LAError.authenticationFailed.rawValue, userInfo: [
                NSLocalizedFailureReasonErrorKey: "Found public key, but couldn't find or access private key. The errSecItemNotFound error is sometimes wrongfully reported when LAContext authentication fails",
                NSUnderlyingErrorKey: underlying
                ])))
        }
        
        internal static func fromError(_ error: CFError?, message: String) -> Error {
            let any = error as Any
            if let authenticationError = any as? LAError {
                return .authentication(error: authenticationError)
            }
            if let error = error,
                let domain = CFErrorGetDomain(error) as String? {
                let code = Int(CFErrorGetCode(error))
                var userInfo = (CFErrorCopyUserInfo(error) as? [String:Any]) ?? [String:Any]()
                if userInfo[NSLocalizedRecoverySuggestionErrorKey] == nil {
                    userInfo[NSLocalizedRecoverySuggestionErrorKey] = "See https://www.osstatus.com/search/results?platform=all&framework=all&search=\(code)"
                }
                let underlying = NSError(domain: domain, code: code, userInfo: userInfo)
                return .underlying(message: message, error: underlying)
            }
            return .inconcistency(message: "\(message) Unknown error occured.")
        }
        
    }
    
    @available(iOS 10.0, *)
    public enum Hash: String {
        
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        
        @available(iOS 10.0, *)
        var signatureMessage: SecKeyAlgorithm {
            switch self {
            case .sha1:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA1
            case .sha224:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224
            case .sha256:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
            case .sha384:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
            case .sha512:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
            }
        }
        
        @available(iOS 10.0, *)
        var encryptionEciesEcdh: SecKeyAlgorithm {
            switch self {
            case .sha1:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA1AESGCM
            case .sha224:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA224AESGCM
            case .sha256:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM
            case .sha384:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA384AESGCM
            case .sha512:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA512AESGCM
            }
        }
    }
    
    public enum Token {
        case secureEnclave
        case keychain
        
        public static var secureEnclaveIfAvailable: Token {
            return Device.hasSecureEnclave ? .secureEnclave : .keychain
        }
    }
    
    public enum Device {
        
        public static var hasTouchID: Bool {
            if #available(OSX 10.12.2, *) {
                return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            } else {
                return false
            }
        }
        
        public static var isSimulator: Bool {
            return TARGET_OS_SIMULATOR != 0
        }
        
        public static var hasSecureEnclave: Bool {
            return hasTouchID && !isSimulator
        }
        
    }
}

extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }
    
    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }
}
