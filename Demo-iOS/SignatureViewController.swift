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

import UIKit
import LocalAuthentication
import EllipticCurveKeyPair

class SignatureViewController: UIViewController {
    
    lazy var keypair: EllipticCurveKeyPair.Manager = {
        EllipticCurveKeyPair.logger = { print($0) }
        let publicAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAlwaysThisDeviceOnly, flags: [])
        let privateAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: {
            return EllipticCurveKeyPair.Device.hasSecureEnclave ? [.userPresence, .privateKeyUsage] : [.userPresence]
        }())
        let config = EllipticCurveKeyPair.Config(
            publicLabel: "wacare.sign.public",
            privateLabel: "wacare.sign.private",
            operationPrompt: "Sign transaction",
            publicKeyAccessControl: publicAccessControl,
            privateKeyAccessControl: privateAccessControl,
            token: .secureEnclaveIfAvailable)
        return EllipticCurveKeyPair.Manager(config: config)
    }()
    
//    var context: LAContext! = LAContext()
    
    @IBOutlet weak var publicKeyTextView: UITextView!
    @IBOutlet weak var digestTextView: UITextView!
    @IBOutlet weak var signatureTextView: UITextView!
    @IBOutlet weak var verifyResultLabel: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        do {
//            try self.keypair.deleteKeyPair()
            // 下面這組 key 是用 java 產生，因為之後要跟 java 對接
            // public ECC
            let publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV+PBO2YXn+WPiRmipqOtjAaNYfQqtCuNgZyMFaXAlCUmnVUM7jpsYsyrrSBcetLm4QYtIANERp6PlOh6Uy9Ylg=="
            // private ECC
            let privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnszUJEAiYjU0qrbXp8Y/p7OwqC83HXvBTHo7Yluh4i2hRANCAARX48E7Zhef5Y+JGaKmo62MBo1h9Cq0K42BnIwVpcCUJSadVQzuOmxizKutIFx60ubhBi0gA0RGno+U6HpTL1iW"

            // import exist key 
            try keypair.importPrivateKeyB64(privateKey)
            try keypair.importPublicKeyB64(publicKey)
            
            // generate key pair
//            try keypair.generateKeyPair()
            
            // 輸出 key 
            let privateKeyData = try keypair.privateKeyDER()
            let publicKeyData = try keypair.publicKeyDER()
            let private_data: String = GTMBase64.string(byEncoding: privateKeyData)
            let public_data: String = GTMBase64.string(byEncoding: publicKeyData)

            let privateKeyPem = try keypair.privateKeyPEM()
            let publicKeyPem = try keypair.publicKeyPEM()
            print("private key:\n\(private_data)")
            print("public key:\n\(public_data)")
            
            publicKeyTextView.text = "\(privateKeyPem)\n\n\(publicKeyPem)"
        } catch {
            publicKeyTextView.text = "Error: \(error)"
            print("Error: \(error)")
        }
    }
    
    @IBAction func regeneratePublicKey(_ sender: Any) {
        do {
            try keypair.deleteKeyPair()
            publicKeyTextView.text = try keypair.publicKeyPEM()
        } catch {
            publicKeyTextView.text = "Error: \(error)"
        }
    }
    
    var cycleIndex = 0
    let digests = ["Lorem ipsum dolor sit amet", "mei nibh tritani ex", "exerci periculis instructior est ad"]
    
    @IBAction func createDigest(_ sender: Any) {
        cycleIndex += 1
        digestTextView.text = digests[cycleIndex % digests.count]
    }
    
    @IBAction func sign(_ sender: Any) {
        
        /*
         
         1. 兩方會產生兩組 private key , public key
         以 a b 來表示兩方
         a                 b
         a privatekey  |   b privatekey
         a publickey   |   b publickey

         2. 雙方交換公鑰
         a                 b
         a privatekey  |   b privatekey
         b publickey   |   a publickey
         
         3. a 送訊給 b，的詳細步驟會是
            1 a 先對訊息明文做 sha256 編碼算出 hash
            2 a 用 a privatekey 對 hash 做加密
            3 a 把加密後的 data 送給對方，此加密後的data 即為 sign(簽章)
        
         4. b 收到加密訊息與簽章後
            1 b 解密訊息
            2 b 把解密明文做 sha256 編碼，取得 hash1
            3 b 把 sign 用 a publickey 做解密，取得 hash2
            4 b 把 hash1 跟 hash2 做比對，檢查兩者是否一致，一致的話表示驗證通過
         
         */
        guard let digest = self.digestTextView.text?.data(using: .utf8) else {
            self.signatureTextView.text = "Missing text in unencrypted text field"
            return
        }

        //------------------------
        // sign
        //------------------------
        var signData: Data?
        do{
            signData = try self.keypair.signUsingSha256(digest)
        } catch {
            print("sign error: \(error)")
            self.signatureTextView.text = "Sign Error: \(error)"
        }
        
        guard let signature = signData else {
            return
        }
        
        //------------------------
        // verify
        //------------------------
        do{
            let sign_b64 = signature.base64EncodedString()
            print("sign: \(sign_b64)")
            self.signatureTextView.text = sign_b64
            try self.keypair.verifyUsingSha256(signature: signature, originalDigest: digest)
            let result = try printVerifySignatureInOpenssl(manager: self.keypair, signed: signature, digest: digest, hashAlgorithm: "sha256")
            self.verifyResultLabel.text = "verify success!\n\(result)"
        } catch {
            print("verify error: \(error)")
            self.signatureTextView.text = "Verify Error: \(error)"
        }
    }
    
}

