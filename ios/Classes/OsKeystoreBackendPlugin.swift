import Flutter
import UIKit
import LocalAuthentication
import Security

public class OsKeystoreBackendPlugin: NSObject, FlutterPlugin {
    
    /// Fixed 26-byte ASN.1/SPKI header for uncompressed P-256 public keys.
    private static let p256SpkiHeader = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00
    ])

    enum OsKeystoreBackendPluginError: Error {
        case keyNotFound(message: String)
        case unsupportedAlgorithm(message: String)
        case deletionError(status: OSStatus)
        case argumentError(message: String)
        case failedToCreateAccessControl(description: String)
        case ecdhError(message: String)
    }

    enum AuthType: Int { case deviceCredential = 1; case biometricOnly = 2; case deviceCredentialOrBiometric = 3; case userPresence = 4 }

    private var channel: FlutterMethodChannel?

    // MARK: - FlutterPlugin conformance

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "os_keystore_backend",
                                           binaryMessenger: registrar.messenger())
        let instance = OsKeystoreBackendPlugin()
        instance.channel = channel
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "getPlatformVersion":
            result("iOS " + UIDevice.current.systemVersion)
            
        case "generateKey":
            do { 
              try handleGenerateKey(call: call, result: result)
            } catch (OsKeystoreBackendPluginError.keyNotFound(let message)) {
                result(FlutterError(code: "generateKey.keyNotFound", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.unsupportedAlgorithm(let message)) {
                result(FlutterError(code: "generateKey.unsuppoertedAlgorithm", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.argumentError(let message)) {
                result(FlutterError(code: "generateKey.argumentError", message: message, details: nil))
            } catch {
                result(FlutterError(code: "generateKey", message: "Unknown error", details: nil))
            }
            
        case "sign":
            do { 
              try handleSign(call: call, result: result)
            } catch (OsKeystoreBackendPluginError.keyNotFound(let message)) {
                result(FlutterError(code: "sign.keyNotFound", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.unsupportedAlgorithm(let message)) {
                result(FlutterError(code: "sign.unsuppoertedAlgorithm", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.argumentError(let message)) {
                result(FlutterError(code: "sign.argumentError", message: message, details: nil))
            } catch {
                result(FlutterError(code: "sign", message: "Unknown error", details: nil))
            }

        case "verify":
            do { 
              try handleVerify(call: call, result: result)
            } catch (OsKeystoreBackendPluginError.keyNotFound(let message)) {
                result(FlutterError(code: "verify.keyNotFound", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.unsupportedAlgorithm(let message)) {
                result(FlutterError(code: "verify.unsuppoertedAlgorithm", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.argumentError(let message)) {
                result(FlutterError(code: "verify.argumentError", message: message, details: nil))
            } catch {
                result(FlutterError(code: "verify", message: "Unknown error", details: nil))
            }
            
        case "getKeyInfo":
            do { 
              try handleGetKeyInfo(call: call, result: result)
            } catch (OsKeystoreBackendPluginError.keyNotFound(let message)) {
                result(FlutterError(code: "getKeyInfo.keyNotFound", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.unsupportedAlgorithm(let message)) {
                result(FlutterError(code: "getKeyInfo.unsuppoertedAlgorithm", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.argumentError(let message)) {
                result(FlutterError(code: "getKeyInfo.argumentError", message: message, details: nil))
            } catch {
                result(FlutterError(code: "getKeyInfo", message: "Unknown error", details: nil))
            }

        case "hasKey":
            do { 
              try handleHasKey(call: call, result: result)
            } catch (OsKeystoreBackendPluginError.keyNotFound(let message)) {
                result(false) // for consumers that iterate through multiple keystores, errors might cause a crash
            } catch (OsKeystoreBackendPluginError.unsupportedAlgorithm(let message)) {
                result(FlutterError(code: "hasKey.unsuppoertedAlgorithm", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.argumentError(let message)) {
                result(FlutterError(code: "hasKey.argumentError", message: message, details: nil))
            } catch {
                result(FlutterError(code: "hasKey", message: "Unknown error", details: nil))
            }
            
            
        case "deleteKey":
            do { 
              try handleDeleteKey(call: call, result: result)
            } catch (OsKeystoreBackendPluginError.keyNotFound(let message)) {
                result(FlutterError(code: "deleteKey.keyNotFound", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.unsupportedAlgorithm(let message)) {
                result(FlutterError(code: "deleteKey.unsuppoertedAlgorithm", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.argumentError(let message)) {
                result(FlutterError(code: "deleteKey.argumentError", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.deletionError(let status)) {
                result(FlutterError(code: "deleteKey.deletionError", message: "Error: \(status)", details: nil))
            } catch {
                result(FlutterError(code: "deleteKey", message: "Unknown error", details: nil))
            }

        case "performEcdh":
            do {
              try handlePerformEcdh(call: call, result: result)
            } catch (OsKeystoreBackendPluginError.keyNotFound(let message)) {
                result(FlutterError(code: "performEcdh.keyNotFound", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.unsupportedAlgorithm(let message)) {
                result(FlutterError(code: "performEcdh.unsuppoertedAlgorithm", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.argumentError(let message)) {
                result(FlutterError(code: "performEcdh.argumentError", message: message, details: nil))
            } catch (OsKeystoreBackendPluginError.ecdhError(let message)) {
                result(FlutterError(code: "ECDH_FAILED", message: message, details: nil))
            } catch {
                result(FlutterError(code: "performEcdh", message: "Unknown error", details: nil))
            }
            
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - Private methods to mimic Kotlin structure

    private func handleGenerateKey(call: FlutterMethodCall, result: @escaping FlutterResult) throws {
        do {
            let context = LAContext()
            
            // this ensures that at least the passcode is set
            if !context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
                throw OsKeystoreBackendPluginError.failedToCreateAccessControl(description: "No authentication enrolled on device")
            }
            // https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
            let args = call.arguments as? [String: Any]
            guard let curve = args?["curve"] as? String else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing curve argument")
            }
            guard let userAuthenticationRequired = args?["userAuthenticationRequired"] as? Bool else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing userAuthenticationRequired argument")
            }
            guard let authTypeRawValue = args?["authType"] as? Int,
                  let authType = AuthType(rawValue: authTypeRawValue) else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing authType argument")
            }
            guard let invalidateByNewBiometric = args?["invalidateByNewBiometric"] as? Bool else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing invalidateByNewBiometric argument")
            }
            let allowKeyAgreement = args?["allowKeyAgreement"] as? Bool ?? false
            if allowKeyAgreement && userAuthenticationRequired {
                throw OsKeystoreBackendPluginError.argumentError(
                    message: "allowKeyAgreement requires userAuthenticationRequired to be false")
            }
            
            // since we dont know the public key when creating the key we create a uuid instead
            let uniqueID = UUID().uuidString
            
            // set the correct access control flags based on the authType
            var accessControlFlags: SecAccessControlCreateFlags = []
            switch authType {
                case .deviceCredential:
                    accessControlFlags = [.privateKeyUsage, .devicePasscode]
                case .biometricOnly:
                    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
                        
                        if(invalidateByNewBiometric) {
                            accessControlFlags = [.privateKeyUsage, .biometryCurrentSet]
                        } else {
                            accessControlFlags = [.privateKeyUsage, .biometryAny]
                        }
                    } else {
                        throw OsKeystoreBackendPluginError.argumentError(message: "biometrics are not setup on this device")
                    }
                case .deviceCredentialOrBiometric:
                    // @note: invalidateByNewBiometric does not invalidate deviceCredential.
                    // 1. user generates key (key is accessable through biometrics OR passcode)
                    // 2. user deletes face
                    // 3. user tries to access key (like signing) -> passcode prompt will still pop up and be valid for access
                    accessControlFlags = [.privateKeyUsage, .devicePasscode]
                    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
                        if(invalidateByNewBiometric) {
                            accessControlFlags.insert(.or)
                            accessControlFlags.insert(.biometryCurrentSet)
                        } else {
                            accessControlFlags.insert(.or)
                            accessControlFlags.insert(.biometryAny)
                        }
                    } else {
                        throw OsKeystoreBackendPluginError.argumentError(message: "biometrics are not setup on this device")
                    }
                case .userPresence:
                    accessControlFlags = [.privateKeyUsage, .userPresence]
            }
            
            let access: SecAccessControl = try {
                let flags: SecAccessControlCreateFlags = userAuthenticationRequired ? accessControlFlags : .privateKeyUsage
                var createAccessControlError: Unmanaged<CFError>?  // Declare an error object to be passed
                
                let accessControl = SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    flags,
                    &createAccessControlError
                )
                
                if let createAccessControlError = createAccessControlError {
                    let errorDescription = createAccessControlError.takeUnretainedValue() as Error
                    print(errorDescription)
                    throw OsKeystoreBackendPluginError.failedToCreateAccessControl(description: errorDescription.localizedDescription)
                }
                
                else { return accessControl! }
            }()
            
            var attributes: NSDictionary = [:]
            if curve == "secp256r1" {
                // apple only supports NIST P-256 elliptic curve keys in the secure enclave OR keychain (secp256r1)
                attributes = [
                    kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                    kSecAttrKeySizeInBits: 256,
                    kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
                    kSecPrivateKeyAttrs: [
                        kSecAttrIsPermanent: true,
                        kSecAttrApplicationTag: uniqueID.data(using: .utf8)!,
                        kSecAttrAccessControl: access,
                        kSecAttrCanDerive: allowKeyAgreement
                    ]
                ]
            }
            /* // 384 and 512 will give error -25311 and -50 indicating that those key sizes are not supported by the keychain for elyptic curves
             else if curve == "secp384r1" {
             attributes = [
             kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
             kSecAttrKeySizeInBits: 384,
             kSecPrivateKeyAttrs: [
             kSecAttrIsPermanent: true,
             kSecAttrApplicationTag: uniqueID.data(using: .utf8)!,
             kSecAttrAccessControl: access
             ]
             ]
             } else if curve == "secp512r1" {
             attributes = [
             kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
             kSecAttrKeySizeInBits: 512,
             kSecPrivateKeyAttrs: [
             kSecAttrIsPermanent: true,
             kSecAttrApplicationTag: uniqueID.data(using: .utf8)!,
             kSecAttrAccessControl: access
             ]
             ]
             } */
            else {
                throw OsKeystoreBackendPluginError.unsupportedAlgorithm(message: "iOS only supports secp256r1 for keychain storage")
            }
            
            var error: Unmanaged<CFError>?
            /*
             The private key is logically part of the keychain, and you can later obtain a reference
             to it. But the key data is encoded, and only the Secure Enclave can make
             use of the key.
             */
            guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            
            result(uniqueID)
        }
        catch let e as OsKeystoreBackendPluginError {
            result(e.asFlutterError)
        }
        catch {
            result(FlutterError(code: "UNEXPECTED", message: error.localizedDescription, details: nil))
        }
    }

    private func handleSign(call: FlutterMethodCall, result: @escaping FlutterResult) throws {
        do {
            let args = call.arguments as? [String: Any]
            guard let data = args?["data"] as? FlutterStandardTypedData else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing data argument")
            }
            guard let keyId = args?["keyId"] as? String else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing keyId argument")
            }
            
            let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                kSecAttrApplicationTag as String: keyId,
                                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                kSecReturnRef as String: true]
            
            var item: CFTypeRef?
            let status = SecItemCopyMatching(getquery as CFDictionary, &item)
            guard status == errSecSuccess else { throw OsKeystoreBackendPluginError.keyNotFound(message: "Error: Copying public key failed")}
            let key: SecKey = item as! SecKey

            let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256

            guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
                throw OsKeystoreBackendPluginError.unsupportedAlgorithm(message: "Algorithm not supported")
            }
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(key, algorithm, data.data as CFData, &error) else {
                throw error!.takeRetainedValue() as Error
            }

            // Return signature
            result(FlutterStandardTypedData(bytes: signature as Data))
        }
        catch let e as OsKeystoreBackendPluginError {
            result(e.asFlutterError)
        }
        catch {
            result(FlutterError(code: "UNEXPECTED", message: error.localizedDescription, details: nil))
        }
    }

    private func handleVerify(call: FlutterMethodCall, result: @escaping FlutterResult) throws {
        do {
            let args = call.arguments as? [String: Any]
            guard let data = args?["data"] as? FlutterStandardTypedData else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing data argument")
            }
            guard let signature = args?["signature"] as? FlutterStandardTypedData else {
            throw OsKeystoreBackendPluginError.argumentError(message: "Missing signature argument")
            }

            guard let keyId = args?["keyId"] as? String else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing keyId argument")
            }

            let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                            kSecAttrApplicationTag as String: keyId,
                            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                            kSecReturnRef as String: true]
            
            var item: CFTypeRef?
            let status = SecItemCopyMatching(getquery as CFDictionary, &item)
            guard status == errSecSuccess else { throw OsKeystoreBackendPluginError.keyNotFound(message: "Error: Copying public key failed with") }
            let key = item as! SecKey
            guard let publicKey = SecKeyCopyPublicKey(key) else {
                throw OsKeystoreBackendPluginError.keyNotFound(message: "Error: Copying public key failed")
            }
            let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
            
            var error: Unmanaged<CFError>?

            guard SecKeyVerifySignature(publicKey,
                                        algorithm,
                                        data.data as CFData,
                                        signature.data as CFData,
                                        &error) else {
                                            result(false)
                                            return
            }
            
            result(true)
        }
        catch let e as OsKeystoreBackendPluginError {
            result(e.asFlutterError)
        }
        catch {
            result(FlutterError(code: "UNEXPECTED", message: error.localizedDescription, details: nil))
        }
    }

    private func handleGetKeyInfo(call: FlutterMethodCall, result: @escaping FlutterResult) throws {
        do {
            // first we check if that key exist and is a private key
            let args = call.arguments as? [String: Any]

            guard let keyId = args?["keyId"] as? String else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing keyId argument")
            }
            
            let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                            kSecAttrApplicationTag as String: keyId,
                            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                            kSecReturnRef as String: true]
            
            var item: CFTypeRef?
            let status = SecItemCopyMatching(getquery as CFDictionary, &item)
            
            guard status == errSecSuccess, let privateKey = item else {
                throw OsKeystoreBackendPluginError.keyNotFound(message: "No private key for id \(keyId)")
            }

            guard let publicKey = SecKeyCopyPublicKey(item as! SecKey) else {
                throw OsKeystoreBackendPluginError.keyNotFound(message: "No public key for id \(keyId)")
            }
            
            let (xData, yData) = try! extractXYFromSecp256r1PublicKey(publicKey)
            
            // check where the key is stored to determine "userAuthenticationRequired" and "isInsideSecureHardware"
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: keyId,
                kSecReturnAttributes as String: true,
                kSecReturnRef as String: true
            ]

            var keyAttributeRef: CFTypeRef?
            let keyAttributeStatus = SecItemCopyMatching(query as CFDictionary, &keyAttributeRef)

            let attributes = keyAttributeRef as! [String: Any]
            //print(attributes)

            var keyOps = ["sign", "verify"]
            let privateSecKey = privateKey as! SecKey
            if let canDerive = attributes[kSecAttrCanDerive as String] as? Bool {
                if canDerive {
                    keyOps.append("deriveKey")
                }
            } else if SecKeyIsAlgorithmSupported(privateSecKey, .keyExchange, .ecdhKeyExchangeStandard) {
                keyOps.append("deriveKey")
            }
            
            // Return a map/dictionary structure to mimic the Android side
            let info: [String: Any] = [
                "x5c": [],
                "kty": "EC",
                "key_ops": keyOps,
                "crv": "P-256",
                "x": xData.base64EncodedString(),
                "y": yData.base64EncodedString(),
                "userAuthenticationRequired": String(describing: attributes["accc"]).contains("oa(true)") ? true : false,
                "isInsideSecureHardware": attributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String
            ]

            result(info)
        }
        catch let e as OsKeystoreBackendPluginError {
            result(e.asFlutterError)
        }
        catch {
            result(FlutterError(code: "UNEXPECTED", message: error.localizedDescription, details: nil))
        }
    }

    private func handleHasKey(call: FlutterMethodCall, result: @escaping FlutterResult) throws {
        do {
            let args = call.arguments as? [String: Any]

            guard let keyId = args?["keyId"] as? String else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing keyId argument")
            }

            let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                kSecAttrApplicationTag as String: keyId,
                                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                kSecReturnRef as String: true]
            
            var item: CFTypeRef?
            let status = SecItemCopyMatching(getquery as CFDictionary, &item)

            guard status != errSecItemNotFound else {throw OsKeystoreBackendPluginError.keyNotFound(message: "")}
            
            result(true)
        }
        catch let e as OsKeystoreBackendPluginError {
            result(e.asFlutterError)
        }
        catch {
            result(FlutterError(code: "UNEXPECTED", message: error.localizedDescription, details: nil))
        }
    }

    private func handleDeleteKey(call: FlutterMethodCall, result: @escaping FlutterResult) throws {
        do {
            let args = call.arguments as? [String: Any]

            guard let keyId = args?["keyId"] as? String else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing keyId argument")
            }

            let getquery: [String: Any] = [kSecClass as String: kSecClassKey, 
            kSecAttrApplicationTag as String: keyId]

            let status = SecItemDelete(getquery as CFDictionary)

            guard status == errSecSuccess || status == errSecItemNotFound 
            else { throw OsKeystoreBackendPluginError.deletionError(status: status) }
            // Return success
            result(true)
        }
        catch let e as OsKeystoreBackendPluginError {
            result(e.asFlutterError)
        }
        catch {
            result(FlutterError(code: "UNEXPECTED", message: error.localizedDescription, details: nil))
        }
    }

    private func handlePerformEcdh(call: FlutterMethodCall, result: @escaping FlutterResult) throws {
        do {
            let args = call.arguments as? [String: Any]
            guard let keyId = args?["keyId"] as? String else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing keyId argument")
            }
            guard let peerPublicKeySpkiBase64 = args?["peerPublicKeySpkiBase64"] as? String else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Missing peerPublicKeySpkiBase64 argument")
            }

            guard let tagData = keyId.data(using: .utf8) else {
                throw OsKeystoreBackendPluginError.argumentError(message: "Invalid keyId")
            }

            let getquery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tagData,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef as String: true
            ]

            var item: CFTypeRef?
            let status = SecItemCopyMatching(getquery as CFDictionary, &item)
            guard status == errSecSuccess, let privateKey = item as! SecKey? else {
                throw OsKeystoreBackendPluginError.keyNotFound(message: "No private key for id \(keyId)")
            }

            // Reject auth-required keys (v1) and keys without CanDerive
            let attrQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tagData,
                kSecReturnAttributes as String: true
            ]
            var attrRef: CFTypeRef?
            let attrStatus = SecItemCopyMatching(attrQuery as CFDictionary, &attrRef)
            let attributes = (attrStatus == errSecSuccess) ? (attrRef as? [String: Any]) : nil
            if let attributes = attributes,
               String(describing: attributes["accc"]).contains("oa(true)") {
                throw OsKeystoreBackendPluginError.ecdhError(
                    message: "performEcdh does not support keys that require user authentication")
            }
            if let canDerive = attributes?[kSecAttrCanDerive as String] as? Bool, !canDerive {
                throw OsKeystoreBackendPluginError.ecdhError(
                    message: "Key was not generated with allowKeyAgreement")
            }

            let algorithm: SecKeyAlgorithm = .ecdhKeyExchangeStandard
            guard SecKeyIsAlgorithmSupported(privateKey, .keyExchange, algorithm) else {
                throw OsKeystoreBackendPluginError.ecdhError(
                    message: "Key was not generated with allowKeyAgreement or ECDH is unsupported")
            }

            let peerPublicKey = try createPeerPublicKey(fromSpkiBase64: peerPublicKeySpkiBase64)

            var error: Unmanaged<CFError>?
            guard let sharedSecret = SecKeyCopyKeyExchangeResult(
                privateKey,
                algorithm,
                peerPublicKey,
                [:] as CFDictionary,
                &error
            ) as Data? else {
                throw error!.takeRetainedValue() as Error
            }

            guard sharedSecret.count == 32 else {
                throw OsKeystoreBackendPluginError.ecdhError(
                    message: "Unexpected shared secret length: \(sharedSecret.count)")
            }

            result(FlutterStandardTypedData(bytes: sharedSecret))
        }
        catch let e as OsKeystoreBackendPluginError {
            result(e.asFlutterError)
        }
        catch {
            result(FlutterError(code: "UNEXPECTED", message: error.localizedDescription, details: nil))
        }
    }

    private func createPeerPublicKey(fromSpkiBase64 base64: String) throws -> SecKey {
        guard let spkiData = Data(base64Encoded: base64) else {
            throw OsKeystoreBackendPluginError.argumentError(message: "Invalid base64 peer public key")
        }
        guard spkiData.count == 91,
              spkiData.prefix(Self.p256SpkiHeader.count) == Self.p256SpkiHeader,
              spkiData[26] == 0x04 else {
            throw OsKeystoreBackendPluginError.argumentError(
                message: "Peer public key must be uncompressed P-256 SPKI DER (91 bytes)")
        }

        let x963Data = spkiData.suffix(from: 26)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]

        var error: Unmanaged<CFError>?
        guard let peerPublicKey = SecKeyCreateWithData(
            x963Data as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }
        return peerPublicKey
    }
    
    func extractXYFromSecp256r1PublicKey(_ publicKey: SecKey) throws -> (x: Data, y: Data) {
        var error: Unmanaged<CFError>?
        guard let rawData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            if let err = error?.takeRetainedValue() {
                throw err
            } else {
                throw NSError(domain: "KeyError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Unknown error"])
            }
        }
        
        // For an uncompressed secp256r1 key, we expect 65 bytes total:
        // [0x04][32 bytes X][32 bytes Y]
        guard rawData.count == 65, rawData.first == 0x04 else {
            throw NSError(domain: "KeyError", code: -1, userInfo: [
                NSLocalizedDescriptionKey: "Unexpected key format or length"
            ])
        }
        
        let x = rawData.subdata(in: 1..<33)   // bytes 1..32
        let y = rawData.subdata(in: 33..<65)  // bytes 33..64
        
        return (x, y)
    }
}

extension OsKeystoreBackendPlugin.OsKeystoreBackendPluginError {

    /// Short, stable strings your Dart code will switch on
    var code: String {
        switch self {
        case .keyNotFound:                 return "KEY_NOT_FOUND"
        case .unsupportedAlgorithm:        return "UNSUPPORTED_ALGO"
        case .deletionError:               return "DELETION_ERROR"
        case .argumentError:               return "BAD_ARGUMENT"
        case .failedToCreateAccessControl: return "ACCESS_CONTROL"
        case .ecdhError:                   return "ECDH_FAILED"
        }
    }

    /// Human-readable message
    var message: String {
        switch self {
        case .keyNotFound(let m),
             .unsupportedAlgorithm(let m),
             .argumentError(let m),
             .failedToCreateAccessControl(let m),
             .ecdhError(let m):
            return m

        case .deletionError(let status):
            return "SecItemDelete failed (\(status))"
        }
    }

    /// Extra details (optional)
    var details: Any? {
        if case .deletionError(let status) = self { return status }
        return nil
    }

    /// One-liner to hand to Flutter
    var asFlutterError: FlutterError {
        FlutterError(code: code, message: message, details: details)
    }
}
