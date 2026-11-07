import 'dart:typed_data';

import 'biometric_prompt_data.dart';
import 'os_keystore_backend_platform_interface.dart';

class OsKeystoreBackend {
  /// Generates a key using the specific elliptic [curve] and returns its identifier in the KeyStore System
  ///
  /// Valid values for [curve] are `secp256r1`, `secp384r1` and `secp521r1`.
  /// Pay attention to the fact that on iOS only secp256r1 is supported and on android
  /// all curves can be supported by trusted execution environment but only secp256r1
  /// with strongbox (secure element).
  ///
  /// [attestationChallenge] is only used in android. If it is set a certificate chain for the new key is generated,
  /// where the certificate for the key contains the given challenge
  ///
  /// [authType] describes which authentication types are allowed for this key (biometric or device credential (pin, passcode, pattern) or both).
  /// On Android this parameter is ignored below Android 11, because there only biometric is allowed.
  /// Default is set to biometric.
  ///
  /// [invalidateByNewBiometric] describes if the key is invalidated in case a new fingerprint/face is enrolled,
  /// Default is set to true, which means that the key is invalidated if a new biometric is added.
  ///
  /// [allowKeyAgreement] enables ECDH key agreement (`performEcdh`) for the generated key.
  /// Defaults to false. Requires [userAuthenticationRequired] to be false (v1). On Android,
  /// requires API 31+.
  Future<String> generateKey(String curve, bool userAuthenticationRequired,
      {String? attestationChallenge,
      AuthType authType = AuthType.biometricOnly,
      bool invalidateByNewBiometric = true,
      bool allowKeyAgreement = false}) {
    if (allowKeyAgreement && userAuthenticationRequired) {
      throw ArgumentError(
          'allowKeyAgreement requires userAuthenticationRequired to be false');
    }
    return OsKeystoreBackendPlatform.instance.generateKey(
        curve,
        userAuthenticationRequired,
        attestationChallenge,
        authType,
        invalidateByNewBiometric,
        allowKeyAgreement);
  }

  /// Sign the given [data] with the key identified by [keyId]
  ///
  /// The returned signature is a plain signature (for ecdsa this means the concatenation of r and s value) as required be json web signatures for example.
  ///
  /// [promptData] is used to customize the System prompt for biometric authentication, when a key with userAuthenticationRequired=true is used.
  /// Android only, because on iOS the prompt cant be customized.
  Future<Uint8List> sign(String keyId, Uint8List data,
      [BiometricPromptData? promptData]) {
    return OsKeystoreBackendPlatform.instance.sign(keyId, data, promptData);
  }

  /// Verifies the given [signature] over [data] with the key identified by [keyId]
  ///
  /// [signature] has to be a plain signature (for ecdsa this means the concatenation of r and s value)
  /// without any additional encoding (e.g. ASN1)
  Future<bool> verify(String keyId, Uint8List data, Uint8List signature) {
    return OsKeystoreBackendPlatform.instance.verify(keyId, data, signature);
  }

  /// Performs ECDH with the private key identified by [keyId] and the peer's
  /// public key given as SPKI DER Base64 ([peerPublicKeySpkiBase64]).
  ///
  /// Returns the raw shared secret Z (32 bytes for P-256). The key must have been
  /// generated with [allowKeyAgreement] true and without user authentication.
  Future<Uint8List> performEcdh(
      String keyId, String peerPublicKeySpkiBase64) {
    return OsKeystoreBackendPlatform.instance
        .performEcdh(keyId, peerPublicKeySpkiBase64);
  }

  /// Returns the public key for [keyId] as SPKI DER encoded in standard Base64.
  ///
  /// For P-256 this is 91 bytes before Base64 (26-byte ASN.1 header + 65-byte
  /// uncompressed point). Prefer this over parsing [getKeyInfo] `x5c` / `x`/`y`
  /// when registering a device public key with a backend.
  Future<String> exportPublicKeySpkiBase64(String keyId) {
    return OsKeystoreBackendPlatform.instance.exportPublicKeySpkiBase64(keyId);
  }

  /// Returns metadata about the key identified by [keyId].
  ///
  /// This metadata has jwk format. The keys kty, key_ops, crv, x5c (to provide the public key on Android) or x and y on iOS,
  /// userAuthenticationRequired and securityLevel (API-Level 31 and above) or insideSecureHardware (Android API-Level below 31 and iOS) are used
  Future<Map> getKeyInfo(String keyId) {
    return OsKeystoreBackendPlatform.instance.getKeyInfo(keyId);
  }

  /// Returns whether the KeyStore controls the key identified by [keyId].
  Future<bool> hasKey(String keyId) {
    return OsKeystoreBackendPlatform.instance.hasKey(keyId);
  }

  /// Deletes the key identified by [keyId].
  Future<bool> deleteKey(String keyId) {
    return OsKeystoreBackendPlatform.instance.deleteKey(keyId);
  }
}

enum AuthType {
  deviceCredential,
  biometricOnly,
  deviceCredentialOrBiometric,
  userPresence,
}
