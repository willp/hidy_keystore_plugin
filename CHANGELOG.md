## 1.4.0

- add optional `allowKeyAgreement` to `generateKey` (default false; requires no user authentication; Android API 31+)
- add `performEcdh` returning raw ECDH shared secret Z (`Uint8List`); peer public key is SPKI DER Base64
- add `exportPublicKeySpkiBase64` returning a uniform SPKI DER Base64 public key on Android and iOS
- iOS `getKeyInfo` reports `deriveKey` in `key_ops` when key agreement is enabled
- throw `UnsupportedAndroidApiException` when `allowKeyAgreement` is used on Android API levels below 31 (Earlier than Android OS 12)

## 1.3.0 

- update min flutter version to 3.44

## 1.2.0

- fix handling of authTypes in iOS and add new one userPresence

## 1.1.0

- add parameter authType and invalidateByNewBiometric to generateKey function

## 1.0.0

- Initial release: Signing and verification with android keystore and iOS secure enclave
