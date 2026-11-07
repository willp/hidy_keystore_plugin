# keystore_plugin

This Plugin makes Android KeyStore and iOS SecureEnclave usable for Flutter Apps.
Generating keys for signing and optional ECDH key agreement is supported.

## Getting Started
Generate a key and use it for signing: 
```
final _osKeystoreBackendPlugin = OsKeystoreBackend();
var keyId = await _osKeystoreBackendPlugin.generateKey('secp256r1', true);
var sig = await _osKeystoreBackendPlugin.sign(
          keyId,
          ascii.encode('abcdefg'));

```

Export the device public key as SPKI DER Base64 (same format on Android and iOS;
prefer this over parsing `getKeyInfo` `x5c` / `x`/`y` for backend registration):
```
var devicePubSpki = await _osKeystoreBackendPlugin.exportPublicKeySpkiBase64(keyId);
```

ECDH (raw shared secret Z). Requires a non-auth key with `allowKeyAgreement: true`.
The peer public key must be uncompressed P-256 SPKI DER encoded as Base64.
On Android, `allowKeyAgreement` requires API 31+; below that, `generateKey` throws
`UnsupportedAndroidApiException` (catchable for a software fallback).
```
try {
  var ecdhKeyId = await _osKeystoreBackendPlugin.generateKey(
    'secp256r1',
    false,
    allowKeyAgreement: true,
  );
  var sharedSecret = await _osKeystoreBackendPlugin.performEcdh(
    ecdhKeyId,
    peerPublicKeySpkiBase64,
  );
  // sharedSecret is a 32-byte Uint8List (P-256). Apply HKDF outside the plugin.
} on UnsupportedAndroidApiException {
  // Device is below Android 12; use a software ECDH fallback if desired.
}
```

For more complex example please have a look at [example](./example).

## Notes
- On Android the plugin tries to use Strongbox first (only possible with curve secp256r1)
if not available the trusted execution environment is used
- On iOS only curve secp256r1 is supported
- `performEcdh` does not support keys with `userAuthenticationRequired: true`
- `exportPublicKeySpkiBase64` returns SPKI DER Base64 suitable for OpenSSL / Node / Go crypto APIs
