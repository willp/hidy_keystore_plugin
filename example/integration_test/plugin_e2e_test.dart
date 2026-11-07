import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:keystore_plugin/keystore_plugin.dart';
import 'package:pointycastle/api.dart' hide Signature;
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:sd_jwt/sd_jwt.dart';

/// Fixed 26-byte ASN.1/SPKI header for uncompressed P-256 public keys.
final _p256SpkiHeader = Uint8List.fromList([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
  0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
  0x42, 0x00,
]);

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Generate key secp256r1', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    expect(keyId, isNotEmpty);
  });

  testWidgets('Sign and verify', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    final data = Uint8List.fromList([1, 2, 3, 4, 5]);
    final signature = await OsKeystoreBackend().sign(keyId, data);
    final verified = await OsKeystoreBackend().verify(keyId, data, signature);
    expect(verified, isTrue);
    final falseData = Uint8List.fromList([1, 2, 3, 4, 6]);
    final verified2 =
        await OsKeystoreBackend().verify(keyId, falseData, signature);
    expect(verified2, isFalse);
  });

  testWidgets('Sign and Verify with jws', (tester) async {
    var jwt = Jwt(additionalClaims: {'test': 'Test'}, issuedAt: DateTime.now());
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    var jws = await jwt.sign(
        signer: KeyStoreCryptoProvider(keyId),
        header: JwsJoseHeader(
            algorithm: SigningAlgorithm.ecdsaSha256Prime, type: 'test'));

    var publicKeyData = await OsKeystoreBackend().getKeyInfo(keyId);

    Jwk jwk;
    if (publicKeyData.containsKey('x5c') &&
        (publicKeyData['x5c'] as List).isNotEmpty) {
      jwk = Jwk.fromCertificate((publicKeyData['x5c'] as List).first);
    } else {
      jwk = Jwk.fromJson(publicKeyData.map((k, v) => MapEntry(k as String, v)));
    }

    var verified = jws.verify(PointyCastleCryptoProvider(jwk.key as dynamic));
    expect(verified, isTrue);
  });

  testWidgets('Get key info', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    final keyInfo = await OsKeystoreBackend().getKeyInfo(keyId);
    expect(keyInfo, isNotNull);
  });

  testWidgets('Has key', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    final hasKey = await OsKeystoreBackend().hasKey(keyId);
    expect(hasKey, isTrue);
  });

  testWidgets('Delete key', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    final deleted = await OsKeystoreBackend().deleteKey(keyId);
    expect(deleted, isTrue);
    try {
      await OsKeystoreBackend().hasKey(keyId);
      fail('Key should be deleted');
    } on PlatformException catch (e) {
      // Verify the error code and message
      expect(e.code, equals('hasKey.keyNotFound'));
    }
  });

  testWidgets('performEcdh returns matching shared secret', (tester) async {
    final backend = OsKeystoreBackend();
    final keyId = await backend.generateKey(
      'secp256r1',
      false,
      allowKeyAgreement: true,
    );

    final keyInfo = await backend.getKeyInfo(keyId);
    expect(keyInfo['key_ops'], contains('deriveKey'));

    final ephemeral = _generateEphemeralP256();
    final peerSpkiBase64 = base64Encode(_encodeP256Spki(ephemeral.publicKey));

    final nativeZ = await backend.performEcdh(keyId, peerSpkiBase64);
    expect(nativeZ.length, 32);

    final devicePublic = _devicePublicKeyFromKeyInfo(keyInfo);
    final expectedZ = _computeEcdhZ(ephemeral.privateKey, devicePublic);
    expect(nativeZ, orderedEquals(expectedZ));
  });

  testWidgets('performEcdh fails without allowKeyAgreement', (tester) async {
    final backend = OsKeystoreBackend();
    final keyId = await backend.generateKey('secp256r1', false);

    final ephemeral = _generateEphemeralP256();
    final peerSpkiBase64 = base64Encode(_encodeP256Spki(ephemeral.publicKey));

    expect(
      () => backend.performEcdh(keyId, peerSpkiBase64),
      throwsA(isA<PlatformException>()),
    );
  });

  testWidgets('allowKeyAgreement with auth fails at generate', (tester) async {
    expect(
      () => OsKeystoreBackend().generateKey(
        'secp256r1',
        true,
        allowKeyAgreement: true,
      ),
      throwsA(isA<ArgumentError>()),
    );
  });
}

AsymmetricKeyPair<ECPublicKey, ECPrivateKey> _generateEphemeralP256() {
  final secureRandom = FortunaRandom();
  final seedSource = Random.secure();
  final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => seedSource.nextInt(256)));
  secureRandom.seed(KeyParameter(seed));

  final keyParams = ECKeyGeneratorParameters(ECCurve_secp256r1());
  final generator = ECKeyGenerator()
    ..init(ParametersWithRandom(keyParams, secureRandom));
  return generator.generateKeyPair();
}

Uint8List _encodeP256Spki(ECPublicKey publicKey) {
  final x = _bigIntToFixedLengthBytes(publicKey.Q!.x!.toBigInteger()!, 32);
  final y = _bigIntToFixedLengthBytes(publicKey.Q!.y!.toBigInteger()!, 32);
  return Uint8List.fromList([..._p256SpkiHeader, 0x04, ...x, ...y]);
}

ECPublicKey _devicePublicKeyFromKeyInfo(Map keyInfo) {
  Jwk jwk;
  if (keyInfo.containsKey('x5c') && (keyInfo['x5c'] as List).isNotEmpty) {
    jwk = Jwk.fromCertificate((keyInfo['x5c'] as List).first);
  } else {
    jwk = Jwk.fromJson(keyInfo.map((k, v) => MapEntry(k as String, v)));
  }
  return jwk.key as ECPublicKey;
}

Uint8List _computeEcdhZ(ECPrivateKey privateKey, ECPublicKey publicKey) {
  final agreement = ECDHBasicAgreement()..init(privateKey);
  final z = agreement.calculateAgreement(publicKey);
  return _bigIntToFixedLengthBytes(z, 32);
}

Uint8List _bigIntToFixedLengthBytes(BigInt value, int length) {
  final bytes = value.toRadixString(16).padLeft(length * 2, '0');
  final result = Uint8List(length);
  for (var i = 0; i < length; i++) {
    result[i] = int.parse(bytes.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

class KeyStoreCryptoProvider extends CryptoProvider {
  String keyId;

  KeyStoreCryptoProvider(this.keyId);
  @override
  Uint8List digest(
      {required Uint8List data, required DigestAlgorithm algorithm}) {
    // TODO: implement digest
    throw UnimplementedError();
  }

  @override
  Key generateKeyPair({required KeyParameters keyParameters}) {
    // TODO: implement generateKeyPair
    throw UnimplementedError();
  }

  @override
  FutureOr<Signature> sign(
      {required Uint8List data, required SigningAlgorithm algorithm}) async {
    var sig = await OsKeystoreBackend().sign(keyId, data);
    return Signature.fromSignatureBytes(sig, algorithm);
  }

  @override
  FutureOr<bool> verify(
      {required Uint8List data,
      required SigningAlgorithm algorithm,
      required Signature signature}) {
    // TODO: implement verify
    throw UnimplementedError();
  }
}
