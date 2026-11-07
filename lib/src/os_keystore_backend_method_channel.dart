import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:pointycastle/asn1.dart' as asn1;

import 'biometric_prompt_data.dart';
import 'os_keystore_backend.dart';
import 'os_keystore_backend_platform_interface.dart';
import 'unsupported_android_api_exception.dart';

/// An implementation of [OsKeystoreBackendPlatform] that uses method channels.
class MethodChannelOsKeystoreBackend extends OsKeystoreBackendPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('os_keystore_backend');

  @override
  Future<String> generateKey(
      String curve,
      bool userAuthenticationRequired,
      String? attestationChallenge,
      AuthType authType,
      bool invalidateByNewBiometric,
      bool allowKeyAgreement) async {
    try {
      final keyId = await methodChannel
          .invokeMethod<String>('generateKey', <String, dynamic>{
        'curve': curve,
        'userAuthenticationRequired': userAuthenticationRequired,
        'attestationChallenge': attestationChallenge,
        'authType': authType.index + 1,
        'invalidateByNewBiometric': invalidateByNewBiometric,
        'allowKeyAgreement': allowKeyAgreement,
      });
      if (keyId != null) {
        return keyId;
      } else {
        throw Exception('Failed to generate Key');
      }
    } on PlatformException catch (e) {
      if (e.code == 'UnsupportedAndroidApi') {
        throw UnsupportedAndroidApiException(
          e.message ??
              'allowKeyAgreement requires Android API 31 (Android 12) or higher.',
        );
      }
      rethrow;
    }
  }

  @override
  Future<Uint8List> sign(
      String keyId, Uint8List data, BiometricPromptData? promptData) async {
    final signature =
        await methodChannel.invokeMethod<Uint8List>('sign', <String, dynamic>{
      'keyId': keyId,
      'data': data,
      'biometricPromptTitle': promptData?.title,
      'biometricPromptSubtitle': promptData?.subtitle,
      'biometricPromptNegative': promptData?.negativeButton
    });
    if (signature != null) {
      return _fromAsn1(signature);
    } else {
      throw Exception('Signature Generation failed');
    }
  }

  @override
  Future<bool> verify(String keyId, Uint8List data, Uint8List signature) async {
    final verified = await methodChannel.invokeMethod<bool>(
        'verify', <String, dynamic>{
      'keyId': keyId,
      'data': data,
      'signature': _toAsn1(signature)
    });
    if (verified != null) {
      return verified;
    } else {
      throw Exception('Verification failed');
    }
  }

  @override
  Future<Map> getKeyInfo(String keyId) async {
    final info = await methodChannel
        .invokeMethod<Map>('getKeyInfo', <String, dynamic>{'keyId': keyId});
    if (info != null) {
      return info;
    } else {
      throw Exception('Fetching information failed');
    }
  }

  @override
  Future<bool> hasKey(String keyId) async {
    bool? info;
    try {
      info = await methodChannel
          .invokeMethod<bool>('hasKey', <String, dynamic>{'keyId': keyId});
    } catch (_) {
      return false;
    }
    if (info != null) {
      return info;
    } else {
      throw Exception('Fetching information failed');
    }
  }

  @override
  Future<bool> deleteKey(String keyId) async {
    final info = await methodChannel
        .invokeMethod<bool>('deleteKey', <String, dynamic>{'keyId': keyId});
    if (info != null) {
      return info;
    } else {
      throw Exception('Fetching information failed');
    }
  }

  @override
  Future<Uint8List> performEcdh(
      String keyId, String peerPublicKeySpkiBase64) async {
    final sharedSecret = await methodChannel.invokeMethod<Uint8List>(
        'performEcdh', <String, dynamic>{
      'keyId': keyId,
      'peerPublicKeySpkiBase64': peerPublicKeySpkiBase64,
    });
    if (sharedSecret != null) {
      return sharedSecret;
    } else {
      throw Exception('ECDH failed');
    }
  }

  Uint8List _fromAsn1(Uint8List asn1Data) {
    var p = asn1.ASN1Parser(asn1Data);
    var dataSequence = p.nextObject() as asn1.ASN1Sequence;
    var r = dataSequence.elements!.first as asn1.ASN1Integer;
    var s = dataSequence.elements!.last as asn1.ASN1Integer;
    var rAsList = _unsignedIntToBytes(r.integer!);
    var sAsList = _unsignedIntToBytes(s.integer!);
    // for signatures with P-521 and SHA-512 sometimes padding is needed
    if (rAsList.length == 65) {
      rAsList = Uint8List.fromList([0, ...rAsList]);
    }
    if (sAsList.length == 65) {
      sAsList = Uint8List.fromList([0, ...sAsList]);
    }
    return Uint8List.fromList(rAsList + sAsList);
  }

  Uint8List _toAsn1(Uint8List plainData) {
    var l = plainData.length ~/ 2;
    var r = plainData.sublist(0, l);
    var s = plainData.sublist(l);
    var seq = asn1.ASN1Sequence(elements: [
      asn1.ASN1Integer(_bytesToUnsignedInt(r)),
      asn1.ASN1Integer(_bytesToUnsignedInt(s))
    ]);
    return seq.encode();
  }

  // Source: pointyCastle src/utils
  final _byteMask = BigInt.from(0xff);

  Uint8List _unsignedIntToBytes(BigInt number) {
    if (number.isNegative) {
      throw Exception('Negative number');
    }
    if (number == BigInt.zero) {
      return Uint8List.fromList([0]);
    }
    var size = number.bitLength + (number.isNegative ? 8 : 7) >> 3;
    var result = Uint8List(size);
    for (var i = 0; i < size; i++) {
      result[size - i - 1] = (number & _byteMask).toInt();
      number = number >> 8;
    }
    return result;
  }

  BigInt _bytesToUnsignedInt(List<int> magnitude) {
    BigInt result;

    if (magnitude.length == 1) {
      result = BigInt.from(magnitude[0]);
    } else {
      result = BigInt.from(0);
      for (var i = 0; i < magnitude.length; i++) {
        var item = magnitude[magnitude.length - i - 1];
        result |= BigInt.from(item) << (8 * i);
      }
    }

    if (result != BigInt.zero) {
      result = result.toUnsigned(result.bitLength);
    }
    return result;
  }
}
