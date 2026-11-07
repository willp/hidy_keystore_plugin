/// Thrown when a feature requires a newer Android API level than the device provides.
///
/// Raised by [OsKeystoreBackend.generateKey] when `allowKeyAgreement` is true on
/// Android API levels below 31 (Android 12).
class UnsupportedAndroidApiException implements Exception {
  final String message;
  final int requiredApiLevel;

  UnsupportedAndroidApiException(
    this.message, {
    this.requiredApiLevel = 31,
  });

  @override
  String toString() => 'UnsupportedAndroidApiException: $message';
}
