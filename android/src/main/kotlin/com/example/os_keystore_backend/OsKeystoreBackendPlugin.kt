package com.example.os_keystore_backend

import android.app.Activity
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.Executor
import javax.crypto.KeyAgreement
import kotlin.random.Random


/** OsKeystoreBackendPlugin */
class OsKeystoreBackendPlugin: FlutterPlugin, MethodCallHandler, ActivityAware {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel : MethodChannel
  private var activity: Activity? = null


  override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "os_keystore_backend")
    channel.setMethodCallHandler(this)
  }


  class UiThreadExecutor : Executor {
    private val handler: Handler = Handler(Looper.getMainLooper())

    override fun execute(command: Runnable) {
      handler.post(command)
    }
  }

  override fun onMethodCall(call: MethodCall, result: Result) {
    if (call.method == "getPlatformVersion") {
      result.success("Android ${android.os.Build.VERSION.RELEASE}")
    } else if(call.method == "generateKey"){
      val curve = call.argument<String>("curve")
      if(curve == null){
        result.error("ArgumentError", "Missing argument curve", "")
        return
      }

      val userAuth = call.argument<Boolean>("userAuthenticationRequired") ?: false
      val attestationChallenge = call.argument<String>("attestationChallenge") ?: ""
      val authType = call.argument<Int>("authType") ?: 2
      val invalidByNewBiometric = call.argument<Boolean>("invalidateByNewBiometric") ?: true
      val allowKeyAgreement = call.argument<Boolean>("allowKeyAgreement") ?: false

      if (allowKeyAgreement && android.os.Build.VERSION.SDK_INT < 31) {
        result.error(
          "UnsupportedAndroidApi",
          "allowKeyAgreement requires Android API 31 (Android 12) or higher.",
          null
        )
        return
      }

      try {
        val keyId = generateKey(curve, userAuth, authType, attestationChallenge, invalidByNewBiometric, allowKeyAgreement)
        result.success(keyId)
      } catch(e: Exception){
        result.error("GenerationError", e.message, e.stackTraceToString())
      }
    } else if(call.method == "sign"){
      val data = call.argument<ByteArray>("data")
      val keyId = call.argument<String>("keyId")

      if(keyId != null && data != null){
        try {
          sign(keyId,
            data,
            result,
            call.argument<String?>("biometricPromptTitle"),
            call.argument<String?>("biometricPromptSubtitle"),
            call.argument<String?>("biometricPromptNegative"))
        }catch (e: Exception){
          result.error("SigningError", e.message, e.stackTraceToString())
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    } else if(call.method == "verify"){
      val data = call.argument<ByteArray>("data")
      val signature = call.argument<ByteArray>("signature")
      val keyId = call.argument<String>("keyId")

      if(keyId != null && data != null && signature != null){
        try {
          val sig = verify(keyId, data, signature)
          result.success(sig)
        }catch (e: Exception){
          result.error("VerificationError", e.message, "")
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    } else if(call.method == "getKeyInfo"){
      val keyId = call.argument<String>("keyId")

      if(keyId != null ){
        try {
          val sig = getKeyInfo(keyId)
          result.success(sig)
        }catch (e: Exception){
          result.error("SigningError", e.message, "")
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    } else if(call.method == "exportPublicKeySpkiBase64"){
      val keyId = call.argument<String>("keyId")

      if(keyId != null ){
        try {
          val spkiBase64 = exportPublicKeySpkiBase64(keyId)
          result.success(spkiBase64)
        }catch (e: Exception){
          result.error("ExportError", e.message, "")
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    }else if(call.method == "hasKey"){
      val keyId = call.argument<String>("keyId")

      if(keyId != null ){
        try {
          val sig = hasKey(keyId)
          result.success(sig)
        }catch (e: Exception){
          result.error("SigningError", e.message, "")
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    }else if(call.method == "deleteKey"){
      val keyId = call.argument<String>("keyId")

      if(keyId != null ){
        try {
          deleteKey(keyId)
          result.success(true)
        }catch (e: Exception){
          result.error("DeletionError", e.message, "")
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    } else if(call.method == "performEcdh"){
      val keyId = call.argument<String>("keyId")
      val peerPublicKeySpkiBase64 = call.argument<String>("peerPublicKeySpkiBase64")

      if(keyId != null && peerPublicKeySpkiBase64 != null){
        try {
          val sharedSecret = performEcdh(keyId, peerPublicKeySpkiBase64)
          result.success(sharedSecret)
        }catch (e: Exception){
          result.error("ECDHError", e.message, e.stackTraceToString())
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    }
    else {
      result.notImplemented()
    }
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }

  private fun generateKey(curve: String, userAuthenticationRequired: Boolean, allowedAuthType: Int, attestationChallenge: String, invalidateByBiometricEnrollment: Boolean, allowKeyAgreement: Boolean): String {
    if (allowKeyAgreement && userAuthenticationRequired) {
      throw Exception("allowKeyAgreement requires userAuthenticationRequired to be false")
    }

    val keyPairGenerator = KeyPairGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
    )

    val charPool : List<Char> = ('a'..'z') + ('A'..'Z') + ('0'..'9')
    var alias: String = (1..10)
      .map { Random.nextInt(0, charPool.size).let { charPool[it] } }
      .joinToString("")

    val digest: String = when(curve) {
      "secp256r1" -> KeyProperties.DIGEST_SHA256
      "secp384r1" -> KeyProperties.DIGEST_SHA384
      "secp521r1" -> KeyProperties.DIGEST_SHA512
      else -> {throw Exception("Unknown curve")}
    }

    alias = "${digest}_$alias"

    var purposes = KeyProperties.PURPOSE_SIGN
    if (allowKeyAgreement) {
      purposes = purposes or KeyProperties.PURPOSE_AGREE_KEY
    }

    val authType = if(android.os.Build.VERSION.SDK_INT >= 30) {
      when(allowedAuthType){
        1 -> KeyProperties.AUTH_DEVICE_CREDENTIAL
        2 -> KeyProperties.AUTH_BIOMETRIC_STRONG
        3 -> KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        4 -> KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL // userPresence fallback
        else -> {throw  Exception("Unknown authType")}
      }
    } else {
      2
    }

    try {
     val builder =
        KeyGenParameterSpec.Builder(
          alias,
          purposes
        )
          .setAlgorithmParameterSpec(ECGenParameterSpec(curve))
          .setDigests(digest)
          .setIsStrongBoxBacked(true)
          .setUserAuthenticationRequired(userAuthenticationRequired)
          .setAttestationChallenge(attestationChallenge.toByteArray())
          .setInvalidatedByBiometricEnrollment(invalidateByBiometricEnrollment)

      if(android.os.Build.VERSION.SDK_INT >= 30){
        builder.setUserAuthenticationParameters(0, authType )
      }

      val r =  builder.build()
      keyPairGenerator.initialize(r)
      keyPairGenerator.generateKeyPair()
    } catch (e: StrongBoxUnavailableException) {
      alias += "_tee"
     val builder = KeyGenParameterSpec.Builder(
       alias,
       purposes
     )
       .setAlgorithmParameterSpec(ECGenParameterSpec(curve))
       .setDigests(digest)
       .setUserAuthenticationRequired(userAuthenticationRequired)
       .setAttestationChallenge(attestationChallenge.toByteArray())
       .setInvalidatedByBiometricEnrollment(invalidateByBiometricEnrollment)

      if(android.os.Build.VERSION.SDK_INT >= 30){
        builder.setUserAuthenticationParameters(0, authType )
      }

      val r =  builder.build()
      keyPairGenerator.initialize(r)
      keyPairGenerator.generateKeyPair()
    } catch(e: InvalidAlgorithmParameterException){
      alias += "_tee"
      val builder = KeyGenParameterSpec.Builder(
        alias,
        purposes
      )
        .setAlgorithmParameterSpec(ECGenParameterSpec(curve))
        .setDigests(digest)
        .setUserAuthenticationRequired(userAuthenticationRequired)
        .setAttestationChallenge(attestationChallenge.toByteArray())
        .setInvalidatedByBiometricEnrollment(invalidateByBiometricEnrollment)

      if(android.os.Build.VERSION.SDK_INT >= 30){
        builder.setUserAuthenticationParameters(0, authType )
      }

      val r =  builder.build()
      keyPairGenerator.initialize(r)
      keyPairGenerator.generateKeyPair()
    }

    return alias
  }

  private fun performEcdh(keyId: String, peerPublicKeySpkiBase64: String): ByteArray {
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }

    val entry: KeyStore.Entry = ks.getEntry(keyId, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      throw Exception("No private key")
    }

    val factory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
    val keyInfo: KeyInfo
    try {
      keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    } catch (e: InvalidKeySpecException) {
      throw Exception("No keyInfo found")
    }

    if (keyInfo.isUserAuthenticationRequired) {
      throw Exception("performEcdh does not support keys that require user authentication")
    }
    if (android.os.Build.VERSION.SDK_INT < 31 ||
        (keyInfo.purposes and KeyProperties.PURPOSE_AGREE_KEY) == 0) {
      throw Exception("Key was not generated with allowKeyAgreement")
    }

    val peerPublicKeyBytes = Base64.getDecoder().decode(peerPublicKeySpkiBase64)
    val peerPublicKey = KeyFactory.getInstance("EC")
      .generatePublic(X509EncodedKeySpec(peerPublicKeyBytes))

    val keyAgreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
    keyAgreement.init(entry.privateKey)
    keyAgreement.doPhase(peerPublicKey, true)
    return keyAgreement.generateSecret()
  }

  private fun sign(keyId: String,
                   data: ByteArray,
                   result: Result,
                   biometricPromptTitle: String?,
                   biometricPromptSubtitle: String?,
                   biometricPromptNegative: String?)  {
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }

    val entry: KeyStore.Entry = ks.getEntry(keyId, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      throw  Exception("No private key")
    }

    val factory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
    val keyInfo: KeyInfo
    try {
      keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    } catch (e: InvalidKeySpecException) {
      result.error("SigningError", "No Key found", null)
      return
    }

    val authType = if(android.os.Build.VERSION.SDK_INT >= 30)
      keyInfo.userAuthenticationType
    else
      2


    var digest = keyInfo.digests.first().split("_").first()

    digest = digest.replace("-", "")

    var signature: ByteArray

    if(keyInfo.isUserAuthenticationRequired){
      if(activity !is FragmentActivity){
        result.error("SigningError", "Not in Fragment Activity", "")
        return
      }

      val biometricPrompt = BiometricPrompt(activity as FragmentActivity, UiThreadExecutor(),
        object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationError(errorCode: Int,
                                             errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            result.error("SigningError", "Authentication error", errString)
          }

          override fun onAuthenticationSucceeded(
            biometricResult: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(biometricResult)
            biometricResult.cryptoObject?.signature!!.update(data)
            signature = biometricResult.cryptoObject?.signature!!.sign()
            result.success(signature)
          }

          override fun onAuthenticationFailed() {
            super.onAuthenticationFailed()
            //result.error("SigningError", "Authentication failed", null)
          }
        })

      val biometricManager = when(authType) {
        1 -> BiometricManager.Authenticators.DEVICE_CREDENTIAL
        2 -> BiometricManager.Authenticators.BIOMETRIC_STRONG
        3 -> BiometricManager.Authenticators.DEVICE_CREDENTIAL or BiometricManager.Authenticators.BIOMETRIC_STRONG
        4 -> BiometricManager.Authenticators.DEVICE_CREDENTIAL or BiometricManager.Authenticators.BIOMETRIC_STRONG // userPresence fallback
        else -> {throw Exception("Unknown authType")}
        }


      val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
        .setTitle(biometricPromptTitle ?: "Biometric login for signing")
        .setSubtitle(biometricPromptSubtitle ?: "Please Authenticate for the usage of your signing key")
        .setAllowedAuthenticators(biometricManager)

      if(authType == 2){ // biometric only
        promptInfoBuilder.setNegativeButtonText(biometricPromptNegative ?: "Cancel")
      }

      val promptInfo = promptInfoBuilder.build()

      val s = Signature.getInstance("${digest}withECDSA")
      s.initSign(entry.privateKey)

      biometricPrompt.authenticate(promptInfo,
        BiometricPrompt.CryptoObject(s))


    } else {
      signature = Signature.getInstance("${digest}withECDSA").run {
        initSign(entry.privateKey)
        update(data)
        sign()
      }
      result.success(signature)
    }


  }

  private fun verify(keyId: String, data: ByteArray, signature: ByteArray) : Boolean {
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }

    val entry: KeyStore.Entry = ks.getEntry(keyId, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      throw  Exception("No private key")
    }

    val factory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
    val keyInfo: KeyInfo
    try {
      keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    } catch (e: InvalidKeySpecException) {
      throw  Exception("No keyInfo found")
    }

    var digest = keyInfo.digests.first().split("_").first()

    digest = digest.replace("-", "")

    val verified: Boolean = Signature.getInstance("${digest}withECDSA").run {
      initVerify(entry.certificate)
      update(data)
      verify(signature)
    }

    return verified
  }

  private fun exportPublicKeySpkiBase64(keyId: String): String {
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }

    val entry: KeyStore.Entry = ks.getEntry(keyId, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      throw Exception("No private key")
    }
    // PublicKey.encoded is already X.509 SubjectPublicKeyInfo (SPKI) DER
    return Base64.getEncoder().encodeToString(entry.certificate.publicKey.encoded)
  }

  private fun getKeyInfo(keyId: String) : Map<String, Any>{
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }

    val entry: KeyStore.Entry = ks.getEntry(keyId, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      throw  Exception("No private key")
    }

    val factory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
    val keyInfo: KeyInfo
    try {
      keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    } catch (e: InvalidKeySpecException) {
      throw  Exception("No keyInfo found")
    }

    val data = LinkedHashMap<String, Any>()
    val x5c = entry.certificateChain.map { c -> Base64.getEncoder().encodeToString(c.encoded) }
    data["x5c"] = x5c
    data["kty"] = "EC"

    val digest = keyInfo.digests.first()
    val curve : String = when(digest) {
      KeyProperties.DIGEST_SHA256 -> "P-256"
      KeyProperties.DIGEST_SHA384 -> "P-384"
      KeyProperties.DIGEST_SHA512 -> "P-521"
      else -> {throw Exception("Unknown curve")}
    }
    data["crv"] = curve


    val keyOps = ArrayList<String>()
    var keyP = keyInfo.purposes
    if(keyP == 128){
      // no other purpose possible
      keyOps.add("attestKey")
    } else {
      if(keyP / 64 == 1 ){
        keyOps.add("deriveKey")
        keyP %= 64
      }
      if(keyP / 32 == 1){
        keyOps.add("wrapKey")
        keyP %= 32
      }
      if(keyP / 8 == 1){
        keyOps.add("verify")
        keyP %= 8
      }
      if(keyP / 4 == 1){
        keyOps.add("sign")
        keyP %= 4
      }
      if(keyP / 2 == 1){
        keyOps.add("decrypt")
        keyP %= 2
      }
      if(keyP == 1){
        keyOps.add("encrypt")
      }
    }
    data["key_ops"] = keyOps
    data["userAuthenticationRequired"] = keyInfo.isUserAuthenticationRequired

    if(android.os.Build.VERSION.SDK_INT >= 31 ){
      data["securityLevel"] = keyInfo.securityLevel
    }else{
      data["isInsideSecureHardware"] = keyInfo.isInsideSecureHardware
    }

    return data
  }

  private fun hasKey(keyId: String): Boolean{
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }
    return ks.isKeyEntry(keyId)
  }

  private fun deleteKey(keyId: String){
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }
    ks.deleteEntry(keyId)
  }

  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    activity = binding.activity
  }

  override fun onDetachedFromActivityForConfigChanges() {
    activity = null
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    activity = binding.activity
  }

  override fun onDetachedFromActivity() {
    activity = null
  }
}
