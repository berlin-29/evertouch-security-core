package com.schuetz.evertouch.util.crypto

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom
import android.util.Base64
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import java.util.UUID

class KeyManager(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val sharedPreferences = EncryptedSharedPreferences.create(
        context,
        "secure_keys",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private val secureRandom = SecureRandom()

    // Cache private key in memory
    private var _privateKey: X25519PrivateKeyParameters? = null

    val privateKey: X25519PrivateKeyParameters?
        get() {
            if (_privateKey == null) {
                _privateKey = loadPrivateKey()
            }
            return _privateKey
        }
    
    val publicKey: X25519PublicKeyParameters?
        get() = _privateKey?.generatePublicKey()

    fun generateKeyPair(): ByteArray {
        val generator = X25519KeyPairGenerator()
        generator.init(X25519KeyGenerationParameters(secureRandom))
        val keyPair = generator.generateKeyPair()
        
        val privKey = keyPair.private as X25519PrivateKeyParameters
        val pubKey = keyPair.public as X25519PublicKeyParameters
        
        savePrivateKey(privKey)
        _privateKey = privKey
        
        return pubKey.encoded
    }

    fun storePrivateKey(rawRepresentation: ByteArray) {
        val privKey = X25519PrivateKeyParameters(rawRepresentation, 0)
        savePrivateKey(privKey)
        _privateKey = privKey
    }

    private fun savePrivateKey(key: X25519PrivateKeyParameters) {
        val encoded = key.encoded
        val base64 = Base64.encodeToString(encoded, Base64.NO_WRAP)
        sharedPreferences.edit().putString("private_key", base64).apply()
    }

    private fun loadPrivateKey(): X25519PrivateKeyParameters? {
        val base64 = sharedPreferences.getString("private_key", null) ?: return null
        val encoded = Base64.decode(base64, Base64.NO_WRAP)
        return X25519PrivateKeyParameters(encoded, 0)
    }
    
    fun deleteKeyPair() {
        sharedPreferences.edit().remove("private_key").apply()
        _privateKey = null
    }

    fun computeSharedSecret(recipientPublicKeyBytes: ByteArray): SecretKey {
        val myPrivateKey = privateKey ?: throw IllegalStateException("Private key unavailable")
        val theirPublicKey = X25519PublicKeyParameters(recipientPublicKeyBytes, 0)
        
        val agreement = X25519Agreement()
        agreement.init(myPrivateKey)
        
        val secret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(theirPublicKey, secret, 0)
        
        // HKDF derivation as per iOS: HKDF(SHA256, salt="evertouch-key-agreement", info="Curve25519.KeyAgreement v1")
        return deriveHKDF(secret)
    }

    private fun deriveHKDF(sharedSecret: ByteArray): SecretKey {
        // Simple HKDF implementation or use Bouncy Castle's HKDFBytesGenerator
        // iOS: salt="evertouch-key-agreement", info="Curve25519.KeyAgreement v1", output=32
        
        val salt = "evertouch-key-agreement".toByteArray(Charsets.UTF_8)
        val info = "Curve25519.KeyAgreement v1".toByteArray(Charsets.UTF_8)
        
        val hkdf = org.bouncycastle.crypto.generators.HKDFBytesGenerator(org.bouncycastle.crypto.digests.SHA256Digest())
        hkdf.init(org.bouncycastle.crypto.params.HKDFParameters(sharedSecret, salt, info))
        
        val derivedKey = ByteArray(32)
        hkdf.generateBytes(derivedKey, 0, 32)
        
        return SecretKeySpec(derivedKey, "AES")
    }
    
    // Save Credentials (Email/Password)
    fun saveCredentials(email: String, secret: String) {
         sharedPreferences.edit()
            .putString("cred_email", email)
            .putString("cred_secret", secret)
            .apply()
    }

    fun saveLiveCardSecret(shareId: UUID, secret: String) {
        sharedPreferences.edit().putString("live_card_secret_$shareId", secret).apply()
    }

    fun loadLiveCardSecret(shareId: UUID): String? {
        return sharedPreferences.getString("live_card_secret_$shareId", null)
    }

    fun deleteLiveCardSecret(shareId: UUID) {
        sharedPreferences.edit().remove("live_card_secret_$shareId").apply()
    }
}
