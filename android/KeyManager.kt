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
// import java.security.MessageDigest // No longer directly used here
import java.util.UUID
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.coroutines.flow.asStateFlow

class KeyManager private constructor(context: Context) {

    companion object {
        @Volatile
        private var INSTANCE: KeyManager? = null

        fun getInstance(context: Context): KeyManager {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: KeyManager(context.applicationContext).also { INSTANCE = it }
            }
        }
    }

    private val cryptoService = CryptoService()
    private val recoveryService = RecoveryService()
    private val secureRandom = SecureRandom()
    private val json = Json { ignoreUnknownKeys = true } // Configure JSON parser

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

    private val _isInitialized = kotlinx.coroutines.flow.MutableStateFlow(false)
    val isInitialized = _isInitialized.asStateFlow()

    // --- In-memory cache for derived/decrypted keys ---
    var authKey: String? = null
        private set
    var encryptionKey: SecretKey? = null
        private set
    
    private var _privateKey: X25519PrivateKeyParameters? = null
    val privateKey: X25519PrivateKeyParameters
        get() = _privateKey ?: throw IllegalStateException("Private key not available. User must be logged in and initialized.")

    val publicKey: X25519PublicKeyParameters
        get() = privateKey.generatePublicKey()

    fun isLoggedInAndInitialized(): Boolean {
        return _privateKey != null && encryptionKey != null
    }

    /**
     * Initializes KeyManager with already available keys. 
     * Useful during signup or migration where keys are generated locally first.
     */
    fun initializeWithKeys(authKey: String, encryptionKey: SecretKey, privateKeyBytes: ByteArray) {
        this.authKey = authKey
        this.encryptionKey = encryptionKey
        this._privateKey = X25519PrivateKeyParameters(privateKeyBytes, 0)
        _isInitialized.value = true
    }

    /**
     * Derives Auth and Encryption keys from password and decrypts the user's private key.
     * This MUST be called after a successful login.
     */
    fun initializeFromLogin(password: String, saltBase64: String, encryptedPrivateKeyBundleBase64: String) {
        // 1. Derive Auth and Encryption keys from password (HKDF)
        val (derivedAuthKey, derivedEncKey) = cryptoService.deriveSplitKeys(password, saltBase64)
        this.authKey = derivedAuthKey
        this.encryptionKey = derivedEncKey

        // 2. Decrypt the private key bundle
        val decodedBundleJson = Base64.decode(encryptedPrivateKeyBundleBase64, Base64.NO_WRAP)
        val encryptedData = json.decodeFromString(EncryptedData.serializer(), String(decodedBundleJson, Charsets.UTF_8))
        
        val privateKeyBytes = try {
            // Attempt 1: Try separate fields (iOS/Standard format for bundles)
            if (encryptedData.tag != null && encryptedData.nonce.isNotEmpty()) {
                val decrypted = cryptoService.decryptWithAESGCM(encryptedData, derivedEncKey)
                android.util.Log.d("KeyManager", "Decrypted private key bundle using separate fields")
                decrypted
            } else {
                // Attempt 2: Try combined format (Android-specific legacy for bundles)
                val decrypted = cryptoService.decryptCombined(encryptedData.ciphertext, derivedEncKey)
                android.util.Log.d("KeyManager", "Decrypted private key bundle using combined format")
                decrypted
            }
        } catch (e: Exception) {
            // Attempt 3: Fallback to legacy PBKDF2 decryption
            android.util.Log.d("KeyManager", "HKDF decryption failed, trying legacy PBKDF2 fallback...")
            val salt = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                java.util.Base64.getDecoder().decode(saltBase64)
            } else {
                Base64.decode(saltBase64, Base64.DEFAULT)
            }
            recoveryService.decryptPrivateKeyBundle(encryptedData, password, salt)
        }
        
        // 3. Load and cache the private key
        _privateKey = X25519PrivateKeyParameters(privateKeyBytes, 0)
        android.util.Log.d("KeyManager", "Private key successfully loaded. Length: ${privateKeyBytes.size} bytes")
        
        // Persist ZK metadata for app restarts
        persistZKMetadata(saltBase64, encryptedPrivateKeyBundleBase64)
        
        _isInitialized.value = true
    }

    fun persistZKMetadata(salt: String, bundle: String) {
        sharedPreferences.edit()
            .putString("zk_salt", salt)
            .putString("zk_bundle", bundle)
            .apply()
    }

    fun getPersistedSalt(): String? = sharedPreferences.getString("zk_salt", null)
    fun getPersistedBundle(): String? = sharedPreferences.getString("zk_bundle", null)

    /**
     * Clears all sensitive keys from memory and disk. Call on logout.
     */
    fun logout() {
        authKey = null
        encryptionKey = null
        _privateKey = null
        sharedPreferences.edit()
            .remove("cred_email")
            .remove("cred_secret")
            .remove("zk_salt")
            .remove("zk_bundle")
            .apply()
        _isInitialized.value = false
    }

    /**
     * Generates a new X25519 key pair. The private key is immediately cached.
     * The caller is responsible for encrypting the private key with the `encryptionKey`
     * and sending it to the server.
     *
     * @return A pair of (raw private key bytes, raw public key bytes)
     */
    fun generateNewKeyPair(): Pair<ByteArray, ByteArray> {
        val generator = X25519KeyPairGenerator()
        generator.init(X25519KeyGenerationParameters(secureRandom))
        val keyPair = generator.generateKeyPair()
        
        val privKey = keyPair.private as X25519PrivateKeyParameters
        val pubKey = keyPair.public as X25519PublicKeyParameters
        
        // Cache the new key immediately
        _privateKey = privKey
        
        // BC lightweight API getEncoded() for X25519 returns the raw 32 bytes.
        return Pair(privKey.encoded, pubKey.encoded)
    }
    
    /**
     * Encrypts the raw private key bytes using the current `encryptionKey`.
     * This is used during signup to create the `encrypted_private_key_bundle` to send to the server.
     */
    fun encryptPrivateKeyBundle(privateKeyBytes: ByteArray, encryptionKey: SecretKey): String {
        // Use separate fields for the bundle to match iOS struct expectations
        val encryptedData = cryptoService.encryptWithAESGCM(privateKeyBytes, encryptionKey)
        val jsonString = json.encodeToString(EncryptedData.serializer(), encryptedData)
        return Base64.encodeToString(jsonString.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    /**
     * Returns the legacy PBKDF2-derived encryption key if needed.
     */
    fun deriveLegacyEncryptionKey(password: String, saltBase64: String): SecretKey {
        val salt = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            java.util.Base64.getDecoder().decode(saltBase64)
        } else {
            Base64.decode(saltBase64, Base64.DEFAULT)
        }
        return recoveryService.deriveKeyPBKDF2(password, salt)
    }

    fun computeSharedSecret(recipientPublicKeyBytes: ByteArray): SecretKey {
        // Ensure the recipient public key is exactly 32 bytes (raw X25519)
        // iOS CryptoKit uses raw 32-byte representation.
        val publicKey = if (recipientPublicKeyBytes.size > 32) {
            recipientPublicKeyBytes.takeLast(32).toByteArray()
        } else {
            recipientPublicKeyBytes
        }
        val theirPublicKey = X25519PublicKeyParameters(publicKey, 0)
        
        val agreement = X25519Agreement()
        agreement.init(privateKey) 
        
        val secret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(theirPublicKey, secret, 0)
        
        // Match iOS exactly: 
        // salt = "evertouch-key-agreement".data(using: .utf8)
        // sharedInfo = "Curve25519.KeyAgreement v1".data(using: .utf8)
        return deriveKeyEncryptionKey(secret)
    }

    private fun deriveKeyEncryptionKey(sharedSecret: ByteArray): SecretKey {
        val salt = "evertouch-share-key-encryption-salt".toByteArray(Charsets.UTF_8)
        val info = "evertouch-share-key-encryption-info".toByteArray(Charsets.UTF_8)
        
        // Use the centralized HKDF implementation in CryptoService
        val derivedKey = cryptoService.hkdfExpand(sharedSecret, salt, info, 32)
        
        return SecretKeySpec(derivedKey, "AES")
    }
    
    fun saveCredentials(email: String, secret: String) {
         sharedPreferences.edit()
            .putString("cred_email", email)
            .putString("cred_secret", secret)
            .apply()
    }

    fun loadCredentials(): Pair<String?, String?> {
        return Pair(
            sharedPreferences.getString("cred_email", null),
            sharedPreferences.getString("cred_secret", null)
        )
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