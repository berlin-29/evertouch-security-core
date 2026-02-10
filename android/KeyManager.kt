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
import java.util.UUID
import kotlinx.serialization.json.Json
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.serializer
import kotlinx.coroutines.flow.asStateFlow
import com.schuetz.evertouch.util.ByteArrayBase64Serializer

enum class KDFType(val value: String) {
    ARGON2ID("Argon2id"),
    PBKDF2("PBKDF2"),
    UNKNOWN("Unknown")
}

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
    private val json = Json { ignoreUnknownKeys = true }

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

    var kdfType: KDFType = KDFType.UNKNOWN

    var authKey: String? = null
        private set
    var encryptionKey: SecretKey? = null
        private set
    
    private var _legacyProfileSymmetricKey: SecretKey? = null
    var legacyProfileSymmetricKey: SecretKey?
        get() {
            if (_legacyProfileSymmetricKey == null) {
                val base64 = sharedPreferences.getString("legacy_profile_key", null)
                if (base64 != null) {
                    val keyBytes = Base64.decode(base64, Base64.NO_WRAP)
                    _legacyProfileSymmetricKey = SecretKeySpec(keyBytes, "AES")
                }
            }
            return _legacyProfileSymmetricKey
        }
        set(value) {
            _legacyProfileSymmetricKey = value
            if (value != null) {
                val base64 = Base64.encodeToString(value.encoded, Base64.NO_WRAP)
                sharedPreferences.edit().putString("legacy_profile_key", base64).apply()
            } else {
                sharedPreferences.edit().remove("legacy_profile_key").apply()
            }
        }
    
    private var _privateKey: X25519PrivateKeyParameters? = null
    val privateKey: X25519PrivateKeyParameters
        get() = _privateKey ?: throw IllegalStateException("Private key not available. User must be logged in and initialized.")

    val publicKey: X25519PublicKeyParameters
        get() = privateKey.generatePublicKey()

    fun isLoggedInAndInitialized(): Boolean {
        return _privateKey != null && encryptionKey != null
    }

    fun initializeWithKeys(authKey: String, encryptionKey: SecretKey, privateKeyBytes: ByteArray) {
        this.authKey = authKey
        this.encryptionKey = encryptionKey
        this._privateKey = X25519PrivateKeyParameters(privateKeyBytes, 0)
        _isInitialized.value = true
    }

    suspend fun initializeFromLogin(password: String, saltBase64: String, encryptedPrivateKeyBundleBase64: String) = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
        var keys: Pair<String, SecretKey>? = null
        try {
            keys = cryptoService.deriveArgon2Keys(password, saltBase64)
            kdfType = KDFType.ARGON2ID
        } catch (e: Exception) {
            keys = cryptoService.deriveSplitKeys(password, saltBase64)
            kdfType = KDFType.PBKDF2
        }
        
        val derivedAuthKey = keys!!.first
        val derivedEncKey = keys!!.second
        
        authKey = derivedAuthKey
        encryptionKey = derivedEncKey
        _legacyProfileSymmetricKey = null // Clear memory state for new session

        // PERSIST METADATA FIRST so legacy derivation has access to salt/bundle if needed
        persistZKMetadata(saltBase64, encryptedPrivateKeyBundleBase64)

        val decodedBundleJson = Base64.decode(encryptedPrivateKeyBundleBase64, Base64.NO_WRAP)
        val encryptedData = json.decodeFromString(serializer<EncryptedData>(), String(decodedBundleJson, Charsets.UTF_8))
        
        val privateKeyBytes = try {
            if (encryptedData.tag != null && encryptedData.nonce.isNotEmpty()) {
                cryptoService.decryptWithAESGCM(encryptedData, derivedEncKey)
            } else {
                cryptoService.decryptCombined(encryptedData.ciphertext, derivedEncKey)
            }
        } catch (e: Exception) {
            if (kdfType == KDFType.ARGON2ID) {
                try {
                    val pbkdf2Key = cryptoService.deriveSplitKeys(password, saltBase64).second
                    if (encryptedData.tag != null && encryptedData.nonce.isNotEmpty()) {
                        cryptoService.decryptWithAESGCM(encryptedData, pbkdf2Key)
                    } else {
                        cryptoService.decryptCombined(encryptedData.ciphertext, pbkdf2Key)
                    }
                } catch (e2: Exception) {
                    throw e2
                }
            } else {
                val salt = Base64.decode(saltBase64, Base64.DEFAULT)
                val legacyKey = recoveryService.deriveKeyPBKDF2(password, salt)
                
                try {
                    if (encryptedData.tag != null && encryptedData.nonce.isNotEmpty()) {
                        cryptoService.decryptWithAESGCM(encryptedData, legacyKey)
                    } else {
                        cryptoService.decryptCombined(encryptedData.ciphertext, legacyKey)
                    }
                } catch (e2: Exception) {
                    throw e2
                }
            }
        }
        
        _privateKey = X25519PrivateKeyParameters(privateKeyBytes, 0)
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
    fun setPendingKdfMigration(pending: Boolean) {
        sharedPreferences.edit()
            .putBoolean("pending_kdf_migration", pending)
            .apply()
    }

    fun isPendingKdfMigration(): Boolean {
        return sharedPreferences.getBoolean("pending_kdf_migration", false)
    }

    fun setHasRecoverySetup(hasSetup: Boolean) {
        sharedPreferences.edit()
            .putBoolean("has_recovery_setup", hasSetup)
            .apply()
    }

    fun hasRecoverySetup(): Boolean? {
        if (!sharedPreferences.contains("has_recovery_setup")) return null
        return sharedPreferences.getBoolean("has_recovery_setup", false)
    }

    fun setRecoveryPhraseVerificationHash(hash: String?) {
        sharedPreferences.edit()
            .putString("recovery_phrase_verification_hash", hash)
            .apply()
    }

    fun getRecoveryPhraseVerificationHash(): String? {
        return sharedPreferences.getString("recovery_phrase_verification_hash", null)
    }

    fun logout() {
        authKey = null
        encryptionKey = null
        _privateKey = null
        _legacyProfileSymmetricKey = null
        sharedPreferences.edit()
            .remove("cred_email")
            .remove("cred_secret")
            .remove("zk_salt")
            .remove("zk_bundle")
            .remove("pending_kdf_migration")
            .remove("legacy_profile_key")
            .remove("has_recovery_setup")
            .remove("recovery_phrase_verification_hash")
            .remove("recovery_mnemonic")
            .apply()
        _isInitialized.value = false
    }

    fun generateNewKeyPair(): Pair<ByteArray, ByteArray> {
        val generator = X25519KeyPairGenerator()
        generator.init(X25519KeyGenerationParameters(secureRandom))
        val keyPair = generator.generateKeyPair()
        
        val privKey = keyPair.private as X25519PrivateKeyParameters
        val pubKey = keyPair.public as X25519PublicKeyParameters
        
        _privateKey = privKey
        return Pair(privKey.encoded, pubKey.encoded)
    }

    @Serializable
    data class RecoveryBundle(
        @Serializable(with = ByteArrayBase64Serializer::class)
        val privateKey: ByteArray,
        @Serializable(with = ByteArrayBase64Serializer::class)
        val profileSymmetricKey: ByteArray
    )

    fun encryptRecoveryBundle(recoveryKey: SecretKey): String {
        val privKey = _privateKey ?: throw IllegalStateException("Private key missing")
        val symKey = encryptionKey ?: throw IllegalStateException("Symmetric key missing")
        
        val bundle = RecoveryBundle(
            privateKey = privKey.encoded,
            profileSymmetricKey = symKey.encoded
        )
        
        val bundleJson = json.encodeToString(serializer<RecoveryBundle>(), bundle)
        val encryptedData = cryptoService.encryptWithAESGCM(bundleJson.toByteArray(Charsets.UTF_8), recoveryKey)
        val encryptedJson = json.encodeToString(serializer<EncryptedData>(), encryptedData)
        return Base64.encodeToString(encryptedJson.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    fun decryptRecoveryBundle(bundleString: String, recoveryKey: SecretKey): Pair<ByteArray, SecretKey> {
        val decodedJson = String(Base64.decode(bundleString, Base64.NO_WRAP), Charsets.UTF_8)
        val encryptedData = json.decodeFromString(serializer<EncryptedData>(), decodedJson)
        val decryptedBytes = cryptoService.decryptWithAESGCM(encryptedData, recoveryKey)
        
        val bundle = json.decodeFromString(serializer<RecoveryBundle>(), String(decryptedBytes, Charsets.UTF_8))
        return Pair(bundle.privateKey, SecretKeySpec(bundle.profileSymmetricKey, "AES"))
    }

    fun encryptRecoveryBundleForReset(privateKey: ByteArray, profileSymmetricKey: SecretKey, recoveryKey: SecretKey): String {
        val bundle = RecoveryBundle(
            privateKey = privateKey,
            profileSymmetricKey = profileSymmetricKey.encoded
        )
        val bundleJson = json.encodeToString(serializer<RecoveryBundle>(), bundle)
        val encryptedData = cryptoService.encryptWithAESGCM(bundleJson.toByteArray(Charsets.UTF_8), recoveryKey)
        val encryptedJson = json.encodeToString(serializer<EncryptedData>(), encryptedData)
        return Base64.encodeToString(encryptedJson.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }
    
    fun encryptPrivateKeyBundle(privateKeyBytes: ByteArray, encryptionKey: SecretKey): String {
        val encryptedData = cryptoService.encryptWithAESGCM(privateKeyBytes, encryptionKey)
        val jsonString = json.encodeToString(serializer<EncryptedData>(), encryptedData)
        return Base64.encodeToString(jsonString.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    fun deriveLegacyEncryptionKey(password: String, saltBase64: String): SecretKey {
        val salt = Base64.decode(saltBase64, Base64.DEFAULT)
        return recoveryService.deriveKeyPBKDF2(password, salt)
    }

    fun computeSharedSecret(recipientPublicKeyBytes: ByteArray): SecretKey {
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
        return deriveKeyEncryptionKey(secret)
    }

    private fun deriveKeyEncryptionKey(sharedSecret: ByteArray): SecretKey {
        val salt = "evertouch-kek-salt-v1".toByteArray(Charsets.UTF_8)
        val info = "evertouch-kek-info-v1".toByteArray(Charsets.UTF_8)
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

    fun saveRecoveryMnemonic(mnemonic: String) {
        sharedPreferences.edit().putString("recovery_mnemonic", mnemonic).apply()
    }

    fun loadRecoveryMnemonic(): String? {
        return sharedPreferences.getString("recovery_mnemonic", null)
    }

    fun deleteRecoveryMnemonic() {
        sharedPreferences.edit().remove("recovery_mnemonic").apply()
    }
}