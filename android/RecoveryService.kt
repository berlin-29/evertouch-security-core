package com.schuetz.evertouch.util.crypto

import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.digests.SHA256Digest
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class RecoveryService {

    companion object {
        private const val ITERATION_COUNT = 600000 // Matched with iOS
        private const val KEY_LENGTH_BITS = 256
    }

    private val cryptoService = CryptoService()

    /**
     * Derives a key using PBKDF2-HMAC-SHA256.
     * iOS explicitly uses UTF-8 bytes for the password.
     */
    fun deriveKeyPBKDF2(passphrase: String, salt: ByteArray): SecretKey {
        val generator = PKCS5S2ParametersGenerator(SHA256Digest())
        
        // Match iOS password.data(using: .utf8)
        val passwordBytes = passphrase.toByteArray(Charsets.UTF_8)
        
        generator.init(passwordBytes, salt, ITERATION_COUNT)
        
        // keySize in generateDerivedParameters is in BITS
        val keyParam = generator.generateDerivedParameters(KEY_LENGTH_BITS) as KeyParameter
        val keyBytes = keyParam.key
        
        return SecretKeySpec(keyBytes, "AES")
    }

    fun encryptPrivateKeyBundle(privateKeyData: ByteArray, passphrase: String): Pair<EncryptedData, ByteArray> {
        val salt = cryptoService.generateSecureRandomBytes(32)
        val derivedKey = deriveKeyPBKDF2(passphrase, salt)
        val encryptedBundle = cryptoService.encryptWithAESGCM(privateKeyData, derivedKey)
        return Pair(encryptedBundle, salt)
    }

    fun decryptPrivateKeyBundle(encryptedBundle: EncryptedData, passphrase: String, salt: ByteArray): ByteArray {
        val derivedKey = deriveKeyPBKDF2(passphrase, salt)
        return cryptoService.decryptWithAESGCM(encryptedBundle, derivedKey)
    }
}
