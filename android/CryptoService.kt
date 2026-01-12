package com.schuetz.evertouch.util.crypto

import java.security.SecureRandom
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider

data class EncryptedData(
    val ciphertext: ByteArray,
    val nonce: ByteArray,
    val tag: ByteArray?,
    val algorithm: String
)

class CryptoService {

    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private val secureRandom = SecureRandom()

    private val AES_MODE = "AES/GCM/NoPadding"
    private val TAG_LENGTH_BITS = 128
    private val IV_LENGTH_BYTES = 12

    fun generateSecureRandomBytes(count: Int): ByteArray {
        val bytes = ByteArray(count)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    fun encryptWithAESGCM(plaintext: ByteArray, key: SecretKey): EncryptedData {
        // Use default provider (Conscrypt) for GCM as it's more standard on Android
        val cipher = Cipher.getInstance(AES_MODE)
        val nonce = generateSecureRandomBytes(IV_LENGTH_BYTES)
        val spec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)
        
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        val ciphertextWithTag = cipher.doFinal(plaintext)
        
        val tagLengthBytes = TAG_LENGTH_BITS / 8
        val actualCiphertextLength = ciphertextWithTag.size - tagLengthBytes
        
        val actualCiphertext = ByteArray(actualCiphertextLength)
        val tag = ByteArray(tagLengthBytes)
        
        System.arraycopy(ciphertextWithTag, 0, actualCiphertext, 0, actualCiphertextLength)
        System.arraycopy(ciphertextWithTag, actualCiphertextLength, tag, 0, tagLengthBytes)
        
        return EncryptedData(actualCiphertext, nonce, tag, "AES-GCM")
    }

    fun decryptWithAESGCM(encryptedData: EncryptedData, key: SecretKey): ByteArray {
        // Use default provider (Conscrypt) for GCM
        val cipher = Cipher.getInstance(AES_MODE)
        val spec = GCMParameterSpec(TAG_LENGTH_BITS, encryptedData.nonce)
        
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        
        val tag = encryptedData.tag ?: throw IllegalArgumentException("Tag is required for AES-GCM")
        
        // Reconstruct ciphertext + tag for doFinal
        val combined = ByteArray(encryptedData.ciphertext.size + tag.size)
        System.arraycopy(encryptedData.ciphertext, 0, combined, 0, encryptedData.ciphertext.size)
        System.arraycopy(tag, 0, combined, encryptedData.ciphertext.size, tag.size)
        
        return cipher.doFinal(combined)
    }

    fun deriveSplitKeys(password: String, saltBase64: String): Pair<String, SecretKey> {
        val salt = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            java.util.Base64.getDecoder().decode(saltBase64)
        } else {
            android.util.Base64.decode(saltBase64, android.util.Base64.DEFAULT)
        }
        
        // 1. Stretch Password (PBKDF2)
        val spec = javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 600000, 256)
        val factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val masterKeyBytes = factory.generateSecret(spec).encoded
        
        // 2. Derive Auth Key (HKDF)
        val authInfo = "auth-v1".toByteArray(Charsets.UTF_8)
        val authKeyBytes = hkdfExpand(masterKeyBytes, ByteArray(0), authInfo, 32)
        
        val authKeyBase64 = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            java.util.Base64.getEncoder().encodeToString(authKeyBytes)
        } else {
            android.util.Base64.encodeToString(authKeyBytes, android.util.Base64.NO_WRAP)
        }
        
        // 3. Derive Encryption Key (HKDF)
        val encInfo = "enc-v1".toByteArray(Charsets.UTF_8)
        val encKeyBytes = hkdfExpand(masterKeyBytes, ByteArray(0), encInfo, 32)
        val encKey = SecretKeySpec(encKeyBytes, "AES")
        
        return Pair(authKeyBase64, encKey)
    }

    private fun hkdfExpand(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hkdf = org.bouncycastle.crypto.generators.HKDFBytesGenerator(org.bouncycastle.crypto.digests.SHA256Digest())
        hkdf.init(org.bouncycastle.crypto.params.HKDFParameters(ikm, salt, info))
        val okm = ByteArray(length)
        hkdf.generateBytes(okm, 0, length)
        return okm
    }

    fun computeSafetyNumber(myPublicKey: ByteArray, theirPublicKey: ByteArray): String {
        // Sort keys to ensure same output for both parties
        val sortedKeys = listOf(myPublicKey, theirPublicKey).sortedBy { 
            val hex = it.joinToString("") { "%02x".format(it) }
            hex
        }
        
        val combined = sortedKeys[0] + sortedKeys[1]
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(combined)
        
        // Take first 30 digits as the safety number
        val bigInt = java.math.BigInteger(1, hash)
        val fullString = bigInt.toString().padStart(60, '0')
        val safetyNumber = fullString.take(30).chunked(5).joinToString(" ")
        
        return safetyNumber
    }
}
