package com.schuetz.evertouch.util.crypto

import java.security.SecureRandom
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider

import kotlinx.serialization.Serializable
import com.schuetz.evertouch.util.Base64ByteArraySerializer

@Serializable
data class EncryptedData(
    @Serializable(with = Base64ByteArraySerializer::class)
    val ciphertext: ByteArray,
    @Serializable(with = Base64ByteArraySerializer::class)
    val nonce: ByteArray,
    @Serializable(with = Base64ByteArraySerializer::class)
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

    /**
     * Encrypts and returns a single ByteArray containing nonce + ciphertext + tag.
     * This matches Apple's CryptoKit.AES.GCM.SealedBox.combined representation.
     */
    fun encryptCombined(plaintext: ByteArray, key: SecretKey): ByteArray {
        val cipher = Cipher.getInstance(AES_MODE)
        val nonce = generateSecureRandomBytes(IV_LENGTH_BYTES)
        val spec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)
        
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        val ciphertextWithTag = cipher.doFinal(plaintext)
        
        val combined = ByteArray(nonce.size + ciphertextWithTag.size)
        System.arraycopy(nonce, 0, combined, 0, nonce.size)
        System.arraycopy(ciphertextWithTag, 0, combined, nonce.size, ciphertextWithTag.size)
        
        return combined
    }

    /**
     * Decrypts a combined ByteArray (nonce + ciphertext + tag).
     * This matches Apple's CryptoKit.AES.GCM.SealedBox(combined:) initialization.
     */
    fun decryptCombined(combined: ByteArray, key: SecretKey): ByteArray {
        if (combined.size < IV_LENGTH_BYTES + (TAG_LENGTH_BITS / 8)) {
            throw IllegalArgumentException("Invalid combined ciphertext length")
        }
        
        val nonce = ByteArray(IV_LENGTH_BYTES)
        val ciphertextWithTag = ByteArray(combined.size - IV_LENGTH_BYTES)
        
        System.arraycopy(combined, 0, nonce, 0, IV_LENGTH_BYTES)
        System.arraycopy(combined, IV_LENGTH_BYTES, ciphertextWithTag, 0, ciphertextWithTag.size)
        
        val cipher = Cipher.getInstance(AES_MODE)
        val spec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)
        
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        return cipher.doFinal(ciphertextWithTag)
    }

    fun deriveSplitKeys(password: String, saltBase64: String): Pair<String, SecretKey> {
        val salt = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            java.util.Base64.getDecoder().decode(saltBase64)
        } else {
            android.util.Base64.decode(saltBase64, android.util.Base64.DEFAULT)
        }
        
        // 1. Stretch Password (PBKDF2) - Use Bouncy Castle to ensure UTF-8 matching with iOS
        val generator = org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator(org.bouncycastle.crypto.digests.SHA256Digest())
        generator.init(password.toByteArray(Charsets.UTF_8), salt, 600000)
        val masterKeyBytes = (generator.generateDerivedParameters(256) as org.bouncycastle.crypto.params.KeyParameter).key
        
        // 2. Derive Auth Key (HKDF)
        val authInfo = "auth-v1".toByteArray(Charsets.UTF_8)
        val authKeyBytes = hkdfExpand(masterKeyBytes, null, authInfo, 32)
        
        val authKeyBase64 = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            java.util.Base64.getEncoder().encodeToString(authKeyBytes)
        } else {
            android.util.Base64.encodeToString(authKeyBytes, android.util.Base64.NO_WRAP)
        }
        
        // 3. Derive Encryption Key (HKDF)
        val encInfo = "enc-v1".toByteArray(Charsets.UTF_8)
        val encKeyBytes = hkdfExpand(masterKeyBytes, null, encInfo, 32)
        val encKey = SecretKeySpec(encKeyBytes, "AES")
        
        return Pair(authKeyBase64, encKey)
    }

    internal fun hkdfExpand(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val hmacAlgo = "HmacSHA256"
        val mac = javax.crypto.Mac.getInstance(hmacAlgo)
        
        // 1. Extract
        val actualSalt = if (salt == null || salt.isEmpty()) ByteArray(32) else salt
        mac.init(SecretKeySpec(actualSalt, hmacAlgo))
        val prk = mac.doFinal(ikm)
        
        // 2. Expand
        mac.init(SecretKeySpec(prk, hmacAlgo))
        val okm = ByteArray(length)
        var lastT = ByteArray(0)
        var offset = 0
        var chunkIndex = 1
        
        while (offset < length) {
            mac.update(lastT)
            mac.update(info)
            mac.update(chunkIndex.toByte())
            lastT = mac.doFinal()
            
            val remaining = length - offset
            val toCopy = if (remaining < lastT.size) remaining else lastT.size
            System.arraycopy(lastT, 0, okm, offset, toCopy)
            
            offset += toCopy
            chunkIndex++
        }
        
        return okm
    }

    fun computeSafetyNumber(myPublicKey: ByteArray, theirPublicKey: ByteArray): String {
        val myPubKeyBase64 = android.util.Base64.encodeToString(myPublicKey, android.util.Base64.NO_WRAP)
        val theirPubKeyBase64 = android.util.Base64.encodeToString(theirPublicKey, android.util.Base64.NO_WRAP)
        
        // 1. Sort Base64 strings (matching iOS)
        val sortedKeys = listOf(myPubKeyBase64, theirPubKeyBase64).sorted()
        
        // 2. Concatenate
        val combinedString = sortedKeys.joined()
        
        // 3. Hash the UTF-8 bytes of the combined string
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(combinedString.toByteArray(Charsets.UTF_8))
        
        // 4. Hex format and take first 60 characters
        val hexString = hash.joinToString("") { "%02x".format(it) }
        val shortFingerprint = hexString.take(60).uppercase()
        
        // 5. Group into chunks of 5
        val safetyNumber = shortFingerprint.chunked(5).joinToString(" ")
        
        return safetyNumber
    }

    // Helper for joining strings (Kotlin doesn't have joined() on List<String> exactly like Swift)
    private fun List<String>.joined(): String = this.joinToString("")
}
