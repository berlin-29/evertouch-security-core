package com.schuetz.evertouch.util.crypto

import java.security.SecureRandom
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName as KSerialName
import com.schuetz.evertouch.util.Base64BytesSerializer
import android.util.Base64
import com.google.gson.annotations.SerializedName

@Serializable
data class EncryptedData(
    @SerializedName("ciphertext") @KSerialName("ciphertext")
    @Serializable(with = Base64BytesSerializer::class)
    val ciphertext: ByteArray,
    @SerializedName("nonce") @KSerialName("nonce")
    @Serializable(with = Base64BytesSerializer::class)
    val nonce: ByteArray,
    @SerializedName("tag") @KSerialName("tag")
    @Serializable(with = Base64BytesSerializer::class)
    val tag: ByteArray?,
    @SerializedName("algorithm") @KSerialName("algorithm")
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
        val cipher = Cipher.getInstance(AES_MODE)
        val spec = GCMParameterSpec(TAG_LENGTH_BITS, encryptedData.nonce)
        
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        
        val tag = encryptedData.tag ?: throw IllegalArgumentException("Tag is required for AES-GCM")
        
        val combined = ByteArray(encryptedData.ciphertext.size + tag.size)
        System.arraycopy(encryptedData.ciphertext, 0, combined, 0, encryptedData.ciphertext.size)
        System.arraycopy(tag, 0, combined, encryptedData.ciphertext.size, tag.size)
        
        return cipher.doFinal(combined)
    }

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

    fun decryptCombined(combined: ByteArray, key: SecretKey): ByteArray {
        val tagLengthBytes = TAG_LENGTH_BITS / 8
        if (combined.size < IV_LENGTH_BYTES + tagLengthBytes) {
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
        val salt = Base64.decode(saltBase64, Base64.DEFAULT)
        
        val generator = org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator(org.bouncycastle.crypto.digests.SHA256Digest())
        generator.init(password.toByteArray(Charsets.UTF_8), salt, 600000)
        val masterKeyBytes = (generator.generateDerivedParameters(256) as org.bouncycastle.crypto.params.KeyParameter).key
        
        val authInfo = "auth-v1".toByteArray(Charsets.UTF_8)
        val authKeyBytes = hkdfExpand(masterKeyBytes, null, authInfo, 32)
        val authKeyBase64 = Base64.encodeToString(authKeyBytes, Base64.NO_WRAP)
        
        val encInfo = "enc-v1".toByteArray(Charsets.UTF_8)
        val encKeyBytes = hkdfExpand(masterKeyBytes, null, encInfo, 32)
        val encKey = SecretKeySpec(encKeyBytes, "AES")
        
        return Pair(authKeyBase64, encKey)
    }

    fun deriveArgon2Keys(password: String, saltBase64: String): Pair<String, SecretKey> {
        val salt = Base64.decode(saltBase64, Base64.DEFAULT)

        val argon2Kt = Argon2Kt()
        val result = argon2Kt.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = password.toByteArray(Charsets.UTF_8),
            salt = salt,
            tCostInIterations = 3,
            mCostInKibibyte = 65536,
            parallelism = 4,
            hashLengthInBytes = 32
        )
        val masterKeyBytes = ByteArray(result.rawHash.remaining())
        result.rawHash.get(masterKeyBytes)

        val authInfo = "auth-v1".toByteArray(Charsets.UTF_8)
        val authKeyBytes = hkdfExpand(masterKeyBytes, null, authInfo, 32)
        val authKeyBase64 = Base64.encodeToString(authKeyBytes, Base64.NO_WRAP)
        
        val encInfo = "enc-v1".toByteArray(Charsets.UTF_8)
        val encKeyBytes = hkdfExpand(masterKeyBytes, null, encInfo, 32)
        val encKey = SecretKeySpec(encKeyBytes, "AES")
        
        return Pair(authKeyBase64, encKey)
    }

    fun decryptLiveCardPayload(cipher: com.schuetz.evertouch.data.model.LiveCardCipher, secret: ByteArray): ByteArray {
        val key = SecretKeySpec(secret, "AES")
        val nonce = Base64.decode(cipher.nonce, Base64.NO_WRAP)
        val ciphertext = Base64.decode(cipher.ct, Base64.NO_WRAP)
        val tag = Base64.decode(cipher.tag, Base64.NO_WRAP)
        
        val encryptedData = EncryptedData(ciphertext, nonce, tag, cipher.alg)
        return decryptWithAESGCM(encryptedData, key)
    }

    internal fun hkdfExpand(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val hmacAlgo = "HmacSHA256"
        val mac = javax.crypto.Mac.getInstance(hmacAlgo)
        
        val actualSalt = if (salt == null || salt.isEmpty()) ByteArray(32) else salt
        mac.init(SecretKeySpec(actualSalt, hmacAlgo))
        val prk = mac.doFinal(ikm)
        
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
        val myPubKeyBase64 = Base64.encodeToString(myPublicKey, Base64.NO_WRAP)
        val theirPubKeyBase64 = Base64.encodeToString(theirPublicKey, Base64.NO_WRAP)
        
        val sortedKeys = listOf(myPubKeyBase64, theirPubKeyBase64).sorted()
        val combinedString = sortedKeys.joinToString("")
        
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(combinedString.toByteArray(Charsets.UTF_8))
        
        val hexString = hash.joinToString("") { "%02x".format(it) }
        val shortFingerprint = hexString.take(60).uppercase()
        val safetyNumber = shortFingerprint.chunked(5).joinToString(" ")
        
        return safetyNumber
    }
}
