//
//  CryptoService.swift
//  evertouch iOS
//
//  Created by theoschuetz on 17.12.25.
//

import Foundation
import CryptoKit

struct EncryptedData: Codable {
    let ciphertext: Data
    let nonce: Data
    let tag: Data? // For AES-GCM, ChaChaPoly includes tag in ciphertext implicitly
    let algorithm: String // "AES-GCM" or "ChaChaPoly"
}

enum CryptoServiceError: LocalizedError {
    case randomByteGenerationFailed

    var errorDescription: String? {
        switch self {
        case .randomByteGenerationFailed:
            return "Failed to generate cryptographically secure random bytes."
        }
    }
}

class CryptoService {

    /// Encrypts plaintext data using AES-GCM.
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - key: The symmetric key to use for encryption.
    /// - Returns: An `EncryptedData` struct containing the ciphertext, nonce, and tag.
    func encryptWithAESGCM(plaintext: Data, key: SymmetricKey) throws -> EncryptedData {
        let sealedBox = try AES.GCM.seal(plaintext, using: key)
        let ciphertext = sealedBox.ciphertext
        let tag = sealedBox.tag
        let nonceData = sealedBox.nonce.withUnsafeBytes { Data($0) }
        return EncryptedData(ciphertext: ciphertext, nonce: nonceData, tag: tag, algorithm: "AES-GCM")
    }

    /// Decrypts data encrypted with AES-GCM.
    /// - Parameters:
    ///   - encryptedData: The `EncryptedData` struct containing ciphertext, nonce, and tag.
    ///   - key: The symmetric key to use for decryption.
    /// - Returns: The decrypted plaintext data.
    func decryptWithAESGCM(encryptedData: EncryptedData, key: SymmetricKey) throws -> Data {
        guard let tag = encryptedData.tag else {
            throw CryptoError.invalidCiphertext
        }
        let nonce = try AES.GCM.Nonce(data: encryptedData.nonce)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encryptedData.ciphertext, tag: tag)
        return try AES.GCM.open(sealedBox, using: key)
    }

    /// Encrypts plaintext data using ChaChaPoly.
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - key: The symmetric key to use for encryption.
    /// - Returns: An `EncryptedData` struct containing the ciphertext and nonce. (Tag is implicit in ChaChaPoly sealedBox.combined)
    func encryptWithChaChaPoly(plaintext: Data, key: SymmetricKey) throws -> EncryptedData {
        let sealedBox = try ChaChaPoly.seal(plaintext, using: key)
        let nonceData = sealedBox.nonce.withUnsafeBytes { Data($0) }
        return EncryptedData(ciphertext: sealedBox.combined, nonce: nonceData, tag: nil, algorithm: "ChaChaPoly")
    }

    /// Decrypts data encrypted with ChaChaPoly.
    /// - Parameters:
    ///   - encryptedData: The `EncryptedData` struct containing ciphertext and nonce.
    ///   - key: The symmetric key to use for decryption.
    /// - Returns: The decrypted plaintext data.
    func decryptWithChaChaPoly(encryptedData: EncryptedData, key: SymmetricKey) throws -> Data {
        let sealedBox = try ChaChaPoly.SealedBox(combined: encryptedData.ciphertext)
        return try ChaChaPoly.open(sealedBox, using: key)
    }

    /// Generates a new random symmetric key of the specified bit size (e.g., 256 for AES-256).
    /// - Parameter bitCount: The desired key size in bits.
    /// - Returns: A new `SymmetricKey`.
    static func generateSymmetricKey(bitCount: Int = 256) -> SymmetricKey {
        switch bitCount {
        case 128: return SymmetricKey(size: .bits128)
        case 192: return SymmetricKey(size: .bits192)
        case 256: return SymmetricKey(size: .bits256)
        default:
            // Fallback for non-standard sizes
            return SymmetricKey(size: SymmetricKeySize(bitCount: bitCount))
        }
    }
    
    /// Converts a symmetric key to Data.
    static func keyToData(_ key: SymmetricKey) -> Data {
        return key.withUnsafeBytes { Data($0) }
    }

    /// Converts Data back to a symmetric key.
    static func dataToKey(_ data: Data) -> SymmetricKey {
        return SymmetricKey(data: data)
    }

    /// Generates cryptographically secure random bytes.
    static func generateSecureRandomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status == errSecSuccess {
            return Data(bytes)
        } else {
            throw CryptoServiceError.randomByteGenerationFailed
        }
    }

    /// Encrypts Live Card payload using AES-256-GCM and a derived secret.
    func encryptLiveCardPayload(payload: Data, secret: Data) throws -> LiveCardCipher {
        let symmetricKey = SymmetricKey(data: secret)
        let nonce = try AES.GCM.Nonce(data: CryptoService.generateSecureRandomBytes(count: 12)) // 12-byte nonce
        
        let sealedBox = try AES.GCM.seal(payload, using: symmetricKey, nonce: nonce)
        
        return LiveCardCipher(
            v: 1,
            alg: "AES-256-GCM",
            nonce: sealedBox.nonce.withUnsafeBytes { Data($0).base64EncodedString() },
            ct: sealedBox.ciphertext.base64EncodedString(),
            tag: sealedBox.tag.base64EncodedString()
        )
    }

    /// Decrypts Live Card payload using AES-256-GCM and a derived secret.
    func decryptLiveCardPayload(cipher: LiveCardCipher, secret: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: secret)
        
        guard let nonceData = Data(base64Encoded: cipher.nonce),
              let ciphertextData = Data(base64Encoded: cipher.ct),
              let tagData = Data(base64Encoded: cipher.tag) else {
            throw CryptoError.invalidCiphertext
        }
        
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextData, tag: tagData)
        
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }

    /// Derives authentication and encryption keys from password and salt using PBKDF2 + HKDF.
    /// - Parameters:
    ///   - password: The user's password.
    ///   - saltBase64: The base64 encoded salt string.
    /// - Returns: A tuple containing the authKey (base64) and the encKey (SymmetricKey).
    func deriveSplitKeys(password: String, saltBase64: String) throws -> (authKey: String, encKey: SymmetricKey) {
        guard let saltData = Data(base64Encoded: saltBase64) else {
            throw CryptoError.invalidCiphertext
        }
        
        // 1. Stretch Password (PBKDF2)
        // NIST recommends 600,000 iterations for PBKDF2-HMAC-SHA256
        let masterKeyData = try PBKDF2Wrapper.deriveKey(password: password, salt: saltData, rounds: 600_000, keyLength: 32)
        let masterKey = SymmetricKey(data: masterKeyData)

        // 2. Derive Auth Key (HKDF)
        // Info: "auth-v1"
        let authKeyInfo = "auth-v1".data(using: .utf8)!
        let authKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterKey,
            salt: Data(), // No extra salt needed for HKDF if input is high entropy
            info: authKeyInfo,
            outputByteCount: 32
        )
        let authKeyBase64 = authKey.withUnsafeBytes { Data($0).base64EncodedString() }

        // 3. Derive Encryption Key (HKDF)
        // Info: "enc-v1"
        let encKeyInfo = "enc-v1".data(using: .utf8)!
        let encKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterKey,
            salt: Data(),
            info: encKeyInfo,
            outputByteCount: 32
        )
        
        return (authKeyBase64, encKey)
    }
}

