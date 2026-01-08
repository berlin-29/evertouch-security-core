//
//  KeyManager.swift
//  evertouch iOS
//
//  Created by theoschuetz on 17.12.25.
//

import Foundation
import CryptoKit
import Security // Added for Keychain Services

// Use a dedicated Keychain wrapper for LiveCard secrets
private class LiveCardKeychainService {
    static let serviceIdentifier = "com.evertouch.LiveCardSecrets"

    private static func dataToDictionary(shareId: UUID, secret: String) -> [String: Any] {
        let secretData = secret.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: shareId.uuidString,
            kSecValueData as String: secretData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock // Accessible after first unlock
        ]
        return query
    }

    static func saveSecret(shareId: UUID, secret: String) throws {
        let query = dataToDictionary(shareId: shareId, secret: secret)
        
        // Delete any existing item first
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CryptoError.keychainError(status: status, message: "Failed to add LiveCard secret.")
        }
    }

    static func loadSecret(shareId: UUID) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: shareId.uuidString,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            if status == errSecItemNotFound { return nil }
            throw CryptoError.keychainError(status: status, message: "Failed to load LiveCard secret.")
        }
        
        guard let data = item as? Data, let secret = String(data: data, encoding: .utf8) else {
            return nil
        }
        return secret
    }

    static func deleteSecret(shareId: UUID) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: shareId.uuidString
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CryptoError.keychainError(status: status, message: "Failed to delete LiveCard secret.")
        }
    }
}

// Dedicated Keychain wrapper for private keys (Curve25519)
private class PrivateKeyKeychainService {
    static let service = "com.evertouch.privateKeyService"
    static let account = "primaryPrivateKey"

    static func savePrivateKey(_ privateKey: Curve25519.KeyAgreement.PrivateKey) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: privateKey.rawRepresentation,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly // More secure
        ]
        
        SecItemDelete(query as CFDictionary) // Delete any existing item first
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CryptoError.keychainError(status: status, message: "Failed to save private key.")
        }
    }

    static func loadPrivateKey() throws -> Curve25519.KeyAgreement.PrivateKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            if status == errSecItemNotFound { return nil }
            throw CryptoError.keychainError(status: status, message: "Failed to load private key.")
        }
        
        guard let data = item as? Data else { return nil }
        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
    }

    static func deletePrivateKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        // -25303 (errSecNoSuchAttr) can happen if the item or its attributes are partially missing/corrupt
        guard status == errSecSuccess || status == errSecItemNotFound || status == -25303 else {
            throw CryptoError.keychainError(status: status, message: "Failed to delete private key.")
        }
    }
}

// Dedicated Keychain wrapper for User Credentials (iCloud Sync)
private class CredentialKeychainService {
    static let service = "com.evertouch.credentials" // Service identifier for web passwords

    static func saveCredentials(email: String, secret: String) throws {
        let secretData = secret.data(using: .utf8)!
        
        // Define the query for an Internet Password
        // Note: For iCloud Keychain sync, we use kSecAttrSynchronizable: kCFBooleanTrue
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: "evertouch.app", // Your domain
            kSecAttrAccount as String: email,
            kSecValueData as String: secretData,
            kSecAttrSynchronizable as String: kCFBooleanTrue!,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        // Delete any existing item first
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CryptoError.keychainError(status: status, message: "Failed to save credentials.")
        }
    }
}

class KeyManager {

    private var _privateKey: Curve25519.KeyAgreement.PrivateKey?

    var privateKey: Curve25519.KeyAgreement.PrivateKey? {
        if _privateKey == nil {
            _privateKey = try? PrivateKeyKeychainService.loadPrivateKey()
        }
        return _privateKey
    }

    var publicKey: Curve25519.KeyAgreement.PublicKey? {
        return privateKey?.publicKey
    }

    init() {
        _privateKey = try? PrivateKeyKeychainService.loadPrivateKey()
    }

    /// Generates a new Curve25519 key pair and stores the private key in the Keychain.
    /// Returns the public key as Data.
    func generateKeyPair() throws -> Data {
        let newPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        _privateKey = newPrivateKey
        try PrivateKeyKeychainService.savePrivateKey(newPrivateKey)
        return newPrivateKey.publicKey.rawRepresentation
    }

    /// Retrieves the stored public key.
    func getPublicKey() -> Data? {
        return publicKey?.rawRepresentation
    }

    /// Stores a private key from its raw representation in the Keychain.
    func storePrivateKey(rawRepresentation: Data) throws {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
        _privateKey = privateKey
        try PrivateKeyKeychainService.savePrivateKey(privateKey)
    }

    /// Deletes the private key from the Keychain.
    func deleteKeyPair() throws {
        _privateKey = nil
        try PrivateKeyKeychainService.deletePrivateKey()
    }

    // MARK: - Symmetric Key for Profile
    
    // DEV_NOTE: This is a temporary, static key for the MVP.
    // Reverted from secure derivation to maintain compatibility with existing data.
    // In a final production app, this should be derived securely and migrated properly.
    var profileSymmetricKey: SymmetricKey? {
        let staticKeyData = Data("a-very-secret-32-byte-static-key".utf8) // Using a 32-byte key for AES-256
        return SymmetricKey(data: staticKeyData)
    }
    
    // MARK: - Credentials (Email/Password)
    
    func saveCredentials(email: String, secret: String) throws {
        try CredentialKeychainService.saveCredentials(email: email, secret: secret)
    }

    // MARK: - LiveCard Secrets
    
    func saveLiveCardSecret(shareId: UUID, secret: String) throws {
        try LiveCardKeychainService.saveSecret(shareId: shareId, secret: secret)
    }

    func loadLiveCardSecret(shareId: UUID) throws -> String? {
        return try LiveCardKeychainService.loadSecret(shareId: shareId)
    }

    func deleteLiveCardSecret(shareId: UUID) throws {
        try LiveCardKeychainService.deleteSecret(shareId: shareId)
    }

    // MARK: - Diffie-Hellman Key Agreement
    
    /// Computes a shared secret with a recipient's public key.
    /// - Parameter recipientPublicKeyData: The raw representation of the recipient's public key.
    /// - Returns: The shared secret as a SymmetricKey.
    /// - Throws: An error if the public key is invalid or private key is not available.
    func computeSharedSecret(with recipientPublicKeyData: Data) throws -> SymmetricKey {
        guard let privateKey = self.privateKey else {
            throw CryptoError.privateKeyUnavailable
        }
        let recipientPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKeyData)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
        // Derive a SymmetricKey from the shared secret using HKDF with HMAC<SHA256>
        let salt = Data("evertouch-key-agreement".utf8)
        let sharedInfo = Data("Curve25519.KeyAgreement v1".utf8)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
        return symmetricKey
    }
}

enum CryptoError: Error, LocalizedError {
    case privateKeyUnavailable
    case symmetricKeyUnavailable
    case invalidPublicKey
    case encryptionFailed
    case decryptionFailed
    case invalidCiphertext
    case randomByteGenerationFailed(errorDescription: String)
    case keychainError(status: OSStatus, message: String) // Added

    var errorDescription: String? {
        switch self {
        case .privateKeyUnavailable:
            return "The private key is not available in the Keychain."
        case .symmetricKeyUnavailable:
            return "The symmetric key for profile data is not available."
        case .invalidPublicKey:
            return "The provided public key is invalid."
        case .encryptionFailed:
            return "Encryption operation failed."
        case .decryptionFailed:
            return "Decryption operation failed."
        case .invalidCiphertext:
            return "Invalid ciphertext for decryption."
        case .randomByteGenerationFailed(let description):
            return description
        case .keychainError(let status, let message):
            return "\(message) Status: \(status)."
        }
    }
}

