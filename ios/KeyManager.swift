//
//  KeyManager.swift
//  evertouch iOS
//
//  Created by theoschuetz on 17.12.25.
//

import Foundation
import CryptoKit
import Security
import Combine

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

// Dedicated Keychain wrapper for Recovery Mnemonic
private class RecoveryMnemonicKeychainService {
    static let service = "com.evertouch.recoveryMnemonic"
    static let account = "primaryRecoveryMnemonic"

    static func saveMnemonic(_ mnemonic: String) throws {
        let data = mnemonic.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly // Require unlock
        ]
        
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CryptoError.keychainError(status: status, message: "Failed to save recovery mnemonic.")
        }
    }

    static func loadMnemonic() throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw CryptoError.keychainError(status: status, message: "Failed to load recovery mnemonic.")
        }
        
        guard let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func deleteMnemonic() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// Dedicated Keychain wrapper for Legacy Symmetric Keys
private class LegacyKeyKeychainService {
    static let service = "com.evertouch.legacySymmetricKey"
    static let account = "primaryLegacyKey"

    static func saveLegacyKey(_ data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CryptoError.keychainError(status: status, message: "Failed to save legacy key.")
        }
    }

    static func loadLegacyKey() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw CryptoError.keychainError(status: status, message: "Failed to load legacy key.")
        }
        return item as? Data
    }

    static func deleteLegacyKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// Dedicated Keychain wrapper for User Credentials
class CredentialKeychainService {
    static let service = "com.evertouch.credentials"

    static func saveCredentials(email: String, secret: String) throws {
        let secretData = secret.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, // Use kSecClassGenericPassword for credentials
            kSecAttrService as String: service,
            kSecAttrAccount as String: email,
            kSecValueData as String: secretData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly // More secure and consistent
        ]
        
        SecItemDelete(query as CFDictionary) // Delete any existing item first
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CryptoError.keychainError(status: status, message: "Failed to add credentials to Keychain.")
        }
    }

    static func loadCredentials(email: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: email,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            if status == errSecItemNotFound { return nil }
            throw CryptoError.keychainError(status: status, message: "Failed to load credentials from Keychain.")
        }
        
        guard let data = item as? Data, let secret = String(data: data, encoding: .utf8) else {
            return nil
        }
        return secret
    }
}

enum KDFType: String {
    case argon2id = "Argon2id"
    case pbkdf2 = "PBKDF2"
    case unknown = "Unknown"
}

class KeyManager {
    static let shared = KeyManager()

    private var _privateKey: Curve25519.KeyAgreement.PrivateKey?
    private var _profileSymmetricKey: SymmetricKey?
    private var _legacyProfileSymmetricKey: SymmetricKey?
    
    let keyDidBecomeAvailable = PassthroughSubject<Void, Never>()
    
    var kdfType: KDFType = .unknown

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
        // Load legacy key if it exists
        if let data = try? LegacyKeyKeychainService.loadLegacyKey() {
            _legacyProfileSymmetricKey = SymmetricKey(data: data)
        }
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

    // MARK: - Legacy Key Support
    
    var legacyProfileSymmetricKey: SymmetricKey? {
        get { _legacyProfileSymmetricKey }
        set {
            _legacyProfileSymmetricKey = newValue
            if let key = newValue {
                try? LegacyKeyKeychainService.saveLegacyKey(key.withUnsafeBytes { Data($0) })
            } else {
                try? LegacyKeyKeychainService.deleteLegacyKey()
            }
        }
    }

    // MARK: - Recovery Bundle
    
    struct RecoveryBundle: Codable {
        let privateKey: Data
        let profileSymmetricKey: Data
    }
    
    /// Encrypts the Private Key AND the current Profile Symmetric Key into a bundle.
    func encryptRecoveryBundle(recoveryKey: SymmetricKey) throws -> Data {
        guard let privateKey = self.privateKey, let symKey = self.profileSymmetricKey else {
            throw CryptoError.privateKeyUnavailable
        }
        
        let bundle = RecoveryBundle(
            privateKey: privateKey.rawRepresentation,
            profileSymmetricKey: symKey.withUnsafeBytes { Data($0) }
        )
        
        let bundleData: Data = try JSONEncoder().encode(bundle)
        let cryptoService = CryptoService()
        let encryptedData: EncryptedData = try cryptoService.encryptWithAESGCM(plaintext: bundleData, key: recoveryKey)
        
        let finalData: Data = try JSONEncoder().encode(encryptedData)
        return finalData
    }
    
    /// Decrypts the bundle and returns the Private Key and Old Profile Symmetric Key.
    func decryptRecoveryBundle(bundleData: Data, recoveryKey: SymmetricKey) throws -> (privateKey: Data, oldSymKey: SymmetricKey) {
        let encryptedData = try JSONDecoder().decode(EncryptedData.self, from: bundleData)
        let cryptoService = CryptoService()
        let decryptedBytes = try cryptoService.decryptWithAESGCM(encryptedData: encryptedData, key: recoveryKey)
        
        let bundle = try JSONDecoder().decode(RecoveryBundle.self, from: decryptedBytes)
        return (bundle.privateKey, SymmetricKey(data: bundle.profileSymmetricKey))
    }
    
    /// Special version for reset flow that takes raw keys.
    func encryptRecoveryBundleForReset(privateKey: Data, profileSymmetricKey: SymmetricKey, recoveryKey: SymmetricKey) throws -> Data {
        let bundle = RecoveryBundle(
            privateKey: privateKey,
            profileSymmetricKey: profileSymmetricKey.withUnsafeBytes { Data($0) }
        )
        
        let bundleData = try JSONEncoder().encode(bundle)
        let cryptoService = CryptoService()
        let encryptedData = try cryptoService.encryptWithAESGCM(plaintext: bundleData, key: recoveryKey)
        
        return try JSONEncoder().encode(encryptedData)
    }

    // MARK: - Recovery Mnemonic
    
    func saveRecoveryMnemonic(_ mnemonic: String) throws {
        try RecoveryMnemonicKeychainService.saveMnemonic(mnemonic)
    }
    
    func loadRecoveryMnemonic() throws -> String? {
        return try RecoveryMnemonicKeychainService.loadMnemonic()
    }
    
    func deleteRecoveryMnemonic() throws {
        try RecoveryMnemonicKeychainService.deleteMnemonic()
    }

    // MARK: - Symmetric Key for Profile
    
    /// The symmetric key used for encrypting/decrypting the user's own profile fields.
    /// Derived from the user's password (HKDF EncKey).
    var profileSymmetricKey: SymmetricKey? {
        get { _profileSymmetricKey }
        set { 
            _profileSymmetricKey = newValue 
            if newValue != nil {
                keyDidBecomeAvailable.send()
            }
        }
    }
    
    // MARK: - Credentials (Email/Password)
    
    func saveCredentials(email: String, secret: String) throws {
        try CredentialKeychainService.saveCredentials(email: email, secret: secret)
    }

    func loadCredentials(email: String) -> String? {
        // Implementation for loading would go here if needed, 
        // though we usually use AuthenticationViewModel for this flow.
        return nil 
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
    case invalidTagForAESGCM
    case invalidUserId // Added
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
        case .invalidTagForAESGCM:
            return "invalidTagForAESGCM"
        case .invalidUserId:
            return "invalidUserId"
        }
    }
}

