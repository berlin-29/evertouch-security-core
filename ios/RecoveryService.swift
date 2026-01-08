//
//  RecoveryService.swift
//  evertouch iOS
//
//  Created by theoschuetz on 17.12.25.
//

import Foundation
import CryptoKit

class RecoveryService {

    /// Secure Key Derivation (PBKDF2). Used for all key derivations from a passphrase.
    /// - Parameters:
    ///   - passphrase: The user's passphrase.
    ///   - salt: The salt data.
    /// - Returns: A `SymmetricKey` derived from the passphrase and salt.
    static func deriveKeyPBKDF2(passphrase: String, salt: Data) throws -> SymmetricKey {
        let derivedData = try PBKDF2Wrapper.deriveKey(password: passphrase, salt: salt)
        return SymmetricKey(data: derivedData)
    }

    /// Encrypts a private key using the secure PBKDF2 derived key.
    /// - Parameters:
    ///   - privateKeyData: The raw data of the private key to encrypt.
    ///   - passphrase: The user's passphrase.
    /// - Returns: A tuple containing the encrypted data (`EncryptedData`) and the salt used.
    static func encryptPrivateKeyBundle(privateKeyData: Data, passphrase: String) throws -> (encryptedBundle: EncryptedData, salt: Data) {
        let salt = Data((0..<32).map { _ in UInt8.random(in: 0...255) }) // Generate a 32-byte random salt
        
        // Always use the secure PBKDF2 method for new encryptions
        let derivedKey = try deriveKeyPBKDF2(passphrase: passphrase, salt: salt)

        let cryptoService = CryptoService()
        let encryptedBundle = try cryptoService.encryptWithAESGCM(plaintext: privateKeyData, key: derivedKey)
        return (encryptedBundle, salt)
    }

    /// Decrypts an encrypted private key bundle using the secure PBKDF2 derived key.
    /// This method now exclusively uses PBKDF2, assuming all bundles are created with it.
    /// - Parameters:
    ///   - encryptedBundle: The `EncryptedData` containing the encrypted private key.
    ///   - passphrase: The user's passphrase.
    ///   - salt: The salt used during encryption.
    /// - Returns: The decrypted private key data.
    static func decryptPrivateKeyBundle(encryptedBundle: EncryptedData, passphrase: String, salt: Data) throws -> Data {
        let cryptoService = CryptoService()
        
        // Exclusively use PBKDF2 for decryption
        let derivedKey = try deriveKeyPBKDF2(passphrase: passphrase, salt: salt)
        let decryptedData = try cryptoService.decryptWithAESGCM(encryptedData: encryptedBundle, key: derivedKey)
        
        return decryptedData
    }
}