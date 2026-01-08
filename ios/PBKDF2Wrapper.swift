//
//  PBKDF2Wrapper.swift
//  evertouch iOS
//
//  Created by Gemini on 02.01.26.
//

import Foundation
import CommonCrypto
import CryptoKit

enum PBKDF2Error: Error {
    case derivationFailed
}

class PBKDF2Wrapper {
    /// Derives a key using PBKDF2-HMAC-SHA256.
    /// - Parameters:
    ///   - password: The user's password.
    ///   - salt: The salt data.
    ///   - rounds: Number of iterations (e.g., 600,000).
    ///   - keyLength: Desired key length in bytes (e.g., 32 for AES-256).
    /// - Returns: Derived key data.
    static func deriveKey(password: String, salt: Data, rounds: UInt32 = 600_000, keyLength: Int = 32) throws -> Data {
        guard let passwordData = password.data(using: .utf8) else {
            throw PBKDF2Error.derivationFailed
        }
        
        var derivedKeyData = Data(count: keyLength)
        
        let status = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                passwordData.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress,
                        passwordData.count,
                        saltBytes.baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        rounds,
                        derivedKeyBytes.baseAddress,
                        keyLength
                    )
                }
            }
        }
        
        guard status == kCCSuccess else {
            throw PBKDF2Error.derivationFailed
        }
        
        return derivedKeyData
    }
}
