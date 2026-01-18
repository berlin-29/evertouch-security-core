//
//  Argon2Wrapper.swift
//  evertouch iOS
//
//  Created by Gemini on 17.01.26.
//

import Foundation
import Argon2Kit

enum Argon2Error: Error {
    case derivationFailed
    case encodingError
}

class Argon2Wrapper {
    /// Derives a key using Argon2id.
    /// This now uses the linked Argon2Kit library.
    static func deriveKey(password: String, salt: Data, t_cost: UInt32 = 3, m_cost: UInt32 = 65536, parallelism: UInt32 = 4, keyLength: Int = 32) throws -> Data {
        guard let _ = password.data(using: .utf8) else {
            throw Argon2Error.encodingError
        }
        
        do {
            // Argon2Kit expects UInt32 for iterations, memory, threads, and length.
            // Our input parameters t_cost, m_cost, and parallelism are already UInt32.
            let result = try Argon2.hash(
                password: password,
                salt: salt,
                iterations: t_cost,
                memory: m_cost,
                threads: parallelism,
                length: UInt32(keyLength),
                type: .id
            )
            // Return the raw derived key bytes rather than the encoded hash string.
            return result.rawData
        } catch {
            print("DEBUG: Argon2 derivation error: \(error)")
            throw Argon2Error.derivationFailed
        }
    }
}

