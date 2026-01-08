# evertouch Security Core

This repository contains the core security and cryptographic logic of **evertouch**. 

Our goal is to be **private by design**. To achieve this, we open-source the "Trust Chain" of our application so that security researchers and technical users can verify that:
1. Encryption and decryption happen exclusively on the user's device.
2. The server never has access to unencrypted personal data.
3. Our key derivation and storage follow industry standards.

## 📂 Repository Structure

- `/ios`: Cryptographic implementation for iOS (Swift/CryptoKit).
- `/android`: Cryptographic implementation for Android (Kotlin/Conscrypt/BouncyCastle).
- `/web`: Decryption logic for the evertouch Web App (Web Crypto API).
- `/backend`: API Schemas demonstrating that the server only accepts encrypted blobs.

## 📖 Key Documentation

- **[ZERO_KNOWLEDGE_ARCHITECTURE.md](./ZERO_KNOWLEDGE_ARCHITECTURE.md)**: A high-level overview of our security model.
- **[SecurityGuide.md](./SecurityGuide.md)**: Technical details on algorithms, key derivation, and threat models.

## 🛡️ Verification

You are encouraged to audit the code in this repository. We use industry-standard protocols including:
- **AES-256-GCM** for data encryption.
- **PBKDF2-HMAC-SHA256** (600,000 iterations) for password stretching.
- **HKDF** for key derivation.
- **ECIES** for secure key exchange.

---
*Note: This repository is automatically synced with our private development codebase. If you find a vulnerability, please contact us at theo@evertouch.app.*
