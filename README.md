# evertouch Security Core 🛡️

> **Private by Design.** This repository contains the core cryptographic implementation and security schemas for evertouch.

evertouch is a secure, self-updating contact identity platform. We believe that privacy shouldn't be a "feature"—it should be the foundation. To back up our claim of being a **Zero-Knowledge** platform, we have open-sourced the "Trust Chain" of our applications.

## 🎯 Purpose

The goal of this repository is to allow security researchers, developers, and users to verify that:
1. **Local Encryption**: All sensitive contact data is encrypted on the device before reaching any network.
2. **Zero-Knowledge**: The evertouch servers never see, store, or have the keys to decrypt your personal information.
3. **Auditability**: Our implementation follows industry-standard cryptographic protocols without backdoors.

## 📂 Repository Structure

This repository is a synced mirror of the security-critical components from our private production codebase.

- **/ios**: iOS implementation using **Swift** and **CryptoKit**. Includes `KeyManager` for Secure Enclave integration and `CryptoService` for AES-GCM/ECIES logic.
- **/android**: Android implementation using **Kotlin**, **Conscrypt**, and **BouncyCastle**.
- **/web**: Web-client decryption logic using the **Web Crypto API**, ensuring data is decrypted locally in the browser.
- **/backend**: **API Schemas** that demonstrate the server-side architecture—proving that the database only accepts and stores encrypted "blobs."

## ⚙️ Technical Specifications

We utilize modern, audited cryptographic primitives:

| Component | Protocol | Details |
| :--- | :--- | :--- |
| **Symmetric Encryption** | AES-256-GCM | Authenticated encryption for all profile data. |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | 600,000 iterations for password stretching. |
| **Master Key Expansion** | HKDF | Separates Authentication and Encryption keys. |
| **Asymmetric Encryption** | ECIES / P-256 | Used for secure key exchange between contacts. |
| **Storage** | Keychain / Keystore | Hardware-backed security where available. |

## 📖 Documentation

For a deeper dive into how evertouch works, please refer to:
- **[ZERO_KNOWLEDGE_ARCHITECTURE.md](./ZERO_KNOWLEDGE_ARCHITECTURE.md)**: Our high-level security model and data flow.
- **[SecurityGuide.md](./ios/SecurityGuide.md)**: Detailed technical breakdown of key rotations and threat models.

## 🤝 Verification & Contributing

We welcome the security community to audit this code. If you find a potential vulnerability, please help us keep evertouch safe by following responsible disclosure:

- **Reporting**: Please email **theo@evertouch.app**
- **Scope**: We are particularly interested in any flaws in the encryption implementation or potential key leakage scenarios.

## 📜 License

The code in this repository is provided for audit and educational purposes. See the [LICENSE](LICENSE.md) file for more details.

---
*This repository is automatically updated. Manual Pull Requests to this repo may be closed; please contact us directly for contributions.*
