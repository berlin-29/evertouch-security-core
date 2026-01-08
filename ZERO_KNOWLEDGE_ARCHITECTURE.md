# Zero-Knowledge / Host-Proof Architecture

This document describes the security architecture of evertouch, focusing on the "Zero-Knowledge" (or "Host-Proof") design that ensures user data remains private even from the server administrators.

## Core Concept: Split-Key Architecture with Stretching

To protect user data from a malicious server or database breach, we employ a **Split-Key** design with **Key Stretching**. This ensures that:
1.  The credential used to *authenticate* (Login) is mathematically distinct from the credential used to *decrypt* (Data Access).
2.  The derivation is computationally expensive to prevent brute-force attacks.

### The Keys

All keys are derived client-side from the user's **Password** and a random **Recovery Salt**.

1.  **Master Key (Stretching Phase):**
    *   Derived as: `PBKDF2-HMAC-SHA256(Password, Salt, Iterations=600,000, KeyLength=256 bits)`
    *   This slow step protects against brute-force attacks if the salt is leaked.
    *   **Status:** Fully implemented in iOS and Android.

2.  **Auth Key (Authentication):**
    *   Derived as: `HKDF(MasterKey, info="auth-v1")`
    *   Sent to the server to prove identity.
    *   Server stores: `bcrypt(AuthKey)`.
    *   **Crucial:** The server cannot reverse `AuthKey` to get the `MasterKey` or `Password`.
    *   **Status:** Implemented in iOS and Android. New and migrated accounts use this.

3.  **Encryption Key (Decryption):**
    *   Derived as: `HKDF(MasterKey, info="enc-v1")`
    *   **NEVER sent to the server.**
    *   Used locally to encrypt/decrypt the user's private key bundle.
    *   **Status:** Implemented and used for new account private key bundles.

### The Handshake (Data Sharing)

evertouch is designed to use an asymmetric (Public/Private key) system to allow users to share data securely.

1.  **Identity Keys (X25519):**
    *   Every user has an X25519 Key Pair.
    *   **Public Key:** Stored openly on the server.
    *   **Private Key:** Stored on the server **encrypted** (via `EncKey` or legacy `PBKDF2`).
    *   **Status:** Key generation and storage implemented in both apps.

2.  **Sharing Flow (Target Architecture):**
    *   Alice fetches Bob's **Public Key**.
    *   Alice derives a shared secret using X25519 DH.
    *   Alice encrypts her contact card using the shared secret.
    *   **Current MVP Shortcut:** For initial compatibility, connections and shared payloads currently use a **Shared Profile Symmetric Key**. This is a transitional state before fully enabling the per-connection DH handshake.

## Authentication Flows

### 1. Registration (Signup)

1.  User enters `Email` and `Password`.
2.  **Client:** Generates a random 32-byte `Salt`.
3.  **Client:** Stretches password: `MasterKey = PBKDF2(Password, Salt, 600k)`.
4.  **Client:** Splits keys: `AuthKey = HKDF(MasterKey, "auth")`, `EncKey = HKDF(MasterKey, "enc")`.
5.  **Client:** Generates X25519 Key Pair.
6.  **Client:** Encrypts Private Key with `EncKey` (AES-GCM).
7.  **Client:** Sends `Email`, `AuthKey` (as password), `PublicKey`, `EncryptedPrivateKeyBundle`, and `Salt` to Server.
8.  **Server:** Hashes `AuthKey` with bcrypt and stores the user record.

### 2. Login

1.  User enters `Email`.
2.  **Client:** Requests `GET /auth/salt/{email}`.
3.  **Server:** Returns the user's `Salt`.
4.  **Client:** Prompts for `Password`.
5.  **Client:** Stretches: `MasterKey = PBKDF2(Password, Salt, 600k)`.
6.  **Client:** Derives `AuthKey` = `HKDF(MasterKey, "auth-v1")`.
7.  **Client:** Sends `AuthKey` to `/auth/login`.
8.  **Server:** Verifies `bcrypt(AuthKey)`. Returns success + `EncryptedPrivateKeyBundle`.
9.  **Client:** Derives `EncKey` = `HKDF(MasterKey, "enc-v1")`.
10. **Client:** Decrypts the Private Key Bundle. User is now online and capable of decryption.

### 3. Migration (Legacy Users)

For users created before this architecture:

1.  **Client:** Tries Login with `AuthKey`. **Fails** (Server has hash of raw password).
2.  **Client:** Fallback: Login with raw `Password`. **Succeeds**.
3.  **Client:** Immediately calls `POST /auth/migrate-hash` with the new `AuthKey`.
4.  **Server:** Updates database to store `bcrypt(AuthKey)`.
5.  **Next Login:** `AuthKey` login succeeds. Raw password is no longer valid.

## Threat Model

| Threat | Impact | Mitigation |
| :--- | :--- | :--- |
| **Database Leak** | **Low.** Attacker gets `bcrypt(AuthKey)` and encrypted blobs. | Cannot decrypt data without `EncKey`. `AuthKey` cannot be reversed to `Password`. |
| **Malicious Admin (Passive)** | **None.** Admin sees encrypted data at rest. | Admin does not have `EncKey`. |
| **Malicious Admin (Active/Sniffer)** | **Medium.** Admin captures `AuthKey` during login. | Admin can impersonate user (log in), but **cannot decrypt** past data because they cannot derive `EncKey` from `AuthKey`. |
| **Brute Force Attack** | **Very Low.** Attacker tries to guess password offline. | `PBKDF2` with 600,000 rounds makes each guess computationally expensive (~0.5s per guess). |
| **Device Compromise** | **High.** Attacker has unlocked keys. | Device security (Biometrics/Pin) is critical. |

## Technical Specifications



*   **Key Stretching:** PBKDF2-HMAC-SHA256 (600,000 iterations).

*   **Key Derivation:** HKDF-SHA256.

*   **Symmetric Encryption:** AES-256-GCM.

*   **Asymmetric Encryption:** X25519 (Key pairs generated, DH handshake in progress).

*   **Transport Security:** HTTPS (TLS 1.2+) required for all API calls.
