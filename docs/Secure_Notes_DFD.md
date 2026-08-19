# Secure Notes – Data Flow Diagram

## Purpose

This Data Flow Diagram describes how note data moves through the Secure
Notes component and identifies the major trust boundaries relevant to
STRIDE threat modeling.

---

## Main Components

1. User
2. Browser / Notes Dashboard
3. Authentication Middleware
4. Notes API
5. Validation and Authorization Layer
6. AES-256-GCM Encryption Utility
7. MongoDB
8. Server Environment / Encryption Key

---

## Data Flow Diagram

```mermaid
flowchart TD

    U[User]

    B[Browser / Notes Dashboard]

    AUTH[Authentication Middleware
    req.user = id, role]

    API[Notes API
    Express.js]

    VAL[Validation + Owner Authorization]

    ENC[AES-256-GCM
    Encryption / Decryption]

    DB[(MongoDB
    Encrypted Notes)]

    ENV[Server Environment
    ENCRYPTION_KEY]

    U -->|User input| B

    B -->|HTTPS Request| AUTH

    AUTH -->|Trusted req.user.id| API

    API --> VAL

    VAL -->|Validated plaintext note| ENC

    ENV -->|Encryption key| ENC

    ENC -->|Ciphertext + IV + Auth Tag| DB

    DB -->|Encrypted note data| ENC

    ENC -->|Decrypted authorized content| API

    API -->|HTTPS Response| B
