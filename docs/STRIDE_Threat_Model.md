# STRIDE Threat Model – Secure Notes Application

## Scope

This threat model focuses on the Secure Notes component of the
application, including note creation, retrieval, update, deletion,
encryption, database storage, and owner-based authorization.

The authentication system, administrative functionality, platform
hardening, and audit infrastructure are implemented by other team
members but are included where they form trust boundaries or security
dependencies.

---

## Protected Assets

- Plaintext note content
- Encrypted note content
- Note ownership information
- Note identifiers
- AES-256-GCM encryption key
- Initialization vectors (IVs)
- Authentication tags
- Authenticated user identity (`req.user.id`)

---

## Trust Boundaries

### TB-1: Browser to Express Application

User-controlled HTTP requests cross from the client browser into the
trusted backend application.

Security concerns include:
- Input manipulation
- IDOR attempts
- CSRF
- Malformed identifiers
- Unauthorized requests

### TB-2: Express Application to MongoDB

Validated and authorized application data crosses from the backend into
MongoDB.

Security concerns include:
- Information disclosure
- Unauthorized modification
- Database compromise
- Incorrect owner-scoped queries

### TB-3: Application to Encryption Key

The backend accesses `ENCRYPTION_KEY` from the server environment.

The key must never be:
- Stored in source code
- Returned through an API
- Sent to the browser
- Committed to GitHub

---

## STRIDE Threat Identification

| ID | Category | Threat | Impact | Mitigation |
|---|---|---|---|---|
| S-01 | Spoofing | An attacker attempts to access notes while impersonating another user. | Unauthorized access to private notes. | Authentication middleware establishes trusted `req.user = { id, role }`. Note authorization never trusts a user ID supplied in the request body. |
| T-01 | Tampering | An attacker or compromised database modifies encrypted note content. | Corrupted or maliciously modified note data. | AES-256-GCM authentication tags cause decryption to fail when ciphertext is modified. |
| T-02 | Tampering | A client attempts to modify protected fields such as `owner`, `iv`, `authTag`, or `encryptedContent`. | Ownership manipulation or corruption of encryption metadata. | Strict allow-list validation accepts only `title` and `content`. Unexpected fields are rejected. |
| R-01 | Repudiation | A user denies creating, updating, or deleting a note. | Difficulty investigating security incidents. | Platform audit logging should record security-relevant actions without storing plaintext note content or cryptographic secrets. |
| I-01 | Information Disclosure | MongoDB is accessed or leaked and plaintext notes are exposed. | Disclosure of sensitive user information. | Note content is encrypted at rest using AES-256-GCM before database storage. |
| I-02 | Information Disclosure | API responses expose encryption internals. | Cryptographic metadata leakage and unnecessary attack surface. | APIs return only required fields and do not expose the encryption key. List responses omit ciphertext, IV, and authentication tags. |
| I-03 | Information Disclosure | User B accesses User A's note by changing the note identifier. | Cross-user disclosure of private notes. | Owner-scoped queries require both `_id` and `owner: req.user.id`. Unauthorized resources return `404`. |
| D-01 | Denial of Service | Attackers submit excessively large note payloads repeatedly. | Resource exhaustion and reduced availability. | Express request-body limit, note length limits, validation, and platform rate limiting. |
| E-01 | Elevation of Privilege | A user modifies note ownership to obtain control of another user's resource. | Unauthorized control over protected data. | `owner` comes exclusively from authenticated server-side `req.user.id`; client-supplied ownership fields are rejected. |
| E-02 | Elevation of Privilege | User B attempts to update or delete User A's note using a known ObjectId. | Unauthorized modification or deletion. | Update and delete operations use owner-scoped database queries. |

---

## Implemented Security Controls

### AES-256-GCM Encryption

Plaintext note content is encrypted before being written to MongoDB.

The encryption operation produces:

- Ciphertext
- A random 96-bit IV
- An authentication tag

A fresh IV is generated for every encryption operation.

Automated tests verify:

- Encryption and successful decryption
- Ciphertext differs from plaintext
- Repeated encryption uses different IVs
- Modified ciphertext is rejected

### Owner-Scoped Authorization

Notes are accessed using database queries that include the authenticated
owner.

Example:

```javascript
Note.findOne({
  _id: req.params.id,
  owner: req.user.id,
});
```
-The application does not authorize note access using the note identifier
alone.

+IDOR Protection

Automated tests use separate User A and User B identities.

The tests verify that User B cannot:

Read User A's note
Update User A's note
Delete User A's note

The API returns 404 NOTE_NOT_FOUND for inaccessible notes to avoid
revealing whether another user's resource exists.

++Input Validation

Only the expected fields are accepted.

Create and update operations validate:

Data types
Empty values
Maximum lengths
Invalid ObjectIds
Unexpected fields

Protected fields such as owner, encryptedContent, iv, and
authTag cannot be controlled by the client.

Security Testing Evidence

The Secure Notes automated test suite covers:

AES-256-GCM encryption
Encryption round-trip
Tamper detection
Unique IV generation
Encrypted-at-rest database storage
Note creation validation
Owner-scoped note listing
Authorized note retrieval
GET IDOR protection
UPDATE IDOR protection
DELETE IDOR protection
Invalid ObjectId handling
Protected-field manipulation
Update re-encryption

At the current development stage, all Secure Notes tests pass together
with the existing platform tests.

Dependencies on Other Team Components

The Secure Notes component depends on:

Member 1 authentication middleware to provide trusted req.user.id
Member 3 CSRF protection for state-changing requests
Member 3 rate limiting and security hardening
Member 3 audit logging
Member 3 centralized platform configuration

A test-only mock authentication middleware is used during isolated
Secure Notes testing and is never installed in production routes.
