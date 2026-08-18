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
  _id: req.params.noteId,
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

---

# Addendum — Identity, Platform and Administration Threats

> **Provenance and review status.** Everything **above** this line is Member
> 2's Secure Notes threat model and has not been altered. Everything **below**
> was added by Members 1 and 3 to cover authentication, session management,
> platform hardening and the administration feature, which were out of scope
> when the original model was written. New identifiers continue the existing
> numbering (`S-02` onward) and do not collide with any existing row.
> Flagged for Member 2's review before the integration merge.

## Additional protected assets

- User credentials (passwords, and the bcrypt hashes derived from them)
- TOTP / multi-factor secrets, both pending and confirmed
- Session tokens (`sn_session` JWTs) and short-lived MFA tickets
- CSRF tokens and the `CSRF_SECRET` used to sign them
- The JWT signing secret (`JWT_SECRET`)
- Role assignments, and the administrator role in particular
- Audit records
- Deployment secrets held in CI (`SNYK_TOKEN`, and any environment values)

## Additional trust boundaries

### TB-4: Unauthenticated internet to the authentication endpoints

`POST /api/auth/register`, `/api/auth/login` and `/api/auth/mfa/verify-login`
are reachable by anyone, with no session yet established. They cannot rely on
CSRF tokens (there is no session to bind one to), so they are defended instead
by CAPTCHA, strict rate limiting, allow-list validation and account lockout.

### TB-5: Ordinary user to administrator privilege

Every `/api/admin/*` route crosses from ordinary-user privilege into
administrative privilege. The only thing standing on that boundary is
`requireRole('admin')` reading `req.user.role`, which is derived from a
verified JWT plus a fresh database lookup — never from client input.

### TB-6: Repository and CI to the deployed application

Source, dependencies and workflow definitions flow from GitHub into the
running application. A compromised dependency, a leaked secret in a commit, or
a malicious workflow change crosses this boundary directly into production.

## STRIDE threats — identity, platform and administration

| ID | Category | Threat | Impact | Mitigation | Where |
|---|---|---|---|---|---|
| S-02 | Spoofing | An attacker guesses credentials at scale against the login endpoint. | Account takeover. | Server-side CAPTCHA, per-IP rate limiting, and 15-minute account lockout after 5 failures. | `middleware/captcha.js`, `middleware/rateLimiter.js`, `controllers/authController.js` |
| S-03 | Spoofing | Injected script reads the session token and replays it. | Full session hijack. | `HttpOnly` session cookie, strict CSP with no `unsafe-inline`, no `innerHTML` use with server data. | `utils/jwt.js`, `app.js`, `public/js/*.js` |
| S-04 | Spoofing | An attacker forges a session JWT (`alg: none`, algorithm confusion, or a weak secret). | Arbitrary identity and role. | Verification pinned to `HS256`, issuer and audience asserted, startup fails without a strong `JWT_SECRET`. | `utils/jwt.js` |
| S-05 | Spoofing | An MFA ticket is captured and replayed within its validity window. | Second factor bypassed. | Ticket is a distinct JWT with `purpose: 'mfa_pending'`, expires in ~2 minutes, and is rejected by `requireAuth`. Single-use enforcement is **not** implemented — see DREAD DR-11. | `utils/jwt.js`, `middleware/auth.js` |
| S-06 | Spoofing | A user picks a weak or already-breached password. | Predictable credentials. | Minimum 10 characters with mixed case, digit and symbol; bcrypt cost factor 12. Breach-corpus checking is **not** implemented — see DREAD DR-13. | `routes/authRoutes.js` |
| S-07 | Spoofing | The session cookie is intercepted on the network. | Session hijack. | `Secure` cookie flag in production, HSTS via Helmet, `SameSite=Strict`. | `utils/jwt.js`, `app.js` |
| T-03 | Tampering | A malicious site triggers an authenticated state-changing request using the victim's cookie. | Unwanted logout, MFA disable, note or user deletion. | `SameSite=Strict` plus a signed double-submit CSRF token required on every authenticated write. | `middleware/csrfProtection.js` |
| T-04 | Tampering | A crafted body or query smuggles a MongoDB operator into a query filter. | Authentication bypass, unintended data access. | Keys beginning with `$` or containing `.` are stripped from body and query before routing; `express-validator` independently enforces types. | `middleware/validate.js` |
| T-05 | Tampering | A request body carries extra fields the handler was not expecting (for example `role` or `status`). | Mass assignment, privilege escalation. | Per-route allow-lists reject unknown top-level fields with `422` before any controller runs. | `middleware/validate.js`, `routes/*.js` |
| R-02 | Repudiation | An administrator denies having deleted or disabled an account. | Disputed administrative action. | Every administrative action writes an audit record with actor, target, outcome and request id. Records are **not** tamper-evident — anyone with database write access could alter them. | `services/auditService.js`, `models/AuditLog.js` |
| I-04 | Information Disclosure | A database compromise exposes stored TOTP secrets. | Permanent, silent MFA bypass. | Secrets encrypted with AES-256-GCM before storage and marked `select: false`. Effectiveness depends entirely on `ENCRYPTION_KEY` staying secret. | `models/User.js`, `utils/encryption.js` |
| I-05 | Information Disclosure | Differing responses or response times reveal which accounts exist. | Targeted credential attacks. | Unknown email, wrong password, locked and disabled accounts all return an identical `401`; a dummy bcrypt comparison levels the timing. Registration deliberately returns `409` for usability. | `controllers/authController.js` |
| I-06 | Information Disclosure | A handler returns a raw user document containing a password hash or MFA secret. | Offline cracking, MFA bypass. | `select: false` at the schema level, `toJSON`/`toObject` transforms strip sensitive fields, and controllers build explicit response objects. | `models/User.js`, all controllers |
| I-07 | Information Disclosure | An error response or log line leaks a stack trace, connection string or secret. | Reconnaissance, credential exposure. | Central error handler returns a generic message for any `5xx`; request logging records only method, path, status and duration. | `middleware/errorHandler.js`, `middleware/requestLogger.js` |
| I-08 | Information Disclosure | A browser origin the team does not control reads authenticated API responses. | Cross-origin data theft. | CORS allows exactly one configured origin with credentials; every other origin is refused with `403 CORS_ORIGIN_DENIED`. | `app.js` |
| D-02 | Denial of Service | An attacker deliberately triggers account lockout on a victim. | Legitimate user locked out. | Lock is time-boxed to 15 minutes and self-clearing; counter resets on success. Accepted trade-off — see DREAD DR-10. | `controllers/authController.js` |
| D-03 | Denial of Service | Bots create accounts in bulk. | Storage exhaustion, unusable admin views. | CAPTCHA and rate limiting on registration; CAPTCHA fails closed on provider outage. | `middleware/captcha.js`, `middleware/rateLimiter.js` |
| D-04 | Denial of Service | An oversized request body exhausts memory or CPU. | Reduced availability. | `express.json({ limit: '10kb', strict: true })` rejects oversized bodies with `413` before parsing completes. | `app.js` |
| E-03 | Elevation of Privilege | A client submits `role: "admin"` during registration or profile update. | Full administrative access. | Registration hard-codes `role: 'user'`, allow-list validation rejects the field, and role is only ever read from the verified session. Administrators are created out of band. | `controllers/authController.js`, `scripts/createAdmin.js` |
| E-04 | Elevation of Privilege | A token captured before logout keeps working. | Session lives past revocation. | Every user has a `tokenVersion` embedded in each token as `tv`; logout, MFA disable and admin deactivation increment it, invalidating all earlier tokens. | `models/User.js`, `middleware/auth.js` |
| E-05 | Elevation of Privilege | An ordinary user reaches an administrative endpoint directly. | Unauthorised user management. | `requireAuth` then `requireRole('admin')` is applied at the router level, so it cannot be forgotten on an individual route. | `routes/adminRoutes.js`, `middleware/rbac.js` |
| E-06 | Elevation of Privilege | An administrator removes the last remaining administrator, or locks themselves out. | Irrecoverable loss of administrative access. | Self-delete and self-disable are refused with `403 SELF_ACTION_DENIED`; a last-active-administrator check is retained as defence in depth. | `controllers/adminController.js` |
| T-06 | Tampering | A compromised or typosquatted dependency ships malicious code. | Full application compromise. | Exact-pinned dependency versions, committed lockfile, `npm audit` and Snyk on every push, and Dependabot-style review before upgrades. | `package.json`, `.github/workflows/security.yml` |
| I-09 | Information Disclosure | A secret is committed to the repository or printed in CI output. | Direct key compromise. | `.env` is git-ignored, `.env.example` holds placeholders only, CI secrets are referenced through GitHub Secrets, and `scripts/createAdmin.js` never prints a password. | `.gitignore`, `.env.example`, workflows |

## Component dependency map

The following table replaces the informal dependency list at the end of the
original document with the concrete, as-built wiring.

| Consumer | Depends on | Provided by |
|---|---|---|
| Secure Notes routes | `requireAuth` setting `req.user = { id, role }` | Member 1 — `middleware/auth.js` |
| Secure Notes writes | `verifyCsrfToken` | Member 3 — `middleware/csrfProtection.js` |
| Secure Notes actions | `recordAuditEvent` | Member 3 — `services/auditService.js` |
| MFA secret storage | `encrypt` / `decrypt` (AES-256-GCM) | Member 2 — `utils/encryption.js` |
| Admin user deletion | `Note` model, for cascade cleanup | Member 2 — `models/Note.js` |
| Admin routes | `User` model and `requireAuth` | Member 1 — `models/User.js`, `middleware/auth.js` |

A note on the test-only mock authentication middleware referenced in the
original document: it is still in use, and that remains correct. Member 2's
note tests mount her controller on a throwaway Express application with
`createMockAuth`, deliberately isolating note logic from the authentication
stack. What has changed is that the mock is no longer the *only* coverage —
the real `requireAuth` is now mounted in `routes/noteRoutes.js`, and
`tests/notes/notesPipeline.integration.test.js` drives the note endpoints
through the fully assembled application using genuine sessions issued by the
real login endpoint. The mock lives under `tests/`, is imported only by
tests, and is never reachable from production code.

## Related documents

- `docs/DREAD_Risk_Assessment.md` — risk scoring and treatment plan for the
  identity threats above (`DR-01` … `DR-15` map to the `S-`, `T-`, `I-`, `D-`
  and `E-` identifiers used here).
- `scans/remediation-log.md` — what CodeQL, Snyk and `npm audit` actually
  found, and what was done about each finding.
