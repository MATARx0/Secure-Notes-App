# Secure Notes Application

A three-member Application Security project: a note-taking web application
where every note is encrypted at rest, every session is revocable, and every
security control is backed by an automated test.

Built with Node.js, Express 5, MongoDB and a plain-JavaScript frontend served
by Express. There is no build step and no frontend framework — the security
behaviour is meant to be readable straight from the source.

---

## Contents

1. [What the application does](#1-what-the-application-does)
2. [Security controls](#2-security-controls)
3. [Requirements](#3-requirements)
4. [Setup](#4-setup)
5. [Environment variables](#5-environment-variables)
6. [Creating the first administrator](#6-creating-the-first-administrator)
7. [Running the tests](#7-running-the-tests)
8. [API surface](#8-api-surface)
9. [How the security design works](#9-how-the-security-design-works)
10. [Project structure](#10-project-structure)
11. [Security documentation](#11-security-documentation)
12. [CI/CD pipeline](#12-cicd-pipeline)
13. [Team contributions](#13-team-contributions)
14. [Known limitations](#14-known-limitations)

---

## 1. What the application does

**For an ordinary user**

- Register an account and log in.
- Optionally enable time-based one-time password (TOTP) multi-factor
  authentication by scanning a QR code with Google Authenticator, Authy, or
  any compatible app.
- Create, read, update and delete private notes. Note content is encrypted
  with AES-256-GCM before it reaches the database and decrypted only for the
  note's owner.
- Log out, which immediately invalidates every session issued to that account.

**For an administrator**

- Review every registered account.
- Disable or re-enable an account. Disabling revokes the user's active
  sessions immediately, not when their token would have expired.
- Delete an account, together with all of its notes.
- Read the audit log of security-relevant actions.

Administrators cannot be created through any HTTP endpoint. See
[section 6](#6-creating-the-first-administrator).

---

## 2. Security controls

Every control below is implemented and covered by at least one automated test.

| # | Control | Implementation | Test |
|---|---|---|---|
| 1 | Password hashing (bcrypt, cost 12) | `src/controllers/authController.js` | `tests/auth/auth.integration.test.js` |
| 2 | Password strength policy | `src/routes/authRoutes.js` | `tests/auth/auth.integration.test.js` |
| 3 | Account lockout after 5 failures | `src/controllers/authController.js` | `tests/auth/auth.integration.test.js` |
| 4 | TOTP multi-factor authentication | `src/controllers/authController.js` | `tests/auth/mfa.integration.test.js` |
| 5 | MFA secrets encrypted at rest | `src/models/User.js`, `src/utils/encryption.js` | `tests/auth/mfa.integration.test.js` |
| 6 | JWT session in an HttpOnly cookie | `src/utils/jwt.js` | `tests/auth/session.integration.test.js` |
| 7 | Session revocation via `tokenVersion` | `src/middleware/auth.js` | `tests/auth/session.integration.test.js` |
| 8 | Algorithm, issuer and audience pinning | `src/utils/jwt.js` | `tests/auth/session.integration.test.js` |
| 9 | Role-based access control | `src/middleware/rbac.js` | `tests/security/rbac.integration.test.js` |
| 10 | CSRF protection (signed double submit) | `src/middleware/csrfProtection.js` | `tests/security/hardening.test.js` |
| 11 | Rate limiting | `src/middleware/rateLimiter.js` | `tests/security/rateLimit.integration.test.js` |
| 12 | CAPTCHA on registration and login | `src/middleware/captcha.js` | `tests/security/hardening.test.js` |
| 13 | Input validation and field allow-lists | `src/middleware/validate.js`, `src/routes/*.js` | `tests/security/hardening.test.js` |
| 14 | NoSQL operator-injection sanitisation | `src/middleware/validate.js` | `tests/security/hardening.test.js` |
| 15 | Security headers and CSP (Helmet) | `src/app.js` | `tests/security/platform.integration.test.js` |
| 16 | Single-origin CORS allow-list | `src/app.js` | `tests/security/platform.integration.test.js` |
| 17 | Request size limit (10 kB) | `src/app.js` | `tests/security/hardening.test.js` |
| 18 | Generic error responses, no stack leakage | `src/middleware/errorHandler.js` | `tests/security/hardening.test.js` |
| 19 | Audit logging | `src/services/auditService.js` | `tests/admin/admin.integration.test.js` |
| 20 | AES-256-GCM note encryption | `src/utils/encryption.js` | `tests/notes/encryption.test.js` |
| 21 | Owner-scoped queries (IDOR prevention) | `src/controllers/noteController.js` | `tests/notes/notesPipeline.integration.test.js` |
| 22 | Static analysis and dependency scanning | `.github/workflows/` | Runs on every push and pull request |

---

## 3. Requirements

- **Node.js 20.19.0 or newer** (developed against Node 20 and 22)
- **npm 10 or newer**
- **MongoDB** — a local server, or a free MongoDB Atlas cluster

Running the test suite does **not** require a MongoDB installation.
`mongodb-memory-server` downloads and manages a temporary instance
automatically on first run.

---

## 4. Setup

```bash
git clone https://github.com/MATARx0/Secure-Notes-App.git
cd Secure-Notes-App

npm ci                  # installs exactly the reviewed versions from the lockfile
cp .env.example .env    # then fill in real values — see section 5
```

Generate the three secrets:

```bash
# JWT_SECRET and CSRF_SECRET (run once for each)
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"

# ENCRYPTION_KEY — must be exactly 32 bytes as 64 hex characters
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Start MongoDB, then start the application:

```bash
npm run dev     # with auto-reload
npm start       # plain node
```

Open <http://localhost:3000/register.html> and confirm the API is alive with
`curl http://localhost:3000/api/health`.

> **Never commit `.env`.** It is git-ignored, and CI fails the build if a
> tracked `.env` ever appears. If a secret is committed by accident, rotate it
> **first**, then clean up the history — the moment it is pushed it must be
> assumed compromised.

### reCAPTCHA keys

Registration and login verify a Google reCAPTCHA v2 token server-side. Get a
key pair at <https://www.google.com/recaptcha/admin> (add `localhost` to the
allowed domains) and set `CAPTCHA_SITE_KEY` and `CAPTCHA_SECRET_KEY`.

To run locally without keys, set `NODE_ENV=development` and
`CAPTCHA_DEV_BYPASS=true`, then send `DEV_BYPASS` as the token. The bypass is
hard-guarded: it is ignored whenever `NODE_ENV` is `production` or `test`, so
it cannot be switched on in a real deployment by a misconfigured variable.

---

## 5. Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `NODE_ENV` | yes | `development`, `test` or `production`. Controls cookie `Secure` flags, HSTS, proxy trust and the CAPTCHA bypass guard. |
| `PORT` | no | HTTP port (default 3000). |
| `MONGO_URI` | yes | MongoDB connection string. |
| `CLIENT_ORIGIN` | yes | The single browser origin allowed by CORS. |
| `JWT_SECRET` | yes | Signs session tokens and MFA tickets. **The server refuses to start if this is missing or under 32 characters.** |
| `JWT_ISSUER` | no | `iss` claim (default `secure-notes-app`). |
| `JWT_AUDIENCE` | no | `aud` claim (default `secure-notes-users`). |
| `JWT_EXPIRES_IN` | no | Session lifetime (default `15m`). Also sets the cookie's `Max-Age`. |
| `MFA_TICKET_EXPIRES_IN` | no | Lifetime of the ticket between the password and TOTP steps (default `2m`). |
| `MFA_ISSUER_NAME` | no | Label shown in the authenticator app. |
| `ENCRYPTION_KEY` | yes | AES-256-GCM key for notes and MFA secrets. **Exactly 64 hex characters.** |
| `CSRF_SECRET` | yes | HMAC key for the CSRF double-submit cookie. |
| `CAPTCHA_PROVIDER` | yes | `recaptcha-v2`. |
| `CAPTCHA_SITE_KEY` | yes | Public key, sent to the browser via `GET /api/config`. |
| `CAPTCHA_SECRET_KEY` | yes | Server-side key. Never leaves the server. |
| `CAPTCHA_DEV_BYPASS` | no | `true` enables the local bypass. Ignored in production and test. |
| `AUTH_RATE_LIMIT_MAX` / `_WINDOW_MS` | no | Auth-endpoint limiter (defaults 10 per 15 minutes). |
| `GENERAL_RATE_LIMIT_MAX` / `_WINDOW_MS` | no | General API limiter (defaults 300 per minute). |
| `ADMIN_EMAIL` / `ADMIN_USERNAME` / `ADMIN_PASSWORD` | no | Read **only** by `npm run create-admin`. Not read by the server and not exposed by any route. |

> **Losing `ENCRYPTION_KEY` means losing every note.** AES-256-GCM is doing
> its job — there is no recovery path. Back it up somewhere safe and separate
> from the database.

---

## 6. Creating the first administrator

There is deliberately **no HTTP route that can create an administrator**.
`POST /api/auth/register` hard-codes `role: 'user'`, and the request-body
allow-list rejects a `role` field outright, so the most common privilege
escalation route in an application like this simply does not exist.

The first administrator is provisioned from the command line:

```bash
ADMIN_EMAIL=admin@example.com \
ADMIN_USERNAME=admin \
ADMIN_PASSWORD='ReplaceMe!Str0ng' \
npm run create-admin
```

The script validates the email format and password strength, hashes the
password with bcrypt exactly as registration does, and never prints the
password. If the account already exists it exits without changing anything, so
it is safe to run twice.

Log in and change the password immediately afterwards.

---

## 7. Running the tests

```bash
npm test                # the full suite
npm run test:coverage   # with a coverage report
npm run security:audit  # npm audit for runtime dependencies
```

The suite spans four areas:

| Area | Files | What it covers |
|---|---|---|
| Authentication | `tests/auth/` | Registration, login, lockout, MFA enrolment and verification, session validity and revocation |
| Notes | `tests/notes/` | Encryption round-trip, tamper detection, CRUD, IDOR protection, and the full pipeline through the assembled app |
| Security | `tests/security/` | RBAC, CSRF, rate limiting, sanitisation, CAPTCHA, headers, CORS, payload limits |
| Administration | `tests/admin/` | User listing, deletion with note cleanup, status changes, audit log |

### If the tests cannot download MongoDB

By default `mongodb-memory-server` fetches a mongod binary (~80 MB) on the
first run and caches it under `~/.cache/mongodb-binaries`. That needs access
to `fastdl.mongodb.org`, which is blocked on a lot of networks — locked-down
university or corporate Wi-Fi, offline machines, and sandboxed containers all
fail on it. The failure is loud and misleading: every database-backed suite
errors at once, which looks like 95 broken tests rather than one blocked
hostname.

```
Download failed for url "https://fastdl.mongodb.org/..." Status Code is 403
```

**Point the tests at any MongoDB you already have instead:**

```bash
TEST_MONGO_URI=mongodb://127.0.0.1:27017 npm test
```

The local MongoDB you installed in section 4 works. So does a container:

```bash
docker run -d -p 27017:27017 --name mongo-test mongo:7
TEST_MONGO_URI=mongodb://127.0.0.1:27017 npm test
```

No download happens at all on this path. `tests/setup/testDb.js` forces the
database name to `secure_notes_automated_tests` and ignores any database named
in the URI, so the tests can only ever touch that one database — pointing
`TEST_MONGO_URI` at a server holding other data cannot damage it. The database
is dropped when the run finishes.

CI uses this path too, via a `mongo:7` service container, so the pipeline does
not depend on a third-party download host either.

**Running only what needs no database:** two of the security files are written
to be database-free on purpose, because those controls have to hold even when
the database is unreachable. They run anywhere, in about four seconds:

```bash
npx jest tests/security/hardening.test.js tests/security/rateLimit.integration.test.js
```

---

## 8. API surface

All responses use one of two envelopes:

```jsonc
// success
{ "success": true,  "message": "…", "data": { } }

// failure
{ "success": false, "error": { "code": "…", "message": "…", "details": [] } }
```

| Method | Path | Auth | CSRF | Notes |
|---|---|---|---|---|
| `GET` | `/api/health` | — | — | Liveness probe |
| `GET` | `/api/config` | — | — | Public CAPTCHA site key only |
| `GET` | `/api/csrf-token` | — | — | Issues the CSRF cookie and token |
| `POST` | `/api/auth/register` | — | — | CAPTCHA + rate limited |
| `POST` | `/api/auth/login` | — | — | CAPTCHA + rate limited |
| `POST` | `/api/auth/mfa/verify-login` | ticket | — | Second step when MFA is enabled |
| `GET` | `/api/auth/me` | yes | — | Current session |
| `POST` | `/api/auth/logout` | yes | yes | Revokes every session for the account |
| `POST` | `/api/auth/mfa/setup` | yes | yes | Returns a QR code and manual key |
| `POST` | `/api/auth/mfa/confirm` | yes | yes | Enables MFA |
| `POST` | `/api/auth/mfa/disable` | yes | yes | Requires password **and** a valid TOTP code |
| `GET` | `/api/notes` | yes | — | Owner-scoped, no ciphertext in the list |
| `POST` | `/api/notes` | yes | yes | |
| `GET` | `/api/notes/:noteId` | yes | — | |
| `PUT` | `/api/notes/:noteId` | yes | yes | |
| `DELETE` | `/api/notes/:noteId` | yes | yes | |
| `GET` | `/api/admin/users` | admin | — | Paginated, safe fields only |
| `DELETE` | `/api/admin/users/:userId` | admin | yes | Also deletes the user's notes |
| `PATCH` | `/api/admin/users/:userId/status` | admin | yes | `"enabled"` or `"disabled"` |
| `GET` | `/api/admin/audit-logs` | admin | — | Paginated |

Status codes: `400` malformed request · `401` not authenticated or bad
credentials · `403` authenticated but not permitted, or CSRF failure · `404`
not found or not yours · `409` conflict · `413` payload too large · `422`
field validation failed · `429` rate limited · `500` unexpected.

Registration and login are the only endpoints without CSRF protection, because
there is no session yet to bind a token to. They are defended instead by
CAPTCHA, rate limiting and account lockout.

---

## 9. How the security design works

### Sessions

Login issues a JWT stored in an `HttpOnly`, `SameSite=Strict` cookie named
`sn_session` (`Secure` as well, in production). JavaScript cannot read it, so
a cross-site script cannot steal it, and the browser will not attach it to a
cross-site request.

Verification pins the algorithm to `HS256` and asserts both issuer and
audience, which closes the `alg: none` and algorithm-confusion families of
attack. The server refuses to start without a strong `JWT_SECRET`.

**Revocation.** JWTs are stateless and cannot be deleted server-side, so every
user carries a `tokenVersion` counter that is embedded in each token as the
`tv` claim. `requireAuth` compares the claim against the stored value on every
request, so incrementing the counter invalidates every previously issued token
at once. Logout, MFA disable and an administrator disabling an account all
increment it.

The cookie is the **only** accepted source of a session. There is no
`Authorization` header fallback and no query-string token, which keeps both
the attack surface and the revocation story unambiguous.

### Multi-factor authentication

Enrolment generates a TOTP secret, encrypts it with AES-256-GCM, and stores it
in `mfaSecret.pending`. It is only promoted to `mfaSecret.enabled` once the
user proves possession by submitting a valid 6-digit code, so a half-finished
enrolment can never lock anyone out.

At login, a correct password for an MFA-enabled account returns a short-lived
**ticket** instead of a session — a separate JWT carrying
`purpose: 'mfa_pending'`, which `requireAuth` refuses outright. Only after the
TOTP code is verified is a real session cookie issued.

Code verification allows a window of ±1 time step (about 30 seconds either
side) to tolerate clock drift. That trade-off is recorded in the DREAD
assessment rather than left implicit.

### CSRF

A signed double-submit token. `GET /api/csrf-token` returns a random value in
the JSON body and sets `sn_csrf` to `<value>.<HMAC-SHA256(value)>`. A
state-changing request must present both the cookie and the raw value in the
`X-CSRF-Token` header; the server checks the signature and then compares the
two with a constant-time comparison.

An attacker's page cannot read the raw value (same-origin policy plus a
single-origin CORS allow-list), and cannot mint one either, because forging
the cookie requires `CSRF_SECRET`. This layers on top of `SameSite=Strict`
rather than replacing it.

### Encryption

Note content and MFA secrets are encrypted with AES-256-GCM before storage. A
fresh random IV is generated per encryption, and the GCM authentication tag
means any tampering with stored ciphertext causes decryption to fail loudly
instead of returning corrupted plaintext. `ENCRYPTION_KEY` is read from the
environment and never appears in source, in an API response, or in a log line.

### Authorisation

`requireAuth` sets `req.user = { id, role }` from the verified token plus a
fresh database lookup — never from anything the client sent. Note queries are
always scoped by `owner: req.user.id`, so another user's note returns `404`
rather than `403`: telling an attacker that a note exists but belongs to
someone else is itself a disclosure.

`requireRole('admin')` is mounted at the router level in `adminRoutes.js`, not
per route, so it cannot be forgotten when someone adds an endpoint later.

---

## 10. Project structure

```
src/
├── app.js                      Express assembly: helmet, CORS, parsing,
│                               sanitisation, logging, rate limiting, routes
├── config/db.js                MongoDB connection lifecycle
├── controllers/
│   ├── authController.js       Register, login, MFA, logout          (Member 1)
│   ├── noteController.js       Note CRUD with encryption             (Member 2)
│   └── adminController.js      User management, audit log            (Member 3)
├── middleware/
│   ├── auth.js                 requireAuth — session verification    (Member 1)
│   ├── rbac.js                 requireRole — role checks             (Member 3)
│   ├── csrfProtection.js       Signed double-submit CSRF             (Member 3)
│   ├── captcha.js              Server-side reCAPTCHA verification    (Member 3)
│   ├── rateLimiter.js          Auth and general limiters             (Member 3)
│   ├── validate.js             Validation, allow-lists, sanitisation (Member 3)
│   ├── validateNote.js         Note-specific validation              (Member 2)
│   ├── requestLogger.js        Request ids and safe logging          (Member 3)
│   ├── errorHandler.js         Central error envelope                (Member 3)
│   └── notFound.js             404 handler                           (Member 3)
├── models/
│   ├── User.js                 Accounts, roles, MFA, lockout         (Member 1)
│   ├── Note.js                 Encrypted notes                       (Member 2)
│   └── AuditLog.js             Security event records                (Member 3)
├── routes/                     authRoutes, noteRoutes, adminRoutes
├── services/auditService.js    Fire-and-forget audit writer          (Member 3)
└── utils/
    ├── jwt.js                  Token signing, verification, cookies  (Member 1)
    └── encryption.js           AES-256-GCM helpers                   (Member 2)

public/                         register, login, mfa, notes, admin pages
scripts/createAdmin.js          One-time administrator provisioning
tests/                          auth/ notes/ security/ admin/ helpers/ setup/
docs/                           STRIDE, DREAD, data flow diagram
scans/                          Scan results and remediation log
.github/workflows/              CodeQL, dependency scanning, tests
```

---

## 11. Security documentation

| Document | Contents |
|---|---|
| [`docs/STRIDE_Threat_Model.md`](docs/STRIDE_Threat_Model.md) | Threat identification across all six STRIDE categories, trust boundaries, and the mitigation mapped to each threat |
| [`docs/DREAD_Risk_Assessment.md`](docs/DREAD_Risk_Assessment.md) | 15 identity and session threats scored 1–10 on each DREAD dimension, before and after mitigation, with a risk treatment plan |
| [`docs/Secure_Notes_DFD.md`](docs/Secure_Notes_DFD.md) | Data flow diagram |
| [`scans/remediation-log.md`](scans/remediation-log.md) | Every scanner and manual-review finding, and what was done about each |

The two threat documents are meant to be read together: STRIDE identifies what
can go wrong, DREAD decides what to fix first. Identifiers cross-reference in
both directions (`DR-07` ↔ `T-04`, and so on).

---

## 12. CI/CD pipeline

Two workflows run on every push and pull request:

**`codeql.yml`** — GitHub CodeQL static analysis with the `security-extended`
query suite, plus a weekly scheduled re-scan so newly published queries are
applied to code that has not changed. Results appear under **Security → Code
scanning**.

**`security.yml`** — four jobs:

| Job | Blocks the build? |
|---|---|
| Full Jest suite | Yes |
| `npm audit` on runtime dependencies (high and above) | Yes |
| Snyk dependency scan | Yes, when `SNYK_TOKEN` is configured; skipped with a clear message otherwise |
| Committed-secret check (`.env`, private keys) | Yes |

To enable Snyk, add a `SNYK_TOKEN` repository secret under
**Settings → Secrets and variables → Actions**.

Dependencies are pinned to exact versions with no `^` or `~` ranges, and CI
installs with `npm ci`, so the build can never silently resolve a version
nobody reviewed.

---

## 13. Team contributions

| Member | Scope | Main deliverables |
|---|---|---|
| **Member 1** | Identity, authentication, session security | `User` model, registration and login, bcrypt hashing, account lockout, TOTP MFA, JWT issuance and revocation, `requireAuth`, auth pages and client script, DREAD risk assessment |
| **Member 2** | Secure notes and cryptography | `Note` model, AES-256-GCM utility, note controller and validation, owner-scoped authorisation, notes page, STRIDE threat model, data flow diagram |
| **Member 3** | Platform hardening, administration, DevSecOps | Helmet/CSP, CORS, rate limiting, CSRF, CAPTCHA, validation and sanitisation, RBAC, error handling, request logging, audit logging, admin feature and page, `createAdmin` script, CI/CD workflows, remediation log, this README |

Branch workflow: `foundation` → `feature/member-1-identity` →
`feature/member-2-secure-notes` → `feature/member-3-platform-admin` →
`integration/final-testing` → `main`.

---

## 14. Known limitations

Recorded openly. Each one is either an accepted risk with a named improvement,
or a small piece of coordination work that has not landed yet.

1. **MFA tickets are not single-use.** A ticket could in principle be replayed
   within its ~2 minute lifetime alongside a still-valid TOTP code. It can
   never be used as a session (`requireAuth` rejects its `purpose` claim).
   *Fix:* store a `jti` per ticket and delete it on first use. — DREAD DR-11.

2. **Account lockout can be used to deny service.** Five wrong passwords lock
   an account for 15 minutes, so someone who knows a victim's email can lock
   them out repeatedly. The lock is time-boxed and self-clearing.
   *Fix:* per-(account, IP) progressive delays. — DREAD DR-10.

3. **No breached-password checking.** Complexity rules accept `Password1!`.
   *Fix:* the Have I Been Pwned range API, or a bundled denylist. — DREAD DR-13.

4. **Rate-limit counters are per process.** `express-rate-limit` uses an
   in-memory store, which is correct for the single-instance deployment this
   project targets but would need a shared store (Redis) behind a load
   balancer.

5. **Multi-document transactions need a replica set.** Deleting a user removes
   their notes inside a transaction where one is available. Against a
   standalone MongoDB instance the code detects the lack of support and falls
   back to sequential deletes, where a crash between the two could leave
   orphaned notes. MongoDB Atlas provides a replica set by default.

6. **Audit records are not tamper-evident.** Anyone with database write access
   could alter them. They support investigation but do not provide strong
   non-repudiation.

7. **`LAST_ADMIN_PROTECTED` is not reachable through the API.** Because
   administrators can never target their own account, any deletion that
   reaches the last-administrator check is necessarily performed by a
   different, still-active administrator. The check is retained as defence in
   depth against a future code path, and the test suite documents this
   honestly rather than asserting a scenario the code cannot produce.

8. **`trust proxy` is set to one hop in production.** This matches a typical
   single-tier platform deployment and **must be re-verified** against
   whatever platform is actually used. Trusting the wrong number of hops lets
   a client spoof `X-Forwarded-For` and defeat rate limiting.

9. **There is no change-password or password-reset endpoint.** Both are
    outside the assignment's scope. It follows that the temporary password
    used by `npm run create-admin` cannot be rotated through the application
    itself yet. `tokenVersion` already exists for exactly this purpose, so
    adding the endpoint later is a small change: verify the current password,
    write the new hash, increment `tokenVersion` to log every other session
    out.

10. **CodeQL and Snyk have not produced results yet.** The workflows are
    committed but have not run on GitHub, so `scans/remediation-log.md`
    records the manual-review findings and leaves the scanner section
    explicitly empty rather than filling it with invented entries.
