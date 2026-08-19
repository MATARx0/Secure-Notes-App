# Branch Notes

How the work on this repository is divided, and how the branches relate to each
other. Written so a reviewer can tell at a glance who wrote what.

## Branch layout

```
main  (foundation + the shared AES-256-GCM encryption utility)
 ├── feature/member-1-identity          Member 1 — identity, auth, sessions   ← you are here
 ├── feature/member-2-secure-notes      Member 2 — notes and cryptography
 └── feature/member-3-platform-admin    Member 3 — hardening, admin, DevSecOps
```

Merge order, exactly as the team workflow document specifies:

```
Foundation → Member 1 → Member 2 → Member 3
```

Every branch sits directly on `main` and runs on its own.

## Why the encryption utility sits in the foundation

`src/utils/encryption.js` was written by Member 2 as part of the Secure Notes
work, and it turned out to have **two** consumers rather than one:

- Member 2 encrypts note content with it.
- Member 1 encrypts TOTP secrets with it, so an MFA seed is never stored in
  plaintext.

That makes it shared infrastructure rather than a feature-branch file, and it
depends on nothing in the project — only Node's built-in `crypto` module. It
was therefore promoted to `main` on its own, in PR #3, **authored by Member 2**,
before any feature branch merged.

This was a deliberate team decision taken after the dependency surfaced during
implementation, not an accident of ordering. Without it, merging Member 1's
work first — as the workflow document requires — would put a
`require('../utils/encryption')` on `main` with nothing behind it, and the
application would fail to start.

## What is on this branch (Member 1)

| Area | Files |
|---|---|
| Account data | `src/models/User.js` |
| Sessions | `src/utils/jwt.js`, `src/middleware/auth.js` |
| Authentication flows | `src/controllers/authController.js`, `src/routes/authRoutes.js` |
| Frontend | `public/register.html`, `public/login.html`, `public/mfa.html`, `public/js/auth.js`, `public/css/styles.css` |
| Tests | `tests/auth/`, `tests/helpers/authFlow.js` |
| Documentation | `docs/DREAD_Risk_Assessment.md` |

## Shared platform files carried on this branch

The API contract (Table 5) requires CAPTCHA and rate limiting on registration
and login, and CSRF protection on logout and the MFA management routes. Those
middlewares are Member 3's deliverables, but the authentication routes cannot
be wired — or tested — without them.

Rather than duplicating them or leaving the routes unprotected, the following
files are carried on this branch in the state Member 1 needs. **Member 3 is
their author and owner**; the authoritative, complete versions live on
`feature/member-3-platform-admin`, which extends several of them:

| File | State on this branch | Extended by Member 3 with |
|---|---|---|
| `src/middleware/validate.js` | `handleValidation`, `rejectUnknownFields` | `stripMongoOperators` (NoSQL operator sanitisation) |
| `src/middleware/captcha.js` | complete | — |
| `src/middleware/rateLimiter.js` | complete | — |
| `src/middleware/csrfProtection.js` | complete | — |
| `src/middleware/requestLogger.js` | complete | — |
| `src/middleware/errorHandler.js` | complete | — |
| `src/models/AuditLog.js` | complete | — |
| `src/services/auditService.js` | complete | — |
| `src/app.js` | auth wiring only | sanitisation mount, admin routes |
| `public/css/styles.css` | shared stylesheet | admin table and dialog styles |

Attribution is preserved in the source: each of these files carries a header
comment describing its purpose and the phase of Member 3's task it belongs to,
and the contribution table in the README on Member 3's branch lists them under
Member 3.

## Not on this branch

Role-based access control, the administration feature and page, the
`createAdmin` provisioning script, the CI/CD workflows, the remediation log,
the note-route wiring, and the security test suite are all Member 3's work and
land on `feature/member-3-platform-admin`.

## Running this branch

```bash
npm ci
cp .env.example .env      # fill in real values
npm run dev
npm test
```

`npm test` uses `mongodb-memory-server`, which downloads a MongoDB binary on
its first run. If that host is unreachable on your network — it is blocked on
plenty of them — point the tests at any MongoDB you already have instead. No
download happens on that path:

```bash
TEST_MONGO_URI=mongodb://127.0.0.1:27017 npm test
```
