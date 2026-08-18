# Branch Notes

How the work on this repository is divided, and why the branches are stacked
the way they are. Written so a reviewer can tell at a glance who wrote what.

## Branch order

```
main (foundation)
 └── feature/member-2-secure-notes      Member 2 — notes and cryptography
      └── feature/member-1-identity     Member 1 — identity, auth, sessions   ← you are here
           └── feature/member-3-platform-admin   Member 3 — hardening, admin, DevSecOps
                └── integration/final-testing
```

The team's workflow document lists the merge order as Member 1 → Member 2 →
Member 3. The branches are stacked in a different order for one concrete
reason: **Member 1's work depends on Member 2's encryption utility.**

TOTP secrets must be encrypted before they are stored, and
`src/utils/encryption.js` (AES-256-GCM) is Member 2's deliverable. Member 2's
branch was already complete and pushed, so branching Member 1's work from it —
rather than from the bare foundation — means this branch is a real, runnable,
testable state instead of one that cannot start. Member 3's branch then
depends on both: it needs Member 1's `User` model and `requireAuth`, and
Member 2's `Note` model for the admin cascade delete.

The final merge into `main` still follows the documented order; only the
development stacking differs.

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

The API contract (Table 5) requires CAPTCHA and rate limiting on
registration and login, and CSRF protection on logout and the MFA management
routes. Those middlewares are Member 3's deliverables, but the authentication
routes cannot be wired — or tested — without them.

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
and the contribution table in the README on Member 3's branch lists them
under Member 3.

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

`npm test` needs internet access on its first run: `mongodb-memory-server`
downloads a MongoDB binary and caches it under `~/.cache/mongodb-binaries`.
