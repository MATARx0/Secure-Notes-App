# Branch Notes

How the work on this repository is divided, and how the branches relate to each
other. Written so a reviewer can tell at a glance who wrote what.

## Branch layout

```
main  (foundation + the shared AES-256-GCM encryption utility)
 ├── feature/member-1-identity          Member 1 — identity, auth, sessions
 ├── feature/member-2-secure-notes      Member 2 — notes and cryptography
 └── feature/member-3-platform-admin    Member 3 — hardening, admin, DevSecOps   <- you are here
```

Merge order, exactly as the team workflow document specifies:

```
Foundation -> Member 1 -> Member 2 -> Member 3
```

Every branch sits directly on `main`. Each was rebased onto `main` in turn as
the branch before it merged, so each pull request shows exactly one member's
work and nobody else's.

## Who wrote what

| Member | Scope | Branch |
|---|---|---|
| Member 1 | Identity, authentication, session security | `feature/member-1-identity` |
| Member 2 | Secure notes and cryptography | `feature/member-2-secure-notes` |
| Member 3 | Platform hardening, administration, DevSecOps | `feature/member-3-platform-admin` |

The contribution table in the README lists the deliverables for each member.
`git log --oneline main..feature/member-3-platform-admin` shows exactly what
this branch adds.

## Why the encryption utility sits in the foundation

`src/utils/encryption.js` was written by Member 2 as part of the Secure Notes
work, and it turned out to have **two** consumers rather than one:

- Member 2 encrypts note content with it.
- Member 1 encrypts TOTP secrets with it, so an MFA seed is never stored in
  plaintext.

That makes it shared infrastructure rather than a feature-branch file, and it
depends on nothing in the project - only Node's built-in `crypto` module. It
was therefore promoted to `main` on its own, in PR #3, **authored by Member 2**,
before any feature branch merged.

This was a deliberate team decision taken after the dependency surfaced during
implementation. Without it, merging Member 1's work first - as the workflow
document requires - would have put a `require('../utils/encryption')` on `main`
with nothing behind it, and the application would have failed to start.

## Shared files, and how they were handled

Three files are genuinely shared, and each was extended rather than rewritten
as the branches merged in turn:

| File | Member 1's branch | This branch adds |
|---|---|---|
| `src/middleware/validate.js` | `handleValidation`, `rejectUnknownFields` | `stripMongoOperators` (NoSQL operator sanitisation) |
| `src/app.js` | auth wiring, CSRF endpoint, rate limiting, CSP | sanitisation mount, admin routes |
| `public/css/styles.css` | shared form and layout styles | admin table, badge and dialog styles |

Member 3's platform middleware (`captcha.js`, `rateLimiter.js`,
`csrfProtection.js`, `requestLogger.js`, `errorHandler.js`, `AuditLog.js`,
`auditService.js`) landed on Member 1's branch rather than this one, because
the API contract requires those protections on the authentication routes - so
those routes could not be wired, or tested, without them. Member 3 remains the
author and owner; the README contribution table lists them under Member 3.

## Cross-branch changes to Member 2's files

Several files owned by Member 2 are touched on this branch. All were agreed in
the team channel before being made, and all are commented in place:

| File | Change | Why |
|---|---|---|
| `src/routes/noteRoutes.js` | Wired the empty placeholder router | The note endpoints were unreachable. Now mounted behind `requireAuth`, with CSRF on every write. |
| `src/controllers/noteController.js` | Three `recordAuditEvent` calls; `req.params.id` -> `req.params.noteId` | Audit logging closes threat R-01, which Member 2's own threat model raised. The rename is described below. |
| `src/middleware/validateNote.js` | `id` -> `noteId`; field validation failures now return `422` | Contract compliance, and consistency with every other route in the project. |
| `public/js/notes.js` | `innerHTML` replaced with safe DOM construction | Removes a stored-XSS vector; see below. |
| `public/notes.html` | Added a header nav and logout link | So a logged-in user can reach the security settings and log out. |
| `tests/notes/*.integration.test.js` | Route mounts and expected status codes updated | Follows mechanically from the two changes above. |
| `docs/STRIDE_Threat_Model.md` | Appended an addendum below a marked divider | Identity and platform threats were out of scope originally. **Nothing above the divider was altered.** |

Rows three to six were proposed by Member 2 in the team channel and carried out
here, with her agreement, so the router, the controller and the tests could be
brought into line in a single verified change.

Splitting that rename across two branches would have been the riskier option:
the router defines the parameter and the controller reads it, so if only one
side changed, every note operation would break - and **no test on either branch
could have caught it**, because Member 2's tests mount the controller on a
throwaway app of their own and Member 3's tests only exercise the assembled
application. The mismatch would surface only after integration. Doing both
halves together, then running the full suite against the assembled app, is what
makes it safe.

### The XSS fix, specifically

`public/js/notes.js` built the note list by interpolating `note.title` straight
into `innerHTML`. A note titled `<img src=x onerror=...>` would therefore have
been parsed as markup when the list rendered - stored XSS, persisted in the
database rather than reflected.

It was not exploitable as shipped, because the Content Security Policy sets
`script-src 'self'` with no `'unsafe-inline'`, which blocks inline event
handlers, and `img-src 'self' data:`, which blocks the usual exfiltration
image. But relying on the CSP alone is fragile: any future relaxation of that
header silently re-opens the hole, and the payload is already sitting in the
database. The list is now built with `document.createElement` and
`textContent`, so the data can never become markup in the first place.

## Known open items

None outstanding. The `:noteId` naming gap and the note-validation status code,
both previously recorded as known limitations, are closed by this branch.

## Running this branch

```bash
npm ci
cp .env.example .env      # fill in real values
npm run create-admin      # provisions the first administrator
npm run dev
npm test
```

`npm test` uses `mongodb-memory-server`, which downloads a MongoDB binary on
its first run. That host is blocked on plenty of networks; if it fails, point
the tests at any MongoDB you already have and no download happens:

```bash
TEST_MONGO_URI=mongodb://127.0.0.1:27017 npm test
```

Two of the security files are deliberately database-free, because those
controls must hold even when the database is unreachable:

```bash
npx jest tests/security/hardening.test.js tests/security/rateLimit.integration.test.js
```
