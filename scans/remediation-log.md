# Security Scan and Remediation Log

**Owner:** Member 3 — Platform Hardening, Admin Feature, DevSecOps
**Purpose:** a single running record of every security finding raised against
this repository — by an automated scanner or by a human reviewer — and what was
actually done about it.

A finding is only closed here when there is something concrete to point at: a
commit, a test, or a written decision to accept the risk. "Looks fine now" is
not a disposition.

---

## 1. How findings are recorded

| Field | Meaning |
|---|---|
| **ID** | `SCAN-nn` for tool findings, `REV-nn` for findings from manual review |
| **Source** | CodeQL, Snyk, `npm audit`, or manual review |
| **Severity** | As reported by the tool, or assessed against the DREAD model for manual findings |
| **Status** | `Open`, `Fixed`, `Accepted (risk)`, or `False positive` |
| **Evidence** | The file, test or commit that proves the disposition |

**Severity response targets** agreed by the team:

| Severity | Action |
|---|---|
| Critical | Fix before any merge to `main` |
| High | Fix before the integration merge |
| Medium | Fix if practical, otherwise record an accepted risk with a named improvement |
| Low | Record; fix opportunistically |

---

## 2. Tooling in place

| Tool | What it looks for | Where it runs | Blocking? |
|---|---|---|---|
| **CodeQL** (`security-extended`) | Injection, authentication, cryptography and data-flow defects in the source | `.github/workflows/codeql.yml` — push, PR, and weekly | Alerts surface in Security → Code scanning |
| **npm audit** | Known advisories in the dependency tree | `.github/workflows/security.yml` | Yes, on high/critical in runtime dependencies |
| **Snyk** | Dependency vulnerabilities with richer advisory data and fix suggestions | `.github/workflows/security.yml` | Yes, at `--severity-threshold=high`, when `SNYK_TOKEN` is configured |
| **Jest suite** | Regression tests for every implemented control | `.github/workflows/security.yml` | Yes |
| **Committed-secret check** | A tracked `.env` file or a committed private key | `.github/workflows/security.yml` | Yes |

---

## 3. Dependency audit — recorded results

**Date:** 2026-08-18 · **Command:** `npm audit` and `npm audit --omit=dev`
**Environment:** Node.js v22.22.2, npm 10.9.7

```
runtime dependencies : found 0 vulnerabilities
all dependencies     : found 0 vulnerabilities
```

Direct runtime dependencies at the time of the audit, all exact-pinned (no
`^` or `~` ranges), so a fresh `npm ci` can never resolve a different version
than the one reviewed:

| Package | Version | Why it is here |
|---|---|---|
| express | 5.2.1 | HTTP framework |
| mongoose | 9.9.1 | MongoDB ODM |
| helmet | 8.3.0 | Security response headers, CSP |
| cors | 2.8.6 | Single-origin CORS allow-list |
| cookie-parser | 1.4.7 | Reads the `sn_session` and `sn_csrf` cookies |
| express-rate-limit | 8.6.2 | Brute-force and abuse limiting |
| express-validator | 7.3.2 | Input validation and allow-listing |
| bcryptjs | 3.0.3 | Password hashing at cost factor 12 |
| jsonwebtoken | 9.0.3 | Session tokens and MFA tickets |
| otplib | 12.0.1 | TOTP generation and verification |
| qrcode | 1.5.4 | Enrolment QR codes |
| dotenv | 17.4.2 | Local environment loading |

**Re-run this section after every dependency change** and paste the real
output rather than editing the numbers.

---

## 4. CodeQL and Snyk results

**First run:** 2026-08-20, commit `82adeac` on `main`.
**Tool:** CodeQL, `security-extended` query suite. **Result:** 12 open alerts,
all rated High by the tool. Every one was triaged individually; none was
dismissed without reading the code it pointed at.

### Summary

| Alerts | Where | Disposition |
|---|---|---|
| 2 | Application code | **Fixed** — see SCAN-01 and SCAN-03 |
| 1 | Application code | **False positive** — see SCAN-02 |
| 9 | Test code | **Out of scope** — scanning rescoped, see below |

### Application-code alerts

| ID | Rule | Location | Severity | Status |
|---|---|---|---|---|
| SCAN-01 | Database query built from user-controlled sources | `src/controllers/authController.js` | High | Fixed |
| SCAN-02 | Missing CSRF middleware | `src/app.js` | High | False positive |
| SCAN-03 | Remote property injection | `src/middleware/validate.js` | High | Fixed |

---

#### SCAN-01 — Database query built from user-controlled sources
**Status: Fixed (hardened)**

`login()` passes `req.body.email` into `User.findOne({ email })`. CodeQL traces
untrusted input to a query sink and cannot see the two controls in between:
`stripMongoOperators` strips operator-shaped keys before routing, and
`express-validator`'s `isEmail()` rejects a non-string with `422`. Both fire
before the controller, so no injection was reachable.

Treated as a finding anyway rather than dismissed. The invariant was real but
it lived three files away, and a controller that depends on middleware staying
mounted in the right order is one refactor from being wrong. `login()` and
`register()` now assert the types locally, immediately before the value becomes
a query filter. That is cheap, self-documenting, and something a static
analyser can actually follow.

#### SCAN-02 — Missing CSRF middleware
**Status: False positive**

The rule fires when `cookie-parser` is mounted without a CSRF middleware it
recognises, and the set it recognises is essentially `csurf` — a package that
has been deprecated since 2022.

This application implements the signed double-submit cookie pattern in
`src/middleware/csrfProtection.js`: an HMAC-signed `sn_csrf` cookie plus a
matching `X-CSRF-Token` header, compared in constant time, required on every
authenticated state-changing route. It is covered by seven cases in
`tests/security/hardening.test.js`, including a forged-signature cookie and one
visitor's token replayed with another's cookie.

**Dismissal reason to record in the GitHub UI:** *Used in tests / False
positive — CSRF protection is implemented as a signed double-submit token in
src/middleware/csrfProtection.js and enforced on all state-changing routes; the
rule only recognises the deprecated csurf package.*

#### SCAN-03 — Remote property injection
**Status: Fixed (hardened)**

`sanitizeInPlace` indexes an object with keys taken from the request body.
Checked by hand and confirmed not exploitable as written: the function only
reads and deletes own enumerable keys, never assigns, so a
`{"__proto__": {...}}` payload polluted nothing. That was verified by running
it, not assumed.

But the check found something the tool had not asked about: `__proto__`,
`constructor` and `prototype` passed straight through the filter, which only
matched `$`-prefixed and dotted keys. Nothing merges a request body onto an
existing object *today* — and that is a property of today's callers, not of the
input. Those keys are now stripped alongside the Mongo operators, with four
tests in `tests/security/hardening.test.js` covering them, including one that
asserts `Object.prototype` is untouched afterwards.

---

### Test-code alerts (9) — scanning rescoped

Nine alerts were in `tests/`, and each was an artefact of what test code is
rather than a defect:

| Rule | Count | Why it fires |
|---|---|---|
| Missing rate limiting | 4 | The note tests mount the controller on a throwaway Express app to exercise it in isolation. That app is three lines long and never listens on a port. |
| Insecure randomness | 3 | `Math.random()` in `tests/helpers/authFlow.js`, used to make each test account's email unique. A collision would fail a test, not weaken a control. |
| Missing CSRF middleware | 1 | Same shape — a minimal app built specifically to test the CSRF middleware. |
| Missing regular expression anchor | 1 | A regex inside a test assertion. |

Leaving nine false positives open would bury the alerts that matter, and
dismissing them one at a time — again after every future test — is worse. Test
code is not deployed and not reachable by an attacker, so
`.github/codeql/codeql-config.yml` now scopes the scan to `src/`, `scripts/`
and `server.js`.

**The trade-off, stated plainly:** a genuine vulnerability introduced *only* in
a test file will no longer be reported. Accepted, because the deployed surface
is what an attacker can reach, and that surface remains fully in scope.

### Snyk

Not yet run — `SNYK_TOKEN` is not configured on the repository, so the job
skips itself with an explicit message rather than failing. `npm audit` covers
the same dependency tree in the meantime and reports 0 vulnerabilities.

### Secret scanning

No alerts. The `.env` and private-key checks in `security.yml` pass on every
run.

## 5. Manual review findings

These were found by reviewing and testing the code during development, not by
a scanner. They are recorded here because a scanner would not have caught most
of them, and because the fixes are part of the security story of this project.

| ID | Severity | Finding | Status | Evidence |
|---|---|---|---|---|
| REV-01 | High | `stripMongoOperators` had no effect on the query string | Fixed | `src/middleware/validate.js`, `tests/security/hardening.test.js` |
| REV-02 | Medium | A disabled account could still complete login | Fixed | `src/controllers/authController.js`, `tests/admin/admin.integration.test.js` |
| REV-03 | Medium | `POST /api/notes` and friends were unauthenticated | Fixed | `src/routes/noteRoutes.js` |
| REV-04 | Low | Inline `style` attribute would be blocked by the CSP | Fixed | `public/admin.html`, `public/css/styles.css` |
| REV-05 | Low | `User.status` enum did not match the agreed API contract | Fixed | `src/models/User.js` |
| REV-06 | Low | The CAPTCHA test seam could never take effect | Fixed | `src/middleware/captcha.js` |
| REV-07 | Medium | MFA tickets are not single-use | Accepted (risk) | DREAD DR-11 |
| REV-08 | Medium | Account lockout can be abused to deny service | Accepted (risk) | DREAD DR-10 |
| REV-09 | Medium | No breached-password checking at registration | Accepted (risk) | DREAD DR-13 |
| REV-10 | High | Nested `select: false` made MFA impossible to enable | Fixed | `src/models/User.js`, `tests/auth/userProjection.test.js` |
| REV-11 | Medium | User deletion returned 500 against a standalone MongoDB | Fixed | `src/controllers/adminController.js` |
| REV-12 | High | Stored XSS sink in the note list (`innerHTML` + note title) | Fixed | `public/js/notes.js`, `tests/security/hardening.test.js` |
| REV-13 | Low | Route parameter was `:id` in the routes but `:noteId` in the contract | Fixed | `src/routes/noteRoutes.js`, `src/controllers/noteController.js` |
| REV-14 | Low | Note validation returned `400` where the rest of the API returns `422` | Fixed | `src/middleware/validateNote.js` |
| REV-15 | High | Note frontend never sent the CSRF token — every write failed with 403 | Fixed | `public/js/notes.js`, `tests/security/hardening.test.js` |

---

## 6. Finding detail

### REV-01 — NoSQL sanitisation silently did nothing to the query string
**Severity: High · Status: Fixed**

**What was wrong.** `stripMongoOperators` sanitised `req.query` in place. Under
Express 5, `req.query` is a getter that re-parses `req.url` on **every** access
and returns a new object each time, so the sanitised copy was discarded
immediately and the original operator keys were still visible to every
downstream handler. The middleware looked correct in review and was completely
ineffective in practice — the worst kind of security bug, because it produces a
false sense of coverage.

**How it was found.** A test asserted that `?$where=1&page=2` reached the
handler as `{ page: '2' }`. It came back as `{ '$where': '1', page: '2' }`.

**Fix.** Parse the query once, sanitise that snapshot, then redefine `req.query`
as an ordinary data property with `Object.defineProperty` (the accessor is
`configurable`, so this is permitted). `req.params` was dropped from the
middleware entirely, because application-level middleware runs before route
matching and parameter keys are author-defined, so sanitising it was dead code
pretending to be a control.

**Evidence.** `src/middleware/validate.js`; five sanitiser cases in
`tests/security/hardening.test.js`.

---

### REV-02 — A disabled account could still complete login
**Severity: Medium · Status: Fixed**

**What was wrong.** `login()` checked for account lockout but never checked
`user.status`. An account an administrator had disabled could still pass the
password step and be issued a valid session cookie. `requireAuth` re-checks
status on every request, so the account could not actually *do* anything — but
the login endpoint reported success, the cookie was issued, and an audit trail
showed a successful login for a disabled account.

**Fix.** Both `login()` and `verifyMfaLogin()` now reject a disabled account
with the same generic `401` used for every other credential failure, and record
an audit event with `reason: 'account_disabled'`. The response is deliberately
identical to a wrong-password response so it cannot be used as an oracle for
account state.

**Evidence.** `src/controllers/authController.js`;
`tests/admin/admin.integration.test.js` (disabling revokes the session),
`tests/auth/session.integration.test.js` (a disabled account's existing cookie
is refused).

---

### REV-03 — Note routes were mounted without authentication
**Severity: Medium · Status: Fixed**

**What was wrong.** `src/routes/noteRoutes.js` existed but was empty, so the
note endpoints were unreachable; when wired up naively they would have had no
authentication in front of them, and `req.user.id` would have been undefined at
the point the controller builds its owner-scoped query.

**Fix.** `router.use(requireAuth)` is applied at the top of the router so it
cannot be forgotten on an individual route, and `verifyCsrfToken` is applied to
every state-changing method.

**Evidence.** `src/routes/noteRoutes.js`; the existing Secure Notes test suite
now runs against real sessions rather than a mock middleware.

---

### REV-04 — Inline style attribute would be blocked by the CSP
**Severity: Low · Status: Fixed**

`public/admin.html` contained `style="margin-top: 0;"`. The Content Security
Policy sets `style-src 'self'` with no `unsafe-inline`, so the browser would
have refused to apply it. Replaced with a class in `public/css/styles.css`.
All HTML files were then checked for `style=`, `onclick=`, `onerror=` and
`onload=` attributes; none remain.

---

### REV-05 — `User.status` enum did not match the API contract
**Severity: Low · Status: Fixed**

The model used `['active', 'disabled']` while the team's API contract specifies
that `PATCH /api/admin/users/:userId/status` accepts exactly `"enabled"` or
`"disabled"`. Left alone, this would have required a silent translation layer
in the controller — the kind of mismatch that eventually produces a bug where
one side of the system disagrees about what a value means. Aligned the model to
the contract instead.

---

### REV-06 — The CAPTCHA test seam could never take effect
**Severity: Low · Status: Fixed**

`__setVerifierForTests` set a module-level variable, but `resolveVerifier()`
returned the built-in test stub whenever `NODE_ENV === 'test'` — which is
exactly when the seam would be used. The override was therefore always
shadowed, and the provider-failure path had no way of being tested. An explicit
override flag now takes precedence over the stub.

---

### REV-07 — MFA tickets are not single-use
**Severity: Medium · Status: Accepted (risk) · DREAD DR-11 (residual 4.4)**

The `mfaTicket` issued after a correct password is a bearer value that is not
stored server-side, so it cannot be marked consumed. Within its ~2 minute
lifetime it could in principle be replayed alongside a still-valid TOTP code.
Mitigating factors: the ticket carries `purpose: 'mfa_pending'` and is rejected
outright by `requireAuth`, so it can never be used as a session; it is
short-lived; and obtaining it already requires the correct password.

**Named improvement:** store a `jti` per issued ticket and delete it on first
use. Not implemented in this iteration.

---

### REV-08 — Account lockout can be abused to deny service
**Severity: Medium · Status: Accepted (risk) · DREAD DR-10 (residual 4.6)**

Five wrong passwords lock an account for 15 minutes, so an attacker who knows a
victim's email address can lock them out repeatedly. This is the deliberate
cost of the strongest control against brute force. The lock is time-boxed and
self-clearing, so no administrator action is needed to recover.

**Named improvement:** per-(account, IP) progressive delays instead of an
account-wide lock.

---

### REV-09 — No breached-password checking
**Severity: Medium · Status: Accepted (risk) · DREAD DR-13 (residual 4.2)**

Complexity rules are enforced (10+ characters, mixed case, digit, symbol) but
nothing checks candidate passwords against a breach corpus, so `Password1!`
is accepted. Complexity rules structurally cannot close this gap.

**Named improvement:** the Have I Been Pwned range API (k-anonymity, so the
password never leaves the server), or a bundled top-100k denylist.

---

### REV-10 — Nested `select: false` made MFA impossible to enable
**Severity: High · Status: Fixed**

**What was wrong.** `mfaSecret` is `select: false` so it never loads by
accident, and the MFA controllers opt back in with `.select('+mfaSecret')`.
The sub-fields `pending` and `enabled` carried `select: false` as well, which
reads like defence in depth and is not: Mongoose applies a sub-path's
exclusion independently of its parent's. The opt-in therefore re-included the
parent while still excluding both children, so every controller received
`mfaSecret: {}`, concluded that no secret had ever been stored, and answered
`400 MFA_SETUP_NOT_STARTED`. Multi-factor authentication could not be switched
on at all.

**Why review missed it.** Nothing looks wrong in isolation. The model is
correct on its own, each controller opts in exactly as intended, and the
interaction only appears in the projection Mongoose builds at query time.

**How it was found.** The first execution of the database-backed suite on a
machine with a working MongoDB. Eight MFA tests failed together, in a cascade
that pointed at the wrong place: confirmation returned 400, so `mfaEnabled`
stayed false, so login never issued a ticket, so `verify-login` failed
validation with 422, so disabling reported `MFA_NOT_ENABLED`. One root cause,
four different status codes.

**Fix.** `select: false` is now set once, on the parent path only. Verified by
inspecting the projection Mongoose actually generates:

```
before   .select('+mfaSecret') -> { "mfaSecret.pending": 0, "mfaSecret.enabled": 0 }
after    .select('+mfaSecret') -> { "passwordHash": 0 }
after    no .select()          -> { "passwordHash": 0, "mfaSecret": 0 }
```

The last line is the point: the secret is still hidden by default, so the
security property is unchanged — only the opt-in works now.

A second bug was found in the same area while fixing it: `setupMfa` queried
without `+mfaSecret`, so the spread that merges the new pending secret saw
`undefined` and would have erased an existing confirmed `enabled` secret,
locking out any user who reopened the enrolment page while MFA was already on.
It now selects the field and merges via `toObject()` rather than spreading a
Mongoose subdocument.

**Regression guard.** `tests/auth/userProjection.test.js` asserts against the
generated projection directly — no database, 11 cases, runs in a second.
Confirmed to fail when the nested `select: false` is reintroduced and to pass
when it is not.

---

### REV-11 — Deleting a user returned 500 against a standalone MongoDB
**Severity: Medium · Status: Fixed**

**What was wrong.** Deleting an account removes its notes in a transaction so
the operation is all-or-nothing. Transactions need a replica set, so the code
carried a fallback to sequential deletes — but it decided when to use it by
pattern-matching the driver's error text for
`Transaction numbers|replica set|mongos`. A standalone `mongod` refuses the
attempt with wording those patterns do not cover, so the error was rethrown
and every deletion answered `500` on the setup most people run locally.

**Why review missed it.** The fallback existed, was commented, and looked
deliberate. Only the trigger condition was wrong, and it could not fire
without a real standalone database to fail against.

**Fix.** Attempt the transaction; fall back on *any* failure. This is safe
rather than lazy: both deletes are idempotent, so running them after a
partly-applied transaction cannot do damage, and a genuine database fault
fails the fallback too and propagates to the 500 it deserves. Which path ran
is now recorded per event as `atomic` in the audit entry, so the weaker
guarantee is visible in the trail rather than assumed. The fallback deletes
notes before the user, so a failure leaves a retryable state instead of
orphaned notes.

---

### REV-12 — Stored XSS sink in the note list
**Severity: High · Status: Fixed**

**What was wrong.** `public/js/notes.js` rendered the note list by
interpolating values into an `innerHTML` template:

```js
notesContainer.innerHTML = notes.map((note) => `
  <h3>${note.title}</h3>
  ...
```

`note.title` is user-supplied and was not escaped, so a note saved with the
title `<img src=x onerror=...>` was parsed as markup every time the owner
opened their list. Stored XSS — the payload sits in the database rather than
being reflected off a URL, so it fires on every visit until the note is
deleted.

**Was it exploitable as shipped?** Not directly, and the reason is worth
stating precisely rather than claiming more than is true. The Content Security
Policy sets `script-src 'self'` with no `'unsafe-inline'`, which blocks inline
event handlers such as `onerror`, and `img-src 'self' data:`, which blocks the
usual exfiltration image. Notes are also owner-scoped, so the only reader is
the author — self-XSS in the first instance.

**Why fix it anyway.** The CSP is the second line of defence and it was doing
all the work. Any future relaxation of that header — adding a CDN, adding
`'unsafe-inline'` to get a third-party widget working — silently re-opens the
hole, and by then the payloads are already stored. Defence that depends on one
header staying exactly as it is today is not defence in depth.

**Fix.** The list is now built with `document.createElement` and assigned
through `textContent`, so a title can never be parsed as markup regardless of
what the CSP says. Listeners are attached to each button as it is created,
which also removes the round-trip of the note id through a `data-` attribute.

**Regression guard.** `tests/security/hardening.test.js` statically scans
`public/js/*.js` for `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
`document.write` and `eval`, and scans `public/*.html` for inline handlers,
inline styles and inline `<script>` blocks. Comments are stripped first, so a
comment explaining why `innerHTML` is avoided does not trip the check. It is a
blunt instrument on purpose: no DOM needed, runs in milliseconds, and fails at
the moment someone reaches for the dangerous API rather than in review later.

**Credit.** Identified by Member 2 while reviewing her own frontend; fixed
during the Member 3 integration pass so the change could be verified against
the assembled application in one run.

---

### REV-13 — Route parameter name did not match the API contract
**Severity: Low · Status: Fixed**

The contract specifies `:noteId`. The routes used `:id`, and the controller and
validator read `req.params.id`.

Low severity because nothing was broken while both sides agreed — but this is
the kind of gap that breaks *silently* when it is fixed halfway. The router
defines the parameter and the controller reads it; change one side only and
every note operation returns `404` with an undefined id, and **no test on
either branch can catch it**: Member 2's tests mount the controller on a
throwaway app of their own, and Member 3's tests only exercise the assembled
application. The mismatch would surface after integration, at the worst
possible time.

Both halves were therefore changed together, with Member 2's agreement, and the
full suite was run against the assembled application afterwards. The admin
routes already used `:userId` as the contract specifies.

---

### REV-14 — Note validation used a different status code from the rest of the API
**Severity: Low · Status: Fixed**

`validateNote.js` returned `400` for field-validation failures. Everywhere else
in the project the split is the one documented in `src/middleware/validate.js`
and the API contract, section 5.5:

- `400` — the request itself is malformed (unparseable body, oversized payload)
- `422` — the request parsed fine but a field failed validation

All three failures in that file are the second kind, including an invalid
`:noteId`: the URL parsed correctly, the value in it simply is not a valid
identifier. The admin routes already answered `422` for exactly that case via
`param('userId').isMongoId()`, so the project had two rules that differed by
which file happened to do the validating. Now it has one.

The affected assertions in Member 2's three note test files were updated to
match.

---

### REV-15 — The note frontend never sent the CSRF token
**Severity: High (availability) · Status: Fixed**

**What was wrong.** `public/js/notes.js` sent every request with
`credentials: 'include'` but never called `GET /api/csrf-token` and never
attached an `X-CSRF-Token` header. `verifyCsrfToken` therefore rejected every
create, update and delete with `403 CSRF cookie is missing`. The notes feature —
the point of the application — did not work in a browser at all.

**How it was found.** Running the application by hand and clicking Save.

**Why 155 passing tests did not catch it.** This is the interesting part, and
it is worth stating plainly rather than glossing over.

`tests/notes/notesPipeline.integration.test.js` covers this endpoint
thoroughly, including two cases asserting that a write *without* a CSRF token
is refused. But every test that expects success attaches the header itself,
because supertest is not a browser and has no page to fetch one from. So the
suite proved the server enforces CSRF correctly — which it does — and was
completely blind to whether any page actually sends it. The server side and
the browser side were each correct in isolation and never met.

That is the same shape as the `:noteId` mismatch recorded in REV-13: two halves
of one contract, each tested on its own, with nothing exercising the seam.

**Fix.** `notes.js` now has a `csrfHeaders()` helper mirroring the one in
`admin.js`: it fetches the token, and the raw value is spread into the headers
of every `POST`, `PUT` and `DELETE`.

**Regression guard.** `tests/security/hardening.test.js` now statically asserts
that any script in `public/js/` containing a state-changing HTTP method also
mentions `X-CSRF-Token`. Deliberately coarse — it proves the token is wired up,
not that it is attached to the right call — but it turns a class of silent
browser-only breakage into a failing test, and it was confirmed to fail when
the fix is reverted.

---

## 7. Secrets handling

| Control | Status |
|---|---|
| `.env` is git-ignored; `.env.example` contains placeholders only | In place |
| Certificate and key file patterns (`*.pem`, `*.key`, `*.p12`, …) are git-ignored | In place |
| `SNYK_TOKEN` is a GitHub Actions secret, never a committed value | In place |
| `scripts/createAdmin.js` reads the initial password from the environment and never prints it | In place |
| CI fails if a real `.env` or a private key is ever committed | In place |
| GitHub push protection enabled on the repository | **Verify in repository settings** |

**If a secret is ever committed:** rotate it first, then remove it from
history. Rotation comes first because the value must be assumed compromised
the moment it is pushed — rewriting history does not un-publish it.

---

## 8. Review cadence

| When | What |
|---|---|
| Every pull request | CI must be green: tests, `npm audit`, Snyk, secret check |
| Every dependency change | Re-run section 3 and paste the real output |
| Weekly | Review new CodeQL alerts from the scheduled scan |
| Before the final submission | Confirm every finding is `Fixed`, `Accepted (risk)` with a named improvement, or `False positive` with a written reason |
