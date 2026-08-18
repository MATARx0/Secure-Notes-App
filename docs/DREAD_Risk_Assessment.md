# DREAD Risk Assessment — Identity, Authentication and Session Security

**Component:** Member 1 — Identity, Authentication and Session Security
**Application:** Secure Notes Application
**Scope of this assessment:** registration, login, multi-factor authentication,
session issuance and revocation, and the account data that supports them.

This document is the risk-rating counterpart to `STRIDE_Threat_Model.md`.
STRIDE answers *"what can go wrong?"*; DREAD answers *"which of those things
should we fix first, and how much did our controls actually help?"* Every
threat below carries a STRIDE identifier so the two documents can be read
side by side.

---

## 1. Scoring model

Each threat is scored on five dimensions from **1 (negligible)** to
**10 (critical)**. The overall risk score is the arithmetic mean of the five,
rounded to one decimal place.

| Dimension | Question it answers | 1–3 | 4–6 | 7–10 |
|---|---|---|---|---|
| **D**amage | How bad is a successful attack? | Cosmetic or nuisance | One account or limited data | Full account or system compromise |
| **R**eproducibility | How reliably does the attack work? | Rarely, needs luck or a race | Works under some conditions | Works every time |
| **E**xploitability | How much skill and access is needed? | Deep expertise plus privileged access | Scripting skill, some prerequisites | Any user with a browser or a basic tool |
| **A**ffected users | How many people are hurt? | A single user | A subset of users | Every user, or every administrator |
| **D**iscoverability | How easily is the weakness found? | Requires source access and study | Findable by an attentive tester | Obvious, or found by automated scanners |

Two scores are given for each threat:

- **Inherent risk** — the risk if the application were built with no control
  for that threat (a plain password login with a stateless token, no rate
  limiting, no MFA, no CSRF defence).
- **Residual risk** — the risk that remains with the controls that are
  actually implemented in this repository.

The gap between the two is the measurable value of the security work; the
residual column is the honest list of what a marker, or an attacker, could
still go after.

**Risk bands:** 1.0–3.9 Low · 4.0–6.9 Medium · 7.0–8.4 High · 8.5–10 Critical

---

## 2. Risk register — summary

| ID | Threat | STRIDE | Inherent | Residual | Band (residual) |
|---|---|---|---|---|---|
| DR-01 | Password brute force / credential stuffing against `/api/auth/login` | S-02 | 8.8 | 3.2 | Low |
| DR-02 | Privilege escalation by mass-assigning `role: "admin"` at registration | E-03 | 9.2 | 2.8 | Low |
| DR-03 | Session cookie theft through cross-site scripting | S-03 | 9.0 | 3.6 | Low |
| DR-04 | Cross-site request forgery against authenticated state-changing routes | T-03 | 8.0 | 2.6 | Low |
| DR-05 | JWT forgery (weak secret, `alg: none`, or algorithm confusion) | S-04 | 9.4 | 2.8 | Low |
| DR-06 | Disclosure of stored TOTP secrets from a database compromise | I-04 | 8.6 | 3.8 | Low |
| DR-07 | NoSQL operator injection at the login query | T-04 | 8.6 | 2.6 | Low |
| DR-08 | Session remains valid after logout or forced revocation | E-04 | 7.4 | 2.8 | Low |
| DR-09 | Account enumeration through differing responses or timing | I-05 | 5.2 | 2.6 | Low |
| DR-10 | Account lockout abused to deny service to a legitimate user | D-02 | 6.0 | 4.6 | Medium |
| DR-11 | MFA ticket replay inside its validity window | S-05 | 7.0 | 4.4 | Medium |
| DR-12 | Automated bulk account creation by bots | D-03 | 6.2 | 3.4 | Low |
| DR-13 | Weak or previously breached passwords accepted at registration | S-06 | 7.2 | 4.2 | Medium |
| DR-14 | Password hash or MFA secret leaking through an API response | I-06 | 8.8 | 2.6 | Low |
| DR-15 | Session hijacking by network interception of the cookie | S-07 | 8.4 | 3.2 | Low |

Note on reading the residual scores: **Damage stays at its inherent value
throughout**. A control changes how likely an attack is to succeed, not how
much harm it does if it does succeed, so a threat whose consequence is account
takeover keeps a high Damage score even when every other dimension collapses.
That is why well-defended threats bottom out around 2.6–3.2 rather than at 1.0.

**Highest residual risks:** DR-10 (4.6), DR-11 (4.4), DR-13 (4.2). These three
are analysed in section 4 and are the recommended next pieces of work.

---

## 3. Detailed assessment

### DR-01 — Password brute force / credential stuffing
**STRIDE:** S-02 (Spoofing) · **Inherent 8.8 → Residual 3.2**

An attacker submits large numbers of password guesses against
`POST /api/auth/login`, either against one account or by replaying a
credential dump across many accounts.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 9 | 10 | 9 | 7 | 9 | **8.8** |
| Residual | 9 | 2 | 2 | 2 | 1 | **3.2** |

Damage stays at 9 because a successful guess still yields a full account
takeover — controls reduce the *likelihood* of reaching that outcome, not its
severity. Reproducibility and exploitability fall sharply because three
independent controls now stack:

- `authLimiter` (`src/middleware/rateLimiter.js`) caps requests per IP per
  window and counts failed attempts too, so bad guesses cannot dodge the
  counter.
- Account lockout in `authController.login()` locks an account for 15 minutes
  after 5 consecutive failures.
- reCAPTCHA verification (`src/middleware/captcha.js`) runs server-side before
  the password is ever checked, so a scripted client cannot submit at machine
  speed at all.

**Evidence:** `tests/security/rateLimit.integration.test.js`,
`tests/auth/auth.integration.test.js` ("locks the account after repeated
failures").

---

### DR-02 — Privilege escalation by mass assignment
**STRIDE:** E-03 (Elevation of Privilege) · **Inherent 9.2 → Residual 2.8**

An attacker adds `"role": "admin"` to the registration or login body, hoping
the field is passed straight into `User.create()`.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 10 | 10 | 10 | 9 | 7 | **9.2** |
| Residual | 10 | 1 | 1 | 1 | 1 | **2.8** |

Three layers make this unreachable rather than merely unlikely:

1. `rejectUnknownFields(['username','email','password','captchaToken'])` in
   `src/routes/authRoutes.js` rejects the request with `422` before a
   controller runs.
2. `authController.register()` never spreads the body — it constructs the
   document field by field and hard-codes `role: 'user'`.
3. `requireRole('admin')` reads the role only from `req.user.role`, which
   `requireAuth` derives from the verified JWT and a fresh database lookup —
   never from client input.

Administrators can only be created out of band through
`scripts/createAdmin.js`.

**Evidence:** `tests/auth/auth.integration.test.js` (mass-assignment case),
`tests/security/rbac.integration.test.js` (forged role in body and query).

---

### DR-03 — Session cookie theft through XSS
**STRIDE:** S-03 (Spoofing) · **Inherent 9.0 → Residual 3.6**

Script injected into a page reads the session token and sends it to an
attacker-controlled host.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 10 | 9 | 8 | 9 | 9 | **9.0** |
| Residual | 10 | 3 | 3 | 1 | 1 | **3.6** |

The session lives in an `HttpOnly` cookie (`sn_session`), so `document.cookie`
cannot read it even if a script does execute. A strict Content Security Policy
with no `'unsafe-inline'` (`src/app.js`) blocks the injected script in the
first place, and the frontend (`public/js/auth.js`, `public/js/admin.js`)
never assigns server data through `innerHTML`. Residual risk is not zero: a
sufficiently powerful XSS could still *act as* the user in-page without ever
reading the token.

---

### DR-04 — Cross-site request forgery
**STRIDE:** T-03 (Tampering) · **Inherent 8.0 → Residual 2.6**

A malicious page causes the victim's browser to submit an authenticated
request (log out, disable MFA, delete a note) using the cookie it sends
automatically.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 7 | 9 | 8 | 8 | 8 | **8.0** |
| Residual | 7 | 2 | 2 | 1 | 1 | **2.6** |

`SameSite=Strict` on `sn_session` already stops the browser attaching the
cookie to a cross-site request. On top of that, every authenticated
state-changing route runs `verifyCsrfToken`, which requires a signed
double-submit token whose raw value is only ever returned in the JSON body of
a same-origin `GET /api/csrf-token` — unreadable cross-origin because of the
same-origin policy and the single-origin CORS allow-list. The HMAC signature
additionally defeats an attacker who can plant a cookie but does not know
`CSRF_SECRET`.

**Evidence:** `tests/security/hardening.test.js` (7 CSRF cases, including a
forged-signature cookie and a cross-visitor token replay).

---

### DR-05 — JWT forgery
**STRIDE:** S-04 (Spoofing) · **Inherent 9.4 → Residual 2.8**

An attacker mints their own session token — by guessing a weak signing secret,
by submitting `"alg": "none"`, or by tricking the server into verifying an
HMAC token against a public key.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 10 | 10 | 8 | 10 | 9 | **9.4** |
| Residual | 10 | 1 | 1 | 1 | 1 | **2.8** |

`src/utils/jwt.js` pins verification to `algorithms: ['HS256']`, so `none` and
algorithm-confusion variants are rejected before any claim is read. Issuer and
audience are both asserted, so a token minted for another system is refused.
The server refuses to start if `JWT_SECRET` is missing or too short, which
removes the "weak secret in a hurry" failure mode.

**Evidence:** `tests/auth/session.integration.test.js` — wrong secret, wrong
issuer, expired token, and an MFA ticket presented as a session cookie are all
rejected with an identical generic `401`.

---

### DR-06 — Disclosure of stored TOTP secrets
**STRIDE:** I-04 (Information Disclosure) · **Inherent 8.6 → Residual 3.8**

An attacker who reads the `users` collection extracts TOTP seeds and can
generate valid second factors indefinitely, silently.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 9 | 10 | 7 | 9 | 8 | **8.6** |
| Residual | 9 | 3 | 3 | 3 | 1 | **3.8** |

MFA secrets are encrypted with AES-256-GCM before storage, reusing Member 2's
`src/utils/encryption.js`, and the schema marks both `mfaSecret.pending` and
`mfaSecret.enabled` as `select: false` so they are never loaded unless a
controller explicitly asks. The residual risk is the honest one: an attacker
who obtains **both** the database dump **and** `ENCRYPTION_KEY` recovers the
secrets, so this control depends entirely on key management (see the note on
key rotation in section 5).

---

### DR-07 — NoSQL operator injection at login
**STRIDE:** T-04 (Tampering) · **Inherent 8.6 → Residual 2.6**

Submitting `{"email": {"$ne": null}}` turns the login lookup into "find any
user", handing the attacker whichever account the database returns first.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 9 | 9 | 8 | 9 | 8 | **8.6** |
| Residual | 9 | 1 | 1 | 1 | 1 | **2.6** |

`stripMongoOperators` removes every key beginning with `$` or containing `.`
from the body and query string before routing, and `express-validator`
independently requires `email` to be a string in valid email format. Both
layers must fail for the attack to work.

> **Implementation note worth recording.** The first version of this control
> mutated `req.query` in place. Under Express 5 `req.query` is a getter that
> re-parses the URL on every access and returns a *new* object each time, so
> the sanitised copy was thrown away and the query string was silently
> unprotected. `tests/security/hardening.test.js` caught it, and
> `src/middleware/validate.js` now redefines the property with the sanitised
> snapshot. This is a good example of why a control is not "done" until a test
> proves it actually fires.

---

### DR-08 — Session valid after logout
**STRIDE:** E-04 (Elevation of Privilege) · **Inherent 7.4 → Residual 2.8**

Stateless JWTs cannot be deleted server-side, so a token captured before
logout would normally keep working until it expires.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 8 | 9 | 6 | 7 | 7 | **7.4** |
| Residual | 8 | 2 | 2 | 1 | 1 | **2.8** |

Every user carries a `tokenVersion`, embedded in each token as the `tv` claim.
`requireAuth` compares the claim against the stored value on every request, so
incrementing it invalidates every token issued before that moment. Logout,
MFA disable, and an administrator disabling an account all bump it.

**Evidence:** `tests/auth/session.integration.test.js` (revoked
`tokenVersion`), `tests/admin/admin.integration.test.js` (disabling a user
immediately kills their existing session).

---

### DR-09 — Account enumeration
**STRIDE:** I-05 (Information Disclosure) · **Inherent 5.2 → Residual 2.6**

An attacker learns which email addresses are registered by comparing responses
or response times, then focuses password attacks on real accounts.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 3 | 8 | 6 | 5 | 4 | **5.2** |
| Residual | 3 | 3 | 3 | 3 | 1 | **2.6** |

Unknown email, wrong password, locked account, and disabled account all return
byte-identical `401 AUTH_INVALID_CREDENTIALS`. Timing is levelled by comparing
the submitted password against a precomputed `DUMMY_HASH` when no user is
found, so both paths perform exactly one bcrypt comparison.

Registration is the deliberate exception: it returns `409 ACCOUNT_EXISTS`,
because a signup form that cannot tell a user their email is already taken is
unusable. That trade-off is accepted, and rate limiting plus CAPTCHA make bulk
probing of the registration endpoint impractical.

---

### DR-10 — Account lockout abused for denial of service
**STRIDE:** D-02 (Denial of Service) · **Inherent 6.0 → Residual 4.6** ⚠️

An attacker who knows a victim's email deliberately submits five wrong
passwords to lock them out, and repeats it every fifteen minutes.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 5 | 8 | 7 | 4 | 6 | **6.0** |
| Residual | 5 | 7 | 4 | 3 | 4 | **4.6** |

This is the clearest example in the project of one control creating a
different risk. Lockout is what makes DR-01 tractable, and removing it would
push brute-force risk back up. The design decision is to keep it and bound the
damage:

- the lock is **time-boxed to 15 minutes** and clears itself, so no
  administrator intervention is required and the denial is temporary;
- the counter resets on any successful login, so a victim who knows their
  password is only ever briefly affected;
- CAPTCHA and rate limiting mean the attacker cannot cheaply lock out many
  accounts in parallel.

**Recommended improvement:** move from account-wide lockout to progressive
delays keyed on the (account, IP) pair, so an attacker on one address cannot
lock out a victim logging in from another. Not implemented in this iteration;
recorded here as accepted residual risk.

---

### DR-11 — MFA ticket replay
**STRIDE:** S-05 (Spoofing) · **Inherent 7.0 → Residual 4.4** ⚠️

The `mfaTicket` returned after a correct password is a short-lived bearer
value. An attacker who captures it, together with a TOTP code still inside its
30-second window, could complete the second step.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 9 | 7 | 6 | 6 | 7 | **7.0** |
| Residual | 9 | 5 | 4 | 3 | 1 | **4.4** |

Current controls: the ticket is a separate JWT carrying `purpose:
'mfa_pending'`, it expires in about two minutes, and `requireAuth` explicitly
refuses any token whose purpose is not `session` — so a ticket can never be
used as a session cookie. What is **not** implemented is server-side
single-use enforcement: the ticket is not stored, so it cannot be marked
consumed.

**Recommended improvement:** persist a one-time identifier (`jti`) for each
issued ticket and delete it on first successful use, or bind the ticket to a
nonce cookie set at the password step. Documented candidly rather than
papered over; the test in `tests/auth/mfa.integration.test.js` accepts either
outcome for a replayed ticket and carries a comment explaining why.

---

### DR-12 — Automated bulk account creation
**STRIDE:** D-03 (Denial of Service) · **Inherent 6.2 → Residual 3.4**

A script registers thousands of accounts, exhausting storage and polluting the
user list an administrator has to review.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 5 | 9 | 8 | 4 | 5 | **6.2** |
| Residual | 5 | 3 | 3 | 3 | 3 | **3.4** |

Server-side reCAPTCHA verification and `authLimiter` both apply to
`POST /api/auth/register`. The CAPTCHA middleware fails closed — a provider
timeout produces `400 CAPTCHA_FAILED`, never a silent pass.

**Evidence:** `tests/security/hardening.test.js` (provider-outage case).

---

### DR-13 — Weak or breached passwords accepted
**STRIDE:** S-06 (Spoofing) · **Inherent 7.2 → Residual 4.2** ⚠️

A user chooses a password that satisfies the complexity rule but is trivially
guessable or already present in a public breach corpus (`Password1!` is the
canonical example).

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 9 | 8 | 7 | 5 | 7 | **7.2** |
| Residual | 9 | 5 | 4 | 2 | 1 | **4.2** |

Enforced today: minimum 10 characters with upper case, lower case, a digit and
a symbol, and storage as a bcrypt hash at cost factor 12 so offline cracking
of a stolen hash is expensive. Not enforced: any check against known-breached
passwords, which is precisely the gap a complexity rule cannot close.

**Recommended improvement:** check candidate passwords against the Have I Been
Pwned range API (k-anonymity, so the password never leaves the server), or
ship a local top-100k denylist for an offline deployment.

---

### DR-14 — Password hash or MFA secret in an API response
**STRIDE:** I-06 (Information Disclosure) · **Inherent 8.8 → Residual 2.6**

A handler returns a raw user document and leaks `passwordHash` or `mfaSecret`
to the browser.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 9 | 10 | 9 | 9 | 7 | **8.8** |
| Residual | 9 | 1 | 1 | 1 | 1 | **2.6** |

Defence is layered so that a future careless handler still fails safe:
`passwordHash` and `mfaSecret` are `select: false` at the schema level, the
`toJSON`/`toObject` transforms strip them plus `tokenVersion`, `lockUntil` and
`failedLoginAttempts`, and every controller builds an explicit response object
rather than returning a document.

**Evidence:** `tests/auth/auth.integration.test.js` and
`tests/admin/admin.integration.test.js` both assert against the raw serialised
response body, not just individual fields, so a newly added sensitive field
would still fail the test.

---

### DR-15 — Session hijacking by network interception
**STRIDE:** S-07 (Spoofing) · **Inherent 8.4 → Residual 3.2**

The session cookie is captured in transit on a hostile network.

| | D | R | E | A | D | Score |
|---|---|---|---|---|---|---|
| Inherent | 10 | 8 | 7 | 8 | 9 | **8.4** |
| Residual | 10 | 2 | 2 | 1 | 1 | **3.2** |

`sessionCookieOptions()` sets `secure: true` whenever `NODE_ENV` is
`production`, so the cookie is never sent over plaintext HTTP in a real
deployment, and Helmet's HSTS header instructs browsers to use HTTPS for
subsequent visits. The residual risk is operational rather than in code: it
depends on the deployment actually terminating TLS correctly, and on
`app.set('trust proxy', 1)` matching the real number of proxy hops — noted in
`src/app.js` as something to re-verify before deployment.

---

## 4. Risk treatment plan

| Priority | ID | Residual | Decision | Action |
|---|---|---|---|---|
| 1 | DR-10 | 4.6 | **Mitigate later** | Replace account-wide lockout with per-(account, IP) progressive delays |
| 2 | DR-11 | 4.4 | **Mitigate later** | Enforce single-use MFA tickets via a stored `jti` |
| 3 | DR-13 | 4.2 | **Mitigate later** | Add a breached-password check at registration |
| 4 | DR-06 | 3.8 | **Accept, with conditions** | Depends on key management; document rotation and never commit `ENCRYPTION_KEY` |
| 5 | DR-03 | 3.6 | **Accept** | `HttpOnly` plus CSP is a reasonable stopping point at this scope |
| 6 | DR-12 | 3.4 | **Accept** | CAPTCHA and rate limiting are proportionate for a course deployment |
| — | all others | ≤ 3.2 | **Accept** | Controls implemented and covered by automated tests |

No residual risk is rated High or Critical. The three Medium items are
carried knowingly, with a named improvement for each, rather than being
quietly dropped.

---

## 5. Assumptions and limitations

1. **Key and secret management is out of scope.** `JWT_SECRET`, `CSRF_SECRET`
   and `ENCRYPTION_KEY` are assumed to be supplied through the environment,
   never committed, and rotated if exposed. DR-06 in particular collapses if
   this assumption fails. No key-rotation procedure is implemented.
2. **The threat actor modelled is a remote, unauthenticated or
   ordinary-privilege attacker.** A malicious administrator, or an attacker
   with shell access to the server, is explicitly outside this model —
   both can read the environment and defeat several controls by definition.
3. **Rate-limit counters are per process.** `express-rate-limit` uses an
   in-memory store, which is correct for the single-instance deployment this
   project targets but would need a shared store behind a load balancer.
4. **Scores are qualitative.** DREAD numbers are a prioritisation aid agreed
   within the team, not measurements. They are useful for ordering work, not
   for claiming an absolute level of security.
5. **Audit records are not tamper-evident.** Anyone with database write access
   could alter them, so they support investigation but do not constitute
   non-repudiation in a strong sense.

---

## 6. Cross-references

- `docs/STRIDE_Threat_Model.md` — threat identification and trust boundaries
- `docs/Secure_Notes_DFD.md` — data flow diagram
- `scans/remediation-log.md` — findings from CodeQL, Snyk and `npm audit`
- `README.md` — the control-to-source-file map
