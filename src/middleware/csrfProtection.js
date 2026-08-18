const crypto = require('crypto');

const CSRF_COOKIE_NAME = 'sn_csrf';
const CSRF_HEADER_NAME = 'x-csrf-token';
const TOKEN_BYTES = 24;
const COOKIE_MAX_AGE_MS = 2 * 60 * 60 * 1000; // 2 hours

// Signed double-submit cookie pattern (allowed by the team standard as an
// alternative to a maintained CSRF library). The browser cannot forge a
// valid header value on its own because the raw token is only ever handed
// back in the JSON response body of a same-origin GET, which cross-site
// requests cannot read due to CORS/SOP. The HMAC signature on the cookie
// additionally stops an attacker who can only set cookies (e.g. through an
// unrelated subdomain) from planting a token of their own choosing.

function getSecret() {
  const secret = process.env.CSRF_SECRET;

  if (!secret || secret.length < 16) {
    throw new Error(
      'CSRF_SECRET is not configured. Set a high-entropy CSRF_SECRET before starting the server.',
    );
  }

  return secret;
}

function sign(raw) {
  return crypto
    .createHmac('sha256', getSecret())
    .update(raw)
    .digest('hex');
}

function safeEqual(a, b) {
  const bufferA = Buffer.from(String(a));
  const bufferB = Buffer.from(String(b));

  if (bufferA.length !== bufferB.length) {
    return false;
  }

  return crypto.timingSafeEqual(bufferA, bufferB);
}

function cookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: COOKIE_MAX_AGE_MS,
  };
}

function issueToken(res) {
  const raw = crypto.randomBytes(TOKEN_BYTES).toString('hex');
  const signature = sign(raw);

  res.cookie(CSRF_COOKIE_NAME, `${raw}.${signature}`, cookieOptions());

  return raw;
}

// GET /api/csrf-token — safe, side-effect-free (other than issuing the
// cookie) endpoint the frontend calls once per page load before rendering
// any form that performs a state-changing request.
function issueCsrfToken(req, res) {
  const csrfToken = issueToken(res);

  return res.status(200).json({
    success: true,
    message: 'CSRF token issued',
    data: {
      csrfToken,
    },
  });
}

function denyCsrf(next, code, message) {
  const error = new Error(message);

  error.statusCode = 403;
  error.code = code;

  return next(error);
}

// Applied only to authenticated, cookie-based, state-changing routes
// (POST/PUT/PATCH/DELETE). Never applied to register/login/mfa-verify-login,
// which do not yet have a session and are protected instead by CAPTCHA and
// rate limiting per the team API contract.
function verifyCsrfToken(req, res, next) {
  const cookieValue = req.cookies ? req.cookies[CSRF_COOKIE_NAME] : undefined;

  if (!cookieValue || typeof cookieValue !== 'string') {
    return denyCsrf(next, 'CSRF_TOKEN_MISSING', 'CSRF cookie is missing');
  }

  const separatorIndex = cookieValue.lastIndexOf('.');

  if (separatorIndex <= 0) {
    return denyCsrf(next, 'CSRF_TOKEN_MISSING', 'CSRF cookie is malformed');
  }

  const raw = cookieValue.slice(0, separatorIndex);
  const signature = cookieValue.slice(separatorIndex + 1);

  let cookieIsValid;

  try {
    cookieIsValid = safeEqual(sign(raw), signature);
  } catch {
    cookieIsValid = false;
  }

  if (!cookieIsValid) {
    return denyCsrf(next, 'CSRF_TOKEN_MISSING', 'CSRF cookie is malformed');
  }

  const headerValue = req.get(CSRF_HEADER_NAME);

  if (!headerValue) {
    return denyCsrf(next, 'CSRF_TOKEN_MISSING', 'X-CSRF-Token header is missing');
  }

  let headerMatches;

  try {
    headerMatches = safeEqual(raw, headerValue);
  } catch {
    headerMatches = false;
  }

  if (!headerMatches) {
    return denyCsrf(next, 'CSRF_TOKEN_INVALID', 'CSRF token is invalid');
  }

  return next();
}

module.exports = {
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
  issueCsrfToken,
  verifyCsrfToken,
};
