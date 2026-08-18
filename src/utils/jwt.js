const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const SESSION_COOKIE_NAME = 'sn_session';
const SESSION_PURPOSE = 'session';
const MFA_TICKET_PURPOSE = 'mfa_pending';
const ALGORITHM = 'HS256';

// --- Fail fast at startup -------------------------------------------------
// Requiring this module is part of the app's require chain
// (server.js -> app.js -> authRoutes -> authController -> jwt.js), so a
// missing or weak secret throws immediately at process startup rather than
// on the first request.

function assertStrongSecret(name, value) {
  if (!value || typeof value !== 'string' || value.length < 32) {
    throw new Error(
      `${name} is missing or too weak. Set a high-entropy value of at least 32 characters (see .env.example).`,
    );
  }

  return value;
}

const JWT_SECRET = assertStrongSecret('JWT_SECRET', process.env.JWT_SECRET);
const JWT_ISSUER = process.env.JWT_ISSUER || 'secure-notes-app';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'secure-notes-users';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const MFA_TICKET_EXPIRES_IN = process.env.MFA_TICKET_EXPIRES_IN || '2m';

const DURATION_PATTERN = /^(\d+)\s*(ms|s|m|h|d)$/i;
const UNIT_TO_MS = {
  ms: 1,
  s: 1000,
  m: 60 * 1000,
  h: 60 * 60 * 1000,
  d: 24 * 60 * 60 * 1000,
};

function parseDurationToMs(value) {
  const match = DURATION_PATTERN.exec(String(value).trim());

  if (!match) {
    throw new Error(`Invalid duration string: ${value}`);
  }

  const amount = Number.parseInt(match[1], 10);
  const unit = match[2].toLowerCase();

  return amount * UNIT_TO_MS[unit];
}

// --- Session tokens (sn_session cookie) -----------------------------------

function signSessionToken({ id, role, tokenVersion }) {
  return jwt.sign(
    {
      role,
      tv: tokenVersion,
      purpose: SESSION_PURPOSE,
    },
    JWT_SECRET,
    {
      subject: String(id),
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      algorithm: ALGORITHM,
      expiresIn: JWT_EXPIRES_IN,
    },
  );
}

function verifySessionToken(token) {
  const decoded = jwt.verify(token, JWT_SECRET, {
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    algorithms: [ALGORITHM],
  });

  if (decoded.purpose !== SESSION_PURPOSE) {
    throw new Error('Token is not a session token');
  }

  return decoded;
}

// One cookie-options function used consistently everywhere the cookie is
// set (login, mfa/verify-login) or cleared (logout), so the flags used to
// clear it always exactly match the flags used to set it.
function sessionCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: parseDurationToMs(JWT_EXPIRES_IN),
  };
}

// --- Short-lived MFA tickets ------------------------------------------------
// Issued after a correct password when MFA is enabled. Deliberately never
// set as a cookie and never accepted by requireAuth — it travels only in
// the POST /api/auth/mfa/verify-login request body and is useless as an
// application session even if intercepted, both because of its short
// lifetime and because its `purpose` claim is rejected by
// verifySessionToken.

function signMfaTicket({ id }) {
  return jwt.sign(
    {
      purpose: MFA_TICKET_PURPOSE,
      jti: crypto.randomBytes(12).toString('hex'),
    },
    JWT_SECRET,
    {
      subject: String(id),
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      algorithm: ALGORITHM,
      expiresIn: MFA_TICKET_EXPIRES_IN,
    },
  );
}

function verifyMfaTicket(token) {
  const decoded = jwt.verify(token, JWT_SECRET, {
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    algorithms: [ALGORITHM],
  });

  if (decoded.purpose !== MFA_TICKET_PURPOSE) {
    throw new Error('Token is not an MFA ticket');
  }

  return decoded;
}

module.exports = {
  SESSION_COOKIE_NAME,
  signSessionToken,
  verifySessionToken,
  sessionCookieOptions,
  signMfaTicket,
  verifyMfaTicket,
  parseDurationToMs,
};
