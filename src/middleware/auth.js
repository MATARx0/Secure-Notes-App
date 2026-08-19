const User = require('../models/User');
const { verifySessionToken, SESSION_COOKIE_NAME } = require('../utils/jwt');

function unauthorized(next, code, message) {
  const error = new Error(message);

  error.statusCode = 401;
  error.code = code;

  return next(error);
}

// Reads the session exclusively from the sn_session HttpOnly cookie. There
// is deliberately no second token source (no Authorization header, no
// query string) — one source keeps the attack surface and the revocation
// story simple and unambiguous.
async function requireAuth(req, res, next) {
  const token = req.cookies ? req.cookies[SESSION_COOKIE_NAME] : undefined;

  if (!token) {
    return unauthorized(next, 'UNAUTHENTICATED', 'Authentication is required');
  }

  let decoded;

  try {
    decoded = verifySessionToken(token);
  } catch {
    // Signature failure, expiry, wrong algorithm, wrong issuer/audience, or
    // a malformed/foreign token all collapse to the same generic response —
    // verification internals are never returned to the client.
    return unauthorized(next, 'SESSION_INVALID', 'Session is invalid or has expired');
  }

  try {
    const user = await User.findById(decoded.sub)
      .select('role tokenVersion status')
      .lean();

    if (!user) {
      return unauthorized(next, 'SESSION_REVOKED', 'Session is no longer valid');
    }

    if (user.status === 'disabled') {
      return unauthorized(next, 'SESSION_REVOKED', 'Session is no longer valid');
    }

    if (user.tokenVersion !== decoded.tv) {
      // Covers logout, forced revocation, and MFA disable — anything that
      // bumps tokenVersion immediately invalidates every JWT issued before
      // the bump, even though JWTs are otherwise stateless.
      return unauthorized(next, 'SESSION_REVOKED', 'Session is no longer valid');
    }

    req.user = {
      id: String(user._id),
      role: user.role,
    };

    return next();
  } catch (error) {
    // Unexpected errors (e.g. a database hiccup) go to the central error
    // handler rather than being swallowed into another 401.
    return next(error);
  }
}

module.exports = requireAuth;
