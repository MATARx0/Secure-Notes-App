const rateLimit = require('express-rate-limit');

// Residual limitation (documented in README and DREAD): express-rate-limit's
// default store is in-memory, so counters are per-process. That is correct
// for the single-instance deployment this project targets. Running more than
// one application instance behind a load balancer would need a shared store
// (for example a Redis store) so every instance sees the same counters.

const AUTH_WINDOW_MS = Number.parseInt(
  process.env.AUTH_RATE_LIMIT_WINDOW_MS || `${15 * 60 * 1000}`,
  10,
);

const AUTH_MAX = Number.parseInt(
  process.env.AUTH_RATE_LIMIT_MAX || '10',
  10,
);

const GENERAL_WINDOW_MS = Number.parseInt(
  process.env.GENERAL_RATE_LIMIT_WINDOW_MS || `${60 * 1000}`,
  10,
);

const GENERAL_MAX = Number.parseInt(
  process.env.GENERAL_RATE_LIMIT_MAX || '300',
  10,
);

function rateLimitHandler(req, res) {
  // Generic response: never reveals whether the underlying account,
  // email, or username exists — only that the caller must slow down.
  res.status(429).json({
    success: false,
    error: {
      code: 'RATE_LIMITED',
      message: 'Too many requests. Please try again later.',
      details: [],
    },
  });
}

// Strict limiter for registration, login, CAPTCHA-protected, and MFA
// verification endpoints. Counts every request that reaches it, whether it
// ultimately succeeds or fails, so an attacker cannot use failed guesses to
// dodge the counter.
const authLimiter = rateLimit({
  windowMs: AUTH_WINDOW_MS,
  max: AUTH_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});

// Looser limiter applied to the general API surface.
const generalLimiter = rateLimit({
  windowMs: GENERAL_WINDOW_MS,
  max: GENERAL_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});

module.exports = {
  authLimiter,
  generalLimiter,
};
