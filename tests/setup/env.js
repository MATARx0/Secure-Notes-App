process.env.NODE_ENV = 'test';
process.env.CLIENT_ORIGIN = 'http://localhost:3000';

// Deterministic, obviously-fake test-only secrets. Never used outside Jest.
// Real deployments must supply their own values through the environment
// (see .env.example) — these are not read anywhere except test bootstrap.
process.env.JWT_SECRET =
  'test-only-jwt-secret-0123456789-not-for-production-use-abcdef';
process.env.JWT_ISSUER = 'secure-notes-app';
process.env.JWT_AUDIENCE = 'secure-notes-users';
process.env.JWT_EXPIRES_IN = '15m';
process.env.MFA_TICKET_EXPIRES_IN = '2m';
process.env.MFA_ISSUER_NAME = 'SecureNotesApp-Test';

// 32 bytes / 64 hex characters, matching src/utils/encryption.js exactly.
process.env.ENCRYPTION_KEY =
  'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';

process.env.CSRF_SECRET =
  'test-only-csrf-secret-0123456789-not-for-production-use-fedcba';

process.env.CAPTCHA_PROVIDER = 'recaptcha-v2';
process.env.CAPTCHA_SECRET_KEY = 'test-captcha-secret';
process.env.CAPTCHA_SITE_KEY = 'test-captcha-site';

// Generous by default so ordinary functional tests never trip the limiter
// by accident. src/middleware/rateLimiter.js reads these once at module
// load time (per test file, since Jest gives each test file its own fresh
// module registry), so a test file that specifically exercises rate
// limiting can override these two variables at the very top of the file —
// before its own `require('../../src/app')` call — to get a low,
// deterministic threshold just for that file.
process.env.AUTH_RATE_LIMIT_MAX = '1000';
process.env.AUTH_RATE_LIMIT_WINDOW_MS = '60000';
process.env.GENERAL_RATE_LIMIT_MAX = '5000';
process.env.GENERAL_RATE_LIMIT_WINDOW_MS = '60000';
