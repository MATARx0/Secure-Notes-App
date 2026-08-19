const request = require('supertest');
const bcrypt = require('bcryptjs');

const User = require('../../src/models/User');

// Matches src/middleware/captcha.js's built-in NODE_ENV==='test' stub —
// this exact string always passes, anything else always fails, with no
// network call involved either way.
const VALID_CAPTCHA_TOKEN = 'test-valid-captcha-token';

function uniqueSuffix() {
  return `${Date.now()}${Math.floor(Math.random() * 1e6)}`;
}

function buildRegistrationPayload(overrides = {}) {
  const suffix = uniqueSuffix();

  return {
    username: `user${suffix}`.slice(0, 30),
    email: `user${suffix}@example.com`,
    password: 'Str0ng!Passw0rd',
    captchaToken: VALID_CAPTCHA_TOKEN,
    ...overrides,
  };
}

async function registerUser(app, overrides = {}) {
  const payload = buildRegistrationPayload(overrides);
  const response = await request(app).post('/api/auth/register').send(payload);

  return { response, payload };
}

function loginUser(app, { email, password }, extra = {}) {
  return request(app)
    .post('/api/auth/login')
    .send({ email, password, captchaToken: VALID_CAPTCHA_TOKEN, ...extra });
}

// Turns a supertest response's `set-cookie` array into a single header
// value suitable for `.set('Cookie', ...)` on a follow-up request.
function extractCookieHeader(setCookieHeaders) {
  return (setCookieHeaders || []).map((entry) => entry.split(';')[0]).join('; ');
}

async function registerAndLogin(app, overrides = {}) {
  const { payload } = await registerUser(app, overrides);
  const loginResponse = await loginUser(app, payload);
  const sessionCookieHeader = extractCookieHeader(loginResponse.headers['set-cookie']);

  return { payload, loginResponse, sessionCookieHeader };
}

// Fetches a fresh CSRF token/cookie pair and returns everything needed to
// attach both the cookie and the X-CSRF-Token header to a follow-up
// state-changing request.
async function getCsrfContext(app, sessionCookieHeader) {
  const response = await request(app)
    .get('/api/csrf-token')
    .set('Cookie', sessionCookieHeader || '');

  const csrfCookieHeader = extractCookieHeader(response.headers['set-cookie']);
  const csrfToken = response.body.data.csrfToken;
  const combinedCookieHeader = [sessionCookieHeader, csrfCookieHeader]
    .filter(Boolean)
    .join('; ');

  return { csrfToken, combinedCookieHeader };
}

// There is deliberately no public/HTTP way to create an administrator (see
// scripts/createAdmin.js) — the public registration endpoint always forces
// role "user". Tests that need an admin session therefore insert the
// account directly with the model, exactly like scripts/createAdmin.js
// does, and then log in for real through POST /api/auth/login so the
// session itself is produced by the real authentication code path.
const ADMIN_PASSWORD = 'Str0ng!AdminPass1';

async function createAdminAndLogin(app, overrides = {}) {
  const suffix = uniqueSuffix();
  const email = overrides.email || `admin${suffix}@example.com`;
  const username = overrides.username || `admin${suffix}`.slice(0, 30);
  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);

  const admin = await User.create({
    username,
    email,
    passwordHash,
    role: 'admin',
  });

  const loginResponse = await loginUser(app, { email, password: ADMIN_PASSWORD });
  const sessionCookieHeader = extractCookieHeader(loginResponse.headers['set-cookie']);

  return {
    admin,
    email,
    username,
    loginResponse,
    sessionCookieHeader,
  };
}

module.exports = {
  VALID_CAPTCHA_TOKEN,
  buildRegistrationPayload,
  registerUser,
  loginUser,
  registerAndLogin,
  extractCookieHeader,
  getCsrfContext,
  createAdminAndLogin,
};
