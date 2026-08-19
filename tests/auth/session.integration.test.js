const jwt = require('jsonwebtoken');
const request = require('supertest');

const app = require('../../src/app');
const User = require('../../src/models/User');
const {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
} = require('../setup/testDb');
const { registerAndLogin, extractCookieHeader } = require('../helpers/authFlow');

beforeAll(async () => {
  await startTestDatabase();
}, 30000);

afterEach(async () => {
  await clearTestDatabase();
});

afterAll(async () => {
  await stopTestDatabase();
});

// Crafts a session cookie value directly with the `jsonwebtoken` library so
// each edge case (expired, wrong secret, wrong issuer/audience, stale
// tokenVersion) can be produced deterministically without waiting on real
// clock time.
function forgeSessionToken(overrides = {}) {
  const {
    id = '507f1f77bcf86cd799439011',
    role = 'user',
    tokenVersion = 0,
    secret = process.env.JWT_SECRET,
    issuer = process.env.JWT_ISSUER,
    audience = process.env.JWT_AUDIENCE,
    expiresIn = '15m',
    purpose = 'session',
  } = overrides;

  return jwt.sign(
    { role, tv: tokenVersion, purpose },
    secret,
    {
      subject: String(id),
      issuer,
      audience,
      algorithm: 'HS256',
      expiresIn,
    },
  );
}

describe('requireAuth / GET /api/auth/me — session validity', () => {
  test('missing cookie is rejected with 401', async () => {
    const response = await request(app).get('/api/auth/me');

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHENTICATED');
  });

  test('a malformed cookie value is rejected with 401 and no internals leaked', async () => {
    const response = await request(app)
      .get('/api/auth/me')
      .set('Cookie', 'sn_session=not-a-real-jwt');

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('SESSION_INVALID');
    expect(JSON.stringify(response.body)).not.toMatch(/jwt|JsonWebTokenError|node_modules/i);
  });

  test('an expired token is rejected with 401', async () => {
    const { payload } = await registerAndLoginRaw();
    const expiredToken = forgeSessionToken({ id: payload.id, expiresIn: '-10s' });

    const response = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `sn_session=${expiredToken}`);

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('SESSION_INVALID');
  });

  test('a token signed with the wrong secret is rejected with 401', async () => {
    const forged = forgeSessionToken({ secret: 'a-completely-different-secret-value-1234567890' });

    const response = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `sn_session=${forged}`);

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('SESSION_INVALID');
  });

  test('a token with the wrong issuer/audience is rejected with 401', async () => {
    const forged = forgeSessionToken({ issuer: 'someone-elses-app' });

    const response = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `sn_session=${forged}`);

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('SESSION_INVALID');
  });

  test('an MFA ticket cannot be used as a session cookie', async () => {
    const forged = forgeSessionToken({ purpose: 'mfa_pending' });

    const response = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `sn_session=${forged}`);

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('SESSION_INVALID');
  });

  test('a revoked session (stale tokenVersion) is rejected even though the JWT itself is still valid', async () => {
    const { payload, sessionCookieHeader } = await registerAndLogin(app);

    // Simulate revocation happening elsewhere (e.g. a second logout, or an
    // admin-initiated deactivation) without going through this same cookie.
    await User.updateOne({ email: payload.email }, { $inc: { tokenVersion: 1 } });

    const response = await request(app).get('/api/auth/me').set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('SESSION_REVOKED');
  });

  test('a disabled account is rejected even with an otherwise valid session', async () => {
    const { payload, sessionCookieHeader } = await registerAndLogin(app);

    await User.updateOne({ email: payload.email }, { $set: { status: 'disabled' } });

    const response = await request(app).get('/api/auth/me').set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('SESSION_REVOKED');
  });

  test('a query-string token is never accepted — the cookie is the only source', async () => {
    const { sessionCookieHeader } = await registerAndLogin(app);
    const token = extractCookieHeader([sessionCookieHeader]).split('sn_session=')[1];

    const response = await request(app).get(`/api/auth/me?token=${encodeURIComponent(token || 'x')}`);

    expect(response.status).toBe(401);
  });

  test('a valid, freshly-issued session is accepted', async () => {
    const { sessionCookieHeader } = await registerAndLogin(app);

    const response = await request(app).get('/api/auth/me').set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(200);
  });
});

// Small local wrapper so the "expired token" test has a real user id to
// embed in the forged token (an expired token for a nonexistent id would
// already be rejected at the signature-verification step, before the id is
// ever looked up, which would not actually exercise expiry handling).
async function registerAndLoginRaw() {
  const { payload, loginResponse } = await registerAndLogin(app);
  const id = loginResponse.body.data.user.id;

  return { payload: { ...payload, id } };
}
