const request = require('supertest');

const app = require('../../src/app');
const User = require('../../src/models/User');
const {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
} = require('../setup/testDb');
const {
  buildRegistrationPayload,
  registerUser,
  loginUser,
  extractCookieHeader,
  getCsrfContext,
} = require('../helpers/authFlow');

beforeAll(async () => {
  await startTestDatabase();
}, 30000);

afterEach(async () => {
  await clearTestDatabase();
});

afterAll(async () => {
  await stopTestDatabase();
});

describe('POST /api/auth/register', () => {
  test('a successful registration returns 201 with only safe fields, and always creates role "user"', async () => {
    const { response, payload } = await registerUser(app);

    expect(response.status).toBe(201);
    expect(response.body.success).toBe(true);
    expect(response.body.data).toMatchObject({
      username: payload.username,
      email: payload.email,
      role: 'user',
    });
    expect(response.body.data.passwordHash).toBeUndefined();
    expect(response.body.data.password).toBeUndefined();
  });

  test('sending role "admin" in the body does not create an administrator', async () => {
    const { response, payload } = await registerUser(app, { role: 'admin' });

    // rejectUnknownFields rejects the whole request because "role" is not
    // an accepted field on this endpoint.
    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');

    const created = await User.findOne({ email: payload.email });
    expect(created).toBeNull();
  });

  test('rejects a weak password', async () => {
    const { response } = await registerUser(app, { password: 'weak' });

    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
    expect(response.body.error.details.some((d) => d.field === 'password')).toBe(true);
  });

  test('rejects an invalid email address', async () => {
    const { response } = await registerUser(app, { email: 'not-an-email' });

    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('rejects duplicate email and duplicate username without a stack trace', async () => {
    const { payload } = await registerUser(app);

    const dupEmail = await request(app)
      .post('/api/auth/register')
      .send(buildRegistrationPayload({ email: payload.email }));

    expect(dupEmail.status).toBe(409);
    expect(dupEmail.body.error.code).toBe('ACCOUNT_EXISTS');
    expect(JSON.stringify(dupEmail.body)).not.toMatch(/at\s+\/|node_modules|\.js:\d+/);

    const dupUsername = await request(app)
      .post('/api/auth/register')
      .send(buildRegistrationPayload({ username: payload.username }));

    expect(dupUsername.status).toBe(409);
  });

  test('stores a bcrypt hash and never the submitted password', async () => {
    const { payload } = await registerUser(app);

    const stored = await User.findOne({ email: payload.email }).select('+passwordHash');

    expect(stored.passwordHash).not.toBe(payload.password);
    expect(stored.passwordHash).toMatch(/^\$2[aby]\$12\$/);
  });

  test('CAPTCHA failure path is rejected before a user is created', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send(buildRegistrationPayload({ captchaToken: 'not-the-valid-test-token' }));

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('CAPTCHA_FAILED');
  });
});

describe('POST /api/auth/login', () => {
  test('a successful login sets the sn_session cookie with the correct flags and never returns the token in the body', async () => {
    const { payload } = await registerUser(app);
    const response = await loginUser(app, payload);

    expect(response.status).toBe(200);
    expect(response.body.data.user).toMatchObject({
      username: payload.username,
      email: payload.email,
      role: 'user',
    });

    // The JWT itself must never appear anywhere in the JSON body.
    expect(JSON.stringify(response.body)).not.toMatch(/^eyJ|[^a-zA-Z0-9]eyJ/);

    const setCookie = (response.headers['set-cookie'] || []).find((c) => c.startsWith('sn_session='));
    expect(setCookie).toBeDefined();
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/SameSite=Strict/i);
    expect(setCookie).toMatch(/Path=\//i);
  });

  test('wrong email and wrong password return an equivalent public error', async () => {
    const { payload } = await registerUser(app);

    const wrongPassword = await loginUser(app, { email: payload.email, password: 'TotallyWr0ng!' });
    const wrongEmail = await loginUser(app, { email: 'nobody-here@example.com', password: payload.password });

    expect(wrongPassword.status).toBe(401);
    expect(wrongEmail.status).toBe(401);
    expect(wrongPassword.body.error.code).toBe(wrongEmail.body.error.code);
    expect(wrongPassword.body.error.message).toBe(wrongEmail.body.error.message);
  });

  test('locks the account after 5 failed attempts and keeps returning the same generic error while locked', async () => {
    const { payload } = await registerUser(app);

    for (let attempt = 0; attempt < 5; attempt += 1) {
      // eslint-disable-next-line no-await-in-loop
      const failed = await loginUser(app, { email: payload.email, password: 'TotallyWr0ng!' });
      expect(failed.status).toBe(401);
    }

    // Even the correct password is now rejected with the same generic
    // response while the account is locked.
    const lockedAttempt = await loginUser(app, payload);

    expect(lockedAttempt.status).toBe(401);
    expect(lockedAttempt.body.error.code).toBe('AUTH_INVALID_CREDENTIALS');

    const stored = await User.findOne({ email: payload.email });
    expect(stored.lockUntil).toBeTruthy();
    expect(stored.lockUntil.getTime()).toBeGreaterThan(Date.now());
  });

  test('rejects malformed/NoSQL-operator-shaped credentials instead of querying with them', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: { $gt: '' },
        password: { $gt: '' },
        captchaToken: 'test-valid-captcha-token',
      });

    // The global operator-stripping middleware removes the "$gt" key
    // in place, leaving an empty object where a string was expected, which
    // field validation then rejects — never a raw Mongo query anomaly and
    // never a 500.
    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });
});

describe('GET /api/auth/me', () => {
  test('requires a valid session', async () => {
    const response = await request(app).get('/api/auth/me');

    expect(response.status).toBe(401);
  });

  test('returns only safe profile fields for an authenticated user', async () => {
    const { payload } = await registerUser(app);
    const loginResponse = await loginUser(app, payload);
    const cookieHeader = extractCookieHeader(loginResponse.headers['set-cookie']);

    const response = await request(app).get('/api/auth/me').set('Cookie', cookieHeader);

    expect(response.status).toBe(200);
    expect(response.body.data.user).toMatchObject({
      username: payload.username,
      email: payload.email,
      role: 'user',
      mfaEnabled: false,
    });
    expect(response.body.data.user.passwordHash).toBeUndefined();
    expect(response.body.data.user.mfaSecret).toBeUndefined();
  });
});

describe('POST /api/auth/logout', () => {
  test('requires authentication', async () => {
    const response = await request(app).post('/api/auth/logout');

    expect(response.status).toBe(401);
  });

  test('requires a CSRF token even with a valid session', async () => {
    const { payload } = await registerUser(app);
    const loginResponse = await loginUser(app, payload);
    const cookieHeader = extractCookieHeader(loginResponse.headers['set-cookie']);

    const response = await request(app).post('/api/auth/logout').set('Cookie', cookieHeader);

    expect(response.status).toBe(403);
    expect(response.body.error.code).toMatch(/CSRF/);
  });

  test('clears and revokes the session so the old cookie no longer works', async () => {
    const { payload } = await registerUser(app);
    const loginResponse = await loginUser(app, payload);
    const cookieHeader = extractCookieHeader(loginResponse.headers['set-cookie']);
    const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, cookieHeader);

    const logoutResponse = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', combinedCookieHeader)
      .set('X-CSRF-Token', csrfToken);

    expect(logoutResponse.status).toBe(200);

    const meAfterLogout = await request(app).get('/api/auth/me').set('Cookie', cookieHeader);

    expect(meAfterLogout.status).toBe(401);
    expect(meAfterLogout.body.error.code).toBe('SESSION_REVOKED');
  });
});

describe('No sensitive data ever leaks in responses', () => {
  test('a validation-error response never includes passwordHash, mfaSecret, or a stack trace', async () => {
    const { response } = await registerUser(app, { password: 'weak' });
    const raw = JSON.stringify(response.body);

    expect(raw).not.toMatch(/passwordHash|mfaSecret|at Object\.|node_modules/);
  });
});
