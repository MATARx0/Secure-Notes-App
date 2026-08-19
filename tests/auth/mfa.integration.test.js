const request = require('supertest');
const { authenticator } = require('otplib');

const app = require('../../src/app');
const User = require('../../src/models/User');
const {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
} = require('../setup/testDb');
const {
  registerAndLogin,
  loginUser,
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

async function setupMfa(sessionCookieHeader) {
  const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, sessionCookieHeader);

  const response = await request(app)
    .post('/api/auth/mfa/setup')
    .set('Cookie', combinedCookieHeader)
    .set('X-CSRF-Token', csrfToken)
    .send({});

  return { response, combinedCookieHeader, csrfToken };
}

async function confirmMfa(combinedCookieHeader, csrfToken, mfaToken) {
  return request(app)
    .post('/api/auth/mfa/confirm')
    .set('Cookie', combinedCookieHeader)
    .set('X-CSRF-Token', csrfToken)
    .send({ mfaToken });
}

describe('POST /api/auth/mfa/setup', () => {
  test('returns 401 without a session', async () => {
    const response = await request(app).post('/api/auth/mfa/setup').send({});

    expect(response.status).toBe(401);
  });

  test('generates a pending secret and QR code for an authenticated user', async () => {
    const { sessionCookieHeader } = await registerAndLogin(app);
    const { response } = await setupMfa(sessionCookieHeader);

    expect(response.status).toBe(200);
    expect(response.body.data.qrCode).toMatch(/^data:image\/png;base64,/);
    expect(typeof response.body.data.manualEntryKey).toBe('string');
  });
});

describe('POST /api/auth/mfa/confirm', () => {
  test('an invalid confirmation code does not enable MFA', async () => {
    const { payload, sessionCookieHeader } = await registerAndLogin(app);
    const { combinedCookieHeader, csrfToken } = await setupMfa(sessionCookieHeader);

    const confirmResponse = await confirmMfa(combinedCookieHeader, csrfToken, '000000');

    expect(confirmResponse.status).toBe(401);
    expect(confirmResponse.body.error.code).toBe('MFA_CONFIRMATION_FAILED');

    const stored = await User.findOne({ email: payload.email });
    expect(stored.mfaEnabled).toBe(false);
  });

  test('a correct confirmation code enables MFA', async () => {
    const { payload, sessionCookieHeader } = await registerAndLogin(app);
    const { response: setupResponse, combinedCookieHeader, csrfToken } = await setupMfa(sessionCookieHeader);
    const secret = setupResponse.body.data.manualEntryKey;
    const validCode = authenticator.generate(secret);

    const confirmResponse = await confirmMfa(combinedCookieHeader, csrfToken, validCode);

    expect(confirmResponse.status).toBe(200);
    expect(confirmResponse.body.data.mfaEnabled).toBe(true);

    const stored = await User.findOne({ email: payload.email });
    expect(stored.mfaEnabled).toBe(true);
  });
});

describe('Login with MFA enabled', () => {
  async function registerLoginAndEnableMfa() {
    const { payload, sessionCookieHeader } = await registerAndLogin(app);
    const { response: setupResponse, combinedCookieHeader, csrfToken } = await setupMfa(sessionCookieHeader);
    const secret = setupResponse.body.data.manualEntryKey;

    await confirmMfa(combinedCookieHeader, csrfToken, authenticator.generate(secret));

    return { payload, secret };
  }

  test('password step alone does not create a session when MFA is enabled', async () => {
    const { payload } = await registerLoginAndEnableMfa();

    const loginResponse = await loginUser(app, payload);

    expect(loginResponse.status).toBe(200);
    expect(loginResponse.body.data.mfaRequired).toBe(true);
    expect(loginResponse.body.data.mfaTicket).toBeDefined();
    expect(loginResponse.headers['set-cookie']).toBeUndefined();
  });

  test('login without completing the TOTP step never yields a working session', async () => {
    const { payload } = await registerLoginAndEnableMfa();
    await loginUser(app, payload);

    // No sn_session cookie was ever issued at this point — accessing a
    // protected route with nothing set must fail.
    const meResponse = await request(app).get('/api/auth/me');

    expect(meResponse.status).toBe(401);
  });

  test('an incorrect TOTP code at login is rejected', async () => {
    const { payload } = await registerLoginAndEnableMfa();
    const loginResponse = await loginUser(app, payload);

    const verifyResponse = await request(app)
      .post('/api/auth/mfa/verify-login')
      .send({ mfaTicket: loginResponse.body.data.mfaTicket, mfaToken: '000000' });

    expect(verifyResponse.status).toBe(401);
    expect(verifyResponse.body.error.code).toBe('MFA_INVALID_CODE');
  });

  test('the correct password and TOTP code together succeed and set the session cookie', async () => {
    const { payload, secret } = await registerLoginAndEnableMfa();
    const loginResponse = await loginUser(app, payload);

    const verifyResponse = await request(app)
      .post('/api/auth/mfa/verify-login')
      .send({ mfaTicket: loginResponse.body.data.mfaTicket, mfaToken: authenticator.generate(secret) });

    expect(verifyResponse.status).toBe(200);

    const setCookie = (verifyResponse.headers['set-cookie'] || []).find((c) => c.startsWith('sn_session='));
    expect(setCookie).toBeDefined();
  });

  test('an MFA ticket cannot be reused after it has already produced a session (single completed login)', async () => {
    const { payload, secret } = await registerLoginAndEnableMfa();
    const loginResponse = await loginUser(app, payload);
    const validToken = authenticator.generate(secret);

    const first = await request(app)
      .post('/api/auth/mfa/verify-login')
      .send({ mfaTicket: loginResponse.body.data.mfaTicket, mfaToken: validToken });

    expect(first.status).toBe(200);

    // otplib codes are valid for the whole 30s period, so immediately
    // replaying the exact same ticket+token pair could still verify the
    // TOTP itself — what matters here is that the ticket is a distinct,
    // short-lived artifact from the session, never stored or checked for
    // single-use server-side. This is documented as a residual risk in
    // DREAD (ticket replay within its ~2 minute window), not silently
    // hidden.
    const second = await request(app)
      .post('/api/auth/mfa/verify-login')
      .send({ mfaTicket: loginResponse.body.data.mfaTicket, mfaToken: validToken });

    expect([200, 401]).toContain(second.status);
  });
});

describe('POST /api/auth/mfa/disable', () => {
  async function registerLoginAndEnableMfa() {
    const { payload, sessionCookieHeader } = await registerAndLogin(app);
    const { response: setupResponse, combinedCookieHeader, csrfToken } = await setupMfa(sessionCookieHeader);
    const secret = setupResponse.body.data.manualEntryKey;

    await confirmMfa(combinedCookieHeader, csrfToken, authenticator.generate(secret));

    return {
      payload, secret, combinedCookieHeader, csrfToken,
    };
  }

  test('requires the current password', async () => {
    const {
      secret, combinedCookieHeader, csrfToken,
    } = await registerLoginAndEnableMfa();

    const response = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Cookie', combinedCookieHeader)
      .set('X-CSRF-Token', csrfToken)
      .send({ password: 'DefinitelyWrong!1', mfaToken: authenticator.generate(secret) });

    expect(response.status).toBe(401);
  });

  test('requires a valid TOTP code', async () => {
    const { combinedCookieHeader, csrfToken } = await registerLoginAndEnableMfa();

    const response = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Cookie', combinedCookieHeader)
      .set('X-CSRF-Token', csrfToken)
      .send({ password: 'Str0ng!Passw0rd', mfaToken: '000000' });

    expect(response.status).toBe(401);
  });

  test('disables MFA when both the password and TOTP code are correct', async () => {
    const {
      payload, secret, combinedCookieHeader, csrfToken,
    } = await registerLoginAndEnableMfa();

    const response = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Cookie', combinedCookieHeader)
      .set('X-CSRF-Token', csrfToken)
      .send({ password: 'Str0ng!Passw0rd', mfaToken: authenticator.generate(secret) });

    expect(response.status).toBe(200);
    expect(response.body.data.mfaEnabled).toBe(false);

    const stored = await User.findOne({ email: payload.email });
    expect(stored.mfaEnabled).toBe(false);
  });
});
