const request = require('supertest');

const app = require('../../src/app');
const User = require('../../src/models/User');
const Note = require('../../src/models/Note');
const {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
} = require('../setup/testDb');
const {
  registerAndLogin,
  createAdminAndLogin,
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

// Well-formed (24 hex chars) but guaranteed not to belong to anyone.
const NONEXISTENT_ID = '507f1f77bcf86cd799439011';

function csrfDelete(path, combinedCookieHeader, csrfToken) {
  return request(app)
    .delete(path)
    .set('Cookie', combinedCookieHeader)
    .set('X-CSRF-Token', csrfToken);
}

function csrfPatch(path, body, combinedCookieHeader, csrfToken) {
  return request(app)
    .patch(path)
    .set('Cookie', combinedCookieHeader)
    .set('X-CSRF-Token', csrfToken)
    .send(body);
}

describe('GET /api/admin/users', () => {
  test('returns only safe fields — no password hash or MFA secret ever leaves the server', async () => {
    await registerAndLogin(app);
    const { sessionCookieHeader } = await createAdminAndLogin(app);

    const response = await request(app)
      .get('/api/admin/users')
      .set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(200);
    expect(response.body.data.users.length).toBeGreaterThanOrEqual(2);

    // A raw-string check, not just individual field assertions, so this
    // fails loudly even if someone later adds a new sensitive field to the
    // projection instead of reusing one of these two names.
    const raw = JSON.stringify(response.body);
    expect(raw).not.toMatch(/passwordHash/i);
    expect(raw).not.toMatch(/mfaSecret/i);

    expect(Object.keys(response.body.data.users[0]).sort()).toEqual(
      ['createdAt', 'email', 'id', 'mfaEnabled', 'role', 'status', 'username'].sort(),
    );
  });

  test('honors page and limit query parameters', async () => {
    const { sessionCookieHeader } = await createAdminAndLogin(app);

    const response = await request(app)
      .get('/api/admin/users?page=1&limit=1')
      .set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(200);
    expect(response.body.data.users).toHaveLength(1);
    expect(response.body.data.limit).toBe(1);
  });

  test('requires an authenticated admin, same as every other admin route', async () => {
    const response = await request(app).get('/api/admin/users');

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHENTICATED');
  });
});

describe('DELETE /api/admin/users/:userId', () => {
  // adminRoutes.js runs verifyCsrfToken, THEN param('userId').isMongoId(),
  // THEN handleValidation — so an id-format failure only surfaces as its
  // own distinct response when a valid CSRF pair is already attached.
  // Per validate.js's documented split (400 = malformed non-field request,
  // 422 = field-level validation failure), a bad :userId is a field-level
  // failure caught by express-validator, so this is 422 VALIDATION_ERROR,
  // not 400 — CastError/400 in errorHandler.js is only a fallback for a
  // route with no such validator.
  test('rejects a malformed id with 422 before ever touching the database', async () => {
    const { sessionCookieHeader } = await createAdminAndLogin(app);
    const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, sessionCookieHeader);

    const response = await csrfDelete('/api/admin/users/not-a-mongo-id', combinedCookieHeader, csrfToken);

    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('a well-formed id that matches no user returns 404', async () => {
    const { sessionCookieHeader } = await createAdminAndLogin(app);
    const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, sessionCookieHeader);

    const response = await csrfDelete(`/api/admin/users/${NONEXISTENT_ID}`, combinedCookieHeader, csrfToken);

    expect(response.status).toBe(404);
    expect(response.body.error.code).toBe('USER_NOT_FOUND');
  });

  test('an administrator cannot delete their own account through this endpoint', async () => {
    const { sessionCookieHeader, admin } = await createAdminAndLogin(app);
    const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, sessionCookieHeader);

    const response = await csrfDelete(`/api/admin/users/${admin._id}`, combinedCookieHeader, csrfToken);

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('SELF_ACTION_DENIED');
    expect(await User.findById(admin._id)).not.toBeNull();
  });

  test('is blocked without a valid CSRF token even with a genuine admin session', async () => {
    const { sessionCookieHeader } = await createAdminAndLogin(app);

    const response = await request(app)
      .delete(`/api/admin/users/${NONEXISTENT_ID}`)
      .set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('deleting another user also removes every note they own, leaving no orphans', async () => {
    const { sessionCookieHeader: adminCookie } = await createAdminAndLogin(app);
    const { loginResponse } = await registerAndLogin(app);
    const targetId = loginResponse.body.data.user.id;

    await Note.create([
      {
        owner: targetId, title: 'first', encryptedContent: 'a'.repeat(32), iv: 'b'.repeat(24), authTag: 'c'.repeat(32),
      },
      {
        owner: targetId, title: 'second', encryptedContent: 'd'.repeat(32), iv: 'e'.repeat(24), authTag: 'f'.repeat(32),
      },
    ]);
    expect(await Note.countDocuments({ owner: targetId })).toBe(2);

    const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, adminCookie);
    const response = await csrfDelete(`/api/admin/users/${targetId}`, combinedCookieHeader, csrfToken);

    expect(response.status).toBe(200);
    expect(await User.findById(targetId)).toBeNull();
    expect(await Note.countDocuments({ owner: targetId })).toBe(0);
  });

  // LAST_ADMIN_PROTECTED exists in adminController.js as defense-in-depth,
  // but is not reachable as a *distinct* scenario through the live HTTP
  // API: every admin endpoint already requires an authenticated admin
  // actor (requireRole('admin')), and an admin can never target their own
  // account through this endpoint (SELF_ACTION_DENIED, tested above). So
  // whenever a delete legitimately reaches the last-admin check, the
  // acting admin is necessarily a different, still-active admin — meaning
  // "other active admins" can never actually be zero at that point. This
  // test documents that boundary honestly instead of asserting a scenario
  // the code can't actually produce.
  test('deleting a fellow administrator succeeds as long as the acting admin remains', async () => {
    const { sessionCookieHeader: actingAdminCookie } = await createAdminAndLogin(app);
    const { admin: secondAdmin } = await createAdminAndLogin(app);

    const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, actingAdminCookie);
    const response = await csrfDelete(`/api/admin/users/${secondAdmin._id}`, combinedCookieHeader, csrfToken);

    expect(response.status).toBe(200);
    expect(await User.findById(secondAdmin._id)).toBeNull();
  });
});

describe('PATCH /api/admin/users/:userId/status', () => {
  test('an administrator cannot disable their own account through this endpoint', async () => {
    const { sessionCookieHeader, admin } = await createAdminAndLogin(app);
    const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, sessionCookieHeader);

    const response = await csrfPatch(
      `/api/admin/users/${admin._id}/status`,
      { status: 'disabled' },
      combinedCookieHeader,
      csrfToken,
    );

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('SELF_ACTION_DENIED');
  });

  test('rejects a status value outside the enabled/disabled contract', async () => {
    const { sessionCookieHeader: adminCookie } = await createAdminAndLogin(app);
    const { loginResponse } = await registerAndLogin(app);
    const targetId = loginResponse.body.data.user.id;
    const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, adminCookie);

    const response = await csrfPatch(
      `/api/admin/users/${targetId}/status`,
      { status: 'banned' },
      combinedCookieHeader,
      csrfToken,
    );

    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('disabling a user immediately revokes their existing session', async () => {
    const { sessionCookieHeader: adminCookie } = await createAdminAndLogin(app);
    const { loginResponse, sessionCookieHeader: targetCookie } = await registerAndLogin(app);
    const targetId = loginResponse.body.data.user.id;

    // The target's own cookie still works right now, before any admin action.
    const before = await request(app).get('/api/auth/me').set('Cookie', targetCookie);
    expect(before.status).toBe(200);

    const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, adminCookie);
    const patchResponse = await csrfPatch(
      `/api/admin/users/${targetId}/status`,
      { status: 'disabled' },
      combinedCookieHeader,
      csrfToken,
    );

    expect(patchResponse.status).toBe(200);
    expect(patchResponse.body.data.status).toBe('disabled');

    // The exact same cookie the target already had in hand is now rejected
    // — the disable is immediate, not "eventually, once the token would
    // have expired anyway".
    const after = await request(app).get('/api/auth/me').set('Cookie', targetCookie);
    expect(after.status).toBe(401);
    expect(after.body.error.code).toBe('SESSION_REVOKED');
  });

  test('re-enabling a disabled user does not resurrect their old, already-revoked session', async () => {
    const { sessionCookieHeader: adminCookie } = await createAdminAndLogin(app);
    const { loginResponse, sessionCookieHeader: targetCookie } = await registerAndLogin(app);
    const targetId = loginResponse.body.data.user.id;

    const disableCtx = await getCsrfContext(app, adminCookie);
    await csrfPatch(`/api/admin/users/${targetId}/status`, { status: 'disabled' }, disableCtx.combinedCookieHeader, disableCtx.csrfToken);

    const enableCtx = await getCsrfContext(app, adminCookie);
    const reEnableResponse = await csrfPatch(
      `/api/admin/users/${targetId}/status`,
      { status: 'enabled' },
      enableCtx.combinedCookieHeader,
      enableCtx.csrfToken,
    );

    expect(reEnableResponse.status).toBe(200);
    expect(reEnableResponse.body.data.status).toBe('enabled');

    // tokenVersion was bumped by the disable step, so the pre-disable
    // cookie is still stale even after re-enabling — the user must log in
    // again to obtain a session that matches the new tokenVersion.
    const staleCheck = await request(app).get('/api/auth/me').set('Cookie', targetCookie);
    expect(staleCheck.status).toBe(401);
    expect(staleCheck.body.error.code).toBe('SESSION_REVOKED');
  });
});

describe('GET /api/admin/audit-logs', () => {
  test('records and returns administrative actions', async () => {
    const { sessionCookieHeader: adminCookie } = await createAdminAndLogin(app);
    const { loginResponse } = await registerAndLogin(app);
    const targetId = loginResponse.body.data.user.id;
    const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, adminCookie);

    await csrfPatch(`/api/admin/users/${targetId}/status`, { status: 'disabled' }, combinedCookieHeader, csrfToken);

    const response = await request(app)
      .get('/api/admin/audit-logs')
      .set('Cookie', adminCookie);

    expect(response.status).toBe(200);
    const actions = response.body.data.events.map((event) => event.action);
    expect(actions).toContain('admin.user.status_change');
  });

  test('requires an authenticated admin, same as every other admin route', async () => {
    const response = await request(app).get('/api/admin/audit-logs');

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHENTICATED');
  });
});
