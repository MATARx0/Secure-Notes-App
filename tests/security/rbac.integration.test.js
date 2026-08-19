const request = require('supertest');

const app = require('../../src/app');
const {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
} = require('../setup/testDb');
const { registerAndLogin, createAdminAndLogin } = require('../helpers/authFlow');

beforeAll(async () => {
  await startTestDatabase();
}, 30000);

afterEach(async () => {
  await clearTestDatabase();
});

afterAll(async () => {
  await stopTestDatabase();
});

const ADMIN_ENDPOINTS = [
  { method: 'get', path: '/api/admin/users' },
  { method: 'get', path: '/api/admin/audit-logs' },
  { method: 'delete', path: '/api/admin/users/507f1f77bcf86cd799439011' },
  { method: 'patch', path: '/api/admin/users/507f1f77bcf86cd799439011/status' },
];

describe('RBAC — every admin endpoint', () => {
  test.each(ADMIN_ENDPOINTS)('rejects an unauthenticated request to $method $path with 401', async ({ method, path }) => {
    const response = await request(app)[method](path);

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHENTICATED');
  });

  test.each(ADMIN_ENDPOINTS)('rejects an authenticated non-admin user on $method $path with 403', async ({ method, path }) => {
    const { sessionCookieHeader } = await registerAndLogin(app);

    const response = await request(app)[method](path).set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('FORBIDDEN');
  });
});

describe('RBAC ignores any client-supplied role', () => {
  test('a forged role in the JSON body does not grant admin access', async () => {
    const { sessionCookieHeader } = await registerAndLogin(app);

    const response = await request(app)
      .get('/api/admin/users')
      .set('Cookie', sessionCookieHeader)
      .send({ role: 'admin' });

    expect(response.status).toBe(403);
  });

  test('a forged role in the query string does not grant admin access', async () => {
    const { sessionCookieHeader } = await registerAndLogin(app);

    const response = await request(app)
      .get('/api/admin/users?role=admin')
      .set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(403);
  });

  test('a genuine administrator session is accepted', async () => {
    const { sessionCookieHeader } = await createAdminAndLogin(app);

    const response = await request(app).get('/api/admin/users').set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(200);
  });
});

describe('Helmet / CSP headers are present on API responses', () => {
  test('every response includes a restrictive Content-Security-Policy', async () => {
    const response = await request(app).get('/api/health');

    expect(response.headers['content-security-policy']).toBeDefined();
    expect(response.headers['content-security-policy']).not.toContain("'unsafe-inline'");
    expect(response.headers['x-content-type-options']).toBe('nosniff');
  });
});
