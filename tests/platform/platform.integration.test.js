const request = require('supertest');
const app = require('../../src/app');

describe('platform foundation', () => {
  test(
    'GET /api/health returns the standard success envelope',
    async () => {
      const response = await request(app)
        .get('/api/health')
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        message: 'Service is healthy',
        data: {
          status: 'ok',
        },
      });

      const csp =
        response.headers['content-security-policy'];

      expect(csp).toBeDefined();
      expect(csp).not.toContain("'unsafe-inline'");
    },
  );

  test(
    'allows only the configured browser origin',
    async () => {
      await request(app)
        .get('/api/health')
        .set('Origin', process.env.CLIENT_ORIGIN)
        .expect(
          'Access-Control-Allow-Origin',
          process.env.CLIENT_ORIGIN,
        )
        .expect(200);

      const response = await request(app)
        .get('/api/health')
        .set('Origin', 'https://evil.example')
        .expect(403);

      expect(response.body.error.code)
        .toBe('CORS_ORIGIN_DENIED');
    },
  );

  test(
    'unknown API routes return the standard error envelope',
    async () => {
      const response = await request(app)
        .get('/api/does-not-exist')
        .expect(404);

      expect(response.body).toEqual({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'Route not found',
          details: [],
        },
      });
    },
  );
});