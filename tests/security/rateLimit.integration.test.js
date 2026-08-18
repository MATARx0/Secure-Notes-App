// This file deliberately overrides the generous defaults set in
// tests/setup/env.js BEFORE requiring the application, so the auth limiter
// has a small, deterministic threshold here and nowhere else. Jest gives
// every test file its own module registry, so this override cannot leak
// into (or be leaked into by) any other test file.
process.env.AUTH_RATE_LIMIT_MAX = '3';
process.env.AUTH_RATE_LIMIT_WINDOW_MS = '60000';
process.env.GENERAL_RATE_LIMIT_MAX = '5000';

// eslint-disable-next-line import/order
const request = require('supertest');
// eslint-disable-next-line import/order
const app = require('../../src/app');

// Every request below is rejected by verifyCaptcha long before any
// controller runs, so this file needs no database at all — which is exactly
// the point being proven: authLimiter counts requests that ultimately FAIL
// too, so an attacker cannot dodge the counter by making bad guesses.

describe('Rate limiting on authentication endpoints', () => {
  test('blocks further login attempts once the auth threshold is exceeded', async () => {
    const attempt = () => request(app)
      .post('/api/auth/login')
      .send({ email: 'nobody@example.com', password: 'whatever', captchaToken: 'wrong-token' });

    const first = await attempt();
    const second = await attempt();
    const third = await attempt();

    // The first three are allowed through the limiter (and then correctly
    // fail CAPTCHA verification with 400).
    expect([first.status, second.status, third.status]).toEqual([400, 400, 400]);

    const fourth = await attempt();

    expect(fourth.status).toBe(429);
    expect(fourth.body).toEqual({
      success: false,
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please try again later.',
        details: [],
      },
    });
  });

  test('the 429 response never reveals whether the targeted account exists', async () => {
    const responses = [];

    for (let i = 0; i < 6; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      responses.push(await request(app)
        .post('/api/auth/login')
        .send({ email: `probe${i}@example.com`, password: 'whatever', captchaToken: 'wrong-token' }));
    }

    const limited = responses.filter((response) => response.status === 429);

    expect(limited.length).toBeGreaterThan(0);
    limited.forEach((response) => {
      expect(response.body.error.message).toBe('Too many requests. Please try again later.');
      expect(JSON.stringify(response.body)).not.toMatch(/probe\d@example\.com/);
    });
  });

  test('unauthenticated read-only endpoints are not blocked by the auth limiter', async () => {
    // /api/health sits under the much looser generalLimiter only; the strict
    // auth limiter must not spill over onto the rest of the API surface.
    const response = await request(app).get('/api/health');

    expect(response.status).toBe(200);
  });
});
