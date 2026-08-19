const fs = require('fs');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const request = require('supertest');

const app = require('../../src/app');
const errorHandler = require('../../src/middleware/errorHandler');
const { stripMongoOperators } = require('../../src/middleware/validate');
const { issueCsrfToken, verifyCsrfToken } = require('../../src/middleware/csrfProtection');
const {
  verifyCaptcha,
  __setVerifierForTests,
  __resetVerifierForTests,
} = require('../../src/middleware/captcha');
const { extractCookieHeader } = require('../helpers/authFlow');

// Every test in this file exercises a hardening control that sits in front
// of (or entirely outside) the data layer, so none of them need a database.
// That is deliberate: these are the controls that must hold even when the
// database is unreachable, and keeping them DB-free means they stay fast
// and can be run on their own.

describe('Request body limits and malformed input (real app)', () => {
  test('a body larger than the configured limit is rejected with 413, not a crash', async () => {
    const oversized = JSON.stringify({ padding: 'a'.repeat(20 * 1024) });

    const response = await request(app)
      .post('/api/auth/register')
      .set('Content-Type', 'application/json')
      .send(oversized);

    expect(response.status).toBe(413);
    expect(response.body.error.code).toBe('PAYLOAD_TOO_LARGE');
  });

  test('malformed JSON is rejected with a clean 400 and leaks no parser internals', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"email": ');

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('MALFORMED_JSON');
    expect(JSON.stringify(response.body)).not.toMatch(/SyntaxError|node_modules|body-parser|at\s+JSON/i);
  });

  test('a non-object JSON body is rejected because strict parsing is enabled', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'application/json')
      .send('"just a string"');

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('MALFORMED_JSON');
  });

  test('an unexpected top-level field is rejected by the allow-list guard', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'someone@example.com',
        password: 'Str0ng!Passw0rd',
        captchaToken: 'test-valid-captcha-token',
        role: 'admin',
      });

    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
    expect(response.body.error.details[0].message).toMatch(/role/);
  });
});

describe('NoSQL operator sanitisation (stripMongoOperators)', () => {
  // Driven through a throwaway Express app rather than a hand-built fake
  // req, so this exercises the middleware exactly as mounted in src/app.js,
  // including Express 5's getter-only req.query.
  function buildSanitiserApp() {
    const testApp = express();

    testApp.use(express.json());
    testApp.use(stripMongoOperators);
    testApp.post('/echo/:userId', (req, res) => {
      res.status(200).json({ body: req.body, params: req.params, query: req.query });
    });

    return testApp;
  }

  test('strips operator keys from the request body', async () => {
    const response = await request(buildSanitiserApp())
      .post('/echo/abc')
      .send({ email: { $ne: null }, password: { $gt: '' }, username: 'legit' });

    expect(response.body.body).toEqual({ email: {}, password: {}, username: 'legit' });
  });

  test('strips operator keys nested inside arrays and sub-objects', async () => {
    const response = await request(buildSanitiserApp())
      .post('/echo/abc')
      .send({ filters: [{ $where: 'sleep(5000)' }, { safe: 1 }], nested: { deep: { $regex: '.*' } } });

    expect(response.body.body).toEqual({ filters: [{}, { safe: 1 }], nested: { deep: {} } });
  });

  test('strips dotted keys, which can be used to reach into sub-documents', async () => {
    const response = await request(buildSanitiserApp())
      .post('/echo/abc')
      .send({ 'mfaSecret.enabled': 'attacker-controlled', title: 'ok' });

    expect(response.body.body).toEqual({ title: 'ok' });
  });

  test('leaves ordinary values completely untouched', async () => {
    const payload = { title: 'Shopping list', tags: ['a', 'b'], count: 3, flag: false };

    const response = await request(buildSanitiserApp()).post('/echo/abc').send(payload);

    expect(response.body.body).toEqual(payload);
  });

  test.each([
    '__proto__',
    'constructor',
    'prototype',
  ])('strips %s, which can reach an object prototype rather than its own data', async (key) => {
    // No live prototype-pollution vector exists today — nothing in this
    // application spreads or Object.assigns a request body onto an existing
    // object, and that was verified rather than assumed. The keys are stripped
    // regardless: "no current caller misuses it" is a property of today's
    // callers, not of the input, and a future handler that does merge a body
    // should not be made unsafe by one it did not write.
    const response = await request(buildSanitiserApp())
      .post('/echo/abc')
      .send(JSON.parse(`{"${key}": {"polluted": 1}, "title": "ok"}`));

    expect(response.body.body).toEqual({ title: 'ok' });
  });

  test('stripping a prototype key does not pollute Object.prototype', async () => {
    await request(buildSanitiserApp())
      .post('/echo/abc')
      .send(JSON.parse('{"__proto__": {"pollutedByTest": "yes"}}'));

    expect({}.pollutedByTest).toBeUndefined();
  });

  test('sanitises the query string without reassigning Express 5\'s read-only req.query', async () => {
    const response = await request(buildSanitiserApp())
      .post('/echo/abc?$where=1&page=2')
      .send({});

    expect(response.status).toBe(200);
    expect(response.body.query).toEqual({ page: '2' });
  });
});

describe('CSRF double-submit verification (verifyCsrfToken)', () => {
  // Mounted on a minimal app so the CSRF middleware can be tested on its
  // own. In the real application it always sits behind requireAuth, which
  // would otherwise require a database just to reach the CSRF check.
  function buildCsrfApp() {
    const testApp = express();

    testApp.use(express.json());
    testApp.use(cookieParser());
    testApp.get('/csrf-token', issueCsrfToken);
    testApp.post('/protected', verifyCsrfToken, (req, res) => {
      res.status(200).json({ success: true, message: 'ok', data: {} });
    });
    testApp.use(errorHandler);

    return testApp;
  }

  async function getToken(testApp) {
    const response = await request(testApp).get('/csrf-token');

    return {
      csrfToken: response.body.data.csrfToken,
      cookieHeader: extractCookieHeader(response.headers['set-cookie']),
      setCookie: response.headers['set-cookie'][0],
    };
  }

  test('the token cookie is HttpOnly and SameSite=Strict', async () => {
    const { setCookie } = await getToken(buildCsrfApp());

    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/SameSite=Strict/i);
  });

  test('a request with no CSRF cookie and no header is rejected with 403', async () => {
    const response = await request(buildCsrfApp()).post('/protected').send({});

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('a cookie with no matching header is rejected with 403', async () => {
    const testApp = buildCsrfApp();
    const { cookieHeader } = await getToken(testApp);

    const response = await request(testApp).post('/protected').set('Cookie', cookieHeader).send({});

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('a header that does not match the cookie is rejected with 403', async () => {
    const testApp = buildCsrfApp();
    const { cookieHeader } = await getToken(testApp);

    const response = await request(testApp)
      .post('/protected')
      .set('Cookie', cookieHeader)
      .set('X-CSRF-Token', 'f'.repeat(48))
      .send({});

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('CSRF_TOKEN_INVALID');
  });

  test('an attacker-planted cookie with a forged signature is rejected', async () => {
    // Models an attacker who can set a cookie (e.g. via a sibling
    // subdomain) but does not know CSRF_SECRET, so cannot produce a valid
    // HMAC over a token value of their choosing.
    const attackerRaw = 'a'.repeat(48);

    const response = await request(buildCsrfApp())
      .post('/protected')
      .set('Cookie', `sn_csrf=${attackerRaw}.${'0'.repeat(64)}`)
      .set('X-CSRF-Token', attackerRaw)
      .send({});

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('a matching cookie and header pair is accepted', async () => {
    const testApp = buildCsrfApp();
    const { cookieHeader, csrfToken } = await getToken(testApp);

    const response = await request(testApp)
      .post('/protected')
      .set('Cookie', cookieHeader)
      .set('X-CSRF-Token', csrfToken)
      .send({});

    expect(response.status).toBe(200);
  });

  test('a token issued for one visitor cannot be replayed with another visitor\'s cookie', async () => {
    const testApp = buildCsrfApp();
    const victim = await getToken(testApp);
    const attacker = await getToken(testApp);

    const response = await request(testApp)
      .post('/protected')
      .set('Cookie', victim.cookieHeader)
      .set('X-CSRF-Token', attacker.csrfToken)
      .send({});

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('CSRF_TOKEN_INVALID');
  });
});

describe('CAPTCHA verification (verifyCaptcha)', () => {
  function buildCaptchaApp() {
    const testApp = express();

    testApp.use(express.json());
    testApp.post('/guarded', verifyCaptcha, (req, res) => {
      res.status(200).json({ success: true, message: 'ok', data: {} });
    });
    testApp.use(errorHandler);

    return testApp;
  }

  afterEach(() => {
    __resetVerifierForTests();
  });

  test('a missing CAPTCHA token is rejected with 400', async () => {
    const response = await request(buildCaptchaApp()).post('/guarded').send({});

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('CAPTCHA_FAILED');
  });

  test('a non-string CAPTCHA token is rejected with 400', async () => {
    const response = await request(buildCaptchaApp()).post('/guarded').send({ captchaToken: 12345 });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('CAPTCHA_FAILED');
  });

  test('a token the provider rejects is refused', async () => {
    __setVerifierForTests(async () => false);

    const response = await request(buildCaptchaApp()).post('/guarded').send({ captchaToken: 'anything' });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('CAPTCHA_FAILED');
  });

  test('a provider outage fails closed rather than silently letting the request through', async () => {
    __setVerifierForTests(async () => {
      throw new Error('ECONNRESET talking to https://www.google.com/recaptcha/api/siteverify');
    });

    const response = await request(buildCaptchaApp()).post('/guarded').send({ captchaToken: 'anything' });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('CAPTCHA_FAILED');
    // The upstream failure detail must not reach the client.
    expect(JSON.stringify(response.body)).not.toMatch(/ECONNRESET|google\.com/i);
  });

  test('the development bypass token is never honoured while NODE_ENV is test or production', async () => {
    process.env.CAPTCHA_DEV_BYPASS = 'true';
    __setVerifierForTests(async () => false);

    try {
      const response = await request(buildCaptchaApp()).post('/guarded').send({ captchaToken: 'DEV_BYPASS' });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('CAPTCHA_FAILED');
    } finally {
      delete process.env.CAPTCHA_DEV_BYPASS;
    }
  });

  test('a valid token is accepted', async () => {
    __setVerifierForTests(async () => true);

    const response = await request(buildCaptchaApp()).post('/guarded').send({ captchaToken: 'anything' });

    expect(response.status).toBe(200);
  });
});

describe('Security response headers and public configuration', () => {
  test('the public config endpoint exposes the site key and nothing secret', async () => {
    const response = await request(app).get('/api/config');

    expect(response.status).toBe(200);
    expect(Object.keys(response.body.data)).toEqual(['captchaSiteKey']);
    expect(JSON.stringify(response.body)).not.toContain(process.env.CAPTCHA_SECRET_KEY);
    expect(JSON.stringify(response.body)).not.toContain(process.env.JWT_SECRET);
    expect(JSON.stringify(response.body)).not.toContain(process.env.ENCRYPTION_KEY);
  });

  test('the framework fingerprint header is removed', async () => {
    const response = await request(app).get('/api/health');

    expect(response.headers['x-powered-by']).toBeUndefined();
  });

  test('clickjacking and MIME-sniffing protections are present', async () => {
    const response = await request(app).get('/api/health');

    expect(response.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(response.headers['x-content-type-options']).toBe('nosniff');
  });

  test('every response carries a correlation id for incident investigation', async () => {
    const response = await request(app).get('/api/health');

    expect(response.headers['x-request-id']).toBeDefined();
  });
});

describe('Frontend cannot reintroduce an HTML-injection sink', () => {
  // A static check, not a browser test. The note list previously interpolated
  // a user-supplied note title into innerHTML, which made a title like
  // `<img src=x onerror=...>` render as markup — stored XSS. The CSP blocked
  // execution, but the sink was there, and a CSP is meant to be the second
  // line of defence rather than the only one.
  //
  // Scanning the source is a blunt instrument and deliberately so: it needs no
  // DOM, runs in milliseconds, and fails the moment anyone reaches for the
  // dangerous API again — which is exactly the moment to catch it, rather than
  // in review months later.

  const FRONTEND_DIR = path.join(__dirname, '..', '..', 'public', 'js');

  function scriptFiles() {
    return fs.readdirSync(FRONTEND_DIR).filter((name) => name.endsWith('.js'));
  }

  // Comments are stripped first so that a comment *explaining* why innerHTML
  // is avoided does not itself trip the check.
  function codeWithoutComments(name) {
    return fs
      .readFileSync(path.join(FRONTEND_DIR, name), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
  }

  test('at least one frontend script is being scanned', () => {
    expect(scriptFiles().length).toBeGreaterThan(0);
  });

  test.each([
    ['innerHTML', /\.innerHTML\s*=/],
    ['outerHTML', /\.outerHTML\s*=/],
    ['insertAdjacentHTML', /\.insertAdjacentHTML\s*\(/],
    ['document.write', /document\s*\.\s*write\s*\(/],
    ['eval', /\beval\s*\(/],
  ])('no frontend script assigns through %s', (_label, pattern) => {
    const offenders = scriptFiles().filter((name) => pattern.test(codeWithoutComments(name)));

    expect(offenders).toEqual([]);
  });
});

describe('No HTML page carries an inline script or handler', () => {
  // The Content Security Policy sets script-src 'self' with no
  // 'unsafe-inline', so an inline handler would simply not run — the page
  // would look fine in review and silently do nothing in a browser. Catching
  // it here turns a confusing runtime non-event into a failing test.

  const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');

  function htmlFiles() {
    return fs.readdirSync(PUBLIC_DIR).filter((name) => name.endsWith('.html'));
  }

  test.each([
    ['an inline event handler', /\son[a-z]+\s*=\s*["']/i],
    ['an inline style attribute', /\sstyle\s*=\s*["']/i],
    ['an inline <script> block', /<script(?![^>]*\ssrc=)[^>]*>/i],
  ])('no page contains %s', (_label, pattern) => {
    const offenders = htmlFiles().filter((name) => pattern.test(
      fs.readFileSync(path.join(PUBLIC_DIR, name), 'utf8'),
    ));

    expect(offenders).toEqual([]);
  });
});
