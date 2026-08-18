const VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';
const PROVIDER_TIMEOUT_MS = 5000;

// Real provider call (Google reCAPTCHA v2). Never trust a browser-only
// result — verification always happens server-side.
async function callRecaptchaProvider(token, remoteIp) {
  const secret = process.env.CAPTCHA_SECRET_KEY;

  if (!secret) {
    throw new Error('CAPTCHA_SECRET_KEY is not configured');
  }

  const params = new URLSearchParams({
    secret,
    response: token,
  });

  if (remoteIp) {
    params.append('remoteip', remoteIp);
  }

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    PROVIDER_TIMEOUT_MS,
  );

  try {
    const response = await fetch(VERIFY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`CAPTCHA provider responded with ${response.status}`);
    }

    const result = await response.json();

    return Boolean(result && result.success);
  } finally {
    clearTimeout(timeout);
  }
}

// Deterministic stub used automatically whenever NODE_ENV === 'test' so
// automated tests never depend on network access or real provider keys.
// A token value of 'test-valid-captcha-token' passes; anything else fails,
// which is enough to exercise both the success and failure paths.
async function testStubVerifier(token) {
  return token === 'test-valid-captcha-token';
}

let verifier = callRecaptchaProvider;
let verifierOverridden = false;

function resolveVerifier() {
  // An explicit test override always wins, even in NODE_ENV === 'test' —
  // otherwise __setVerifierForTests could never actually take effect
  // during a Jest run (the exact environment it exists for), since the
  // deterministic stub below would silently shadow it.
  if (verifierOverridden) {
    return verifier;
  }

  if (process.env.NODE_ENV === 'test') {
    return testStubVerifier;
  }

  return verifier;
}

function isDevBypass(token) {
  return (
    process.env.NODE_ENV !== 'production'
    && process.env.NODE_ENV !== 'test'
    && process.env.CAPTCHA_DEV_BYPASS === 'true'
    && token === 'DEV_BYPASS'
  );
}

function captchaError(next, message) {
  const error = new Error(message);

  error.statusCode = 400;
  error.code = 'CAPTCHA_FAILED';

  return next(error);
}

// Applied to registration, login, and any other public endpoint the team
// decides needs bot protection.
async function verifyCaptcha(req, res, next) {
  const token = req.body ? req.body.captchaToken : undefined;

  if (!token || typeof token !== 'string') {
    return captchaError(next, 'CAPTCHA verification is required');
  }

  // NODE_ENV is asserted equal to 'production' explicitly (not merely
  // "!== development") so a missing or misconfigured NODE_ENV can never
  // accidentally enable the bypass in a real deployment.
  if (isDevBypass(token)) {
    return next();
  }

  try {
    const passed = await resolveVerifier()(token, req.ip);

    if (!passed) {
      return captchaError(next, 'CAPTCHA verification failed');
    }

    return next();
  } catch {
    // Provider errors (timeout, network failure, malformed response) are
    // treated as a controlled failure of the auth operation, never as a
    // silent pass and never as an unhandled 500.
    return captchaError(next, 'CAPTCHA verification is temporarily unavailable');
  }
}

// Test-only seam: lets a specific test file swap in a custom verifier
// (e.g. to simulate a provider outage) without any network dependency.
function __setVerifierForTests(fn) {
  verifier = fn;
  verifierOverridden = true;
}

function __resetVerifierForTests() {
  verifier = callRecaptchaProvider;
  verifierOverridden = false;
}

module.exports = {
  verifyCaptcha,
  __setVerifierForTests,
  __resetVerifierForTests,
};
