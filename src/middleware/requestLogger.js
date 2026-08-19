const crypto = require('crypto');

// Minimal, safe request logging: request id, method, path, status, timing.
// Deliberately never logs headers, cookies, query strings, or the request
// body, so it cannot leak passwords, note content, JWTs, CAPTCHA tokens,
// MFA secrets, or authorization headers.
function requestLogger(req, res, next) {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-Id', req.id);

  if (process.env.NODE_ENV === 'test') {
    return next();
  }

  const startedAt = process.hrtime.bigint();

  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;

    console.log(
      JSON.stringify({
        requestId: req.id,
        method: req.method,
        path: req.path,
        statusCode: res.statusCode,
        durationMs: Math.round(durationMs),
      }),
    );
  });

  return next();
}

module.exports = requestLogger;
