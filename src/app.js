const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/authRoutes');
const noteRoutes = require('./routes/noteRoutes');
const adminRoutes = require('./routes/adminRoutes');
const notFound = require('./middleware/notFound');
const errorHandler = require('./middleware/errorHandler');
const requestLogger = require('./middleware/requestLogger');
const { generalLimiter } = require('./middleware/rateLimiter');
const { issueCsrfToken } = require('./middleware/csrfProtection');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const allowedOrigin = process.env.CLIENT_ORIGIN;

// Trust exactly one reverse-proxy hop in production (matches a typical
// single-tier PaaS deployment such as Render, which sits directly in front
// of the app). This must be re-verified against whatever platform is
// actually used before deployment — trusting the wrong number of hops lets
// a client spoof X-Forwarded-* headers and defeats rate limiting and
// secure-cookie detection.
if (isProduction) {
  app.set('trust proxy', 1);
}

const helmetOptions = {
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      // reCAPTCHA renders its challenge inside an iframe served by Google.
      frameSrc: ["'self'", 'https://www.google.com/recaptcha/'],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      // reCAPTCHA's client script must load from Google's script origins.
      // No other third-party origin and no unsafe-inline/wildcard is added.
      scriptSrc: [
        "'self'",
        'https://www.google.com/recaptcha/',
        'https://www.gstatic.com/recaptcha/',
      ],
      styleSrc: ["'self'"],
    },
  },
};

if (!isProduction) {
  helmetOptions.strictTransportSecurity = false;
}

app.disable('x-powered-by');
app.use(helmet(helmetOptions));

app.use(
  cors({
    credentials: true,
    methods: [
      'GET',
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
      'OPTIONS',
    ],
    allowedHeaders: [
      'Content-Type',
      'X-CSRF-Token',
    ],
    origin(origin, callback) {
      if (!origin || (allowedOrigin && origin === allowedOrigin)) {
        return callback(null, true);
      }

      const error = new Error('Origin not allowed');
      error.statusCode = 403;
      error.code = 'CORS_ORIGIN_DENIED';
      return callback(error);
    },
  }),
);

app.use(express.json({
  limit: '10kb',
  strict: true,
}));

app.use(cookieParser());

app.use(requestLogger);

app.use(
  express.static(
    path.join(__dirname, '..', 'public'),
    {
      dotfiles: 'deny',
      index: false,
    },
  ),
);

app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Service is healthy',
    data: {
      status: 'ok',
    },
  });
});

// Public, non-secret configuration the browser needs before rendering a
// form (e.g. the reCAPTCHA *site* key — by design meant to be public and
// embedded in client-side HTML, unlike CAPTCHA_SECRET_KEY which never
// leaves the server). Nothing here should ever be a secret.
app.get('/api/config', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Public configuration',
    data: {
      captchaSiteKey: process.env.CAPTCHA_SITE_KEY || '',
    },
  });
});

// Applies to every /api route mounted below. Sensitive routes (auth
// register/login, MFA verification) additionally layer the stricter
// authLimiter on top inside their own route files.
app.use('/api', generalLimiter);

// Safe, side-effect-limited endpoint the frontend calls before rendering
// any form that performs a state-changing request. See
// src/middleware/csrfProtection.js for the signed double-submit design.
app.get('/api/csrf-token', issueCsrfToken);

app.use('/api/auth', authRoutes);
app.use('/api/notes', noteRoutes);
app.use('/api/admin', adminRoutes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
