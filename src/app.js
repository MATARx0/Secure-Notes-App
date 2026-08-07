const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const authRoutes = require('./routes/authRoutes');
const noteRoutes = require('./routes/noteRoutes');
const adminRoutes = require('./routes/adminRoutes');
const notFound = require('./middleware/notFound');
const errorHandler = require('./middleware/errorHandler');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const allowedOrigin = process.env.CLIENT_ORIGIN;

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
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'"],
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

app.use('/api/auth', authRoutes);
app.use('/api/notes', noteRoutes);
app.use('/api/admin', adminRoutes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;