const express = require('express');
const { body } = require('express-validator');

const authController = require('../controllers/authController');
const requireAuth = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const { verifyCaptcha } = require('../middleware/captcha');
const { verifyCsrfToken } = require('../middleware/csrfProtection');
const { handleValidation, rejectUnknownFields } = require('../middleware/validate');

const router = express.Router();

const USERNAME_PATTERN = /^[a-zA-Z0-9_.-]{3,30}$/;
const MFA_TOKEN_PATTERN = /^\d{6}$/;
// At least one lower-case letter, one upper-case letter, one digit, and one
// symbol. Length is checked separately by isLength so this stays readable.
const PASSWORD_COMPLEXITY_PATTERN =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$/;

const emailField = body('email')
  .trim()
  .toLowerCase()
  .isEmail()
  .withMessage('A valid email address is required')
  .isLength({ max: 254 });

const usernameField = body('username')
  .trim()
  .isLength({ min: 3, max: 30 })
  .withMessage('Username must be 3-30 characters')
  .matches(USERNAME_PATTERN)
  .withMessage('Username may only contain letters, numbers, dots, underscores, and hyphens');

const strongPasswordField = body('password')
  .isString()
  .isLength({ min: 10, max: 128 })
  .withMessage('Password must be at least 10 characters')
  .matches(PASSWORD_COMPLEXITY_PATTERN)
  .withMessage('Password must include upper case, lower case, a number, and a symbol');

const presentPasswordField = body('password')
  .isString()
  .notEmpty()
  .withMessage('Password is required');

const captchaField = body('captchaToken')
  .isString()
  .notEmpty()
  .withMessage('CAPTCHA verification is required');

const mfaTokenField = body('mfaToken')
  .isString()
  .matches(MFA_TOKEN_PATTERN)
  .withMessage('Authentication code must be exactly 6 digits');

// --- POST /api/auth/register -------------------------------------------------
router.post(
  '/register',
  authLimiter,
  verifyCaptcha,
  rejectUnknownFields(['username', 'email', 'password', 'captchaToken']),
  usernameField,
  emailField,
  strongPasswordField,
  captchaField,
  handleValidation,
  authController.register,
);

// --- POST /api/auth/login ----------------------------------------------------
router.post(
  '/login',
  authLimiter,
  verifyCaptcha,
  rejectUnknownFields(['email', 'password', 'captchaToken']),
  emailField,
  presentPasswordField,
  captchaField,
  handleValidation,
  authController.login,
);

// --- POST /api/auth/mfa/verify-login -----------------------------------------
router.post(
  '/mfa/verify-login',
  authLimiter,
  rejectUnknownFields(['mfaTicket', 'mfaToken']),
  body('mfaTicket').isString().notEmpty().withMessage('MFA ticket is required'),
  mfaTokenField,
  handleValidation,
  authController.verifyMfaLogin,
);

// --- GET /api/auth/me ---------------------------------------------------------
router.get('/me', requireAuth, authController.getCurrentUser);

// --- POST /api/auth/logout ----------------------------------------------------
router.post(
  '/logout',
  requireAuth,
  verifyCsrfToken,
  authController.logout,
);

// --- POST /api/auth/mfa/setup -------------------------------------------------
router.post(
  '/mfa/setup',
  requireAuth,
  verifyCsrfToken,
  authLimiter,
  rejectUnknownFields([]),
  authController.setupMfa,
);

// --- POST /api/auth/mfa/confirm -----------------------------------------------
router.post(
  '/mfa/confirm',
  requireAuth,
  verifyCsrfToken,
  authLimiter,
  rejectUnknownFields(['mfaToken']),
  mfaTokenField,
  handleValidation,
  authController.confirmMfa,
);

// --- POST /api/auth/mfa/disable -----------------------------------------------
router.post(
  '/mfa/disable',
  requireAuth,
  verifyCsrfToken,
  authLimiter,
  rejectUnknownFields(['password', 'mfaToken']),
  presentPasswordField,
  mfaTokenField,
  handleValidation,
  authController.disableMfa,
);

module.exports = router;
