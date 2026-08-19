const bcrypt = require('bcryptjs');
// Pinned to otplib v12's classic `authenticator` API (sync generateSecret /
// keyuri / check) rather than v13. v13 ships its crypto sub-plugins as
// TypeScript source behind an ESM "exports" map that Jest's default CJS
// resolver cannot load without an extra ts-jest/babel transform — it works
// fine under plain Node but fails the whole test suite. v12 is stable, pure
// CJS, and this is the well-documented API most TOTP tutorials/tools use.
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

const User = require('../models/User');
const { recordAuditEvent } = require('../services/auditService');
const { encrypt, decrypt } = require('../utils/encryption');
const {
  SESSION_COOKIE_NAME,
  signSessionToken,
  sessionCookieOptions,
  signMfaTicket,
  verifyMfaTicket,
} = require('../utils/jwt');

const BCRYPT_COST = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MS = 15 * 60 * 1000;
// TOTP codes are checked with a window of 1 step (±30s) either side of the
// current time. This is a deliberate usability/security tradeoff: it
// tolerates modest client/server clock drift at the cost of a slightly
// larger acceptance window an attacker with a stolen-but-stale code could
// exploit. Documented in DREAD.
authenticator.options = { window: 1 };

// eslint-disable-next-line require-await
async function isTotpCodeValid(secret, token) {
  // Wrapped in an async function (even though otplib v12's check() is
  // synchronous) so every call site can `await` it uniformly and swapping
  // TOTP libraries later never requires touching the call sites again.
  return authenticator.check(token, secret);
}

// Precomputed once so an unknown-email login takes roughly the same time as
// a known-email/wrong-password login (both perform one bcrypt.compare),
// which avoids leaking account existence through response timing.
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing-safety', BCRYPT_COST);

function genericAuthError() {
  const error = new Error('Invalid email or password');

  error.statusCode = 401;
  error.code = 'AUTH_INVALID_CREDENTIALS';

  return error;
}

function toSafeProfile(user) {
  return {
    id: String(user._id),
    username: user.username,
    email: user.email,
    role: user.role,
  };
}

async function registerLockoutFailure(user) {
  user.failedLoginAttempts += 1;

  if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
    user.lockUntil = new Date(Date.now() + LOCK_DURATION_MS);
    user.failedLoginAttempts = 0;
  }

  await user.save();
}

async function resetLockoutState(user) {
  if (user.failedLoginAttempts !== 0 || user.lockUntil) {
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save();
  }
}

function issueSessionAndRespond(res, user, message) {
  const token = signSessionToken({
    id: user._id,
    role: user.role,
    tokenVersion: user.tokenVersion,
  });

  res.cookie(SESSION_COOKIE_NAME, token, sessionCookieOptions());

  return res.status(200).json({
    success: true,
    message,
    data: {
      mfaRequired: false,
      user: toSafeProfile(user),
    },
  });
}

// --- Registration ----------------------------------------------------------

async function register(req, res, next) {
  try {
    const { username, email, password } = req.body;

    // Same reasoning as in login() below: restate the type invariant where the
    // value becomes a query filter, rather than relying on middleware order.
    if (
      typeof username !== 'string'
      || typeof email !== 'string'
      || typeof password !== 'string'
    ) {
      const error = new Error('Validation failed');

      error.statusCode = 422;
      error.code = 'VALIDATION_ERROR';
      error.details = [{ field: 'body', message: 'Invalid field types' }];

      return next(error);
    }

    const existing = await User.findOne({
      $or: [{ username }, { email }],
    })
      .select('_id')
      .lean();

    if (existing) {
      const error = new Error('Username or email is already registered');

      error.statusCode = 409;
      error.code = 'ACCOUNT_EXISTS';

      return next(error);
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

    const user = await User.create({
      username,
      email,
      passwordHash,
      role: 'user',
    });

    await recordAuditEvent({
      actorId: user._id,
      actorRole: user.role,
      action: 'auth.register',
      targetType: 'User',
      targetId: user._id,
      outcome: 'success',
      requestId: req.id,
    });

    return res.status(201).json({
      success: true,
      message: 'Registration successful',
      data: {
        id: String(user._id),
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    return next(error);
  }
}

// --- Login (step 1: password) ----------------------------------------------

async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    // The route already guarantees these are strings — stripMongoOperators
    // removes operator-shaped keys before routing, and express-validator's
    // isEmail()/isString() reject anything else with 422. This check restates
    // that guarantee locally, right where the value is about to become a
    // query filter, because a controller should not silently depend on a
    // middleware three files away staying mounted in the right order. It also
    // gives a static analyser something it can actually see: CodeQL flags this
    // line as "database query built from user-controlled sources" precisely
    // because it cannot follow the validator chain.
    if (typeof email !== 'string' || typeof password !== 'string') {
      return next(genericAuthError());
    }

    const user = await User.findOne({ email })
      .select('+passwordHash +mfaSecret')
      .exec();

    if (!user) {
      await bcrypt.compare(password, DUMMY_HASH);

      await recordAuditEvent({
        action: 'auth.login',
        outcome: 'failure',
        requestId: req.id,
        context: { reason: 'invalid_credentials' },
      });

      return next(genericAuthError());
    }

    if (user.isLocked()) {
      // Deliberately identical response to "wrong password" — see
      // DREAD_Risk_Assessment.md for the account-lockout tradeoff. Password
      // work is skipped entirely while locked.
      await recordAuditEvent({
        actorId: user._id,
        actorRole: user.role,
        action: 'auth.login',
        outcome: 'failure',
        requestId: req.id,
        context: { reason: 'account_locked' },
      });

      return next(genericAuthError());
    }

    if (user.status === 'disabled') {
      // Fail fast with the same generic response rather than issuing a
      // session cookie that requireAuth would immediately reject on the
      // very next request anyway (it independently re-checks status on
      // every call). Kept generic for the same reason lockout is generic:
      // this must not double as an account-existence/state oracle.
      await recordAuditEvent({
        actorId: user._id,
        actorRole: user.role,
        action: 'auth.login',
        outcome: 'failure',
        requestId: req.id,
        context: { reason: 'account_disabled' },
      });

      return next(genericAuthError());
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatches) {
      await registerLockoutFailure(user);

      await recordAuditEvent({
        actorId: user._id,
        actorRole: user.role,
        action: 'auth.login',
        outcome: 'failure',
        requestId: req.id,
        context: { reason: 'invalid_credentials' },
      });

      return next(genericAuthError());
    }

    if (user.mfaEnabled) {
      const mfaTicket = signMfaTicket({ id: user._id });

      return res.status(200).json({
        success: true,
        message: 'MFA verification required',
        data: {
          mfaRequired: true,
          mfaTicket,
        },
      });
    }

    await resetLockoutState(user);

    await recordAuditEvent({
      actorId: user._id,
      actorRole: user.role,
      action: 'auth.login',
      outcome: 'success',
      requestId: req.id,
    });

    return issueSessionAndRespond(res, user, 'Login successful');
  } catch (error) {
    return next(error);
  }
}

// --- Login (step 2: TOTP) ---------------------------------------------------

async function verifyMfaLogin(req, res, next) {
  try {
    const { mfaTicket, mfaToken } = req.body;

    let decodedTicket;

    try {
      decodedTicket = verifyMfaTicket(mfaTicket);
    } catch {
      const error = new Error('MFA verification session is invalid or has expired');

      error.statusCode = 401;
      error.code = 'MFA_TICKET_INVALID';

      return next(error);
    }

    const user = await User.findById(decodedTicket.sub)
      .select('+mfaSecret')
      .exec();

    if (!user || !user.mfaEnabled || !user.isMfaSecretPresent('enabled')) {
      const error = new Error('MFA verification session is invalid or has expired');

      error.statusCode = 401;
      error.code = 'MFA_TICKET_INVALID';

      return next(error);
    }

    if (user.isLocked() || user.status === 'disabled') {
      const error = new Error('Invalid or expired authentication code');

      error.statusCode = 401;
      error.code = 'MFA_INVALID_CODE';

      return next(error);
    }

    const secret = decrypt(user.mfaSecret.enabled);
    const codeIsValid = await isTotpCodeValid(secret, mfaToken);

    if (!codeIsValid) {
      await registerLockoutFailure(user);

      await recordAuditEvent({
        actorId: user._id,
        actorRole: user.role,
        action: 'auth.login',
        outcome: 'failure',
        requestId: req.id,
        context: { reason: 'invalid_totp' },
      });

      const error = new Error('Invalid or expired authentication code');

      error.statusCode = 401;
      error.code = 'MFA_INVALID_CODE';

      return next(error);
    }

    await resetLockoutState(user);

    await recordAuditEvent({
      actorId: user._id,
      actorRole: user.role,
      action: 'auth.login',
      outcome: 'success',
      requestId: req.id,
      context: { mfa: true },
    });

    return issueSessionAndRespond(res, user, 'Login successful');
  } catch (error) {
    return next(error);
  }
}

// --- Current session ---------------------------------------------------------

async function getCurrentUser(req, res, next) {
  try {
    const user = await User.findById(req.user.id).exec();

    if (!user) {
      const error = new Error('Session is no longer valid');

      error.statusCode = 401;
      error.code = 'SESSION_REVOKED';

      return next(error);
    }

    return res.status(200).json({
      success: true,
      message: 'Current session',
      data: {
        user: {
          id: String(user._id),
          username: user.username,
          email: user.email,
          role: user.role,
          mfaEnabled: user.mfaEnabled,
        },
      },
    });
  } catch (error) {
    return next(error);
  }
}

// --- Logout ------------------------------------------------------------------

async function logout(req, res, next) {
  try {
    await User.updateOne(
      { _id: req.user.id },
      { $inc: { tokenVersion: 1 } },
    ).exec();

    res.clearCookie(SESSION_COOKIE_NAME, sessionCookieOptions());

    await recordAuditEvent({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'auth.logout',
      outcome: 'success',
      requestId: req.id,
    });

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully',
      data: {},
    });
  } catch (error) {
    return next(error);
  }
}

// --- MFA enrollment ------------------------------------------------------------

async function setupMfa(req, res, next) {
  try {
    // +mfaSecret matters here even though this handler only writes `pending`.
    // Without it the field is never loaded, the spread below sees undefined,
    // and saving would wipe an existing confirmed `enabled` secret — locking
    // out any user who re-opened the enrolment page while MFA was already on.
    const user = await User.findById(req.user.id).select('+mfaSecret').exec();

    if (!user) {
      const error = new Error('Session is no longer valid');

      error.statusCode = 401;
      error.code = 'SESSION_REVOKED';

      return next(error);
    }

    const secret = authenticator.generateSecret();
    const encryptedSecret = encrypt(secret);

    // toObject() rather than a bare spread: user.mfaSecret is a Mongoose
    // subdocument, and spreading one copies its internal machinery instead of
    // its fields.
    const existingSecret = user.mfaSecret ? user.mfaSecret.toObject() : {};

    user.mfaSecret = {
      ...existingSecret,
      pending: encryptedSecret,
    };

    await user.save();

    const otpauthUrl = authenticator.keyuri(
      user.email,
      process.env.MFA_ISSUER_NAME || 'SecureNotesApp',
      secret,
    );

    const qrCode = await QRCode.toDataURL(otpauthUrl);

    await recordAuditEvent({
      actorId: user._id,
      actorRole: user.role,
      action: 'auth.mfa.setup',
      outcome: 'success',
      requestId: req.id,
    });

    return res.status(200).json({
      success: true,
      message: 'Scan the QR code with your authenticator app, then confirm with a 6-digit code',
      data: {
        qrCode,
        manualEntryKey: secret,
      },
    });
  } catch (error) {
    return next(error);
  }
}

async function confirmMfa(req, res, next) {
  try {
    const { mfaToken } = req.body;

    const user = await User.findById(req.user.id)
      .select('+mfaSecret')
      .exec();

    if (!user || !user.isMfaSecretPresent('pending')) {
      const error = new Error('Start MFA setup before confirming');

      error.statusCode = 400;
      error.code = 'MFA_SETUP_NOT_STARTED';

      return next(error);
    }

    const secret = decrypt(user.mfaSecret.pending);
    const codeIsValid = await isTotpCodeValid(secret, mfaToken);

    if (!codeIsValid) {
      await recordAuditEvent({
        actorId: user._id,
        actorRole: user.role,
        action: 'auth.mfa.enable',
        outcome: 'failure',
        requestId: req.id,
        context: { reason: 'invalid_totp' },
      });

      const error = new Error('Invalid authentication code');

      error.statusCode = 401;
      error.code = 'MFA_CONFIRMATION_FAILED';

      return next(error);
    }

    user.mfaSecret = {
      enabled: user.mfaSecret.pending,
      pending: undefined,
    };
    user.mfaEnabled = true;

    await user.save();

    await recordAuditEvent({
      actorId: user._id,
      actorRole: user.role,
      action: 'auth.mfa.enable',
      outcome: 'success',
      requestId: req.id,
    });

    return res.status(200).json({
      success: true,
      message: 'MFA enabled successfully',
      data: {
        mfaEnabled: true,
      },
    });
  } catch (error) {
    return next(error);
  }
}

async function disableMfa(req, res, next) {
  try {
    const { password, mfaToken } = req.body;

    const user = await User.findById(req.user.id)
      .select('+passwordHash +mfaSecret')
      .exec();

    if (!user) {
      const error = new Error('Session is no longer valid');

      error.statusCode = 401;
      error.code = 'SESSION_REVOKED';

      return next(error);
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatches) {
      return next(genericAuthError());
    }

    if (!user.mfaEnabled || !user.isMfaSecretPresent('enabled')) {
      const error = new Error('MFA is not currently enabled');

      error.statusCode = 400;
      error.code = 'MFA_NOT_ENABLED';

      return next(error);
    }

    const secret = decrypt(user.mfaSecret.enabled);
    const codeIsValid = await isTotpCodeValid(secret, mfaToken);

    if (!codeIsValid) {
      await recordAuditEvent({
        actorId: user._id,
        actorRole: user.role,
        action: 'auth.mfa.disable',
        outcome: 'failure',
        requestId: req.id,
        context: { reason: 'invalid_totp' },
      });

      const error = new Error('Invalid authentication code');

      error.statusCode = 401;
      error.code = 'MFA_INVALID_CODE';

      return next(error);
    }

    user.mfaEnabled = false;
    user.mfaSecret = { pending: undefined, enabled: undefined };

    await user.save();

    await recordAuditEvent({
      actorId: user._id,
      actorRole: user.role,
      action: 'auth.mfa.disable',
      outcome: 'success',
      requestId: req.id,
    });

    return res.status(200).json({
      success: true,
      message: 'MFA disabled successfully',
      data: {
        mfaEnabled: false,
      },
    });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  register,
  login,
  verifyMfaLogin,
  getCurrentUser,
  logout,
  setupMfa,
  confirmMfa,
  disableMfa,
};
