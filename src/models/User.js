const mongoose = require('mongoose');

const USERNAME_PATTERN = /^[a-zA-Z0-9_.-]{3,30}$/;
// Standard practical email pattern; deliberately not RFC-5322-exhaustive.
// Route-level express-validator also validates email format, so this is a
// defence-in-depth schema-level check, not the only line of defense.
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Sub-document shape mirrors src/utils/encryption.js's encrypt() output
// exactly (encryptedContent/iv/authTag, hex-encoded) so mfaSecret values can
// be passed straight into decrypt() with no reshaping.
const encryptedSecretSchema = new mongoose.Schema(
  {
    encryptedContent: { type: String, required: true },
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
  },
  { _id: false },
);

// Note on projection: `select: false` is set ONCE, on the parent `mfaSecret`
// path below, and deliberately NOT repeated on `pending` and `enabled`.
//
// Repeating it here looks like defence in depth but silently breaks the
// feature. Mongoose applies a sub-path's `select: false` independently of the
// parent's, so `.select('+mfaSecret')` would re-include the parent while
// still excluding both children — every controller would receive an empty
// `mfaSecret: {}` and conclude no secret had ever been stored. That produced
// eight failing MFA tests: enrolment appeared to work, confirmation then
// answered 400 MFA_SETUP_NOT_STARTED, and MFA could never be switched on.
// Opting the children back in would have meant writing
// `.select('+mfaSecret.pending +mfaSecret.enabled')` at every call site —
// one forgotten `+` away from the same bug.
//
// The parent's `select: false` is the real control and is sufficient: a query
// that does not ask for `mfaSecret` never loads any part of it. The toJSON /
// toObject transforms below strip it a second time regardless.
const mfaSecretSchema = new mongoose.Schema(
  {
    // Set as soon as POST /api/auth/mfa/setup generates a TOTP secret, but
    // not yet trusted for login until POST /api/auth/mfa/confirm succeeds.
    pending: {
      type: encryptedSecretSchema,
      default: undefined,
    },
    // Only set once enrollment is confirmed; this is the secret actually
    // used to verify TOTP codes at login.
    enabled: {
      type: encryptedSecretSchema,
      default: undefined,
    },
  },
  { _id: false },
);

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      minlength: 3,
      maxlength: 30,
      match: USERNAME_PATTERN,
    },

    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      unique: true,
      maxlength: 254,
      match: EMAIL_PATTERN,
    },

    passwordHash: {
      type: String,
      required: true,
      select: false,
    },

    // Never settable from a public request body — only assigned server-side
    // (registration always forces 'user'; only scripts/createAdmin.js and a
    // direct database action can produce 'admin').
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
      required: true,
    },

    mfaEnabled: {
      type: Boolean,
      default: false,
    },

    mfaSecret: {
      type: mfaSecretSchema,
      default: () => ({}),
      select: false,
    },

    failedLoginAttempts: {
      type: Number,
      default: 0,
      min: 0,
    },

    lockUntil: {
      type: Date,
      default: null,
    },

    // Bumped on logout and on any forced revocation (password change, MFA
    // disable, admin-initiated deactivation). Every JWT embeds the
    // tokenVersion that was current at sign time; requireAuth rejects a
    // token whose version does not match the current stored value, which is
    // how a stateless JWT is "revoked" without a server-side session table.
    tokenVersion: {
      type: Number,
      default: 0,
    },

    // Values match the shared API contract's PATCH /api/admin/users/:userId/status
    // body exactly ("enabled" | "disabled") so no internal/external name
    // mapping is needed at the controller boundary.
    status: {
      type: String,
      enum: ['enabled', 'disabled'],
      default: 'enabled',
    },
  },
  {
    timestamps: true,
  },
);

// unique: true above creates a MongoDB unique index, which is necessary but
// not sufficient by itself: it only rejects a duplicate at the storage
// layer (raising a driver-level E11000 error) and does nothing to make that
// error a clean HTTP response. src/middleware/errorHandler.js normalizes
// E11000 into a controlled 409, and authController performs its own
// pre-check for a friendlier message — the index is the source of truth
// that closes the race condition the pre-check alone cannot.

userSchema.methods.isLocked = function isLocked() {
  return Boolean(this.lockUntil) && this.lockUntil.getTime() > Date.now();
};

userSchema.methods.isMfaSecretPresent = function isMfaSecretPresent(kind) {
  return Boolean(
    this.mfaSecret
    && this.mfaSecret[kind]
    && this.mfaSecret[kind].encryptedContent,
  );
};

function stripSensitiveFields(doc, ret) {
  delete ret.passwordHash;
  delete ret.mfaSecret;
  delete ret.failedLoginAttempts;
  delete ret.lockUntil;
  delete ret.tokenVersion;
  delete ret.__v;
  return ret;
}

userSchema.set('toJSON', { transform: stripSensitiveFields });
userSchema.set('toObject', { transform: stripSensitiveFields });

const User = mongoose.model('User', userSchema);

module.exports = User;
