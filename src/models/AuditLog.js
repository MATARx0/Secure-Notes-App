const mongoose = require('mongoose');

// Retention (documented per Member 3 Phase 11): for this class project,
// audit records are retained for the lifetime of the database with no
// automatic expiry — the assignment scope is a bounded demo/evaluation
// window, not a production deployment with a real retention policy. A real
// deployment should replace this with an explicit policy, for example a
// MongoDB TTL index such as:
//   auditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 180 });

const auditLogSchema = new mongoose.Schema(
  {
    actorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },

    // Captured at write time (not populated later) so the record still
    // makes sense even if the actor account is later deleted.
    actorRole: {
      type: String,
      enum: ['user', 'admin', 'anonymous'],
      default: 'anonymous',
    },

    action: {
      type: String,
      required: true,
      maxlength: 80,
    },

    targetType: {
      type: String,
      default: null,
      maxlength: 40,
    },

    targetId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
    },

    outcome: {
      type: String,
      enum: ['success', 'failure'],
      required: true,
    },

    requestId: {
      type: String,
      default: null,
    },

    // Minimal, deliberately-safe extra context only, e.g. { reason:
    // 'invalid_totp' }. Never passwords, tokens, keys, or note/user content
    // — enforced by convention in auditService.recordAuditEvent, which is
    // the only supported way to write this collection.
    context: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  },
);

auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ actorId: 1, createdAt: -1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
