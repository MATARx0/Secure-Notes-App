const AuditLog = require('../models/AuditLog');

const SENSITIVE_KEY_PATTERN =
  /password|secret|token|jwt|cookie|authtag|iv$|key|qrcode|content/i;

// Defence in depth: even though every call site is expected to pass only a
// small safe context object, strip anything that looks sensitive by key
// name before it is ever written to the audit collection.
function sanitizeContext(context) {
  if (!context || typeof context !== 'object') {
    return {};
  }

  return Object.keys(context).reduce((safe, key) => {
    if (!SENSITIVE_KEY_PATTERN.test(key)) {
      safe[key] = context[key];
    }
    return safe;
  }, {});
}

// Design decision (documented, per Member 3 Phase 11): a failure to write
// an audit record must never block or fail the primary operation it is
// describing (login, note CRUD, admin action). Audit writes are therefore
// best-effort and fire-and-forget from the caller's perspective — this
// function never throws. The failure itself is still logged server-side
// (safely, without payload) so a systemic audit-write problem is visible in
// operational logs even though no single request ever sees it.
async function recordAuditEvent({
  actorId,
  actorRole,
  action,
  targetType,
  targetId,
  outcome,
  requestId,
  context,
}) {
  try {
    await AuditLog.create({
      actorId: actorId || null,
      actorRole: actorRole || 'anonymous',
      action,
      targetType: targetType || null,
      targetId: targetId || null,
      outcome,
      requestId: requestId || null,
      context: sanitizeContext(context),
    });
  } catch (error) {
    if (process.env.NODE_ENV !== 'test') {
      console.error(
        JSON.stringify({
          message: 'Failed to record audit event',
          action,
          error: error.message,
        }),
      );
    }
  }
}

module.exports = {
  recordAuditEvent,
};
