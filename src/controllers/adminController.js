const mongoose = require('mongoose');

const User = require('../models/User');
const Note = require('../models/Note');
const AuditLog = require('../models/AuditLog');
const { recordAuditEvent } = require('../services/auditService');

const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 50;

function parsePagination(query) {
  const page = Math.max(1, Number.parseInt(query.page, 10) || 1);
  const requestedLimit = Number.parseInt(query.limit, 10) || DEFAULT_PAGE_SIZE;
  const limit = Math.min(Math.max(1, requestedLimit), MAX_PAGE_SIZE);

  return { page, limit, skip: (page - 1) * limit };
}

function notFoundError() {
  const error = new Error('User not found');

  error.statusCode = 404;
  error.code = 'USER_NOT_FOUND';

  return error;
}

// --- List users --------------------------------------------------------------

async function listUsers(req, res, next) {
  try {
    const { page, limit, skip } = parsePagination(req.query);

    const [users, total] = await Promise.all([
      User.find({})
        .select('username email role mfaEnabled status createdAt')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      User.countDocuments({}),
    ]);

    return res.status(200).json({
      success: true,
      message: 'Users retrieved successfully',
      data: {
        users: users.map((user) => ({
          id: String(user._id),
          username: user.username,
          email: user.email,
          role: user.role,
          mfaEnabled: user.mfaEnabled,
          status: user.status,
          createdAt: user.createdAt,
        })),
        page,
        limit,
        total,
      },
    });
  } catch (error) {
    return next(error);
  }
}

// --- Delete user (hard delete, with safe note cleanup) -----------------------

async function deleteUser(req, res, next) {
  try {
    const { userId } = req.params;

    if (userId === req.user.id) {
      const error = new Error('Administrators cannot delete their own account through this endpoint');

      error.statusCode = 403;
      error.code = 'SELF_ACTION_DENIED';

      return next(error);
    }

    const target = await User.findById(userId).exec();

    if (!target) {
      return next(notFoundError());
    }

    if (target.role === 'admin') {
      const otherActiveAdmins = await User.countDocuments({
        role: 'admin',
        status: 'enabled',
        _id: { $ne: target._id },
      });

      if (otherActiveAdmins === 0) {
        const error = new Error('Cannot remove the last active administrator');

        error.statusCode = 403;
        error.code = 'LAST_ADMIN_PROTECTED';

        return next(error);
      }
    }

    // Removing an account and its notes should be all-or-nothing, so the
    // preferred path is a multi-document transaction. Those require a replica
    // set or a sharded cluster; a standalone mongod — what most people run
    // locally — cannot do them at all.
    //
    // An earlier version chose whether to fall back by pattern-matching the
    // driver's error text for "Transaction numbers|replica set|mongos". That
    // was wrong. A standalone instance can refuse the attempt with wording
    // those patterns do not cover, the message is not part of any stable
    // contract, and the result was a 500 on every deletion against a
    // standalone database.
    //
    // So: attempt the transaction, and fall back to sequential deletes on ANY
    // failure. That is safe rather than lazy — both deletes are idempotent,
    // so running them after a partly-applied transaction cannot do damage,
    // and if the real cause was a genuine database fault the fallback fails
    // too and that error propagates to the 500 it deserves.
    //
    // Residual risk on the fallback path: a crash between the two deletes
    // could leave orphaned notes. Recorded per-event as `atomic` in the audit
    // entry below, and in the README's known limitations. MongoDB Atlas
    // provides a replica set by default, so a real deployment takes the
    // atomic path.
    let deletedAtomically = false;

    try {
      const session = await mongoose.startSession();

      try {
        await session.withTransaction(async () => {
          await Note.deleteMany({ owner: target._id }, { session });
          await User.deleteOne({ _id: target._id }, { session });
        });

        deletedAtomically = true;
      } finally {
        await session.endSession();
      }
    } catch {
      deletedAtomically = false;
    }

    if (!deletedAtomically) {
      // Notes first on purpose: if this half fails, the account still exists
      // and the request can simply be retried. Deleting the user first and
      // then failing would strand notes with no owner left to find them by.
      await Note.deleteMany({ owner: target._id });
      await User.deleteOne({ _id: target._id });
    }

    await recordAuditEvent({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'admin.user.delete',
      targetType: 'User',
      targetId: target._id,
      outcome: 'success',
      requestId: req.id,
      context: { atomic: deletedAtomically },
    });

    return res.status(200).json({
      success: true,
      message: 'User deleted successfully',
      data: {
        id: String(target._id),
      },
    });
  } catch (error) {
    return next(error);
  }
}

// --- Activate / deactivate user (soft, reversible) ----------------------------

async function updateUserStatus(req, res, next) {
  try {
    const { userId } = req.params;
    const { status } = req.body;

    if (userId === req.user.id && status === 'disabled') {
      const error = new Error('Administrators cannot disable their own account through this endpoint');

      error.statusCode = 403;
      error.code = 'SELF_ACTION_DENIED';

      return next(error);
    }

    const target = await User.findById(userId).exec();

    if (!target) {
      return next(notFoundError());
    }

    if (status === 'disabled' && target.role === 'admin') {
      const otherActiveAdmins = await User.countDocuments({
        role: 'admin',
        status: 'enabled',
        _id: { $ne: target._id },
      });

      if (otherActiveAdmins === 0) {
        const error = new Error('Cannot disable the last active administrator');

        error.statusCode = 403;
        error.code = 'LAST_ADMIN_PROTECTED';

        return next(error);
      }
    }

    target.status = status;

    if (status === 'disabled') {
      // Revoke every existing session for this account immediately, on top
      // of the status flag requireAuth already checks.
      target.tokenVersion += 1;
    }

    await target.save();

    await recordAuditEvent({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'admin.user.status_change',
      targetType: 'User',
      targetId: target._id,
      outcome: 'success',
      requestId: req.id,
      context: { status },
    });

    return res.status(200).json({
      success: true,
      message: 'User status updated',
      data: {
        id: String(target._id),
        status: target.status,
      },
    });
  } catch (error) {
    return next(error);
  }
}

// --- Audit log listing ---------------------------------------------------------

async function listAuditLogs(req, res, next) {
  try {
    const { page, limit, skip } = parsePagination(req.query);

    const [events, total] = await Promise.all([
      AuditLog.find({})
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      AuditLog.countDocuments({}),
    ]);

    return res.status(200).json({
      success: true,
      message: 'Audit log retrieved successfully',
      data: {
        events: events.map((event) => ({
          id: String(event._id),
          actorId: event.actorId ? String(event.actorId) : null,
          actorRole: event.actorRole,
          action: event.action,
          targetType: event.targetType,
          targetId: event.targetId ? String(event.targetId) : null,
          outcome: event.outcome,
          createdAt: event.createdAt,
        })),
        page,
        limit,
        total,
      },
    });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  listUsers,
  deleteUser,
  updateUserStatus,
  listAuditLogs,
};
