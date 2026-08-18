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

    let transactionSucceeded = false;

    try {
      const session = await mongoose.startSession();

      try {
        await session.withTransaction(async () => {
          await Note.deleteMany({ owner: target._id }, { session });
          await User.deleteOne({ _id: target._id }, { session });
        });

        transactionSucceeded = true;
      } finally {
        await session.endSession();
      }
    } catch (transactionError) {
      const message = String((transactionError && transactionError.message) || '');
      const transactionsUnsupported = /Transaction numbers|replica set|mongos/i.test(message);

      if (!transactionsUnsupported) {
        throw transactionError;
      }

      // Documented fallback (Member 3 Phase 10 / Phase 15): a standalone
      // MongoDB instance (no replica set) cannot run multi-document
      // transactions. When that is detected, fall back to sequential
      // deletes. Residual risk: a crash between the two operations could
      // leave orphaned notes; acceptable for this course deployment and
      // recommended to revisit if deployed against a replica set, which
      // MongoDB Atlas provides by default.
    }

    if (!transactionSucceeded) {
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
