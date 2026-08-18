const express = require('express');
const { param, query, body } = require('express-validator');

const adminController = require('../controllers/adminController');
const requireAuth = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { verifyCsrfToken } = require('../middleware/csrfProtection');
const { handleValidation, rejectUnknownFields } = require('../middleware/validate');

const router = express.Router();

const paginationValidators = [
  query('page').optional().isInt({ min: 1 }).withMessage('page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 50 }).withMessage('limit must be between 1 and 50'),
];

// Every route below requires an authenticated administrator. Role comes
// exclusively from req.user.role, set by requireAuth from the verified
// session — never from the request body, query string, or client state.
router.use(requireAuth, requireRole('admin'));

router.get(
  '/users',
  paginationValidators,
  handleValidation,
  adminController.listUsers,
);

router.delete(
  '/users/:userId',
  verifyCsrfToken,
  param('userId').isMongoId().withMessage('userId must be a valid identifier'),
  handleValidation,
  adminController.deleteUser,
);

router.patch(
  '/users/:userId/status',
  verifyCsrfToken,
  param('userId').isMongoId().withMessage('userId must be a valid identifier'),
  rejectUnknownFields(['status']),
  body('status').isIn(['enabled', 'disabled']).withMessage('status must be "enabled" or "disabled"'),
  handleValidation,
  adminController.updateUserStatus,
);

router.get(
  '/audit-logs',
  paginationValidators,
  handleValidation,
  adminController.listAuditLogs,
);

module.exports = router;
