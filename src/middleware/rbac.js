// Role-based access control. Always mounted after requireAuth, never before.
// The allow-list of roles is fixed in server-side route code — it is never
// read from the request body, query string, headers, or any client state.
function requireRole(...allowedRoles) {
  const roles = new Set(allowedRoles);

  return function requireRoleMiddleware(req, res, next) {
    if (!req.user || !req.user.id) {
      const error = new Error('Authentication is required');

      error.statusCode = 401;
      error.code = 'UNAUTHENTICATED';

      return next(error);
    }

    if (!roles.has(req.user.role)) {
      const error = new Error('You do not have permission to perform this action');

      error.statusCode = 403;
      error.code = 'FORBIDDEN';

      return next(error);
    }

    return next();
  };
}

module.exports = {
  requireRole,
};
