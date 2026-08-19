function createMockAuth(userId, role = 'user') {
  return function mockAuth(req, res, next) {
    req.user = {
      id: userId,
      role,
    };

    return next();
  };
}

module.exports = {
  createMockAuth,
};