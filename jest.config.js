module.exports = {
  testEnvironment: 'node',
  setupFiles: ['<rootDir>/tests/setup/env.js'],
  clearMocks: true,
  restoreMocks: true,
  collectCoverageFrom: [
    'server.js',
    'src/**/*.js',
    '!src/routes/*.js',
  ],
};