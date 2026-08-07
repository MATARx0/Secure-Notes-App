require('dotenv').config();

const app = require('./src/app');
const {
  connectDatabase,
  disconnectDatabase,
} = require('./src/config/db');

const port = Number.parseInt(
  process.env.PORT || '3000',
  10,
);

let httpServer;
let isShuttingDown = false;

function validateStartupConfig() {
  if (
    !Number.isInteger(port)
    || port < 1
    || port > 65535
  ) {
    throw new Error(
      'PORT must be an integer between 1 and 65535',
    );
  }

  if (!process.env.MONGO_URI) {
    throw new Error('MONGO_URI is required');
  }
}

async function startServer() {
  validateStartupConfig();

  await connectDatabase(process.env.MONGO_URI);

  httpServer = app.listen(port, () => {
    console.log(
      `Secure Notes API listening on port ${port}`,
    );
  });

  return httpServer;
}

async function shutdown(reason, exitCode = 0) {
  if (isShuttingDown) return;

  isShuttingDown = true;
  console.log(`Shutting down: ${reason}`);

  try {
    if (httpServer) {
      await new Promise((resolve, reject) => {
        httpServer.close((error) => (
          error ? reject(error) : resolve()
        ));
      });
    }

    await disconnectDatabase();
  } catch {
    exitCode = 1;
    console.error('Graceful shutdown failed');
  }

  process.exit(exitCode);
}

if (require.main === module) {
  startServer().catch(() => {
    console.error('Application startup failed');
    process.exit(1);
  });

  process.once(
    'SIGINT',
    () => shutdown('SIGINT'),
  );

  process.once(
    'SIGTERM',
    () => shutdown('SIGTERM'),
  );

  process.once(
    'unhandledRejection',
    () => shutdown('unhandledRejection', 1),
  );

  process.once(
    'uncaughtException',
    () => shutdown('uncaughtException', 1),
  );
}

module.exports = {
  startServer,
  shutdown,
};