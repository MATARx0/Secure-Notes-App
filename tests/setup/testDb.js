const mongoose = require('mongoose');
const {
  MongoMemoryServer,
} = require('mongodb-memory-server');

let mongoServer;

async function startTestDatabase() {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
}

async function clearTestDatabase() {
  const collections = Object.values(
    mongoose.connection.collections,
  );

  await Promise.all(
    collections.map(
      (collection) => collection.deleteMany({}),
    ),
  );
}

async function stopTestDatabase() {
  await mongoose.disconnect();

  if (mongoServer) {
    await mongoServer.stop();
  }
}

module.exports = {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
};