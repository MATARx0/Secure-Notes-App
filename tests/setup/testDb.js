const mongoose = require('mongoose');

// Test database lifecycle, with two interchangeable backends.
//
// Default: mongodb-memory-server spins up a throwaway MongoDB. Nothing to
// install, but the FIRST run downloads a ~80 MB mongod binary from
// fastdl.mongodb.org and caches it under ~/.cache/mongodb-binaries.
//
// Alternative: set TEST_MONGO_URI to point at a MongoDB that is already
// running, and the download never happens at all. This exists because the
// download host is unreachable from a surprising number of environments —
// locked-down corporate networks, offline machines, and container sandboxes
// with an egress allow-list all fail on it, and the failure looks like 95
// broken tests rather than one blocked hostname:
//
//   Download failed for url "https://fastdl.mongodb.org/..." Status Code is 403
//
// Any MongoDB will do — the one already installed to run the app locally, or
// a container:
//
//   TEST_MONGO_URI=mongodb://127.0.0.1:27017 npm test
//   docker run -d -p 27017:27017 mongo:7
//
// CI uses this path too (see .github/workflows/security.yml), which makes the
// pipeline independent of a third-party download host.
//
// SAFETY: the database name is forced to TEST_DB_NAME below and any database
// named in TEST_MONGO_URI is deliberately ignored, so this helper can only
// ever read, clear or drop that one database. Pointing TEST_MONGO_URI at a
// server holding real data still cannot damage anything outside it.

const TEST_DB_NAME = 'secure_notes_automated_tests';

let memoryServer;
let usingExternalServer = false;

async function startTestDatabase() {
  const externalUri = process.env.TEST_MONGO_URI;

  if (externalUri) {
    usingExternalServer = true;

    // dbName overrides whatever path the URI carries — see SAFETY above.
    await mongoose.connect(externalUri, { dbName: TEST_DB_NAME });

    // A previous run that was killed part-way (Ctrl-C, a crashed watcher)
    // can leave documents behind, and an external server does not get thrown
    // away between runs the way the in-memory one does. Start from empty.
    await mongoose.connection.dropDatabase();

    return;
  }

  usingExternalServer = false;

  // Required lazily so that a project using TEST_MONGO_URI does not need the
  // package to be installable or loadable at all.
  // eslint-disable-next-line global-require
  const { MongoMemoryServer } = require('mongodb-memory-server');

  memoryServer = await MongoMemoryServer.create();
  await mongoose.connect(memoryServer.getUri(), { dbName: TEST_DB_NAME });
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
  // An external server outlives the test run, so leaving a populated test
  // database behind would be untidy at best and would leak fixture data into
  // the next run at worst. The in-memory server is discarded wholesale, so
  // dropping there would only waste time.
  if (usingExternalServer && mongoose.connection.readyState === 1) {
    await mongoose.connection.dropDatabase();
  }

  await mongoose.disconnect();

  if (memoryServer) {
    await memoryServer.stop();
    memoryServer = undefined;
  }
}

module.exports = {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
};
