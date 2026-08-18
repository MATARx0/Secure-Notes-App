const express = require('express');
const mongoose = require('mongoose');
const request = require('supertest');

const Note = require('../../src/models/Note');
const { encrypt } = require('../../src/utils/encryption');
const {
  getMyNotes,
  getNoteById,
} = require('../../src/controllers/noteController');
const { validateNoteId } = require('../../src/middleware/validateNote');
const { createMockAuth } = require('../helpers/mockAuth');
const errorHandler = require('../../src/middleware/errorHandler');
const {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
} = require('../setup/testDb');

const TEST_KEY = 'a'.repeat(64);

let userA;
let userB;

function buildTestApp(userId) {
  const app = express();

  app.use(express.json());

  app.get('/api/notes', createMockAuth(userId), getMyNotes);

  app.get(
    '/api/notes/:id',
    createMockAuth(userId),
    validateNoteId,
    getNoteById,
  );

  app.use(errorHandler);

  return app;
}

async function createEncryptedNote({ owner, title, content }) {
  const encrypted = encrypt(content);

  return Note.create({
    owner,
    title,
    encryptedContent: encrypted.encryptedContent,
    iv: encrypted.iv,
    authTag: encrypted.authTag,
  });
}

beforeAll(async () => {
  process.env.ENCRYPTION_KEY = TEST_KEY;

  await startTestDatabase();

  userA = new mongoose.Types.ObjectId();
  userB = new mongoose.Types.ObjectId();
}, 30000);

afterEach(async () => {
  await clearTestDatabase();
});

afterAll(async () => {
  delete process.env.ENCRYPTION_KEY;
  await stopTestDatabase();
});

describe('GET /api/notes', () => {
  test('returns only notes owned by the authenticated user', async () => {
    await createEncryptedNote({
      owner: userA,
      title: 'User A Note',
      content: 'Private content A',
    });

    await createEncryptedNote({
      owner: userB,
      title: 'User B Note',
      content: 'Private content B',
    });

    const app = buildTestApp(userA);
    const response = await request(app).get('/api/notes');

    expect(response.status).toBe(200);
    expect(response.body.data.notes).toHaveLength(1);
    expect(response.body.data.notes[0].title).toBe('User A Note');
  });
});

describe('GET /api/notes/:id', () => {
  test('returns and decrypts a note owned by the authenticated user', async () => {
    const note = await createEncryptedNote({
      owner: userA,
      title: 'Secret Note',
      content: 'Very private information',
    });

    const app = buildTestApp(userA);
    const response = await request(app).get(`/api/notes/${note._id}`);

    expect(response.status).toBe(200);
    expect(response.body.data.note.title).toBe('Secret Note');
    expect(response.body.data.note.content).toBe('Very private information');
  });

  test('prevents User B from reading User A note', async () => {
    const userANote = await createEncryptedNote({
      owner: userA,
      title: 'User A Secret',
      content: 'User A private data',
    });

    const app = buildTestApp(userB);
    const response = await request(app).get(`/api/notes/${userANote._id}`);

    expect(response.status).toBe(404);
    expect(response.body.success).toBe(false);
    expect(response.body.error.code).toBe('NOTE_NOT_FOUND');
    expect(JSON.stringify(response.body)).not.toContain('User A private data');
  });

  test('rejects an invalid note ObjectId', async () => {
    const app = buildTestApp(userA);
    const response = await request(app).get('/api/notes/not-a-valid-object-id');

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('INVALID_NOTE_ID');
  });
});

