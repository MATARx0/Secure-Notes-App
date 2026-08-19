const express = require('express');
const mongoose = require('mongoose');
const request = require('supertest');

const Note = require('../../src/models/Note');
const { decrypt } = require('../../src/utils/encryption');
const { createNote } = require('../../src/controllers/noteController');
const { validateCreateNote } = require('../../src/middleware/validateNote');
const { createMockAuth } = require('../helpers/mockAuth');
const errorHandler = require('../../src/middleware/errorHandler');
const {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
} = require('../setup/testDb');

const TEST_KEY = 'a'.repeat(64);

describe('POST /api/notes', () => {
  let app;
  let testUserId;

  beforeAll(async () => {
    process.env.ENCRYPTION_KEY = TEST_KEY;

    await startTestDatabase();

    testUserId = new mongoose.Types.ObjectId();

    app = express();
    app.use(express.json());

    app.post(
      '/api/notes',
      createMockAuth(testUserId),
      validateCreateNote,
      createNote,
    );

    app.use(errorHandler);
  }, 30000);

  beforeEach(async () => {
    await clearTestDatabase();
  });

  afterAll(async () => {
    delete process.env.ENCRYPTION_KEY;
    await stopTestDatabase();
  });

  test('creates a note and stores its content encrypted', async () => {
    const plaintext = 'This is my secret cybersecurity note';

    const response = await request(app)
      .post('/api/notes')
      .send({
        title: 'University',
        content: plaintext,
      });

    expect(response.status).toBe(201);
    expect(response.body.success).toBe(true);
    expect(response.body.data.note.title).toBe('University');

    const storedNote = await Note.findOne({
      owner: testUserId,
    });

    expect(storedNote).not.toBeNull();
    expect(storedNote.encryptedContent).not.toBe(plaintext);
    expect(storedNote.iv).toBeDefined();
    expect(storedNote.authTag).toBeDefined();

    const decryptedContent = decrypt({
      encryptedContent: storedNote.encryptedContent,
      iv: storedNote.iv,
      authTag: storedNote.authTag,
    });

    expect(decryptedContent).toBe(plaintext);
  });

  test('rejects a note with an empty title', async () => {
    const response = await request(app)
      .post('/api/notes')
      .send({
        title: '   ',
        content: 'Valid content',
      });

    expect(response.status).toBe(422);
    expect(response.body.success).toBe(false);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('rejects a note with empty content', async () => {
    const response = await request(app)
      .post('/api/notes')
      .send({
        title: 'Valid title',
        content: '',
      });

    expect(response.status).toBe(422);
    expect(response.body.success).toBe(false);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('rejects a non-string title', async () => {
    const response = await request(app)
      .post('/api/notes')
      .send({
        title: { $ne: null },
        content: 'Valid content',
      });

    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('rejects unexpected note fields', async () => {
    const response = await request(app)
      .post('/api/notes')
      .send({
        title: 'Normal title',
        content: 'Normal content',
        owner: new mongoose.Types.ObjectId().toString(),
      });

    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');

    const noteCount = await Note.countDocuments();

    expect(noteCount).toBe(0);
  });
});