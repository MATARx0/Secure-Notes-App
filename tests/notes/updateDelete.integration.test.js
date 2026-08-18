const express = require('express');
const mongoose = require('mongoose');
const request = require('supertest');

const Note = require('../../src/models/Note');
const { encrypt, decrypt } = require('../../src/utils/encryption');
const {
  updateNote,
  deleteNote,
} = require('../../src/controllers/noteController');
const {
  validateUpdateNote,
  validateNoteId,
} = require('../../src/middleware/validateNote');
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

  app.put(
    '/api/notes/:id',
    createMockAuth(userId),
    validateNoteId,
    validateUpdateNote,
    updateNote,
  );

  app.delete(
    '/api/notes/:id',
    createMockAuth(userId),
    validateNoteId,
    deleteNote,
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

describe('PUT /api/notes/:id', () => {
  test('updates and re-encrypts a note owned by the user', async () => {
    const note = await createEncryptedNote({
      owner: userA,
      title: 'Old title',
      content: 'Old secret',
    });

    const oldCiphertext = note.encryptedContent;
    const oldIv = note.iv;

    const app = buildTestApp(userA);
    const response = await request(app)
      .put(`/api/notes/${note._id}`)
      .send({
        title: 'New title',
        content: 'New secret',
      });

    expect(response.status).toBe(200);
    expect(response.body.data.note.title).toBe('New title');
    expect(response.body.data.note.content).toBe('New secret');

    const updatedNote = await Note.findById(note._id);

    expect(updatedNote.encryptedContent).not.toBe('New secret');
    expect(updatedNote.encryptedContent).not.toBe(oldCiphertext);
    expect(updatedNote.iv).not.toBe(oldIv);

    const decrypted = decrypt({
      encryptedContent: updatedNote.encryptedContent,
      iv: updatedNote.iv,
      authTag: updatedNote.authTag,
    });

    expect(decrypted).toBe('New secret');
  });

  test('prevents User B from updating User A note', async () => {
    const note = await createEncryptedNote({
      owner: userA,
      title: 'User A Note',
      content: 'User A secret',
    });

    const app = buildTestApp(userB);
    const response = await request(app)
      .put(`/api/notes/${note._id}`)
      .send({
        title: 'Hacked title',
        content: 'Hacked content',
      });

    expect(response.status).toBe(404);
    expect(response.body.error.code).toBe('NOTE_NOT_FOUND');

    const unchangedNote = await Note.findById(note._id);

    expect(unchangedNote.title).toBe('User A Note');

    const originalContent = decrypt({
      encryptedContent: unchangedNote.encryptedContent,
      iv: unchangedNote.iv,
      authTag: unchangedNote.authTag,
    });

    expect(originalContent).toBe('User A secret');
  });

  test('rejects an update with no editable fields', async () => {
    const note = await createEncryptedNote({
      owner: userA,
      title: 'Existing Note',
      content: 'Existing content',
    });

    const app = buildTestApp(userA);
    const response = await request(app)
      .put(`/api/notes/${note._id}`)
      .send({});

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('rejects attempts to modify protected note fields', async () => {
    const note = await createEncryptedNote({
      owner: userA,
      title: 'Protected Note',
      content: 'Protected content',
    });

    const attackerId = new mongoose.Types.ObjectId();
    const app = buildTestApp(userA);
    const response = await request(app)
      .put(`/api/notes/${note._id}`)
      .send({
        title: 'Changed title',
        owner: attackerId.toString(),
      });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');

    const storedNote = await Note.findById(note._id);

    expect(storedNote.owner.toString()).toBe(userA.toString());
    expect(storedNote.title).toBe('Protected Note');
  });
});

describe('DELETE /api/notes/:id', () => {
  test('deletes a note owned by the user', async () => {
    const note = await createEncryptedNote({
      owner: userA,
      title: 'Delete Me',
      content: 'Temporary secret',
    });

    const app = buildTestApp(userA);
    const response = await request(app).delete(`/api/notes/${note._id}`);

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);

    const deletedNote = await Note.findById(note._id);

    expect(deletedNote).toBeNull();
  });

  test('prevents User B from deleting User A note', async () => {
    const note = await createEncryptedNote({
      owner: userA,
      title: 'Do Not Delete',
      content: 'User A data',
    });

    const app = buildTestApp(userB);
    const response = await request(app).delete(`/api/notes/${note._id}`);

    expect(response.status).toBe(404);
    expect(response.body.error.code).toBe('NOTE_NOT_FOUND');

    const existingNote = await Note.findById(note._id);

    expect(existingNote).not.toBeNull();
  });
});