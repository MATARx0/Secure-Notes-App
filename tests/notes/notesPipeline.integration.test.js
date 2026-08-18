const request = require('supertest');

const app = require('../../src/app');
const Note = require('../../src/models/Note');
const {
  startTestDatabase,
  clearTestDatabase,
  stopTestDatabase,
} = require('../setup/testDb');
const { registerAndLogin, getCsrfContext } = require('../helpers/authFlow');

// Integration coverage owned by Members 1 and 3, added without modifying any
// of Member 2's existing note tests.
//
// Her tests mount noteController on a throwaway Express app with a mock
// authentication middleware, which is the right way to test note logic in
// isolation. What that approach cannot prove is that the *assembled*
// application is wired correctly: that requireAuth actually guards these
// routes, that req.user.id really is the authenticated user's id and not
// something a client can influence, and that CSRF protection is applied to
// exactly the state-changing methods. Those are the seams between the three
// members' work, so they are tested here through the real src/app.js.

beforeAll(async () => {
  await startTestDatabase();
}, 30000);

afterEach(async () => {
  await clearTestDatabase();
});

afterAll(async () => {
  await stopTestDatabase();
});

async function authedSession() {
  const { loginResponse, sessionCookieHeader } = await registerAndLogin(app);
  const { csrfToken, combinedCookieHeader } = await getCsrfContext(app, sessionCookieHeader);

  return {
    userId: loginResponse.body.data.user.id,
    sessionCookieHeader,
    csrfToken,
    combinedCookieHeader,
  };
}

function createNote(session, body) {
  return request(app)
    .post('/api/notes')
    .set('Cookie', session.combinedCookieHeader)
    .set('X-CSRF-Token', session.csrfToken)
    .send(body);
}

describe('Note routes require a real session', () => {
  const routes = [
    { method: 'get', path: '/api/notes' },
    { method: 'post', path: '/api/notes' },
    { method: 'get', path: '/api/notes/507f1f77bcf86cd799439011' },
    { method: 'put', path: '/api/notes/507f1f77bcf86cd799439011' },
    { method: 'delete', path: '/api/notes/507f1f77bcf86cd799439011' },
  ];

  test.each(routes)('$method $path is rejected with 401 when unauthenticated', async ({ method, path }) => {
    const response = await request(app)[method](path).send({});

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHENTICATED');
  });
});

describe('CSRF protection is applied to state-changing note routes only', () => {
  test('creating a note without a CSRF token is refused', async () => {
    const { sessionCookieHeader } = await registerAndLogin(app);

    const response = await request(app)
      .post('/api/notes')
      .set('Cookie', sessionCookieHeader)
      .send({ title: 'x', content: 'y' });

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('deleting a note without a CSRF token is refused', async () => {
    const { sessionCookieHeader } = await registerAndLogin(app);

    const response = await request(app)
      .delete('/api/notes/507f1f77bcf86cd799439011')
      .set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('reading notes does not require a CSRF token', async () => {
    const { sessionCookieHeader } = await registerAndLogin(app);

    const response = await request(app).get('/api/notes').set('Cookie', sessionCookieHeader);

    expect(response.status).toBe(200);
  });
});

describe('Full note lifecycle through the assembled application', () => {
  test('a note can be created, listed, read back, updated and deleted', async () => {
    const session = await authedSession();

    const created = await createNote(session, { title: 'Passport', content: 'Expires in March' });
    expect(created.status).toBe(201);
    const noteId = created.body.data.note.id;

    const listed = await request(app).get('/api/notes').set('Cookie', session.sessionCookieHeader);
    expect(listed.status).toBe(200);
    expect(listed.body.data.notes).toHaveLength(1);
    // The list projection must never carry ciphertext or crypto metadata.
    expect(Object.keys(listed.body.data.notes[0]).sort()).toEqual(
      ['createdAt', 'id', 'title', 'updatedAt'].sort(),
    );

    const fetched = await request(app)
      .get(`/api/notes/${noteId}`)
      .set('Cookie', session.sessionCookieHeader);
    expect(fetched.status).toBe(200);
    expect(fetched.body.data.note.content).toBe('Expires in March');

    const updated = await request(app)
      .put(`/api/notes/${noteId}`)
      .set('Cookie', session.combinedCookieHeader)
      .set('X-CSRF-Token', session.csrfToken)
      .send({ content: 'Expires in April' });
    expect(updated.status).toBe(200);
    expect(updated.body.data.note.content).toBe('Expires in April');

    const removed = await request(app)
      .delete(`/api/notes/${noteId}`)
      .set('Cookie', session.combinedCookieHeader)
      .set('X-CSRF-Token', session.csrfToken);
    expect(removed.status).toBe(200);
    expect(await Note.countDocuments({})).toBe(0);
  });

  test('the note is stored encrypted, and the plaintext never reaches the database', async () => {
    const session = await authedSession();
    const secret = 'my bank pin is 4821';

    await createNote(session, { title: 'Private', content: secret });

    const stored = await Note.findOne({}).lean();

    expect(stored.encryptedContent).toBeDefined();
    expect(stored.encryptedContent).not.toContain(secret);
    expect(JSON.stringify(stored)).not.toContain(secret);
  });
});

describe('Ownership is taken from the session, never from the client', () => {
  test('a client-supplied owner field cannot redirect the note to another user', async () => {
    const victim = await authedSession();
    const attacker = await authedSession();

    const created = await createNote(attacker, {
      title: 'Planted',
      content: 'should belong to the attacker',
      owner: victim.userId,
    });

    // Whether the allow-list validator rejects the extra field outright or
    // the controller simply ignores it, the one outcome that must never
    // happen is the note landing in the victim's account.
    if (created.status === 201) {
      const stored = await Note.findById(created.body.data.note.id).lean();
      expect(String(stored.owner)).toBe(attacker.userId);
    } else {
      expect(created.status).toBeGreaterThanOrEqual(400);
      expect(await Note.countDocuments({})).toBe(0);
    }

    const victimList = await request(app).get('/api/notes').set('Cookie', victim.sessionCookieHeader);
    expect(victimList.body.data.notes).toHaveLength(0);
  });

  test('one user cannot read, update or delete another user\'s note', async () => {
    const owner = await authedSession();
    const attacker = await authedSession();

    const created = await createNote(owner, { title: 'Mine', content: 'private' });
    const noteId = created.body.data.note.id;

    const read = await request(app)
      .get(`/api/notes/${noteId}`)
      .set('Cookie', attacker.sessionCookieHeader);
    expect(read.status).toBe(404);

    const update = await request(app)
      .put(`/api/notes/${noteId}`)
      .set('Cookie', attacker.combinedCookieHeader)
      .set('X-CSRF-Token', attacker.csrfToken)
      .send({ content: 'tampered' });
    expect(update.status).toBe(404);

    const remove = await request(app)
      .delete(`/api/notes/${noteId}`)
      .set('Cookie', attacker.combinedCookieHeader)
      .set('X-CSRF-Token', attacker.csrfToken);
    expect(remove.status).toBe(404);

    // A 404 rather than a 403 is intentional: telling an attacker that a
    // note exists but belongs to someone else is itself a disclosure.
    const stillThere = await request(app)
      .get(`/api/notes/${noteId}`)
      .set('Cookie', owner.sessionCookieHeader);
    expect(stillThere.status).toBe(200);
    expect(stillThere.body.data.note.content).toBe('private');
  });

  test('a revoked session can no longer reach the note endpoints', async () => {
    const session = await authedSession();

    await createNote(session, { title: 'Before logout', content: 'x' });

    const logout = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', session.combinedCookieHeader)
      .set('X-CSRF-Token', session.csrfToken);
    expect(logout.status).toBe(200);

    const afterLogout = await request(app).get('/api/notes').set('Cookie', session.sessionCookieHeader);

    expect(afterLogout.status).toBe(401);
    expect(afterLogout.body.error.code).toBe('SESSION_REVOKED');
  });
});

describe('Note actions are recorded in the audit log', () => {
  test('creating and deleting a note produces audit events an administrator can review', async () => {
    const session = await authedSession();

    const created = await createNote(session, { title: 'Audited', content: 'x' });
    await request(app)
      .delete(`/api/notes/${created.body.data.note.id}`)
      .set('Cookie', session.combinedCookieHeader)
      .set('X-CSRF-Token', session.csrfToken);

    const AuditLog = require('../../src/models/AuditLog');
    const actions = (await AuditLog.find({}).lean()).map((event) => event.action);

    expect(actions).toContain('note.create');
    expect(actions).toContain('note.delete');
  });
});
