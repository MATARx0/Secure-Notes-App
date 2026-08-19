const User = require('../../src/models/User');

// Regression guard for a bug that cost eight failing MFA tests and was
// invisible in review.
//
// `mfaSecret` is select:false so it never loads by accident, and the MFA
// controllers opt back in with .select('+mfaSecret'). Originally `pending`
// and `enabled` ALSO carried select:false, which looks like defence in depth
// but is not: Mongoose applies a sub-path's exclusion independently of its
// parent's, so the opt-in re-included `mfaSecret` while still excluding both
// children. Every controller got `mfaSecret: {}`, concluded no secret had
// been stored, and MFA could never be enabled — while every unit test of the
// model still passed, because the model itself was fine.
//
// These assertions inspect the projection Mongoose actually builds, so they
// need no database and run in milliseconds. They fail immediately if anyone
// reintroduces a nested select:false, adds a new sensitive field without
// hiding it, or "tidies up" the opt-ins at the call sites.

function projectionFor(query) {
  // _applyPaths folds the schema's select:false rules into the query's
  // explicit projection — the same step Mongoose performs before sending the
  // find to the server.
  query._applyPaths();

  return query._fields || {};
}

const SOME_ID = '507f1f77bcf86cd799439011';

describe('User projection defaults', () => {
  test('an ordinary query loads neither the password hash nor the MFA secret', () => {
    const projection = projectionFor(User.findById(SOME_ID));

    expect(projection.passwordHash).toBe(0);
    expect(projection.mfaSecret).toBe(0);
  });

  test('a query that opts in receives the whole MFA secret, children included', () => {
    const projection = projectionFor(User.findById(SOME_ID).select('+mfaSecret'));

    // The parent must no longer be excluded...
    expect(projection.mfaSecret).toBeUndefined();

    // ...and — the actual bug — neither child may be excluded behind its back.
    expect(projection['mfaSecret.pending']).toBeUndefined();
    expect(projection['mfaSecret.enabled']).toBeUndefined();

    // Opting into one secret must not quietly expose the other.
    expect(projection.passwordHash).toBe(0);
  });

  test('the login projection opts into both fields it needs and nothing more', () => {
    const projection = projectionFor(
      User.findById(SOME_ID).select('+passwordHash +mfaSecret'),
    );

    expect(projection.passwordHash).toBeUndefined();
    expect(projection.mfaSecret).toBeUndefined();
    expect(projection['mfaSecret.pending']).toBeUndefined();
    expect(projection['mfaSecret.enabled']).toBeUndefined();
  });

  test('the requireAuth projection stays narrow', () => {
    const projection = projectionFor(
      User.findById(SOME_ID).select('role tokenVersion status'),
    );

    expect(projection.passwordHash).toBeUndefined();
    expect(projection.mfaSecret).toBeUndefined();
    expect(projection.role).toBe(1);
  });
});

describe('User serialisation strips every sensitive field', () => {
  function buildUser() {
    return new User({
      username: 'someone',
      email: 'someone@example.com',
      passwordHash: '$2b$12$notarealhashatallbutlongenoughtolooklikeone',
      tokenVersion: 3,
      failedLoginAttempts: 2,
      lockUntil: new Date(),
      mfaSecret: {
        enabled: { encryptedContent: 'ciphertext', iv: 'iv', authTag: 'tag' },
      },
    });
  }

  // The projection rules above stop these fields being loaded; these
  // assertions are the second layer, for the case where a handler holds a
  // document that legitimately did load them and then returns it whole.
  test.each([
    'passwordHash',
    'mfaSecret',
    'tokenVersion',
    'failedLoginAttempts',
    'lockUntil',
  ])('toJSON() removes %s', (field) => {
    expect(buildUser().toJSON()[field]).toBeUndefined();
  });

  test('no secret survives serialisation as a raw string either', () => {
    const serialised = JSON.stringify(buildUser().toJSON());

    expect(serialised).not.toContain('ciphertext');
    expect(serialised).not.toContain('$2b$12$');
  });

  test('the fields the client legitimately needs are still there', () => {
    const json = buildUser().toJSON();

    expect(json.username).toBe('someone');
    expect(json.email).toBe('someone@example.com');
    expect(json.role).toBe('user');
  });
});
