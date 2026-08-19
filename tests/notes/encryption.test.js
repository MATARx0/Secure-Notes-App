const {
  encrypt,
  decrypt,
} = require('../../src/utils/encryption');

const TEST_KEY = 'a'.repeat(64);

beforeEach(() => {
  process.env.ENCRYPTION_KEY = TEST_KEY;
});

afterAll(() => {
  delete process.env.ENCRYPTION_KEY;
});

describe('AES-256-GCM encryption utility', () => {
  test('encrypts plaintext and does not return plaintext as ciphertext', () => {
    const plaintext = 'My very secret note';

    const result = encrypt(plaintext);

    expect(result.encryptedContent).toBeDefined();
    expect(result.iv).toBeDefined();
    expect(result.authTag).toBeDefined();

    expect(result.encryptedContent).not.toBe(plaintext);
  });

  test('decrypts encrypted content back to the original plaintext', () => {
    const plaintext = 'Cybersecurity notes are secret';

    const encrypted = encrypt(plaintext);

    const decrypted = decrypt(encrypted);

    expect(decrypted).toBe(plaintext);
  });

  test('uses a different IV for each encryption operation', () => {
    const plaintext = 'Same note';

    const first = encrypt(plaintext);
    const second = encrypt(plaintext);

    expect(first.iv).not.toBe(second.iv);
    expect(first.encryptedContent).not.toBe(
      second.encryptedContent,
    );
  });

  test('rejects tampered ciphertext', () => {
    const encrypted = encrypt(
      'This message must remain authentic',
    );

    const tamperedBuffer = Buffer.from(
      encrypted.encryptedContent,
      'hex',
    );

    tamperedBuffer[0] ^= 0xff;

    const tamperedData = {
      ...encrypted,
      encryptedContent: tamperedBuffer.toString('hex'),
    };

    expect(() => decrypt(tamperedData)).toThrow();
  });
});