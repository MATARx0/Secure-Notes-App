const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;

function getEncryptionKey() {
  const encodedKey = process.env.ENCRYPTION_KEY;

  if (!encodedKey) {
    throw new Error('ENCRYPTION_KEY is not configured');
  }

  if (!/^[0-9a-fA-F]{64}$/.test(encodedKey)) {
    throw new Error(
      'ENCRYPTION_KEY must be 32 bytes encoded as 64 hexadecimal characters',
    );
  }

  return Buffer.from(encodedKey, 'hex');
}

function encrypt(plaintext) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('Plaintext must be a string');
  }

  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(
    ALGORITHM,
    key,
    iv,
  );

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return {
    encryptedContent: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
}

function decrypt({
  encryptedContent,
  iv,
  authTag,
}) {
  const key = getEncryptionKey();

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, 'hex'),
  );

  decipher.setAuthTag(
    Buffer.from(authTag, 'hex'),
  );

  const decrypted = Buffer.concat([
    decipher.update(
      Buffer.from(encryptedContent, 'hex'),
    ),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

module.exports = {
  encrypt,
  decrypt,
};