#!/usr/bin/env node
/* eslint-disable no-console */

// One-time, local/CI-only provisioning of the first administrator account.
// Deliberately NOT exposed as an HTTP route: the public registration
// endpoint (POST /api/auth/register) can never create an admin, and this is
// the only supported way to create one.
//
// Usage:
//   ADMIN_EMAIL=admin@example.com \
//   ADMIN_USERNAME=admin \
//   ADMIN_PASSWORD='Temp-Str0ng-Pass!' \
//   MONGO_URI=mongodb://... \
//   node scripts/createAdmin.js
//
// or simply `npm run create-admin` after populating those variables in
// your local .env (see .env.example).
//
// After running this once, remove ADMIN_PASSWORD from your shell history
// and .env file, and have the administrator change their password on
// first login (password rotation itself is a documented known limitation
// — see README "Known limitations", since a change-password endpoint is
// outside this assignment's scope).

require('dotenv').config();

const bcrypt = require('bcryptjs');

const { connectDatabase, disconnectDatabase } = require('../src/config/db');
const User = require('../src/models/User');

const BCRYPT_COST = 12;
const USERNAME_PATTERN = /^[a-zA-Z0-9_.-]{3,30}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_COMPLEXITY_PATTERN =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$/;

function fail(message) {
  console.error(`createAdmin: ${message}`);
  process.exitCode = 1;
  return false;
}

function validateInputs({ email, username, password }) {
  if (!email || !EMAIL_PATTERN.test(email)) {
    return fail('ADMIN_EMAIL is missing or not a valid email address.');
  }

  if (!username || !USERNAME_PATTERN.test(username)) {
    return fail(
      'ADMIN_USERNAME is missing or invalid (3-30 chars: letters, numbers, dots, underscores, hyphens).',
    );
  }

  if (!password || password.length < 10 || !PASSWORD_COMPLEXITY_PATTERN.test(password)) {
    return fail(
      'ADMIN_PASSWORD is missing or too weak. Use at least 10 characters with upper, lower, a number, and a symbol.',
    );
  }

  return true;
}

async function run() {
  const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const username = (process.env.ADMIN_USERNAME || '').trim();
  const password = process.env.ADMIN_PASSWORD || '';

  if (!validateInputs({ email, username, password })) {
    return;
  }

  if (!process.env.MONGO_URI) {
    fail('MONGO_URI is required.');
    return;
  }

  await connectDatabase(process.env.MONGO_URI);

  try {
    const existing = await User.findOne({
      $or: [{ email }, { username }],
    })
      .select('_id email username role')
      .lean();

    // Safe to rerun: an existing matching account is left completely
    // untouched rather than silently overwritten or re-hashed.
    if (existing) {
      console.log(
        `createAdmin: an account already exists for "${existing.email}" / "${existing.username}" — nothing was changed.`,
      );
      return;
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

    const admin = await User.create({
      username,
      email,
      passwordHash,
      role: 'admin',
    });

    // Confirms success without ever printing the password.
    console.log(
      `createAdmin: administrator account created (id: ${admin._id}, username: ${admin.username}, email: ${admin.email}).`,
    );
    console.log(
      'createAdmin: remove ADMIN_PASSWORD from your shell history and .env file now.',
    );
  } finally {
    await disconnectDatabase();
  }
}

if (require.main === module) {
  run().catch((error) => {
    console.error('createAdmin: unexpected failure:', error.message);
    process.exitCode = 1;
  });
}

module.exports = { run };
