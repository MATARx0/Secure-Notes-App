# Secure Notes App

Secure Notes is a three-member Application Security project built with Node.js, Express, MongoDB, and a browser frontend served by Express.

## Current scope

This branch contains only the project foundation: repository structure, Express bootstrap, database lifecycle, route mount points, secure platform defaults, and the shared test harness.

Authentication, secure notes, and admin features are delivered through their approved feature branches.

## Requirements

- Node.js 20.19.0 or newer
- npm
- MongoDB for local runtime

## Local setup

1. Run `npm ci`.
2. Copy `.env.example` to `.env`.
3. Replace every placeholder locally.
4. Start MongoDB.
5. Run `npm run dev`.
6. Request `GET http://localhost:3000/api/health`.

Never commit `.env` or real secrets.

## Verification

```bash
npm ci
npm test
npm audit --omit=dev