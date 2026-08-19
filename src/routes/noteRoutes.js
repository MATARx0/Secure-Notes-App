const express = require('express');

const noteController = require('../controllers/noteController');
const {
  validateCreateNote,
  validateUpdateNote,
  validateNoteId,
} = require('../middleware/validateNote');
const requireAuth = require('../middleware/auth');
const { verifyCsrfToken } = require('../middleware/csrfProtection');

// Integration note (agreed cross-branch step, requested directly by
// Member 2 once feature/member-1-identity and the platform CSRF/rate-limit
// middleware existed): this file was an empty router. It is wired here
// using Member 1's requireAuth and Member 3's CSRF middleware exactly as
// published in the team API contract, together with Member 2's own
// validateNote middleware and noteController — neither of which is
// modified by this file.
//
// Parameter naming (API contract, Table 10): the routes, the controller and
// the validator all use `:noteId`. This was previously `:id` on one side and
// `:noteId` in the contract, which is the kind of gap that breaks silently —
// the router defines the parameter and the controller reads it, so changing
// only one side leaves every note operation returning 404 with nothing in
// either member's test suite able to catch it. Both halves were changed
// together, with Member 2's agreement, and the full suite was run against the
// assembled application afterwards.

const router = express.Router();

router.use(requireAuth);

router.get('/', noteController.getMyNotes);

router.post(
  '/',
  verifyCsrfToken,
  validateCreateNote,
  noteController.createNote,
);

router.get(
  '/:noteId',
  validateNoteId,
  noteController.getNoteById,
);

router.put(
  '/:noteId',
  verifyCsrfToken,
  validateNoteId,
  validateUpdateNote,
  noteController.updateNote,
);

router.delete(
  '/:noteId',
  verifyCsrfToken,
  validateNoteId,
  noteController.deleteNote,
);

module.exports = router;
