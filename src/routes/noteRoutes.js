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
// Known open item (tracked in the API contract, Table 10, jointly owned by
// Members 2 & 3): the contract's target convention is `:noteId`, but
// noteController.js and validateNote.js currently read `req.params.id`.
// Renaming the param here without updating those two files would break
// them, so this route intentionally keeps `:id` until that small joint PR
// lands — see README "Known limitations".

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
  '/:id',
  validateNoteId,
  noteController.getNoteById,
);

router.put(
  '/:id',
  verifyCsrfToken,
  validateNoteId,
  validateUpdateNote,
  noteController.updateNote,
);

router.delete(
  '/:id',
  verifyCsrfToken,
  validateNoteId,
  noteController.deleteNote,
);

module.exports = router;
