const Note = require('../models/Note');
const {
  encrypt,
  decrypt,
} = require('../utils/encryption');
// Small, agreed cross-branch addition (Member 3 Phase 11: "Coordinate small
// audit-service calls with Members 1 and 2 through reviewed pull
// requests") wiring the create/update/delete paths below into the shared
// audit service. No existing logic, validation, or response shape below is
// changed by this addition — see docs/STRIDE_Threat_Model.md R-01, which
// already anticipated this exact gap.
const { recordAuditEvent } = require('../services/auditService');

async function createNote(req, res, next) {
  try {
    const { title, content } = req.body;

    const encrypted = encrypt(content);

    const note = await Note.create({
      owner: req.user.id,
      title,
      encryptedContent: encrypted.encryptedContent,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
    });

    await recordAuditEvent({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'note.create',
      targetType: 'Note',
      targetId: note._id,
      outcome: 'success',
      requestId: req.id,
    });

    return res.status(201).json({
      success: true,
      message: 'Note created successfully',
      data: {
        note: {
          id: note._id,
          title: note.title,
          createdAt: note.createdAt,
          updatedAt: note.updatedAt,
        },
      },
    });
  } catch (error) {
    return next(error);
  }
 

}
async function getMyNotes(req, res, next) {
  try {
    const notes = await Note.find({
      owner: req.user.id,
    })
      .select('_id title createdAt updatedAt')
      .sort({ updatedAt: -1 });

    return res.status(200).json({
      success: true,
      message: 'Notes retrieved successfully',
      data: {
        notes: notes.map((note) => ({
          id: note._id,
          title: note.title,
          createdAt: note.createdAt,
          updatedAt: note.updatedAt,
        })),
      },
    });
  } catch (error) {
    return next(error);
  }
}
async function getNoteById(req, res, next) {
  try {
    const note = await Note.findOne({
      _id: req.params.noteId,
      owner: req.user.id,
    });

    if (!note) {
      const error = new Error('Note not found');

      error.statusCode = 404;
      error.code = 'NOTE_NOT_FOUND';

      return next(error);
    }

    const content = decrypt({
      encryptedContent: note.encryptedContent,
      iv: note.iv,
      authTag: note.authTag,
    });

    return res.status(200).json({
      success: true,
      message: 'Note retrieved successfully',
      data: {
        note: {
          id: note._id,
          title: note.title,
          content,
          createdAt: note.createdAt,
          updatedAt: note.updatedAt,
        },
      },
    });
  } catch (error) {
    return next(error);
  }
}
async function updateNote(req, res, next) {
  try {
    const updateFields = {};

    if (req.body.title !== undefined) {
      updateFields.title = req.body.title;
    }

    if (req.body.content !== undefined) {
      const encrypted = encrypt(req.body.content);

      updateFields.encryptedContent =
        encrypted.encryptedContent;

      updateFields.iv = encrypted.iv;
      updateFields.authTag = encrypted.authTag;
    }

    const note = await Note.findOneAndUpdate(
      {
        _id: req.params.noteId,
        owner: req.user.id,
      },
      
      {
        $set: updateFields,
      },

      {
        returnDocument: 'after',
        runValidators: true,
      },
    );

    if (!note) {
      const error = new Error('Note not found');

      error.statusCode = 404;
      error.code = 'NOTE_NOT_FOUND';

      return next(error);
    }

    const content = decrypt({
      encryptedContent: note.encryptedContent,
      iv: note.iv,
      authTag: note.authTag,
    });

    await recordAuditEvent({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'note.update',
      targetType: 'Note',
      targetId: note._id,
      outcome: 'success',
      requestId: req.id,
    });

    return res.status(200).json({
      success: true,
      message: 'Note updated successfully',
      data: {
        note: {
          id: note._id,
          title: note.title,
          content,
          createdAt: note.createdAt,
          updatedAt: note.updatedAt,
        },
      },
    });
  } catch (error) {
    return next(error);
  }
}
async function deleteNote(req, res, next) {
  try {
    const note = await Note.findOneAndDelete({
      _id: req.params.noteId,
      owner: req.user.id,
    });

    if (!note) {
      const error = new Error('Note not found');

      error.statusCode = 404;
      error.code = 'NOTE_NOT_FOUND';

      return next(error);
    }

    await recordAuditEvent({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'note.delete',
      targetType: 'Note',
      targetId: note._id,
      outcome: 'success',
      requestId: req.id,
    });

    return res.status(200).json({
      success: true,
      message: 'Note deleted successfully',
      data: {
        id: note._id,
      },
    });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  createNote,
  getMyNotes,
  getNoteById,
  updateNote,
  deleteNote,
};
