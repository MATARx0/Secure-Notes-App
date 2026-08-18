const Note = require('../models/Note');
const {
  encrypt,
  decrypt,
} = require('../utils/encryption');

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
      _id: req.params.id,
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
module.exports = {
  createNote,
  getMyNotes,
  getNoteById,
};