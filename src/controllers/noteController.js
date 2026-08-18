const Note = require('../models/Note');
const { encrypt } = require('../utils/encryption');

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

module.exports = {
  createNote,
};