const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema(
  {
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
      ref: 'User',
    },

    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120,
    },

    encryptedContent: {
      type: String,
      required: true,
    },

    iv: {
      type: String,
      required: true,
    },

    authTag: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  },
);

const Note = mongoose.model('Note', noteSchema);

module.exports = Note;