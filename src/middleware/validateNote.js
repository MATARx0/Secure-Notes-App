const ALLOWED_NOTE_FIELDS = new Set(['title', 'content']);

function getUnexpectedFields(body) {
  return Object.keys(body).filter(
    (field) => !ALLOWED_NOTE_FIELDS.has(field),
  );
}

function validateCreateNote(req, res, next) {
  const errors = [];

  const unexpectedFields = getUnexpectedFields(req.body);

  if (unexpectedFields.length > 0) {
    errors.push({
      field: 'body',
      message: `Unexpected field(s): ${unexpectedFields.join(', ')}`,
    });
  }

  const { title, content } = req.body;

  if (typeof title !== 'string' || title.trim().length === 0) {
    errors.push({
      field: 'title',
      message: 'Title is required',
    });
  } else if (title.trim().length > 120) {
    errors.push({
      field: 'title',
      message: 'Title must not exceed 120 characters',
    });
  }

  if (
    typeof content !== 'string'
    || content.trim().length === 0
  ) {
    errors.push({
      field: 'content',
      message: 'Content is required',
    });
  } else if (content.length > 5000) {
    errors.push({
      field: 'content',
      message: 'Content must not exceed 5000 characters',
    });
  }

  if (errors.length > 0) {
    const error = new Error('Validation failed');

    error.statusCode = 400;
    error.code = 'VALIDATION_ERROR';
    error.details = errors;

    return next(error);
  }

  req.body.title = title.trim();

  return next();
}

function validateNoteId(req, res, next) {
  const { id } = req.params;

  const objectIdPattern =
    /^[0-9a-fA-F]{24}$/;

  if (
    typeof id !== 'string'
    || !objectIdPattern.test(id)
  ) {
    const error = new Error(
      'Invalid note identifier',
    );

    error.statusCode = 400;
    error.code = 'INVALID_NOTE_ID';

    return next(error);
  }

  return next();
}
function validateUpdateNote(req, res, next) {
  const errors = [];

  const unexpectedFields = getUnexpectedFields(req.body);

  if (unexpectedFields.length > 0) {
    errors.push({
      field: 'body',
      message: `Unexpected field(s): ${unexpectedFields.join(', ')}`,
    });
  }

  const { title, content } = req.body;

  if (title === undefined && content === undefined) {
    errors.push({
      field: 'body',
      message: 'At least one of title or content is required',
    });
  }

  if (title !== undefined) {
    if (
      typeof title !== 'string'
      || title.trim().length === 0
    ) {
      errors.push({
        field: 'title',
        message: 'Title must be a non-empty string',
      });
    } else if (title.trim().length > 120) {
      errors.push({
        field: 'title',
        message: 'Title must not exceed 120 characters',
      });
    }
  }

  if (content !== undefined) {
    if (
      typeof content !== 'string'
      || content.trim().length === 0
    ) {
      errors.push({
        field: 'content',
        message: 'Content must be a non-empty string',
      });
    } else if (content.length > 5000) {
      errors.push({
        field: 'content',
        message: 'Content must not exceed 5000 characters',
      });
    }
  }

  if (errors.length > 0) {
    const error = new Error('Validation failed');

    error.statusCode = 400;
    error.code = 'VALIDATION_ERROR';
    error.details = errors;

    return next(error);
  }

  if (title !== undefined) {
    req.body.title = title.trim();
  }

  return next();
}
module.exports = {
  validateCreateNote,
  validateUpdateNote,
  validateNoteId,
};