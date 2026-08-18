function validateCreateNote(req, res, next) {
  const errors = [];

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

module.exports = {
  validateCreateNote,
};