const { validationResult } = require('express-validator');

// Central express-validator result handler. Every validated route ends its
// validator chain with this middleware before reaching the controller.
// Consistent HTTP 400 vs 422 split (per the team API contract, section 5.5):
//   400 - malformed request that is not a field-validation error
//   422 - field-level input validation failure
function handleValidation(req, res, next) {
  const result = validationResult(req);

  if (result.isEmpty()) {
    return next();
  }

  const details = result.array({ onlyFirstError: true }).map((item) => ({
    field: item.type === 'field' ? item.path : item.type,
    // Never echo the dangerous raw value back to the client, only the
    // field name and a safe, static message.
    message: item.msg,
  }));

  const error = new Error('Validation failed');

  error.statusCode = 422;
  error.code = 'VALIDATION_ERROR';
  error.details = details;

  return next(error);
}

// Generic allow-list body guard usable by any route that must reject
// unexpected top-level fields before a controller ever sees them.
function rejectUnknownFields(allowedFields) {
  const allowed = new Set(allowedFields);

  return function rejectUnknownFieldsMiddleware(req, res, next) {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const unexpected = Object.keys(body).filter((key) => !allowed.has(key));

    if (unexpected.length > 0) {
      const error = new Error('Validation failed');

      error.statusCode = 422;
      error.code = 'VALIDATION_ERROR';
      error.details = [
        {
          field: 'body',
          message: `Unexpected field(s): ${unexpected.join(', ')}`,
        },
      ];

      return next(error);
    }

    return next();
  };
}

module.exports = {
  handleValidation,
  rejectUnknownFields,
};
