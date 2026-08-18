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

const DANGEROUS_KEY_PATTERN = /^\$|\./;

function sanitizeInPlace(value) {
  if (Array.isArray(value)) {
    value.forEach(sanitizeInPlace);
    return;
  }

  if (value === null || typeof value !== 'object') {
    return;
  }

  Object.keys(value).forEach((key) => {
    if (DANGEROUS_KEY_PATTERN.test(key)) {
      delete value[key];
      return;
    }

    sanitizeInPlace(value[key]);
  });
}

// NoSQL operator-injection mitigation. Strips any object key starting with
// "$" or containing "." so an attacker cannot smuggle a Mongo operator
// object (e.g. {"email": {"$ne": null}}) into a query filter.
//
// The two request surfaces are handled differently on purpose:
//
//   req.body  — a plain data property created by express.json(), so it can
//               simply be mutated in place.
//
//   req.query — in Express 5 this is a getter-only accessor that RE-PARSES
//               req.url on every single access and returns a brand new
//               object each time (see express/lib/request.js). Mutating the
//               object it hands back therefore changes a throwaway copy and
//               has no effect at all — a bug caught by
//               tests/security/hardening.test.js. Assigning to req.query is
//               also not an option (the property has no setter). The
//               accessor is however `configurable`, so the correct fix is to
//               parse it once, sanitise that snapshot, and redefine the
//               property as an ordinary data property. This also removes the
//               repeated re-parsing on every read.
//
// req.params is deliberately NOT handled here. This middleware is mounted at
// the application level, which runs before route matching, so req.params is
// still empty at this point; and route parameter *keys* come from the route
// patterns the team writes (":userId"), never from the client, while their
// values are always strings and can never be an operator object. Sanitising
// it here would be dead code masquerading as a control.
function stripMongoOperators(req, res, next) {
  sanitizeInPlace(req.body);

  const query = req.query;

  sanitizeInPlace(query);

  Object.defineProperty(req, 'query', {
    value: query,
    writable: true,
    enumerable: true,
    configurable: true,
  });

  return next();
}

module.exports = {
  handleValidation,
  rejectUnknownFields,
  stripMongoOperators,
};
