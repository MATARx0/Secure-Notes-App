// Normalizes a handful of well-known non-HTTP error shapes (Mongoose,
// body-parser) into the team's standard error envelope. Returns null when
// the error does not match a known shape, so the caller falls back to the
// original generic handling below.
function normalizeKnownError(error) {
  if (error && error.name === 'CastError') {
    return {
      statusCode: 400,
      code: 'INVALID_ID',
      message: 'The provided identifier is not valid',
      details: [],
    };
  }

  if (error && (error.code === 11000 || error.code === 11001)) {
    const duplicatedField = error.keyValue
      ? Object.keys(error.keyValue)[0]
      : 'value';

    return {
      statusCode: 409,
      code: 'DUPLICATE_KEY',
      message: `${duplicatedField} is already registered`,
      details: [],
    };
  }

  if (error && error.type === 'entity.parse.failed') {
    return {
      statusCode: 400,
      code: 'MALFORMED_JSON',
      message: 'Request body is not valid JSON',
      details: [],
    };
  }

  if (error && error.type === 'entity.too.large') {
    return {
      statusCode: 413,
      code: 'PAYLOAD_TOO_LARGE',
      message: 'Request body is too large',
      details: [],
    };
  }

  if (error && error.name === 'ValidationError' && error.errors) {
    return {
      statusCode: 422,
      code: 'VALIDATION_ERROR',
      message: 'Validation failed',
      details: Object.keys(error.errors).map((field) => ({
        field,
        message: 'Invalid value',
      })),
    };
  }

  return null;
}

function errorHandler(error, req, res, next) {
  if (res.headersSent) {
    return next(error);
  }

  const normalized = normalizeKnownError(error);

  const candidateStatus = normalized
    ? normalized.statusCode
    : (Number.isInteger(error.statusCode) ? error.statusCode : 500);

  const statusCode =
    candidateStatus >= 400 && candidateStatus <= 599
      ? candidateStatus
      : 500;

  const isUnexpected = statusCode >= 500;

  if (isUnexpected) {
    if (process.env.NODE_ENV === 'production') {
      console.error(
        JSON.stringify({ requestId: req.id, message: 'Unexpected server error' }),
      );
    } else if (process.env.NODE_ENV !== 'test') {
      console.error(error);
    }
  }

  const code = normalized
    ? normalized.code
    : (isUnexpected ? 'INTERNAL_SERVER_ERROR' : error.code || 'REQUEST_ERROR');

  const message = normalized
    ? normalized.message
    : (isUnexpected
      ? 'An unexpected error occurred'
      : error.message || 'Request failed');

  const details = normalized
    ? normalized.details
    : (Array.isArray(error.details) ? error.details : []);

  // A request id is exposed through the X-Request-Id response header (set
  // by requestLogger) rather than the JSON body, so the standard error
  // envelope shape agreed in the API contract stays exactly {success,
  // error:{code,message,details}} with no extra fields.
  return res.status(statusCode).json({
    success: false,
    error: {
      code,
      message,
      details,
    },
  });
}

module.exports = errorHandler;
