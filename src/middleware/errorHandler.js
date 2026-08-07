function errorHandler(error, req, res, next) {
  if (res.headersSent) {
    return next(error);
  }

  const candidateStatus = Number.isInteger(error.statusCode)
    ? error.statusCode
    : 500;

  const statusCode =
    candidateStatus >= 400 && candidateStatus <= 599
      ? candidateStatus
      : 500;

  const isUnexpected = statusCode >= 500;

  if (isUnexpected) {
    if (process.env.NODE_ENV === 'production') {
      console.error('Unexpected server error');
    } else {
      console.error(error);
    }
  }

  return res.status(statusCode).json({
    success: false,
    error: {
      code: isUnexpected
        ? 'INTERNAL_SERVER_ERROR'
        : error.code || 'REQUEST_ERROR',
      message: isUnexpected
        ? 'An unexpected error occurred'
        : error.message || 'Request failed',
      details: Array.isArray(error.details)
        ? error.details
        : [],
    },
  });
}

module.exports = errorHandler;