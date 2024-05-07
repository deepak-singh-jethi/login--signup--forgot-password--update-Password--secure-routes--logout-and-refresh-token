errorContoller = (error, req, res, next) => {
  res.status(error.statusCode || 500);
  res.json({
    error: {
      message: error.message,
      stack: error.stack,
      error: error,
    },
  });
};

module.exports = errorContoller;
