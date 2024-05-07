const jwt = require("jsonwebtoken");
const catchAsync = require("../util/catchAsync");
const User = require("../models/user");
const AppError = require("../util/appError");

exports.protect = catchAsync(async (req, res, next) => {
  // * get token from cookies
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  // * check if token is present
  if (!token) {
    return next(new AppError("Unauthorized Request", 401));
  }

  // * verify token
  const decoded = jwt.verify(token, process.env.JWT_ACCESS_KEY);

  // * check if user still exists
  const currentUser = await User.findById(decoded.id);

  if (!currentUser) {
    return next(new AppError("User no longer exists", 401));
  }

  // * 4) check if user changed password after the token was issued
  if (currentUser.isPasswordChangedAfterTokenIssued(decoded.iat)) {
    return next(new AppError("User recently changed password", 401));
  }

  // * grant access to protected route
  req.user = currentUser;
  next();
});
