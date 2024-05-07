const User = require("../models/user");
const catchAsync = require("../util/catchAsync");
const AppError = require("../util/appError");
const jwt = require("jsonwebtoken");
const generateAccessAndRefreshToken = require("../util/generateTokens");
const sendMail = require("../util/email");

// ! register middleware
exports.register = catchAsync(async (req, res, next) => {
  const newUser = req.body;
  const user = await User.create(newUser);
  res.status(201).json({ user });
});

// ! login middleware
exports.login = async (req, res, next) => {
  const { email, password } = req.body;

  // * find user
  const user = await User.findOne({ email }).select("+password");

  if (!user) {
    return next(new AppError("User does not exist with that email", 400));
  }

  // * check if password is correct
  if (!(await user.isCorrectPassword(password, user.password))) {
    return next(new AppError("Incorrect password", 400));
  }

  // * generate access and refresh token
  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id
  );

  // * filter user data before sending response to hide secret details
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("refreshToken", refreshToken, options)
    .cookie("accessToken", accessToken, options)
    .json({
      message: "Logged in successfully",
      user: loggedInUser,
      accessToken,
      refreshToken,
    });
};

// ! logout middleware
exports.logout = catchAsync(async (req, res, next) => {
  // console.log(req.user);
  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    {
      refreshToken: null,
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .clearCookie("refreshToken", options)
    .clearCookie("accessToken", options)
    .json({ message: "Logged out successfully" });
});

// ! refresh access token
exports.refreshAccessToken = catchAsync(async (req, res, next) => {
  // * get incoming refresh token from cookies or body

  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  // * check if token is present
  if (!incomingRefreshToken) {
    return next(new AppError("Unauthorized Request", 401));
  }

  // * verify token
  const decoded = jwt.verify(incomingRefreshToken, process.env.JWT_REFRESH_KEY);

  // * check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new AppError("User no longer exists", 401));
  }

  // * check if incoming refresh token is same as database referesh token

  if (currentUser.refreshToken !== incomingRefreshToken) {
    return next(new AppError("Refresh token is expired or invalid", 401));
  }

  // * generate new access token
  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    currentUser._id
  );

  // * set cookie

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("refreshToken", refreshToken, options)
    .cookie("accessToken", accessToken, options)
    .json({
      message: "Refreshed successfully",
      accessToken,
      refreshToken,
    });
});

// ! update Password middleware
exports.updatePassword = catchAsync(async (req, res, next) => {
  const { currentPassword, password, passwordConfirm } = req.body;

  // * get user with password
  const user = await User.findById(req.user.id).select("+password");

  if (!(await user.isCorrectPassword(currentPassword, user.password))) {
    return next(new AppError("Incorrect password", 400));
  }

  // * generate new access token
  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id
  );

  user.password = password;
  user.passwordConfirm = passwordConfirm;
  const updatedUser = await user.save({
    new: true,
  });

  const options = {
    httpOnly: true,
    secure: true,
  };
  res
    .status(200)
    .cookie("refreshToken", refreshToken, options)
    .cookie("accessToken", accessToken, options)
    .json({
      message: "Password updated successfully",
      updatedUser,
      accessToken,
      refreshToken,
    });
});

// !forgot password middleware

exports.forgotPassword = catchAsync(async (req, res, next) => {
  //* check if email exist on body
  const email = req.body.email;

  if (!email) {
    return next(new AppError("Please provide email", 400));
  }

  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new AppError("No user found with that email", 404));
  }

  // * generate random reset token
  const resetToken = user.createPasswordResetToken();

  // * save reset token to database
  await user.save({ validateBeforeSave: false });

  // * send reset url  to user's email

  const resetURL = `${req.protocol}://${req.get(
    "host"
  )}/users/resetPassword/${resetToken}`;

  const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

  // * implement reset password route
  try {
    await sendMail({
      email: user.email,
      subject: "Your password reset token (valid for 10 min)",
      message,
    });
    res.json({
      status: "success",
      message: "Token sent to email",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError("There was an error sending the email. Try again later!"),
      500
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  const resetToken = req.params.token;
  const { password, passwordConfirm } = req.body;

  // find user with that reset token
  const user = await User.findOne({
    passwordResetToken: resetToken,
    passwordResetExpires: { $gt: Date.now() },
  });
  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }

  // if user exist generate new access token
  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id
  );

  // update password  and new refresh token in db
  user.password = password;
  user.passwordConfirm = passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  user.refreshToken = refreshToken;
  await user.save();

  const options = {
    httpOnly: true,
    secure: true,
  };
  res
    .status(200)
    .cookie("refreshToken", refreshToken, options)
    .cookie("accessToken", accessToken, options)
    .json({
      message: "Password reset successfully",
      user,
      accessToken,
      refreshToken,
    });
});
