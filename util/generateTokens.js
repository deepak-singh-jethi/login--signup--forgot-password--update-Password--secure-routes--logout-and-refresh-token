const User = require("../models/user");

const generateAccessAndRefreshToken = async (userId) => {
  // find  user
  const user = await User.findById(userId);

  // generate access token and refresh token
  const refreshToken = await user.createRefreshToken();
  const accessToken = await user.createAccessToken();

  // save referesh token in db
  user.refreshToken = refreshToken;

  await user.save({ validateBeforeSave: false });

  return { accessToken, refreshToken };
};

module.exports = generateAccessAndRefreshToken;
