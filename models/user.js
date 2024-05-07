const mongoose = require("mongoose");
const bycrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, "please provide emial"],
    unique: true,
    lowercase: true,
    validate: {
      validator: function (value) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
      },
      message: "please provide valid email",
    },
  },
  password: {
    type: String,
    required: true,
    validate: {
      validator: function (value) {
        return value.length >= 8;
      },
      message: "password must be at least 8 characters",
    },
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: true,
    validate: {
      validator: function (value) {
        return value === this.password;
      },
      message: "passwords do not match",
    },
  },
  role: {
    type: String,
    default: "user",
    enum: ["user", "admin", "super-admin"],
  },
  refreshToken: String,
  passwordResetToken: String,
  passwordResetExpires: Date,
  passwordChangedAt: Date,
});

// ! stored encrypted password in db
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  this.password = await bycrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

// ! add password change field if it changes
userSchema.pre("save", function (next) {
  if (!this.isModified("password") || this.isNew) {
    return next();
  }
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// ! check if password is changed after token issued
userSchema.methods.isPasswordChangedAfterTokenIssued = function (jwtTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return jwtTimestamp < changedTimestamp;

    // 200 < 300 => password is changed after token issued => true
    // 300 < 200 => password is changed before token issued => false
  }
  return false;
};

// ! check password is correct
userSchema.methods.isCorrectPassword = async function (
  inputPassword,
  dbPassword
) {
  const isEqual = await bycrypt.compare(inputPassword, dbPassword);
  return isEqual;
};

// ! create access token
userSchema.methods.createAccessToken = function () {
  const token = jwt.sign(
    {
      id: this._id,
      email: this.email,
    },
    process.env.JWT_ACCESS_KEY,
    {
      expiresIn: process.env.JWT_EXPIRES_IN,
    }
  );
  return token;
};

// ! create referesh token

userSchema.methods.createRefreshToken = function () {
  const token = jwt.sign(
    {
      id: this._id,
    },
    process.env.JWT_REFRESH_KEY,
    {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
    }
  );
  return token;
};

// ! create password reset token
userSchema.methods.createPasswordResetToken = function () {
  const token = jwt.sign(
    {
      id: this._id,
    },
    process.env.JWT_RESET_KEY,
    {
      expiresIn: process.env.JWT_RESET_EXPIRES_IN,
    }
  );
  // save hashed reset token in db
  this.passwordResetToken = token;
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  return token;
};

const User = mongoose.model("User", userSchema);

module.exports = User;
