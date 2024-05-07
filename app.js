const express = require("express");
const userRoutes = require("./routes/userRoutes");
const AppError = require("./util/AppError");
const errorContoller = require("./controllers/errorController");
const cookies = require("cookie-parser");

const app = express();

app.use(express.json());
app.use(cookies());

app.use("/users", userRoutes);

app.all("*", (req, res, next) => {
  console.log(req.originalUrl);
  next(new AppError("This route does not exist", 404));
});

app.use(errorContoller);

module.exports = app;
