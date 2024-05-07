const express = require("express");
const authController = require("../controllers/authControllers");
const middleware = require("../middleware/protectMiddleware");

const router = express.Router();

router.post("/register", authController.register);
router.post("/login", authController.login);
router.get("/logout", middleware.protect, authController.logout);
router.get("/refresh", authController.refreshAccessToken);
router.post(
  "/updatePassword",
  middleware.protect,
  authController.updatePassword
);
router.post("/forgotPassword", authController.forgotPassword);
router.patch("/resetPassword/:token", authController.resetPassword);

module.exports = router;
