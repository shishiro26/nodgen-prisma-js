import express from "express";
const router = express.Router();
import {
  login,
  logout,
  updatePassword,
  register,
  userInfo,
  refreshToken,
  updateImage,
} from "../controllers/User.controllers.js";
import multer from "multer";
import { verifyAccessToken } from "../utils/GenerateToken.js";

const storage = multer.memoryStorage();
const upload = multer({ storage });

router.post("/register", register);
router.post("/login", login);
router.post("/refresh-token", refreshToken);
router.post("/logout", logout);
router.patch("/updatePwd", verifyAccessToken, updatePassword);
router.get("/userInfo", verifyAccessToken, userInfo);
router.patch(
  "/updateImage",
  upload.single("image"),
  verifyAccessToken,
  updateImage
);

export default router;
