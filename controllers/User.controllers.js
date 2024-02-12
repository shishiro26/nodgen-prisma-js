import bcrypt from "bcrypt";
import otpGenerator from "otp-generator";
import { sendMailer } from "../utils/SendMail.js";
import {
  AccessToken,
  RefreshToken,
  verifyRefreshToken,
} from "../utils/GenerateToken.js";
import { db } from "../prisma/index.js";

export const register = async (req, res) => {
  try {
    const { Username, email, password } = req.body;
    const duplicate = await db.user.findFirst({
      where: {
        OR: [{ email }, { Username }],
      },
    });

    if (duplicate) {
      if (duplicate.Username === Username) {
        return res.status(409).json({
          message: "Username taken. Try signing up with a different username",
        });
      }
      if (duplicate.email === email) {
        return res.status(409).json({
          message:
            "User already exists. Try signing up with a different email.",
        });
      }
    }

    const salt = await bcrypt.genSalt();
    const hashedPwd = await bcrypt.hash(password, salt);

    const otp = await otpGenerator.generate(6, {
      digits: true,
      specialChars: false,
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
    });

    const user = await db.user.create({
      data: {
        Username,
        email,
        password: hashedPwd,
        image: `https://api.dicebear.com/5.x/initials/svg?seed=${Username}`,
        isVerified: false,
      },
    });

    if (!user) {
      throw new Error("Failed to create user");
    }

    const otpExpirationMinutes = 2;
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + otpExpirationMinutes);

    await db.oTP.create({
      data: {
        email,
        otp,
        expiresAt: expiresAt,
      },
    });
    sendMailer(email, otp, user.Username, "registration");
    const accessToken = await AccessToken(user.id);
    const refreshToken = await RefreshToken(user.id);

    res.cookie("AccessToken", accessToken, {
      secure: true,
      sameSite: "strict",
      maxAge: 20 * 60 * 1000,
    });
    res.cookie("RefreshToken", refreshToken, {
      secure: true,
      sameSite: "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.status(201).json({
      message:
        "User registered successfully. Please verify your email to login. OTP sent to your email.",
    });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

/* logging in the user */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.user.findUnique({ where: { email } });

    if (!user) {
      throw new Error("User not found");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new Error("Invalid credentials");
    }

    const accessToken = await AccessToken(user.id);
    const refreshToken = await RefreshToken(user.id);

    res.cookie("AccessToken", accessToken, {
      secure: true,
      sameSite: "strict",
      maxAge: 20 * 60 * 1000,
    });
    res.cookie("RefreshToken", refreshToken, {
      secure: true,
      sameSite: "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      message: "Logged in successfully",
    });
  } catch (err) {
    console.error(err);
    let errorMessage = "Internal server error. Please try again later.";
    if (err.message === "User not found") {
      res.status(404);
      errorMessage = "User not found";
    } else if (err.message === "Invalid credentials") {
      res.status(401);
      errorMessage = "Invalid credentials";
    }
    res.json({ error: errorMessage });
  }
};

export const updatePassword = async (req, res) => {
  try {
    const id = req?.payload.aud;
    const { oldPassword, newPassword } = req.body;

    const userDetails = await db.user.findUnique({ where: { id } });

    if (!userDetails) {
      throw new Error("User not found");
    }

    if (!userDetails.isVerified) {
      throw new Error("User is not verified");
    }
    const salt = await bcrypt.genSalt();

    const isPasswordMatch = bcrypt.compareSync(
      oldPassword,
      userDetails.password
    );

    if (!isPasswordMatch) {
      throw new Error("Invalid old password");
    }

    const hashedPwd = await bcrypt.hash(newPassword, salt);

    await db.user.update({
      where: { id },
      data: { password: hashedPwd },
    });

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error(error);
    let errorMessage = "Internal server error. Please try again later.";
    if (error.message === "User not found") {
      res.status(404);
      errorMessage = "User not found";
    } else if (error.message === "User is not verified") {
      res.status(401);
      errorMessage = "User is not verified";
    } else if (error.message === "New passwords do not match") {
      res.status(400);
      errorMessage = "New passwords do not match";
    } else if (error.message === "Invalid old password") {
      res.status(401);
      errorMessage = "Invalid old password";
    }
    res.json({ error: errorMessage });
  }
};

/*Updating the image*/
export const updateImage = async (req, res) => {
  try {
    const id = req?.payload.aud;

    const user = await db.user.findUnique({ where: { id } });

    if (!user) {
      throw new Error("User not found");
    }

    if (!user.isVerified) {
      throw new Error("User is not verified");
    }

    if (!req?.file) {
      throw new Error("No image file provided");
    }

    const base64Image = req?.file?.buffer.toString("base64");

    await db.user.update({
      where: { id },
      data: { image: base64Image },
    });

    res.status(200).json({ message: "Image updated successfully" });
  } catch (err) {
    console.error(err);
    let errorMessage = "Internal server error. Please try again later.";
    if (err.message === "Invalid user ID format") {
      res.status(400);
      errorMessage = "Invalid user ID format";
    } else if (err.message === "User not found") {
      res.status(404);
      errorMessage = "User not found";
    } else if (err.message === "User is not verified") {
      res.status(401);
      errorMessage = "User is not verified";
    } else if (err.message === "No image file provided") {
      res.status(400);
      errorMessage = "No image file provided";
    }
    res.json({ error: errorMessage });
  }
};

/* Logout the user */
export const logout = (req, res) => {
  res.cookie("AccessToken", "", {
    httpOnly: true,
    expires: new Date(0),
  });
  res.cookie("RefreshToken", "", {
    httpOnly: true,
    expires: new Date(0),
  });
  res.status(200).json({ message: "user logged out successfully" });
};

/* Get the user Info */
export const userInfo = async (req, res) => {
  try {
    const id = req?.payload.aud;

    const user = await db.user.findUnique({ where: { id } });

    if (!user) {
      throw new Error("User not found");
    }

    if (!user.isVerified) {
      throw new Error("User is not verified");
    }

    res.status(200).json({ data: user });
  } catch (error) {
    console.error(error);
    let errorMessage = "Internal server error. Please try again later.";
    if (error.message === "Invalid user ID format") {
      res.status(400);
      errorMessage = "Invalid user ID format";
    } else if (error.message === "Invalid access token") {
      res.status(401);
      errorMessage = "Invalid access token";
    } else if (error.message === "User not found") {
      res.status(404);
      errorMessage = "User not found";
    } else if (error.message === "User is not verified") {
      res.status(401);
      errorMessage = "User is not verified";
    }
    res.json({ error: errorMessage });
  }
};

export const refreshToken = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.RefreshToken;
    if (!refreshToken) {
      throw new Error("Refresh token not found");
    }
    const userId = await verifyRefreshToken(refreshToken);
    const accessToken = await AccessToken(userId);
    const refToken = await RefreshToken(userId);

    res.cookie("AccessToken", accessToken, {
      secure: true,
      httpOnly: true,
      sameSite: "strict",
      maxAge: 20 * 60 * 1000,
    });

    res.cookie("RefreshToken", refToken, {
      secure: true,
      httpOnly: true,
      sameSite: "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({ accessToken: accessToken, refreshToken: refToken });
  } catch (error) {
    next(error);
  }
};
