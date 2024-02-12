import otpGenerator from "otp-generator";
import { sendMailer } from "../utils/SendMail.js";
import { db } from "../prisma/index.js";

/* Verify OTP */
export const verifyOtp = async (req, res) => {
  try {
    const { otp, email } = req.body;

    const verifyOTP = await db.oTP.findUnique({ where: { email, otp } });
    if (!verifyOTP) {
      throw new Error("Invalid OTP or Email");
    }

    const user = await db.user.update({
      where: { email },
      data: { isVerified: true },
    });
    if (!user) {
      throw new Error("User not found");
    }

    res.status(200).json({ message: "User verified successfully" });
  } catch (err) {
    console.error(err);
    if (err.message === "Invalid OTP") {
      res.status(401).json({ error: err.message });
    } else if (err.message === "User not found") {
      res.status(404).json({ error: err.message });
    } else {
      res.status(500).json({ error: "Internal server error" });
    }
  }
};

export const resendOtp = async (req, res) => {
  try {
    const id = req?.payload.aud;

    console.log(id);

    const user = await db.user.findUnique({ where: { id } });
    if (!user) {
      throw new Error("User not found");
    }

    const otp = await otpGenerator.generate(6, {
      digits: true,
      specialChars: false,
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
    });

    let email = user.email;

    const existingOtp = await db.oTP.findMany({ where: { email } });

    if (existingOtp) {
      await db.oTP.deleteMany({ where: { email } });
    }
    const expirationTime = new Date();
    expirationTime.setMinutes(expirationTime.getMinutes() + 2);

    await db.oTP.create({
      data: {
        otp,
        email,
        expiresAt: expirationTime,
      },
    });
    sendMailer(email, otp, user.Username, "resendOTP");

    res.status(200).json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error(err);
    if (err.message === "User not found") {
      res.status(404).json({ error: err.message });
    } else {
      res.status(500).json({ error: "Failed to resend OTP" });
    }
  }
};
