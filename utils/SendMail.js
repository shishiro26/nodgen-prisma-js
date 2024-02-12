import nodemailer from "nodemailer";
import {
  REGISTRATION_TEMPLATES,
  RESEND_OTP,
  RESET_PASSWORD,
} from "../mail/templates.js";

const getTemplate = (template) => {
  switch (template) {
    case "registration":
      return REGISTRATION_TEMPLATES;
    case "passwordReset":
      return RESET_PASSWORD;
    case "resendOTP":
      return RESEND_OTP;
    default:
      throw new Error("Invalid template type");
  }
};

export const sendMailer = async (email, otp, Username, template) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.HOST,
      service: "gmail",
      auth: {
        user: process.env.USER,
        pass: process.env.PASS,
      },
    });

    const projectName = process.env.PROJECT_NAME || "The Project Name";
    const { subject, text, html } = getTemplate(template);
    const subjectString =
      typeof subject === "function" ? subject(projectName) : subject;
    const textString = text(Username, projectName, otp);
    const htmlString = html(Username, projectName, otp);

    const mailOptions = {
      from: `'${projectName} ||  <${process.env.USER}>`,
      to: email,
      subject: subjectString,
      text: textString,
      html: htmlString,
    };

    await transporter.sendMail(mailOptions);
    console.log("Email sent successfully!📩");
  } catch (error) {
    console.log("👎Email not sent!");
    console.log(error);
    return error;
  }
};
