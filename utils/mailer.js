// utils/mailer.js
import nodemailer from "nodemailer";
import { google } from "googleapis";

const oAuth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  process.env.GMAIL_REDIRECT_URI
);
oAuth2Client.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });

export async function sendAdminNotice(subject, html) {
  try {
    const accessToken = await oAuth2Client.getAccessToken();
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        type: "OAuth2",
        user: process.env.GMAIL_USER,
        clientId: process.env.GMAIL_CLIENT_ID,
        clientSecret: process.env.GMAIL_CLIENT_SECRET,
        refreshToken: process.env.GMAIL_REFRESH_TOKEN,
        accessToken
      }
    });

    await transporter.sendMail({
      from: `"Cross-Verified AI Notifier" <${process.env.GMAIL_USER}>`,
      to: process.env.ADMIN_EMAIL,
      subject,
      html
    });
    console.log(`📨 Admin notice sent → ${process.env.ADMIN_EMAIL}`);
  } catch (err) {
    console.error("❌ Mail send failed:", err.message);
  }
}
