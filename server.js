// server.js — Cross-Verified AI Proxy (Gmail OAuth2 + HTML Mail)
import express from "express";
import nodemailer from "nodemailer";
import { google } from "googleapis";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Flutter Web 빌드 경로
const buildPath = path.join(__dirname, "build", "web");
if (fs.existsSync(buildPath)) {
  app.use(express.static(buildPath));
  console.log("✅ Serving Flutter web files from:", buildPath);
} else {
  console.warn("⚠️ build/web not found. API only mode.");
}

// ✅ 헬스체크
app.get("/api/ping", (req, res) => {
  res.json({
    message: "✅ Proxy active and responding",
    version: "10.7.0",
    time: new Date().toISOString(),
  });
});

// ✅ Gmail OAuth2 설정
const OAuth2 = google.auth.OAuth2;
const oauth2Client = new OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  "https://developers.google.com/oauthplayground"
);
oauth2Client.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });

// ✅ 이메일 발송 함수 (HTML 버전)
async function sendAlertEmail(subject, bodyText, bodyHTML) {
  const accessToken = await oauth2Client.getAccessToken();

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      type: "OAuth2",
      user: process.env.MAIL_FROM,
      clientId: process.env.GMAIL_CLIENT_ID,
      clientSecret: process.env.GMAIL_CLIENT_SECRET,
      refreshToken: process.env.GMAIL_REFRESH_TOKEN,
      accessToken: accessToken.token,
    },
  });

  const mailOptions = {
    from: `"Cross-Verified AI" <${process.env.MAIL_FROM}>`,
    to: process.env.MAIL_TO,
    subject,
    text: bodyText,
    html: bodyHTML,
  };

  await transporter.sendMail(mailOptions);
  console.log(`✅ HTML Email sent successfully to ${process.env.MAIL_TO}`);
}

// ✅ HTML 템플릿 생성 함수
function generateHtmlTemplate(title, message, level = "info") {
  const color =
    level === "error" ? "#ff4c4c" :
    level === "warn" ? "#ffa726" : "#4caf50";

  return `
    <div style="font-family: 'Segoe UI', sans-serif; background:#f4f4f4; padding:24px;">
      <div style="max-width:600px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 12px rgba(0,0,0,0.1);">
        <div style="background:${color}; padding:16px; border-radius:10px 10px 0 0; color:white; font-size:20px; font-weight:bold;">
          ${title}
        </div>
        <div style="padding:24px; font-size:15px; color:#333;">
          <p>${message}</p>
          <hr style="border:none; border-top:1px solid #eee; margin:24px 0;">
          <p style="color:#777; font-size:13px;">Cross-Verified AI Alert System<br>${new Date().toLocaleString()}</p>
        </div>
      </div>
    </div>
  `;
}

// ✅ 테스트용 엔드포인트
app.get("/api/test-email", async (req, res) => {
  try {
    const htmlBody = generateHtmlTemplate(
      "📡 Cross-Verified AI Test Email",
      "✅ This is a styled test email from the Gmail API system. Everything looks good!",
      "info"
    );

    await sendAlertEmail(
      "✅ Cross-Verified AI Email System Test",
      "This is the plain text fallback.",
      htmlBody
    );

    res.json({ success: true, message: "HTML test email sent successfully." });
  } catch (err) {
    console.error("❌ HTML email send failed:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ SPA 라우팅
app.get("*", (req, res) => {
  const indexPath = path.resolve(buildPath, "index.html");
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.status(404).send("❌ index.html not found.");
});

// ✅ Render 호환
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
