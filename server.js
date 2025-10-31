// server.js — Cross-Verified AI Proxy (Render + Gmail API OAuth2)
import express from "express";
import nodemailer from "nodemailer";
import { google } from "googleapis";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

// ✅ 경로 설정
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Flutter Web 빌드 경로
const buildPath = path.join(__dirname, "build", "web");
if (!fs.existsSync(buildPath)) {
  console.warn("⚠️  Warning: build/web not found. Serving API only.");
} else {
  console.log("✅ Serving static Flutter web files from:", buildPath);
  app.use(express.static(buildPath));
}

// ✅ 기본 헬스체크 API
app.get("/api/ping", (req, res) => {
  res.json({
    message: "✅ Proxy active and responding",
    version: "10.6.1",
    time: new Date().toISOString(),
  });
});

////////////////////////////////////////////////////////////
// ✅ Gmail API 기반 Nodemailer 설정
////////////////////////////////////////////////////////////
const OAuth2 = google.auth.OAuth2;
const oauth2Client = new OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  "https://developers.google.com/oauthplayground" // Redirect URI
);

// Refresh Token 등록
oauth2Client.setCredentials({
  refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
});

// ✅ Gmail Transporter 생성 함수
async function createGmailTransporter() {
  try {
    const accessToken = await oauth2Client.getAccessToken();

    return nodemailer.createTransport({
      service: "gmail",
      auth: {
        type: "OAuth2",
        user: process.env.MAIL_FROM,
        clientId: process.env.GMAIL_CLIENT_ID,
        clientSecret: process.env.GMAIL_CLIENT_SECRET,
        refreshToken: process.env.GOOGLE_REFRESH_TOKEN,
        accessToken: accessToken.token,
      },
    });
  } catch (error) {
    console.error("❌ Gmail OAuth2 AccessToken Error:", error.message);
    throw new Error("Failed to create Gmail transporter");
  }
}

////////////////////////////////////////////////////////////
// ✅ 이메일 발송 함수
////////////////////////////////////////////////////////////
async function sendAlertEmail(subject, message) {
  const from = process.env.MAIL_FROM;
  const to = process.env.ALERT_RECEIVER || process.env.MAIL_TO;

  if (!from || !to) {
    console.error("❌ MAIL_FROM 또는 MAIL_TO 환경변수가 없습니다.");
    return;
  }

  try {
    const transporter = await createGmailTransporter();
    await transporter.sendMail({
      from: `"Cross-Verified AI" <${from}>`,
      to,
      subject: subject || "🚨 Cross-Verified AI Notification",
      text: message || "✅ This is a test alert from Cross-Verified AI Proxy.",
    });
    console.log("✅ Gmail API 이메일 발송 성공:", to);
  } catch (err) {
    console.error("❌ Gmail API 발송 실패:", err.message);
  }
}

////////////////////////////////////////////////////////////
// ✅ 테스트용 엔드포인트
////////////////////////////////////////////////////////////
app.get("/api/test-email", async (req, res) => {
  try {
    await sendAlertEmail(
      "📬 Cross-Verified AI Email Test",
      `✅ Gmail API test email sent at ${new Date().toLocaleString()}`
    );
    res.json({ success: true, message: "Gmail API test email sent successfully." });
  } catch (err) {
    console.error("❌ 테스트 이메일 발송 실패:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

////////////////////////////////////////////////////////////
// ✅ SPA 라우팅 (404 방지)
////////////////////////////////////////////////////////////
app.get("*", (req, res) => {
  const indexPath = path.resolve(buildPath, "index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send("❌ index.html not found. Please build Flutter web first.");
  }
});

////////////////////////////////////////////////////////////
// ✅ Render 호환 바인딩
////////////////////////////////////////////////////////////
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Cross-Verified AI Proxy (Gmail API Mode) running on port ${PORT}`);
});
