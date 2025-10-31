// server.js — Cross-Verified AI Proxy (Render Compatible + Naver SMTP)
import express from "express";
import nodemailer from "nodemailer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

// 경로 설정
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
    version: "10.6.0",
    time: new Date().toISOString(),
  });
});

// ✅ Nodemailer 설정 (NAVER SMTP)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.naver.com",
  port: process.env.SMTP_PORT || 465,
  secure: process.env.SMTP_SECURE === "true", // true = 465 (SSL)
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ✅ 이메일 발송 함수
async function sendAlertEmail(subject, message) {
  const from = process.env.MAIL_FROM || process.env.SMTP_USER;
  const to = process.env.ALERT_RECEIVER || process.env.MAIL_TO;

  if (!to) {
    console.error("❌ ALERT_RECEIVER or MAIL_TO not defined.");
    return;
  }

  const mailOptions = {
    from: `"Cross-Verified AI" <${from}>`,
    to,
    subject: subject || "🚨 Cross-Verified AI Notification",
    text: message || "This is a test alert from Cross-Verified AI proxy server.",
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("✅ Email alert sent successfully to:", to);
  } catch (err) {
    console.error("❌ Email send failed:", err.message);
  }
}

// ✅ 이메일 테스트 엔드포인트
app.get("/api/test-email", async (req, res) => {
  try {
    await sendAlertEmail(
      "📬 Cross-Verified AI Email Test",
      `✅ Test email sent at ${new Date().toLocaleString()}`
    );
    res.json({ success: true, message: "Test email sent successfully." });
  } catch (err) {
    console.error("❌ 이메일 발송 실패:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ SPA 라우팅 (404 방지)
app.get("*", (req, res) => {
  const indexPath = path.resolve(buildPath, "index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send("❌ index.html not found. Please build Flutter web first.");
  }
});

// ✅ Render 호환: 반드시 0.0.0.0 바인딩
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
