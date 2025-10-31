// server.js — Cross-Verified AI Proxy (Render Compatible + Naver SMTP + Auto Fallback)
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

// ✅ Flutter Web 빌드 경로 설정
const buildPath = path.join(__dirname, "build", "web");
if (!fs.existsSync(buildPath)) {
  console.warn("⚠️ build/web not found — Serving API only.");
} else {
  console.log("✅ Serving Flutter web files from:", buildPath);
  app.use(express.static(buildPath));
}

// ✅ 기본 헬스체크
app.get("/api/ping", (req, res) => {
  res.json({
    message: "✅ Proxy active and responding",
    version: "10.6.1",
    time: new Date().toISOString(),
  });
});

// ✅ Nodemailer Transporter 생성 함수 (자동 fallback 포함)
function createTransporter(isFallback = false) {
  const port = isFallback ? 587 : (process.env.SMTP_PORT || 465);
  const secure = isFallback ? false : (process.env.SMTP_SECURE === "true");

  console.log(`📡 Creating transporter: ${isFallback ? "TLS (587)" : "SSL (465)"}`);

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || "smtp.naver.com",
    port,
    secure,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: { rejectUnauthorized: false },
    connectionTimeout: 10000, // 10초 타임아웃
  });
}

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
    const transporter = createTransporter(false);
    await transporter.sendMail(mailOptions);
    console.log("✅ Email sent successfully (SSL 465) →", to);
  } catch (err) {
    console.error("⚠️ SSL 465 failed:", err.message);
    console.log("🔁 Retrying with TLS 587...");
    try {
      const fallbackTransporter = createTransporter(true);
      await fallbackTransporter.sendMail(mailOptions);
      console.log("✅ Email sent successfully (TLS 587) →", to);
    } catch (fallbackErr) {
      console.error("❌ Email send failed (TLS 587):", fallbackErr.message);
      throw fallbackErr;
    }
  }
}

// ✅ 이메일 테스트용 엔드포인트
app.get("/api/test-email", async (req, res) => {
  try {
    await sendAlertEmail(
      "📬 Cross-Verified AI Email Test",
      `✅ Test email sent successfully at ${new Date().toLocaleString()}`
    );
    res.json({ success: true, message: "✅ Test email sent successfully." });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "❌ Email send failed",
      error: err.message,
    });
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

// ✅ Render 호환: 반드시 0.0.0.0으로 바인딩
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
