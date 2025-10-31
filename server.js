// server.js — Cross-Verified AI Proxy (Gmail API version v10.7.3)
import express from "express";
import path from "path";
import fs from "fs";
import { google } from "googleapis";
import { fileURLToPath } from "url";

// ------------------------------------------------------
// 📁 경로 설정
// ------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ------------------------------------------------------
// 🧩 환경변수 검증 (Render 배포 시 누락 방지)
// ------------------------------------------------------
console.log("🧩 [ENV CHECK] START ---------------------------");
const requiredVars = [
  "GMAIL_CLIENT_ID",
  "GMAIL_CLIENT_SECRET",
  "GMAIL_REFRESH_TOKEN",
  "MAIL_FROM",
  "MAIL_TO",
];
for (const key of requiredVars) {
  if (!process.env[key]) {
    console.warn(`⚠️ Missing environment variable: ${key}`);
  } else {
    console.log(`✅ ${key} loaded`);
  }
}
console.log("🧩 [ENV CHECK] END -----------------------------");

// ------------------------------------------------------
// 📦 Flutter Web 빌드 경로 설정
// ------------------------------------------------------
const buildPath = path.join(__dirname, "build", "web");
if (fs.existsSync(buildPath)) {
  console.log("✅ Serving Flutter web files from:", buildPath);
  app.use(express.static(buildPath));
} else {
  console.warn("⚠️ build/web not found — API mode only.");
}

// ------------------------------------------------------
// 🩺 서버 헬스체크
// ------------------------------------------------------
app.get("/api/ping", (req, res) => {
  res.json({
    message: "✅ Proxy active and responding",
    version: "10.7.3",
    time: new Date().toISOString(),
  });
});

// ------------------------------------------------------
// ✉️ Gmail API 설정
// ------------------------------------------------------
const oauth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  "https://developers.google.com/oauthplayground"
);

oauth2Client.setCredentials({
  refresh_token: process.env.GMAIL_REFRESH_TOKEN,
});

const gmail = google.gmail({ version: "v1", auth: oauth2Client });

// ------------------------------------------------------
// 📤 이메일 전송 함수
// ------------------------------------------------------
async function sendGmail(to, subject, html) {
  const encodedMessage = Buffer.from(
    `To: ${to}\r\n` +
      `Subject: ${subject}\r\n` +
      `Content-Type: text/html; charset=utf-8\r\n\r\n` +
      `${html}`
  ).toString("base64");

  try {
    await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw: encodedMessage },
    });
    console.log(`✅ Gmail API: HTML email sent to ${to}`);
    return true;
  } catch (err) {
    console.error("❌ Gmail API send error:", err.message);
    return false;
  }
}

// ------------------------------------------------------
// 🧪 테스트용 이메일 발송 엔드포인트
// ------------------------------------------------------
app.get("/api/test-email", async (req, res) => {
  const from = process.env.MAIL_FROM || "noreply@example.com";
  const to = process.env.MAIL_TO || from;
  const subject = "📬 Cross-Verified AI Gmail API Test";
  const html = `
    <h2>✅ Gmail API 테스트 성공!</h2>
    <p>이 이메일은 <b>Cross-Verified AI Proxy Server</b>에서 Gmail API를 통해 발송되었습니다.</p>
    <p><b>보낸 시각:</b> ${new Date().toLocaleString()}</p>
  `;

  const success = await sendGmail(to, subject, html);

  if (success) {
    res.json({ success: true, message: "HTML Gmail API email sent successfully." });
  } else {
    res.status(500).json({ success: false, error: "Gmail API send failed." });
  }
});

// ------------------------------------------------------
// ⚙️ SPA 라우팅 (Flutter Web index.html 반환)
// ------------------------------------------------------
app.get("*", (req, res) => {
  const indexPath = path.resolve(buildPath, "index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send("❌ index.html not found. Please build Flutter web first.");
  }
});

// ------------------------------------------------------
// 🚀 서버 실행
// ------------------------------------------------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Cross-Verified AI Proxy (Gmail API mode) running on port ${PORT}`);
});
