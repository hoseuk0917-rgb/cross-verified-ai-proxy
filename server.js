// server.js — Cross-Verified AI Proxy (Gmail API Direct Send + HTML Template)
import express from "express";
import { google } from "googleapis";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { Buffer } from "buffer";

// ⬇️ 경로 설정
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Flutter Web 빌드 폴더 확인
const buildPath = path.join(__dirname, "build", "web");
if (fs.existsSync(buildPath)) {
  app.use(express.static(buildPath));
  console.log("✅ Serving Flutter web files from:", buildPath);
} else {
  console.warn("⚠️  Warning: build/web not found. Serving API only.");
}

// ✅ 기본 헬스체크
app.get("/api/ping", (req, res) => {
  res.json({
    status: "ok",
    version: "11.0.0",
    time: new Date().toISOString(),
  });
});

// ✅ Gmail OAuth2 설정
const oauth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  "https://developers.google.com/oauthplayground"
);
oauth2Client.setCredentials({
  refresh_token: process.env.GMAIL_REFRESH_TOKEN,
});

const gmail = google.gmail({ version: "v1", auth: oauth2Client });

// ✅ HTML 이메일 템플릿 생성
function generateHtmlTemplate(title, message, level = "info") {
  const color =
    level === "error" ? "#ff4c4c" :
    level === "warn" ? "#ffa726" : "#4caf50";

  return `
    <div style="font-family:'Segoe UI',sans-serif;background:#f4f4f4;padding:24px;">
      <div style="max-width:600px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 12px rgba(0,0,0,0.1);">
        <div style="background:${color};padding:16px;border-radius:10px 10px 0 0;color:white;font-size:20px;font-weight:bold;">
          ${title}
        </div>
        <div style="padding:24px;font-size:15px;color:#333;">
          <p>${message}</p>
          <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
          <p style="color:#777;font-size:13px;">Cross-Verified AI Notification System<br>${new Date().toLocaleString()}</p>
        </div>
      </div>
    </div>
  `;
}

// ✅ Gmail API 발송 함수
async function sendEmail(subject, bodyText, bodyHTML) {
  try {
    const rawMessage = [
      `From: Cross-Verified AI <${process.env.MAIL_FROM}>`,
      `To: ${process.env.MAIL_TO}`,
      `Subject: ${subject}`,
      "MIME-Version: 1.0",
      "Content-Type: text/html; charset=UTF-8",
      "",
      bodyHTML,
    ].join("\n");

    const encodedMessage = Buffer.from(rawMessage)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw: encodedMessage },
    });

    console.log(`✅ Gmail API: HTML email sent to ${process.env.MAIL_TO}`);
    return { success: true };
  } catch (err) {
    console.error("❌ Gmail API send error:", err.message);
    throw err;
  }
}

// ✅ 테스트용 엔드포인트
app.get("/api/test-email", async (req, res) => {
  try {
    const htmlBody = generateHtmlTemplate(
      "📡 Cross-Verified AI System Test",
      "✅ Gmail API direct send test email. Everything looks operational.",
      "info"
    );
    await sendEmail("Cross-Verified AI Email Test", "Gmail API HTML test", htmlBody);
    res.json({ success: true, message: "HTML Gmail API email sent successfully." });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ SPA 라우팅
app.get("*", (req, res) => {
  const indexPath = path.resolve(buildPath, "index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send("❌ index.html not found. Please build Flutter web first.");
  }
});

// ✅ Render 호환 서버 실행
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Cross-Verified AI Proxy (Gmail API mode) running on port ${PORT}`);
});
