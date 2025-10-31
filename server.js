// server.js — Cross-Verified AI Proxy (Render Compatible + Gmail API Direct Send)
import express from "express";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { google } from "googleapis";

// 경로 설정
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Flutter Web 빌드 경로
const buildPath = path.join(__dirname, "build", "web");
if (!fs.existsSync(buildPath)) {
  console.warn("⚠️  build/web not found. Serving API only.");
} else {
  console.log("✅ Serving Flutter web files from:", buildPath);
  app.use(express.static(buildPath));
}

// ✅ 기본 헬스체크 API
app.get("/api/ping", (req, res) => {
  res.json({
    message: "✅ Proxy active and responding",
    version: "10.7.0",
    time: new Date().toISOString(),
  });
});

// ✅ Gmail OAuth2 클라이언트 구성
const gmailOAuth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  "https://developers.google.com/oauthplayground"
);

gmailOAuth2Client.setCredentials({
  refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
});

// ✅ Gmail 메일 발송 함수 (직접 호출)
async function sendGmailAPI(subject, body) {
  try {
    const accessToken = await gmailOAuth2Client.getAccessToken();
    const gmail = google.gmail({ version: "v1", auth: gmailOAuth2Client });

    const message = [
      "From: Cross Verified AI <" + process.env.MAIL_FROM + ">",
      "To: " + (process.env.MAIL_TO || process.env.ALERT_RECEIVER),
      "Subject: " + subject,
      "Content-Type: text/plain; charset=utf-8",
      "",
      body,
    ].join("\n");

    const encodedMessage = Buffer.from(message)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw: encodedMessage },
    });

    console.log("✅ Gmail API test email sent successfully.");
    return true;
  } catch (err) {
    console.error("❌ Gmail API 발송 실패:", err.message);
    return false;
  }
}

// ✅ 이메일 테스트 엔드포인트
app.get("/api/test-email", async (req, res) => {
  const result = await sendGmailAPI(
    "📬 Cross-Verified AI Email Test",
    `✅ Gmail API test email sent at ${new Date().toLocaleString()}`
  );
  if (result) res.json({ success: true, message: "Gmail API test email sent successfully." });
  else res.status(500).json({ success: false, message: "Gmail API send failed" });
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
