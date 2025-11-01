// server.js — Cross-Verified AI Proxy (Render + Gmail API Direct Send)
import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { google } from "googleapis";
import { fileURLToPath } from "url";

// ------------------------------
// 📂 경로 설정
// ------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ------------------------------
// 🌐 Flutter Web 정적 파일 경로
// ------------------------------
const buildPath = path.join(__dirname, "build", "web");
if (fs.existsSync(buildPath)) {
  app.use(express.static(buildPath));
  console.log("✅ Serving Flutter web files from:", buildPath);
} else {
  console.warn("⚠️ build/web 폴더 없음. API 전용 모드로 실행 중");
}

// ------------------------------
// ✅ 헬스체크 (Render용 Ping)
// ------------------------------
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    message: "✅ Proxy active and responding",
    version: "10.8.0",
    time: new Date().toISOString(),
  });
});

// ------------------------------
// ✉️ Gmail OAuth2 인증 설정
// ------------------------------
const {
  GMAIL_CLIENT_ID,
  GMAIL_CLIENT_SECRET,
  GMAIL_REFRESH_TOKEN,
  MAIL_FROM,
  MAIL_TO,
} = process.env;

// ✅ Gmail OAuth2 클라이언트 구성
const oauth2Client = new google.auth.OAuth2(
  GMAIL_CLIENT_ID,
  GMAIL_CLIENT_SECRET,
  "https://developers.google.com/oauthplayground" // redirect URI
);
oauth2Client.setCredentials({ refresh_token: GMAIL_REFRESH_TOKEN });

// ------------------------------
// 📬 Gmail API로 직접 이메일 발송 함수
// ------------------------------
async function sendGmail(subject, bodyText) {
  try {
    // 1️⃣ Access Token 갱신
    const { token } = await oauth2Client.getAccessToken();

    // 2️⃣ 이메일 헤더/본문 생성 (base64로 인코딩)
    const emailLines = [
      `To: ${MAIL_TO}`,
      `From: ${MAIL_FROM}`,
      "Content-Type: text/plain; charset=UTF-8",
      "MIME-Version: 1.0",
      `Subject: ${subject}`,
      "",
      bodyText,
    ];
    const rawEmail = Buffer.from(emailLines.join("\n")).toString("base64");

    // 3️⃣ Gmail API 호출
    const gmail = google.gmail({ version: "v1", auth: oauth2Client });
    await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw: rawEmail },
    });

    console.log("📨 Gmail API 발송 성공:", MAIL_TO);
    return { success: true };
  } catch (err) {
    console.error("❌ Gmail API 발송 실패:", err.message);
    return { success: false, error: err.message };
  }
}

// ------------------------------
// 🧪 이메일 테스트 엔드포인트
// ------------------------------
app.get("/api/test-email", async (req, res) => {
  const result = await sendGmail(
    "📬 Cross-Verified AI 테스트 메일",
    `✅ ${new Date().toLocaleString()} 에 테스트 메일이 성공적으로 발송되었습니다.`
  );
  if (result.success) res.json({ success: true, message: "Test email sent successfully." });
  else res.status(500).json(result);
});

// ------------------------------
// 📋 화이트리스트 자동 점검 엔드포인트
// ------------------------------
const whitelistPath = path.join(__dirname, "data", "whitelist.json");

app.get("/api/check-whitelist", async (req, res) => {
  try {
    if (!fs.existsSync(whitelistPath)) {
      return res.status(404).json({ success: false, message: "화이트리스트 파일을 찾을 수 없습니다." });
    }

    const data = JSON.parse(fs.readFileSync(whitelistPath, "utf8"));
    const lastUpdated = new Date(data.lastUpdated);
    const today = new Date();

    // 한 달(30일) 이상 지났는지 확인
    const diffDays = Math.floor((today - lastUpdated) / (1000 * 60 * 60 * 24));

    if (diffDays >= 30) {
      console.log("⚠️ 화이트리스트 갱신 필요: 마지막 업데이트 이후", diffDays, "일 경과");
      await sendGmail(
        "🚨 화이트리스트 갱신 알림",
        `마지막 업데이트: ${lastUpdated.toLocaleString()}\n경과일수: ${diffDays}일\n화이트리스트 갱신이 필요합니다.`
      );
      res.json({ success: true, updated: false, message: "갱신 필요. 관리자에게 알림 전송됨." });
    } else {
      console.log("✅ 화이트리스트 유효:", diffDays, "일 경과");
      res.json({ success: true, updated: true, daysPassed: diffDays });
    }
  } catch (err) {
    console.error("❌ 화이트리스트 점검 실패:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ------------------------------
// 🌍 SPA 라우팅 (404 방지)
// ------------------------------
app.get("*", (req, res) => {
  const indexPath = path.resolve(buildPath, "index.html");
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.status(404).send("❌ index.html not found. Please build Flutter web first.");
});

// ------------------------------
// 🚀 Render 서버 실행
// ------------------------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Cross-Verified AI Proxy (Gmail API mode) running on port ${PORT}`);
});
