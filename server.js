import express from "express";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import nodemailer from "nodemailer";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ JSON 파싱
app.use(express.json());

// ✅ Flutter Web 빌드 경로
const buildPath = path.join(__dirname, "build", "web");
if (!fs.existsSync(buildPath)) {
  console.warn("⚠️ No build/web found. Serving API only.");
} else {
  app.use(express.static(buildPath));
  console.log("✅ Serving static web files:", buildPath);
}

// ✅ nodemailer 트랜스포터 설정
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT) || 465,
  secure: Number(process.env.SMTP_PORT) === 465, // 465 → true
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ✅ 공용 메일 전송 함수
async function sendAlertEmail(subject, text) {
  const receiver = process.env.ALERT_RECEIVER;
  if (!receiver) throw new Error("ALERT_RECEIVER not defined");

  await transporter.sendMail({
    from: `"Cross-Verified AI" <${process.env.SMTP_USER}>`,
    to: receiver,
    subject,
    text,
  });
  console.log(`📨 Alert mail sent → ${receiver}`);
}

// ✅ 헬스체크
app.get("/api/ping", (req, res) => {
  res.json({ message: "✅ Proxy active", time: new Date().toISOString() });
});

// ✅ 이메일 테스트
app.get("/api/test-email", async (req, res) => {
  try {
    await sendAlertEmail("테스트 알림: 서버 동작 확인", "✅ 서버 메일 알림 테스트 성공");
    res.json({ status: "ok", message: "테스트 메일 발송 완료" });
  } catch (err) {
    console.error("❌ 이메일 발송 실패:", err);
    res.status(500).json({ status: "error", message: err.message });
  }
});

// ✅ 화이트리스트 업데이트 이벤트
app.post("/api/whitelist/update", async (req, res) => {
  const { updatedBy, count, notes } = req.body;
  const msg = `화이트리스트가 업데이트되었습니다.\n\n- 수정자: ${updatedBy}\n- 총 항목: ${count}\n- 비고: ${notes || "없음"}\n- 시각: ${new Date().toLocaleString("ko-KR")}`;
  try {
    await sendAlertEmail("🔔 화이트리스트 갱신 알림", msg);
    res.json({ status: "ok", message: "알림 메일 발송 완료" });
  } catch (err) {
    console.error("❌ 알림 발송 실패:", err);
    res.status(500).json({ status: "error", message: err.message });
  }
});

// ✅ SPA 라우팅
app.get("*", (req, res) => {
  const indexPath = path.resolve(buildPath, "index.html");
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.status(404).send("❌ index.html not found");
});

// ✅ 서버 시작
app.listen(PORT, "0.0.0.0", () =>
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`)
);
