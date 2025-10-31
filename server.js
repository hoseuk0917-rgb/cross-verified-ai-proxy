// server.js (v10.6.1 - Naver SMTP 버전)
import express from "express";
import bodyParser from "body-parser";
import path from "path";
import fs from "fs";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
app.use(bodyParser.json());

// ✅ Flutter Web 정적파일 서빙
const buildPath = path.join(__dirname, "build", "web");
if (!fs.existsSync(buildPath)) {
  console.warn("⚠️ build/web not found. Serving API only.");
} else {
  console.log("✅ Serving static Flutter web files from:", buildPath);
  app.use(express.static(buildPath));
}

// ✅ Health check
app.get("/api/ping", (req, res) => {
  res.json({ status: "ok", version: "10.6.1", time: new Date().toISOString() });
});

// ✅ Whitelist 메모리 저장소
let whitelist = { updatedAt: null, entries: ["NAVER_KEY_001"] };

// ✅ Naver SMTP 기반 메일 발송기
async function sendAdminMail(subject, message) {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST || "smtp.naver.com",
      port: process.env.MAIL_PORT || 465,
      secure: true,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
    });

    const mailOptions = {
      from: `"Cross-Verified AI Notifier" <${process.env.MAIL_USER}>`,
      to: process.env.ADMIN_NOTIFY_TARGET,
      subject,
      text: message,
    };

    await transporter.sendMail(mailOptions);
    console.log("✅ Admin mail sent to:", process.env.ADMIN_NOTIFY_TARGET);
  } catch (err) {
    console.error("❌ Mail send failed:", err.message);
  }
}

// ✅ Whitelist 조회
app.get("/api/whitelist", (req, res) => {
  res.json({ success: true, whitelist });
});

// ✅ Whitelist 업데이트 + 관리자 알림
app.post("/api/whitelist/update", async (req, res) => {
  const { updatedBy, newEntries } = req.body;
  if (!updatedBy || !Array.isArray(newEntries)) {
    return res.status(400).json({ success: false, error: "Missing updatedBy or newEntries" });
  }

  whitelist = {
    updatedAt: new Date().toISOString(),
    entries: newEntries,
  };

  console.log("✅ Whitelist updated by:", updatedBy);

  const mailBody = `
📢 Whitelist Updated

🕒 Time: ${whitelist.updatedAt}
👤 Updated By: ${updatedBy}
🔑 Entries: ${newEntries.join(", ")}

✅ Render 서버에서 자동 알림 메일이 발송되었습니다.
`;

  await sendAdminMail("[Whitelist Updated] Cross-Verified AI", mailBody);
  res.json({ success: true, whitelist });
});

// ✅ 메일 테스트
app.post("/api/admin/test-email", async (req, res) => {
  await sendAdminMail("[Test] Cross-Verified AI Server", "✅ This is a test mail from Render server.");
  res.json({ success: true, message: "Test mail sent." });
});

// ✅ SPA 라우팅
app.get("*", (req, res) => {
  const indexPath = path.resolve(buildPath, "index.html");
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send("❌ index.html not found.");
  }
});

// ✅ 서버 시작
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Cross-Verified AI Proxy (Naver SMTP) running on port ${PORT}`);
});
