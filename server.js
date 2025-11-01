// server.js
import express from "express";
import fs from "fs";
import path from "path";
import cors from "cors";
import nodemailer from "nodemailer";

const app = express();
app.use(cors());
app.use(express.json());

/* ==========================================
   1️⃣ Whitelist Check API
   ========================================== */
app.get("/api/check-whitelist", async (req, res) => {
  try {
    const filePath = path.resolve("./whitelist.json");

    // Load existing whitelist file if it exists
    let oldList = [];
    if (fs.existsSync(filePath)) {
      oldList = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    }

    // Example: new whitelist data (replace this with real data later)
    const newList = ["NAVER", "GOOGLE", "K-LAW", "GITHUB", "RENDER"];

    // Compare old and new lists
    const diff = newList.filter(x => !oldList.includes(x));
    let updated = false;

    if (diff.length > 0) {
      // Save updated whitelist
      fs.writeFileSync(filePath, JSON.stringify(newList, null, 2));
      updated = true;

      // Send email alert when updated
      await sendUpdateAlert(diff);
      console.log("✅ 화이트리스트가 업데이트되었습니다:", diff);
    }

    // Send response
    res.json({
      상태: "정상",
      업데이트됨: updated,
      변경항목: diff,
      마지막점검시간: new Date().toISOString(),
      메시지: updated
        ? "화이트리스트가 변경되어 관리자에게 알림이 전송되었습니다."
        : "변경사항이 없습니다.",
    });
  } catch (err) {
    console.error("❌ 화이트리스트 점검 실패:", err);
    res.status(500).json({ 오류: err.message });
  }
});

/* ==========================================
   2️⃣ Gmail Notification Function
   ========================================== */
async function sendUpdateAlert(diff) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      type: "OAuth2",
      user: process.env.MAIL_FROM,
      clientId: process.env.GMAIL_CLIENT_ID,
      clientSecret: process.env.GMAIL_CLIENT_SECRET,
      refreshToken: process.env.GMAIL_REFRESH_TOKEN,
    },
  });

  const mailOptions = {
    from: process.env.MAIL_FROM,
    to: process.env.MAIL_TO,
    subject: "🔔 Cross-Verified AI 화이트리스트 변경 알림",
    text: `다음 항목이 변경되었습니다:\n\n${diff.join("\n")}\n\n확인 후 필요한 조치를 진행해주세요.`,
  };

  await transporter.sendMail(mailOptions);
  console.log("📨 관리자에게 화이트리스트 변경 알림 이메일을 전송했습니다!");
}

/* ==========================================
   3️⃣ Flutter Web Static Serving
   ========================================== */
const webPath = path.resolve("build/web");
app.use(express.static(webPath));

// Static routing should be defined last
app.get("*", (_, res) => {
  res.sendFile(path.join(webPath, "index.html"));
});

/* ==========================================
   4️⃣ Server Start
   ========================================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Cross-Verified AI Proxy 서버가 포트 ${PORT}에서 실행 중입니다.`);
});
