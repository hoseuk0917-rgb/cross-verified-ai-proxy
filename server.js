/**
 * Cross-Verified AI Proxy Server
 * Version: 10.8.1
 * Description: Render-compatible Express backend
 * Author: Ho Seok Goh
 */

import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import morgan from "morgan";
import dotenv from "dotenv";
import { google } from "googleapis";

dotenv.config();
const app = express();

// ===================== 기본 설정 =====================
app.use(cors());
app.use(bodyParser.json());
app.use(morgan("dev"));

const PORT = process.env.PORT || 3000;

// ===================== 헬스체크 =====================
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    uptime: process.uptime(),
    time: new Date().toISOString(),
  });
});

// ===================== 핑 (서버 응답 테스트) =====================
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    message: "✅ Proxy active and responding",
    version: "10.8.1",
    time: new Date().toISOString(),
  });
});

// ===================== 화이트리스트 확인 =====================
app.get("/api/check-whitelist", (req, res) => {
  try {
    const whitelist = [
      "hoseuk0917@gmail.com",
      "crossverified.ai@app.dev",
      "test@crossai.local",
    ];
    const user = req.query.user || "anonymous";
    const allowed = whitelist.includes(user);

    res.json({
      success: true,
      user,
      allowed,
      updated: true,
      daysPassed: null,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ check-whitelist error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===================== Gmail API 테스트 =====================
app.post("/api/test-email", async (req, res) => {
  try {
    const { to, subject, text } = req.body;
    if (!to || !subject || !text)
      return res.status(400).json({ error: "Missing email parameters" });

    const auth = new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET,
      process.env.GMAIL_REDIRECT_URI
    );
    auth.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });

    const gmail = google.gmail({ version: "v1", auth });

    const encodedMessage = Buffer.from(
      `To: ${to}\r\nSubject: ${subject}\r\n\r\n${text}`
    ).toString("base64");

    await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw: encodedMessage },
    });

    res.json({ success: true, message: "✅ Test email sent successfully" });
  } catch (err) {
    console.error("❌ Gmail send error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===================== 기본 라우트 =====================
app.get("/", (req, res) => {
  res.send("🚀 Cross-Verified AI Proxy Server (v10.8.1) is running.");
});

// ===================== Render 웹서빙 =====================
import path from "path";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, "src/build/web")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "src/build/web/index.html"));
});

// ===================== 서버 시작 =====================
app.listen(PORT, () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
