/**
 * Cross-Verified AI Proxy Server
 * Version: 10.8.3
 * Author: Ho Seok Goh
 * Description: Render-compatible Express backend with full API endpoints
 */

import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import morgan from "morgan";
import dotenv from "dotenv";
import { google } from "googleapis";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();

// ==================================================
// 🔧 Middleware
// ==================================================
app.use(cors());
app.use(bodyParser.json());
app.use(morgan("dev"));

const PORT = process.env.PORT || 3000;

// ==================================================
// ✅ 1. Health Check (Render 전용, 반드시 최상단)
// ==================================================
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    uptime: process.uptime(),
    time: new Date().toISOString(),
  });
});

// ==================================================
// ✅ 2. Ping (서버 응답 확인)
// ==================================================
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    message: "✅ Proxy active and responding",
    version: "10.8.3",
    time: new Date().toISOString(),
  });
});

// ==================================================
// ✅ 3. Whitelist 확인
// ==================================================
app.get("/api/check-whitelist", (req, res) => {
  try {
    const whitelist = [
      "hoseuk0917@gmail.com",
      "crossverified.ai@app.dev",
      "admin@crossai.local",
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

// ==================================================
// ✅ 4. Gmail API 테스트
// ==================================================
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

// ==================================================
// ✅ 5. Gemini (QV/FV/DV/CV) 시뮬레이션
// ==================================================
app.post("/api/callGemini", (req, res) => {
  try {
    const { mode, query, user } = req.body;

    if (!query || !mode) {
      return res
        .status(400)
        .json({ success: false, error: "Missing mode or query" });
    }

    // 모드별 시뮬레이션 응답
    let simulated = "";
    switch (mode) {
      case "QV":
        simulated = `질문검증(QV): "${query}"는 신뢰성 있는 질문입니다.`;
        break;
      case "FV":
        simulated = `사실검증(FV): "${query}"에 대한 근거가 확인되었습니다.`;
        break;
      case "DV":
        simulated = `개발검증(DV): "${query}" 관련 코드 검증 완료.`;
        break;
      case "CV":
        simulated = `코드검증(CV): "${query}" 분석 성공.`;
        break;
      default:
        simulated = `Unknown mode "${mode}".`;
    }

    res.json({
      success: true,
      user: user || "localTestUser",
      mode,
      query,
      simulated,
      time: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ callGemini error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==================================================
// ✅ 6. GitHub Token 테스트
// ==================================================
app.post("/api/github-test", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: "Missing GitHub token" });

    const response = await fetch("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await response.json();

    if (response.ok)
      res.json({ success: true, message: "✅ GitHub token valid", data });
    else res.status(401).json({ success: false, error: data.message });
  } catch (err) {
    console.error("❌ GitHub Test Error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==================================================
// ✅ 7. Naver API 테스트
// ==================================================
app.post("/api/naver-test", async (req, res) => {
  try {
    const { clientId, clientSecret } = req.body;
    if (!clientId || !clientSecret)
      return res.status(400).json({ error: "Missing Naver credentials" });

    const response = await fetch("https://openapi.naver.com/v1/search/news.json?query=UAM", {
      headers: {
        "X-Naver-Client-Id": clientId,
        "X-Naver-Client-Secret": clientSecret,
      },
    });
    const data = await response.json();

    if (response.ok)
      res.json({ success: true, message: "✅ Naver API test successful", sample: data.items?.slice(0, 2) });
    else res.status(401).json({ success: false, error: data });
  } catch (err) {
    console.error("❌ Naver Test Error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==================================================
// ✅ 8. 기본 루트
// ==================================================
app.get("/", (req, res) => {
  res.send("🚀 Cross-Verified AI Proxy v10.8.3 is running.");
});

// ==================================================
// ✅ 9. Flutter Web 정적 서빙
// ==================================================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, "src/build/web")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "src/build/web/index.html"));
});

// ==================================================
// ✅ 10. 서버 시작
// ==================================================
app.listen(PORT, () => {
  console.log(`✅ Cross-Verified AI Proxy v10.8.3 running on port ${PORT}`);
});
