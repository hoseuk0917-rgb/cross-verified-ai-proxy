/**
 * Cross-Verified AI Proxy v10.3.0
 * 서버 메인 엔트리 — 사용자 입력형 Key 구조로 개편
 */

const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const session = require("express-session");
const jwt = require("jsonwebtoken");
const path = require("path");

const gemini = require("./engine/gemini");
const verification = require("./engine/verification");
const truthscore = require("./engine/truthscore");

const app = express();
const PORT = process.env.PORT || 3000;

// ========== 미들웨어 설정 ==========
app.use(cors());
app.use(bodyParser.json({ limit: "2mb" }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "cross-verified-secret",
    resave: false,
    saveUninitialized: true,
  })
);

// ========== HEALTH CHECK ==========
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    version: "10.3.0",
    timestamp: new Date().toISOString(),
  });
});

// ========== GEMINI API ==========
app.post("/api/gemini/generate", async (req, res) => {
  try {
    const { apiKey, model, prompt } = req.body;
    if (!apiKey) return res.status(400).json({ success: false, error: "API key missing" });

    const result = await gemini.callGemini({ apiKey, model, prompt });
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ========== TRUTH SCORE 계산 ==========
app.post("/api/truthscore/calculate", async (req, res) => {
  try {
    const result = await truthscore.calculate(req.body);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ========== VERIFY (단일 엔진) ==========
app.post("/api/verify/:engine", async (req, res) => {
  try {
    const { engine } = req.params;
    const { query, keys } = req.body;
    const result = await verification.verifySingleEngine(engine, query, keys);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ========== VERIFY (전체 엔진 병렬) ==========
app.post("/api/verify/all", async (req, res) => {
  try {
    const { query, keys } = req.body;
    const result = await verification.verifyAllEngines(query, keys);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ========== 기본 라우트 ==========
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// ========== 서버 시작 ==========
app.listen(PORT, () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
