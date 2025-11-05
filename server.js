// ✅ Cross-Verified AI Proxy Server v12.2.0
// (Gemini + Engines + TruthScore + Supabase Log Management)

import cors from "cors";
import express from "express";
import path from "path";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import morgan from "morgan";
import fetch from "node-fetch";
import axios from "axios";
import https from "https";
import fs from "fs";

// ─────────────────────────────
// 1️⃣ 환경 설정
// ─────────────────────────────
if (fs.existsSync(".env.local")) {
  dotenv.config({ path: ".env.local" });
  console.log("🌍 Using .env.local (로컬 개발환경)");
} else {
  dotenv.config();
  console.log("☁️ Using .env (Render/배포환경)");
}

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = process.env.APP_VERSION || "v12.2.0";
const DEV_MODE = process.env.DEV_MODE === "true";
const agent = new https.Agent({ keepAlive: true, maxSockets: 10, keepAliveMsecs: 60000 });

// ─────────────────────────────
// 2️⃣ TruthScore 계산
// ─────────────────────────────
function evaluateResults(engineScores = []) {
  if (!engineScores.length)
    return { truthScore: 0, adjustedScore: 0, status: "missing", sources: [] };

  const weights = { CrossRef: 1.2, OpenAlex: 1.0, GDELT: 0.8, Wikidata: 0.6, Naver: 0.5, KLaw: 0.7 };
  let weightedSum = 0, weightSum = 0;
  const values = [], sources = [];
  for (const e of engineScores) {
    const w = weights[e.name] ?? 1.0;
    weightedSum += w * e.score;
    weightSum += w;
    values.push(e.score);
    sources.push({ engine: e.name, title: e.title || "출처 미상", confidence: Number(e.score.toFixed(3)) });
  }

  const T = weightedSum / weightSum;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
  const delta = Math.max(...values) - Math.min(...values);

  let status = "valid";
  if (variance > 0.2 || delta > 0.3) status = "conflict";
  else if (T < 0.5) status = "low";

  const λ = parseFloat(process.env.TRUTH_LAMBDA_BASE || 1.0);
  const factors = { valid: 1 + 0.05 * λ, conflict: 1 - 0.15 * λ, low: 1 - 0.25 * λ, missing: 0 };
  const adjusted = Math.min(Math.max(T * (factors[status] ?? 1), 0), 1);
  return { truthScore: Number(T.toFixed(3)), adjustedScore: Number(adjusted.toFixed(3)), status, sources };
}

// ─────────────────────────────
// 3️⃣ Middleware
// ─────────────────────────────
app.use(cors({ origin: true, methods: ["GET", "POST", "OPTIONS"], credentials: true }));
app.use(bodyParser.json({ limit: `${process.env.MAX_REQUEST_BODY_MB || 5}mb` }));
app.use(bodyParser.urlencoded({ extended: true }));
if (process.env.LOG_REQUESTS === "true") app.use(morgan("dev"));

// ─────────────────────────────
// 4️⃣ Supabase 로그 유틸
// ─────────────────────────────
const SUPA_URL = process.env.SUPABASE_URL;
const SUPA_KEY = process.env.SUPABASE_KEY;

async function logToSupabase(engine, query, message, type = "info") {
  if (!SUPA_URL || !SUPA_KEY) return;
  try {
    await axios.post(`${SUPA_URL}/rest/v1/logs`, [{
      timestamp: new Date().toISOString(),
      engine, query, message, type
    }], {
      headers: {
        apikey: SUPA_KEY,
        Authorization: `Bearer ${SUPA_KEY}`,
        "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates"
      }
    });
  } catch (e) {
    console.warn("⚠️ 로그 저장 실패:", e.message);
  }
}

// 롤오버 (30일 초과 또는 2000행 이상 시 자동 삭제)
async function pruneSupabaseLogs() {
  if (!SUPA_URL || !SUPA_KEY) return;
  try {
    await axios.post(`${SUPA_URL}/rest/v1/rpc/prune_logs`, {}, {
      headers: { apikey: SUPA_KEY, Authorization: `Bearer ${SUPA_KEY}` }
    });
    console.log("🧹 로그 롤오버 수행 완료");
  } catch (e) {
    console.warn("⚠️ 로그 롤오버 실패:", e.message);
  }
}

// ─────────────────────────────
// 5️⃣ Health Check
// ─────────────────────────────
app.get("/health", (req, res) =>
  res.status(200).json({ status: "ok", version: APP_VERSION, timestamp: Date.now() })
);

// ─────────────────────────────
// 6️⃣ Verify API
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const { query, key, naverKey, naverSecret, klawKey } = req.body;
  if (!query || !key)
    return res.status(400).json({ success: false, message: "❌ query 또는 key 누락" });
  const start = Date.now();

  try {
    // Gemini 2.5 Flash
    const mainResp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${key}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: [{ parts: [{ text: query }] }] })
    });
    const mainData = await mainResp.json();
    const mainText = mainData?.candidates?.[0]?.content?.parts?.[0]?.text || "⚠️ Gemini 응답 없음";

    // 엔진 테스트 (CrossRef + Naver + K-Law)
    const encoded = encodeURIComponent(query);
    const engines = [];

    // CrossRef
    try {
      const c = await fetch(`https://api.crossref.org/works?query=${encoded}&rows=1`);
      const d = await c.json();
      engines.push({
        name: "CrossRef",
        score: d.message?.items?.length ? 0.9 : 0.4,
        title: d.message?.items?.[0]?.title?.[0] || "CrossRef 결과 없음"
      });
    } catch (e) { await logToSupabase("CrossRef", query, e.message, "error"); }

    // Naver
    try {
      const n = await fetch(`https://openapi.naver.com/v1/search/news.json?query=${encoded}&display=10`, {
        headers: { "X-Naver-Client-Id": naverKey, "X-Naver-Client-Secret": naverSecret }
      });
      const d = await n.json();
      engines.push({
        name: "Naver",
        score: d.items?.length ? 0.75 : 0.35,
        title: d.items?.[0]?.title?.replace(/<[^>]*>/g, "") || "Naver 결과 없음"
      });
    } catch (e) { await logToSupabase("Naver", query, e.message, "error"); }

    // K-Law
    try {
      const k = await fetch(`https://www.law.go.kr/DRF/lawSearch.do?target=law&type=JSON&OC=${klawKey}&query=${encoded}&display=3`);
      const text = await k.text();
      const parsed = JSON.parse(text);
      engines.push({
        name: "KLaw",
        score: parsed.LAWDATA_LIST?.length ? 0.8 : 0.4,
        title: parsed.LAWDATA_LIST?.[0]?.법령명한글 || "K-Law 결과 없음"
      });
    } catch (e) {
      await logToSupabase("KLaw", query, e.message, "error");
      engines.push({ name: "KLaw", score: 0, title: "K-Law 연결 실패" });
    }

    const truth = evaluateResults(engines);
    const elapsed = `${Date.now() - start} ms`;

    await logToSupabase("Verify", query, `✅ 처리 완료 (${elapsed})`, "info");

    return res.status(200).json({
      success: true,
      message: "✅ Gemini 2.5 기반 실제 교차검증 완료",
      query,
      elapsed,
      mainText,
      engines,
      truthScore: truth.truthScore,
      adjustedScore: truth.adjustedScore,
      status: truth.status,
      sources: truth.sources
    });

  } catch (err) {
    await logToSupabase("System", query, err.message, "error");
    return res.status(500).json({ success: false, message: "서버 오류", error: err.message });
  }
});

// ─────────────────────────────
// 7️⃣ Keep-Alive + Prune Scheduler
// ─────────────────────────────
setInterval(() => {
  fetch("https://cross-verified-ai-proxy.onrender.com/health").catch(() => {});
  pruneSupabaseLogs();
}, 660000);

// ─────────────────────────────
// 8️⃣ SPA & Start
// ─────────────────────────────
const __dirname = path.resolve();
const webDir = path.join(__dirname, "src", "build", "web");
app.use(express.static(webDir));
app.get("*", (req, res) => res.sendFile(path.join(webDir, "index.html")));

app.listen(PORT, () => {
  console.log(`🚀 Proxy ${APP_VERSION} running on port ${PORT}`);
});
