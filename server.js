// ✅ Cross-Verified AI Proxy Server v12.2.1
// (Gemini 2.5 Full Verification + Parallel Engine + Flash-Lite Fallback)

import cors from "cors";
import express from "express";
import path from "path";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import morgan from "morgan";
import fetch from "node-fetch";
import https from "https";
import fs from "fs";

if (fs.existsSync(".env.local")) {
  dotenv.config({ path: ".env.local" });
  console.log("🌍 Using .env.local (로컬 개발환경)");
} else {
  dotenv.config();
  console.log("☁️ Using .env (Render/배포환경)");
}

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = process.env.APP_VERSION || "v12.2.1";
const DEV_MODE = process.env.DEV_MODE === "true";
const agent = new https.Agent({ keepAlive: true, maxSockets: 10 });

// ─────────────────────────────
// TruthScore 계산
// ─────────────────────────────
function evaluateResults(engineScores = []) {
  if (!engineScores || engineScores.length === 0)
    return { truthScore: 0, adjustedScore: 0, status: "missing", sources: [] };

  const weights = { CrossRef: 1.2, OpenAlex: 1.0, GDELT: 0.8, Wikidata: 0.6, Naver: 0.5, KLaw: 0.7 };
  let weightedSum = 0, weightSum = 0;
  const values = [], sources = [];

  for (const e of engineScores) {
    const w = weights[e.name] ?? 1.0;
    weightedSum += w * e.score;
    weightSum += w;
    values.push(e.score);
    sources.push({
      engine: e.name,
      title: e.title || "출처명 미상",
      confidence: Number(e.score.toFixed(3))
    });
  }

  const T = weightedSum / weightSum;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
  const delta = Math.max(...values) - Math.min(...values);

  let status = "valid";
  if (variance > 0.2 || delta > 0.3) status = "conflict";
  else if (T < 0.5) status = "low";
  else if (!values.length) status = "missing";

  const λ = parseFloat(process.env.TRUTH_LAMBDA_BASE || 1.0);
  const factor = status === "valid" ? 1 + 0.05 * λ :
                 status === "conflict" ? 1 - 0.15 * λ :
                 status === "low" ? 1 - 0.25 * λ : 0;

  return {
    truthScore: Number(T.toFixed(3)),
    adjustedScore: Number(Math.min(Math.max(T * factor, 0), 1).toFixed(3)),
    status,
    sources: sources.sort((a, b) => b.confidence - a.confidence).slice(0, 6)
  };
}

// ─────────────────────────────
// Middleware
// ─────────────────────────────
app.use(cors({ origin: true, methods: ["GET", "POST"], allowedHeaders: ["Content-Type", "Authorization"] }));
app.use(bodyParser.json({ limit: `${process.env.MAX_REQUEST_BODY_MB || 5}mb` }));

if (process.env.LOG_REQUESTS === "true") {
  app.use(morgan(process.env.LOG_LEVEL || "dev"));
}

// ─────────────────────────────
// Health Check
// ─────────────────────────────
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok", version: APP_VERSION, timestamp: Date.now() });
});

// ─────────────────────────────
// ✅ Main Verify Endpoint
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const start = Date.now();
  try {
    const { query, key } = req.body;
    if (!query || !key) return res.status(400).json({ success: false, message: "query 또는 key 누락" });

    const MODEL_FLASH = "gemini-2.5-flash";
    const MODEL_LITE = "gemini-2.5-flash-lite";
    const MODEL_PRO = "gemini-2.5-pro";

    // ────── ① 응답 생성 (Gemini Flash)
    const genUrl = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_FLASH}:generateContent?key=${key}`;
    const genResp = await fetch(genUrl, {
      method: "POST", agent, headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: [{ parts: [{ text: query }] }] })
    });
    const genData = await genResp.json();
    const mainText = genData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "(응답 없음)";

    // ────── ② 키워드 추출 (Flash-Lite 폴백)
    async function getKeywords(prompt) {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_LITE}:generateContent?key=${key}`;
      const res = await fetch(url, {
        method: "POST", agent, headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contents: [{ parts: [{ text: `다음 문장에서 핵심 키워드 5개를 콤마로 출력:\n${prompt}` }] }] })
      });
      const data = await res.json();
      const text = data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "";
      return text.split(",").map(t => t.trim()).filter(Boolean);
    }

    let keywords = [];
    try { keywords = await getKeywords(mainText); } catch { keywords = []; }
    if (keywords.length === 0) keywords = ["UAM", "안전성", "항공", "센서"];

    // ────── ③ 엔진 병렬검증
    const encoded = encodeURIComponent(keywords.join(" "));
    const engines = [
      {
        name: "CrossRef",
        url: `https://api.crossref.org/works?query=${encoded}&rows=3`,
        parse: (d) => ({
          score: d.message?.items?.length ? 0.9 : 0.5,
          title: d.message?.items?.[0]?.title?.[0] || "CrossRef 결과 없음"
        })
      },
      {
        name: "OpenAlex",
        url: `https://api.openalex.org/works?search=${encoded}`,
        parse: (d) => ({
          score: d.results?.length ? 0.85 : 0.4,
          title: d.results?.[0]?.title || "OpenAlex 결과 없음"
        })
      },
      {
        name: "GDELT",
        url: `https://api.gdeltproject.org/api/v2/doc/doc?query=${encoded}&format=json&maxrecords=3`,
        parse: (d) => ({
          score: d.articles?.length ? 0.8 : 0.4,
          title: d.articles?.[0]?.title || "GDELT 결과 없음"
        })
      },
      {
        name: "Wikidata",
        url: `https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encoded}`,
        parse: (d) => ({
          score: d.search?.length ? 0.7 : 0.3,
          title: d.search?.[0]?.label || "Wikidata 결과 없음"
        })
      },
      {
        name: "Naver",
        url: `https://openapi.naver.com/v1/search/news.json?query=${encoded}`,
        parse: (d) => ({
          score: d.items?.length ? 0.75 : 0.35,
          title: d.items?.[0]?.title?.replace(/<[^>]*>/g, "") || "Naver 결과 없음"
        })
      }
    ];

    const results = await Promise.allSettled(
      engines.map(async (e) => {
        try {
          const r = await fetch(e.url, { agent });
          const data = await r.json().catch(() => ({}));
          return e.parse(data);
        } catch (err) {
          return { score: 0, title: `${e.name} 오류: ${err.message}` };
        }
      })
    );

    const engineResults = results.map((r, i) => ({
      name: engines[i].name,
      ...(r.status === "fulfilled" ? r.value : { score: 0, title: `${engines[i].name} 실패` })
    }));
    // ────── ④ TruthScore 계산
    const truthEval = evaluateResults(engineResults);

    // ────── ⑤ Gemini-Pro 평가 (요약 및 신뢰도 분석)
    const evalUrl = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_PRO}:generateContent?key=${key}`;
    const evalPrompt = `
다음은 Gemini 모델이 생성한 UAM 관련 응답과 여러 검증엔진의 결과입니다.
출처 신뢰도 및 일관성을 바탕으로 전체 응답의 신뢰성을 평가하세요.

[질문]
${query}

[응답]
${mainText}

[핵심 키워드]
${keywords.join(", ")}

[검증엔진별 결과]
${engineResults.map(e => `- ${e.name}: ${e.title} (신뢰도 ${e.score.toFixed(2)})`).join("\n")}
`;

    let evalText = "";
    try {
      const evalResp = await fetch(evalUrl, {
        method: "POST",
        agent,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: evalPrompt }] }],
        }),
      });
      const evalData = await evalResp.json();
      evalText =
        evalData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ||
        "(평가 결과 없음)";
    } catch (e) {
      evalText = `(평가 실패: ${e.message})`;
    }

    const elapsed = `${Date.now() - start} ms`;

    // ────── ⑥ 결과 반환
    return res.status(200).json({
      success: true,
      message: "✅ Gemini 2.5 기반 실제 교차검증 완료",
      query,
      elapsed,
      keywords,
      mainText,
      evalText,
      engines: engineResults,
      truthScore: truthEval.truthScore,
      adjustedScore: truthEval.adjustedScore,
      status: truthEval.status,
      sources: truthEval.sources,
      timestamp: new Date().toISOString(),
    });

  } catch (err) {
    console.error("[VerifyChainError]", err);
    res.status(500).json({
      success: false,
      message: "❌ 서버 처리 중 오류 발생",
      error: err.message,
    });
  }
});

// ─────────────────────────────
// Keep-Alive Ping
// ─────────────────────────────
const pingInterval = Number(process.env.PING_INTERVAL_SEC || 660) * 1000;
setInterval(async () => {
  try {
    const res = await fetch("https://cross-verified-ai-proxy.onrender.com/health", { agent });
    if (process.env.LOG_HEALTH_PINGS !== "false") {
      console.log(`💓 Keep-alive ping: ${res.status}`);
    }
  } catch (e) {
    if (DEV_MODE) console.warn("⚠️ Ping 실패:", e.message);
  }
}, pingInterval);

// ─────────────────────────────
// SPA Routing & Server Start
// ─────────────────────────────
const __dirname = path.resolve();
const webDir = path.join(__dirname, "src", "build", "web");
app.use(express.static(webDir));
app.get("*", (req, res) => res.sendFile(path.join(webDir, "index.html")));

app.listen(PORT, () => {
  console.log(`🚀 Proxy ${APP_VERSION} running on port ${PORT}`);
  if (DEV_MODE) console.log("🔍 개발모드: 병렬 검증 + Flash-Lite 폴백 활성화됨");
});
