// ✅ Cross-Verified AI Proxy Server v12.1.4
// (Full Cross-Verification: Gemini + Engines + TruthScore)

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
const APP_VERSION = process.env.APP_VERSION || "v12.1.4";
const DEV_MODE = process.env.DEV_MODE === "true";

const agent = new https.Agent({ keepAlive: true, maxSockets: 10, keepAliveMsecs: 60000 });

// ─────────────────────────────
// TruthScore 계산 모듈
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
  if (values.length === 0) status = "missing";
  else if (variance > 0.2 || delta > 0.3) status = "conflict";
  else if (T < 0.5) status = "low";

  const λ = parseFloat(process.env.TRUTH_LAMBDA_BASE || 1.0);
  let factor = 1.0;
  if (status === "valid") factor = 1 + 0.05 * λ;
  else if (status === "conflict") factor = 1 - 0.15 * λ;
  else if (status === "low") factor = 1 - 0.25 * λ;
  else if (status === "missing") factor = 0;

  const adjusted = Math.min(Math.max(T * factor, 0), 1);
  return {
    truthScore: Number(T.toFixed(3)),
    adjustedScore: Number(adjusted.toFixed(3)),
    status,
    sources: sources.sort((a, b) => b.confidence - a.confidence).slice(0, 6)
  };
}

// ─────────────────────────────
// Middleware
// ─────────────────────────────
app.use(cors({
  origin: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));
app.use(bodyParser.json({ limit: `${process.env.MAX_REQUEST_BODY_MB || 5}mb` }));
app.use(bodyParser.urlencoded({ extended: true }));

if (process.env.LOG_REQUESTS === "true") {
  app.use(morgan(process.env.LOG_LEVEL || "dev", {
    skip: (req) => process.env.LOG_HEALTH_PINGS === "false" && req.url === "/health",
  }));
}

// Static Web
const __dirname = path.resolve();
const webDir = path.join(__dirname, "src", "build", "web");
app.use(express.static(webDir));
app.use("/api", express.json());
app.get("/api/*", (req, res, next) => next());

// Health Check
app.get("/health", (req, res) =>
  res.status(200).json({
    status: "ok",
    version: APP_VERSION,
    timestamp: Date.now(),
    ping_interval_sec: process.env.PING_INTERVAL_SEC || 660,
  })
);
// ─────────────────────────────
// ✅ Gemini 체인 기반 교차검증 (응답 → 요약 → 엔진검증 → 평가)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  try {
    const { mode, query, model = "pro" } = req.body;
    let gemini_key = req.body.gemini_key;
    const authHeader = req.get("Authorization");
    if (!gemini_key && authHeader?.startsWith("Bearer "))
      gemini_key = authHeader.substring(7).trim();

    if (!query || !mode)
      return res.status(400).json({ success: false, message: "❌ mode 또는 query 누락" });
    if (!gemini_key)
      return res.status(400).json({ success: false, message: "❌ Gemini Key 누락" });
    if (query.length > 4000)
      return res.status(413).json({ message: "⚠️ 요청 문장이 너무 깁니다 (4000자 제한)" });

    // 모델 정의
    const MODEL_FLASH = "gemini-2.5-flash";
    const MODEL_LITE = "gemini-2.5-flash-lite";
    const MODEL_PRO = "gemini-2.5-pro";

    // ──────────────── ① 응답 생성 (Flash/Pro)
    const mainUrl = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_FLASH}:generateContent?key=${gemini_key}`;
    const start = Date.now();
    const mainResp = await fetch(mainUrl, {
      method: "POST",
      agent,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: `질문: ${query}\n\n해당 질문에 대해 명확하고 근거 기반의 응답을 작성하세요.` }] }],
      }),
    });
    const mainData = await mainResp.json();
    const mainText =
      mainData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ||
      "⚠️ Gemini 응답 없음";

    // ──────────────── ② 핵심 키워드 추출 (Flash-Lite)
    const keywordUrl = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_LITE}:generateContent?key=${gemini_key}`;
    const keyResp = await fetch(keywordUrl, {
      method: "POST",
      agent,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: `다음 문장에서 핵심 키워드 3~5개를 추출하고 콤마(,)로 구분해 출력:\n${mainText}` }] }],
      }),
    });
    const keyData = await keyResp.json();
    const keywordText =
      keyData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "";
    const keywords = keywordText
      .replace(/\n/g, "")
      .split(",")
      .map(k => k.trim())
      .filter(Boolean);

    // ──────────────── ③ 교차검증 엔진 호출
    async function queryEngine(name, url, parseFn) {
      try {
        const r = await fetch(url);
        if (!r.ok) return { name, score: 0, title: `${name} 연결 실패` };
        const data = await r.json();
        const parsed = parseFn(data);
        return { name, ...parsed };
      } catch (e) {
        return { name, score: 0, title: `${name} 오류: ${e.message}` };
      }
    }

    // 엔진 URL 구성
    const encodedQuery = encodeURIComponent(keywords.join(" "));
    const engines = [
      {
        name: "CrossRef",
        url: `https://api.crossref.org/works?query=${encodedQuery}&rows=3`,
        parseFn: (data) => ({
          score: data.message?.items?.length ? 0.9 : 0.5,
          title: data.message?.items?.[0]?.title?.[0] || "CrossRef 결과 없음",
        }),
      },
      {
        name: "OpenAlex",
        url: `https://api.openalex.org/works?search=${encodedQuery}`,
        parseFn: (data) => ({
          score: data.results?.length ? 0.85 : 0.4,
          title: data.results?.[0]?.title || "OpenAlex 결과 없음",
        }),
      },
      {
        name: "GDELT",
        url: `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodedQuery}&format=json`,
        parseFn: (data) => ({
          score: data.articles?.length ? 0.8 : 0.4,
          title: data.articles?.[0]?.title || "GDELT 결과 없음",
        }),
      },
      {
        name: "Wikidata",
        url: `https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encodedQuery}`,
        parseFn: (data) => ({
          score: data.search?.length ? 0.7 : 0.3,
          title: data.search?.[0]?.label || "Wikidata 결과 없음",
        }),
      },
      {
        name: "Naver",
        url: `https://openapi.naver.com/v1/search/news.json?query=${encodedQuery}`,
        parseFn: (data) => ({
          score: data.items?.length ? 0.75 : 0.35,
          title: data.items?.[0]?.title?.replace(/<[^>]*>/g, "") || "Naver 결과 없음",
        }),
      },
    ];

    // ──────────────── ④ K-Law 검증 포함
    const klawUrl = `https://www.law.go.kr/DRF/lawSearch.do?target=law&type=json&OC=${encodeURIComponent(
      process.env.KLAW_USERID || "demoUser"
    )}&query=${encodedQuery}`;
    engines.push({
      name: "KLaw",
      url: klawUrl,
      parseFn: (data) => ({
        score: data.LAWDATA_LIST?.length ? 0.8 : 0.4,
        title: data.LAWDATA_LIST?.[0]?.법령명한글 || "K-Law 결과 없음",
      }),
    });

    const engineResults = await Promise.all(
      engines.map(e => queryEngine(e.name, e.url, e.parseFn))
    );

    const truthEval = evaluateResults(engineResults);
    const elapsed = `${Date.now() - start} ms`;
    // ──────────────── ⑤ Gemini-Pro 평가 (응답 + 엔진 검증 결과 종합)
    const evalUrl = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_PRO}:generateContent?key=${gemini_key}`;
    const evalPrompt = `
다음은 AI가 생성한 응답과 검증엔진들이 반환한 결과입니다.
출처 신뢰도와 일관성을 바탕으로 전체 응답의 신뢰성을 평가하세요.

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

    // ──────────────── ⑥ 결과 반환
    return res.status(200).json({
      success: true,
      mode,
      chain: true,
      elapsed,
      query,
      keywords,
      models: {
        main: MODEL_FLASH,
        keyword: MODEL_LITE,
        evaluator: MODEL_PRO,
      },
      steps: {
        main: mainText,
        eval: evalText,
      },
      engines: engineResults,
      truthScore: truthEval.truthScore,
      adjustedScore: truthEval.adjustedScore,
      status: truthEval.status,
      sources: truthEval.sources,
      message: "✅ 교차검증 완료 + 실제 엔진 검증 반영",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[VerifyChainError]", err);
    res.status(500).json({
      success: false,
      message: "❌ 서버 처리 중 예외 발생",
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
    if (process.env.LOG_HEALTH_PINGS !== "false")
      console.log(`💓 Keep-alive ping: ${res.status}`);
  } catch (e) {
    if (DEV_MODE) console.warn("⚠️ Ping 실패:", e.message);
  }
}, pingInterval);

// ─────────────────────────────
// SPA Routing & Server Start
// ─────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(webDir, "index.html")));

app.listen(PORT, () => {
  console.log(`🚀 Proxy ${APP_VERSION} running on port ${PORT} | DEV_MODE: ${DEV_MODE}`);
  if (DEV_MODE) console.log("🔍 TruthScore 및 교차검증 모듈 활성화됨");
});
