// ✅ Cross-Verified AI Proxy Server v12.2.0
// (실제 연동 Full Version: Gemini + 6엔진 + TruthScore + Elapsed Time)

import cors from "cors";
import express from "express";
import path from "path";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import morgan from "morgan";
import fetch from "node-fetch";
import https from "https";
import fs from "fs";

// ─────────────────────────────
// ① 환경설정
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
const APP_VERSION = "v12.2.0";
const DEV_MODE = process.env.DEV_MODE === "true";
const agent = new https.Agent({ keepAlive: true, maxSockets: 10, keepAliveMsecs: 60000 });

// ─────────────────────────────
// ② TruthScore 계산 모듈
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
      title: e.title || "출처 없음",
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
// ③ Middleware
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
  app.use(morgan("dev"));
}

// Static Web
const __dirname = path.resolve();
const webDir = path.join(__dirname, "src", "build", "web");
app.use(express.static(webDir));

// Health Check
app.get("/health", (req, res) =>
  res.status(200).json({ status: "ok", version: APP_VERSION, timestamp: Date.now() })
);
// ─────────────────────────────
// ✅ Gemini / 엔진 실연동 라우트
// ─────────────────────────────

// 🔹 Gemini Key 유효성 검사
app.post("/api/test-gemini", async (req, res) => {
  try {
    const { key, model = "gemini-2.5-flash" } = req.body;
    const testUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
    const r = await fetch(testUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: [{ parts: [{ text: "ping" }] }] }),
    });
    if (r.status === 200) return res.json({ success: true, message: "✅ Gemini 연결 성공" });
    else return res.status(400).json({ success: false, message: `❌ ${r.status} 응답` });
  } catch (e) {
    res.status(500).json({ success: false, message: `❌ 오류: ${e.message}` });
  }
});

// 🔹 K-Law 연결 테스트
app.post("/api/klaw-test", async (req, res) => {
  try {
    const { klawId } = req.body;
    const url = `https://www.law.go.kr/DRF/lawSearch.do?OC=${klawId}&target=law&type=json&query=항공`;
    const r = await fetch(url);
    if (r.ok) {
      const d = await r.json();
      const hasData = d.LAWDATA_LIST?.length > 0;
      res.json({ success: hasData, message: hasData ? "✅ K-Law 연결 성공" : "⚠️ 결과 없음" });
    } else res.status(400).json({ success: false, message: "❌ 연결 실패" });
  } catch (e) {
    res.status(500).json({ success: false, message: `❌ 오류: ${e.message}` });
  }
});

// 🔹 GitHub 연결 테스트
app.post("/api/github-test", async (req, res) => {
  try {
    const { token } = req.body;
    const r = await fetch("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (r.ok) {
      const data = await r.json();
      res.json({ success: true, user: data.login, message: "✅ GitHub 연결 성공" });
    } else res.status(400).json({ success: false, message: "❌ GitHub 토큰 오류" });
  } catch (e) {
    res.status(500).json({ success: false, message: `❌ 오류: ${e.message}` });
  }
});

// 🔹 Naver 연결 테스트
app.post("/api/naver-test", async (req, res) => {
  try {
    const { clientId, clientSecret } = req.body;
    const r = await fetch(`https://openapi.naver.com/v1/search/news.json?query=UAM`, {
      headers: {
        "X-Naver-Client-Id": clientId,
        "X-Naver-Client-Secret": clientSecret,
      },
    });
    if (r.ok) {
      const data = await r.json();
      const count = data.items?.length || 0;
      res.json({ success: true, message: `✅ Naver 연결 성공 (${count}건)` });
    } else res.status(400).json({ success: false, message: "❌ Naver 인증 실패" });
  } catch (e) {
    res.status(500).json({ success: false, message: `❌ 오류: ${e.message}` });
  }
});

// ─────────────────────────────
// ✅ /api/verify — 실제 교차검증 수행
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  try {
    const { mode, query, model = "gemini-2.5-pro", key, naverId, naverSecret, klawId } = req.body;
    if (!query || !key) return res.status(400).json({ message: "❌ 요청 누락" });
    const start = Date.now();

    // ──────────────── Gemini 응답 생성
    const mainUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
    const gRes = await fetch(mainUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: `질문: ${query}\n명확하고 근거 기반으로 답변.` }] }],
      }),
    });
    const gData = await gRes.json();
    const mainText = gData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "응답 없음";

    // ──────────────── 키워드 추출
    const kwUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=${key}`;
    const kwRes = await fetch(kwUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: `다음 문장에서 핵심 키워드 3~5개 추출:\n${mainText}` }] }],
      }),
    });
    const kwData = await kwRes.json();
    const keywords = (kwData?.candidates?.[0]?.content?.parts?.[0]?.text || "")
      .replace(/\n/g, "")
      .split(",")
      .map(k => k.trim())
      .filter(Boolean);
    // ──────────────── 교차검증 엔진 호출
    async function queryEngine(name, url, parseFn) {
      try {
        const r = await fetch(url, { agent });
        if (!r.ok) return { name, score: 0, title: `${name} 연결 실패` };
        const d = await r.json();
        const parsed = parseFn(d);
        return { name, ...parsed };
      } catch (e) {
        return { name, score: 0, title: `${name} 오류: ${e.message}` };
      }
    }

    // ──────────────── 엔진 URL 구성
    const encoded = encodeURIComponent(keywords.join(" ") || query);
    const engines = [
      {
        name: "CrossRef",
        url: `https://api.crossref.org/works?query=${encoded}&rows=2`,
        parseFn: (d) => ({
          score: d.message?.items?.length ? 0.9 : 0.5,
          title: d.message?.items?.[0]?.title?.[0] || "CrossRef 결과 없음",
        }),
      },
      {
        name: "OpenAlex",
        url: `https://api.openalex.org/works?search=${encoded}`,
        parseFn: (d) => ({
          score: d.results?.length ? 0.85 : 0.4,
          title: d.results?.[0]?.title || "OpenAlex 결과 없음",
        }),
      },
      {
        name: "GDELT",
        url: `https://api.gdeltproject.org/api/v2/doc/doc?query=${encoded}&format=json`,
        parseFn: (d) => ({
          score: d.articles?.length ? 0.8 : 0.4,
          title: d.articles?.[0]?.title || "GDELT 결과 없음",
        }),
      },
      {
        name: "Wikidata",
        url: `https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encoded}`,
        parseFn: (d) => ({
          score: d.search?.length ? 0.7 : 0.3,
          title: d.search?.[0]?.label || "Wikidata 결과 없음",
        }),
      },
    ];

    // ──────────────── Naver News 검색 (키 필요)
    if (naverId && naverSecret) {
      engines.push({
        name: "Naver",
        url: `https://openapi.naver.com/v1/search/news.json?query=${encoded}`,
        parseFn: (d) => ({
          score: d.items?.length ? 0.75 : 0.35,
          title: d.items?.[0]?.title?.replace(/<[^>]*>/g, "") || "Naver 결과 없음",
        }),
      });
    }

    // ──────────────── K-Law 검색 (OC ID 필요)
    if (klawId) {
      engines.push({
        name: "KLaw",
        url: `https://www.law.go.kr/DRF/lawSearch.do?target=law&type=json&OC=${klawId}&query=${encoded}`,
        parseFn: (d) => ({
          score: d.LAWDATA_LIST?.length ? 0.8 : 0.4,
          title: d.LAWDATA_LIST?.[0]?.법령명한글 || "K-Law 결과 없음",
        }),
      });
    }

    // 병렬 호출
    const engineResults = await Promise.all(
      engines.map((e) => queryEngine(e.name, e.url, e.parseFn))
    );

    // TruthScore 계산
    const truthEval = evaluateResults(engineResults);
    const elapsed = `${Date.now() - start} ms`;

    // ──────────────── Gemini Pro 평가 (신뢰성 문장 작성)
    const evalPrompt = `
질문: ${query}
응답: ${mainText}
핵심 키워드: ${keywords.join(", ")}
검증엔진 결과:
${engineResults
  .map((e) => `- ${e.name}: ${e.title} (신뢰도 ${e.score.toFixed(2)})`)
  .join("\n")}
`;

    let evalText = "";
    try {
      const evalUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=${key}`;
      const eRes = await fetch(evalUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: evalPrompt }] }],
        }),
      });
      const eData = await eRes.json();
      evalText =
        eData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ||
        "(평가 결과 없음)";
    } catch (err) {
      evalText = `(평가 오류: ${err.message})`;
    }

    // ──────────────── 최종 결과 반환
    res.status(200).json({
      success: true,
      mode,
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
      message: "✅ 실제 교차검증 완료",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[VerifyError]", err);
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
setInterval(async () => {
  try {
    const r = await fetch("https://cross-verified-ai-proxy.onrender.com/health", { agent });
    console.log(`💓 Ping: ${r.status}`);
  } catch (e) {
    if (DEV_MODE) console.warn("⚠️ Ping 실패:", e.message);
  }
}, 600000); // 10 분

// ─────────────────────────────
// SPA Routing + 서버 시작
// ─────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(webDir, "index.html")));

app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy ${APP_VERSION} 실행 중 (port=${PORT})`);
  if (DEV_MODE) console.log("🔍 개발 모드 활성화됨");
});
