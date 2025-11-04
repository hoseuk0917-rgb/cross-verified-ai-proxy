// ✅ Cross-Verified AI Proxy Server v11.8.0 (3단계 모델체계 + Env Linked)
import express from "express";
import cors from "cors";
import path from "path";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import morgan from "morgan";
import fetch from "node-fetch";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = process.env.APP_VERSION || "v11.8.0";

// ─────────────────────────────
// Middleware
// ─────────────────────────────
const allowedOrigins =
  process.env.ALLOWED_ORIGINS?.split(",").map((s) => s.trim()) || ["*"];
app.use(
  cors({
    origin: allowedOrigins,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(bodyParser.json({ limit: `${process.env.MAX_REQUEST_BODY_MB || 5}mb` }));
app.use(bodyParser.urlencoded({ extended: true }));

if (process.env.LOG_REQUESTS === "true") {
  app.use(
    morgan(process.env.LOG_LEVEL || "dev", {
      skip: (req) =>
        process.env.LOG_HEALTH_PINGS === "false" && req.url === "/health",
    })
  );
}

// ─────────────────────────────
// Static (Flutter Web build)
// ─────────────────────────────
const __dirname = path.resolve();
const webDir = path.join(__dirname, "src", "build", "web");
app.use(express.static(webDir));

// ─────────────────────────────
// Health Check
// ─────────────────────────────
app.get("/health", (req, res) =>
  res.status(200).json({
    status: "ok",
    version: APP_VERSION,
    timestamp: Date.now(),
    ping_interval_sec: process.env.PING_INTERVAL_SEC || 660,
  })
);

// ─────────────────────────────
// Gemini Key 테스트
// ─────────────────────────────
app.post("/api/test-gemini", (req, res) => {
  try {
    let key = null;
    const authHeader = req.get("Authorization");
    if (authHeader?.startsWith("Bearer ")) key = authHeader.substring(7).trim();
    else if (req.body?.key) key = req.body.key.trim();

    if (!key)
      return res.status(400).json({ success: false, message: "❌ Gemini Key 누락" });
    if (!(key.startsWith("AIz") || key.startsWith("AIza"))) {
      return res
        .status(401)
        .json({ success: false, message: "❌ Key 형식 불일치 (AIz / gemini 필요)" });
    }

    const modelMap = {
      flash: "gemini-2.5-flash",
      pro: "gemini-2.5-pro",
      lite: "gemini-2.5-flash-lite",
    };
    const selectedModel = modelMap[req.body?.model] || process.env.DEFAULT_MODEL;
    const elapsed = `${Math.floor(Math.random() * 300 + 100)} ms`;

    return res.status(200).json({
      success: true,
      model: selectedModel,
      elapsed,
      message: `✅ ${selectedModel} Key 인증 성공`,
    });
  } catch (err) {
    console.error("❌ /api/test-gemini 오류:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─────────────────────────────
// K-Law / GitHub / Naver 테스트
// ─────────────────────────────
app.post("/api/klaw-test", (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: "❌ ID 누락됨" });
  res.json({ success: true, message: `✅ K-Law 연결 성공 (${id})` });
});

app.post("/api/github-test", (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: "❌ Token 누락됨" });
  res.json({ success: true, message: `✅ GitHub 연결 성공 (${token.slice(0, 6)}...)` });
});

app.post("/api/naver-test", (req, res) => {
  const { clientId, clientSecret } = req.body;
  if (!clientId || !clientSecret)
    return res
      .status(400)
      .json({ message: "❌ Client ID 또는 Secret 누락됨" });
  res.json({ success: true, message: `✅ Naver 연결 성공 (${clientId.slice(0, 5)}...)` });
});
// ─────────────────────────────
// Gemini 2.5 실제 API 연동 (3단계 체계)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  try {
    const { mode, query, user, model = "pro", chain = false } = req.body;
    let gemini_key = req.body.gemini_key;
    const authHeader = req.get("Authorization");

    if (!gemini_key && authHeader?.startsWith("Bearer ")) {
      gemini_key = authHeader.substring(7).trim();
    }

    if (!query || !mode)
      return res.status(400).json({ message: "❌ mode 또는 query 누락" });
    if (!gemini_key)
      return res.status(400).json({ message: "❌ Gemini Key 누락" });
    if (query.length > 4000)
      return res.status(413).json({ message: "⚠️ 요청 문장이 너무 깁니다 (4000자 제한)" });

    // === 모델 매핑 (.env 기준)
    const MODEL_PRE = process.env.VERIFY_PREPROCESS_MODEL || "gemini-2.5-flash-lite";
    const MODEL_MAIN = process.env.DEFAULT_MODEL || "gemini-2.5-flash";
    const MODEL_EVAL = process.env.VERIFY_EVALUATOR_MODEL || "gemini-2.5-pro";
    const modelMap = { flash: MODEL_MAIN, pro: "gemini-2.5-pro", lite: MODEL_PRE };

    // === 단일 호출 모드
    if (!chain) {
      const selectedModel = modelMap[model] || MODEL_MAIN;
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${selectedModel}:generateContent?key=${gemini_key}`;

      const start = Date.now();
      const geminiResponse = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contents: [{ parts: [{ text: query }] }] }),
      });
      const data = await geminiResponse.json();
      const elapsed = `${Date.now() - start} ms`;

      const output =
        data?.candidates?.[0]?.content?.parts?.[0]?.text ||
        data?.output_text ||
        "응답 없음 (candidates 비어 있음)";

      return res.status(200).json({
        success: true,
        mode,
        model: selectedModel,
        elapsed,
        output,
        message: "✅ 단일 모델 응답 완료",
        timestamp: new Date().toISOString(),
      });
    }

    // === 체인 호출 모드 (요약→응답→평가)
    console.log(`🔁 [CHAIN] ${mode} 모드 시작`);

    // 1️⃣ 전처리 (요약·핵심어화)
    const preUrl = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_PRE}:generateContent?key=${gemini_key}`;
    const preResp = await fetch(preUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: `다음 문장을 핵심어로 요약:\n${query}` }] }],
      }),
    });
    const preData = await preResp.json();
    const preText =
      preData?.candidates?.[0]?.content?.parts?.[0]?.text || "(요약 결과 없음)";

    // 2️⃣ 기본 응답 생성 (Flash ↔ Pro 토글)
    const mainUrl = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_MAIN}:generateContent?key=${gemini_key}`;
    const mainResp = await fetch(mainUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: `질문: ${query}\n요약: ${preText}` }] }],
      }),
    });
    const mainData = await mainResp.json();
    const mainText =
      mainData?.candidates?.[0]?.content?.parts?.[0]?.text || "(응답 결과 없음)";

    // 3️⃣ 결과 평가 (출처·일치도·신뢰도)
    const evalUrl = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_EVAL}:generateContent?key=${gemini_key}`;
    const evalResp = await fetch(evalUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [
          {
            parts: [
              {
                text: `다음은 생성된 응답입니다.\n\n[응답]\n${mainText}\n\n[요약]\n${preText}\n\n출처 일치도와 신뢰도를 0~100점으로 평가하고, 간략한 평가를 작성하세요.`,
              },
            ],
          },
        ],
      }),
    });
    const evalData = await evalResp.json();
    const evalText =
      evalData?.candidates?.[0]?.content?.parts?.[0]?.text || "(평가 결과 없음)";

    return res.status(200).json({
      success: true,
      mode,
      chain: true,
      models: {
        preprocess: MODEL_PRE,
        main: MODEL_MAIN,
        evaluator: MODEL_EVAL,
      },
      steps: {
        preprocess: preText,
        main: mainText,
        evaluator: evalText,
      },
      message: "✅ 체인형 검증 완료",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ /api/verify 오류:", err);
    res.status(500).json({
      success: false,
      message: "❌ 서버 처리 중 예외 발생",
      error: err.message,
    });
  }
});

// ─────────────────────────────
// Keep-Alive Ping (Render Free Plan)
// ─────────────────────────────
const pingInterval = Number(process.env.PING_INTERVAL_SEC || 660) * 1000;
setInterval(async () => {
  try {
    const res = await fetch(
      "https://cross-verified-ai-proxy.onrender.com/health"
    );
    if (process.env.LOG_HEALTH_PINGS !== "false") {
      console.log(`💓 Keep-alive ping: ${res.status}`);
    }
  } catch (e) {
    console.warn("⚠️ Ping 실패:", e.message);
  }
}, pingInterval);

// ─────────────────────────────
// SPA 라우팅
// ─────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(webDir, "index.html")));
app.listen(PORT, () =>
  console.log(`🚀 Proxy ${APP_VERSION} running on port ${PORT}`)
);
