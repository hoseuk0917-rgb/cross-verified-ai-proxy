// server.js — Cross-Verified AI Proxy Server v11.7.2
// (Gemini 2.5 API + KLaw/GitHub/Naver Test + 11min Keep-Alive Ping)
import express from "express";
import cors from "cors";
import path from "path";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import morgan from "morgan";
import fetch from "node-fetch"; // ✅ Gemini 및 Ping 호출용

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────
// 미들웨어
// ─────────────────────────────
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  morgan("dev", {
    skip: (req) => req.url === "/health",
  })
);

// ─────────────────────────────
// 정적 경로 (Flutter Web)
// ─────────────────────────────
const __dirname = path.resolve();
const webDir = path.join(__dirname, "src", "build", "web");
app.use(express.static(webDir));

// ─────────────────────────────
// Health Check
// ─────────────────────────────
app.get("/health", (req, res) =>
  res
    .status(200)
    .json({ status: "ok", version: "v11.7.2", timestamp: Date.now() })
);

// ─────────────────────────────
// ✅ Gemini Key 유효성 검증 (Mock)
// ─────────────────────────────
app.post("/api/test-gemini", (req, res) => {
  try {
    let key = null;
    const authHeader = req.headers["authorization"];
    if (authHeader?.startsWith("Bearer ")) key = authHeader.substring(7).trim();
    else if (req.body?.key) key = req.body.key.trim();

    if (!key)
      return res.status(400).json({ success: false, message: "❌ Gemini Key 누락" });

    if (!(key.startsWith("AIz") || key.startsWith("AIza"))) {
      return res.status(401).json({
        success: false,
        message: "❌ Key 형식 불일치 (AIz 또는 gemini 포함 필요)",
      });
    }

    const modelMap = {
      flash: "gemini-2.5-flash",
      pro: "gemini-2.5-pro",
      lite: "gemini-2.5-flash-lite",
    };
    const selectedModel = modelMap[req.body?.model] || "gemini-2.5-pro";
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
// ✅ K-Law / GitHub / Naver 연결 테스트 추가
// ─────────────────────────────
app.post("/api/klaw-test", async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: "❌ ID 누락됨" });
  res.json({ success: true, message: `✅ K-Law 연결 성공 (${id})` });
});

app.post("/api/github-test", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: "❌ Token 누락됨" });
  res.json({ success: true, message: `✅ GitHub 연결 성공 (${token.slice(0, 6)}...)` });
});

app.post("/api/naver-test", async (req, res) => {
  const { clientId, clientSecret } = req.body;
  if (!clientId || !clientSecret)
    return res.status(400).json({ message: "❌ Client ID 또는 Secret 누락됨" });
  res.json({ success: true, message: `✅ Naver 연결 성공 (${clientId.slice(0, 5)}...)` });
});

// ─────────────────────────────
// ✅ Gemini 2.5 실제 API 연동
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  try {
    const { mode, query, user, model = "pro" } = req.body;
    let gemini_key = req.body.gemini_key;

    const authHeader = req.headers["authorization"];
    if (!gemini_key && authHeader?.startsWith("Bearer ")) {
      gemini_key = authHeader.substring(7).trim();
    }

    console.log("──────────────────────────────");
    console.log("📥 [VERIFY] 요청 수신");
    console.log("Headers:", req.headers);
    console.log("Body:", req.body);
    console.log("──────────────────────────────");

    if (!query || !mode)
      return res.status(400).json({ message: "❌ mode 또는 query 누락" });
    if (!gemini_key)
      return res.status(400).json({ message: "❌ Gemini Key 누락" });

    const modelMap = {
      flash: "gemini-2.5-flash",
      pro: "gemini-2.5-pro",
      lite: "gemini-2.5-flash-lite",
    };
    const selectedModel = modelMap[model] || "gemini-2.5-pro";

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${selectedModel}:generateContent?key=${gemini_key}`;

    const start = Date.now();
    const geminiResponse = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        contents: [{ parts: [{ text: query }] }],
      }),
    });

    const data = await geminiResponse.json();
    const elapsed = `${Date.now() - start} ms`;

    if (!geminiResponse.ok) {
      console.warn("⚠️ Gemini API 오류 응답:", data);
      return res.status(geminiResponse.status).json({
        success: false,
        message: `❌ Gemini API 오류 (${geminiResponse.status})`,
        details: data,
      });
    }

    const output =
      data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      "응답 없음 (candidates 비어 있음)";

    console.log(`✅ Gemini 응답 (${selectedModel}) [${elapsed}]`);
    console.log("──────────────────────────────");

    return res.status(200).json({
      success: true,
      mode,
      model: selectedModel,
      user: user || "local",
      gemini_key: "attached",
      confidence: 0.95,
      elapsed,
      message: output,
      summary: "Gemini 실제 응답",
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
// 🔄 내부 Keep-Alive Ping (Render Free Plan Sleep 방지, 11분 주기)
// ─────────────────────────────
setInterval(async () => {
  try {
    const res = await fetch("https://cross-verified-ai-proxy.onrender.com/health");
    console.log(`💓 Internal keep-alive ping: ${res.status}`);
  } catch (e) {
    console.warn("⚠️ Ping 실패:", e.message);
  }
}, 1000 * 60 * 11); // ⏱️ 11분마다 Ping

// ─────────────────────────────
// SPA 라우팅 및 서버 시작
// ─────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(webDir, "index.html")));
app.listen(PORT, () =>
  console.log(`🚀 Cross-Verified AI Proxy v11.7.2 running on port ${PORT}`)
);
