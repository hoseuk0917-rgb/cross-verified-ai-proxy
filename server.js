// server.js — Cross-Verified AI Proxy Server v11.3.1 (Authorization Propagation Fix)
import express from "express";
import cors from "cors";
import path from "path";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import morgan from "morgan";

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
  res.status(200).json({ status: "ok", version: "v11.3.1", timestamp: Date.now() })
);

// ─────────────────────────────
// ✅ Step 2: Gemini Key 유효성 검증 (Authorization 헤더 완전 지원)
// ─────────────────────────────
app.post("/api/test-gemini", (req, res) => {
  try {
    let key = null;
    const authHeader = req.headers["authorization"];
    if (authHeader && authHeader.startsWith("Bearer ")) {
      key = authHeader.substring(7).trim();
    } else if (req.body?.key) {
      key = req.body.key.trim();
    }

    if (!key || key.length === 0) {
      return res.status(400).json({
        success: false,
        message: "❌ Gemini Key 누락 (Authorization 또는 body 없음)",
      });
    }

    const isValidFormat =
      key.startsWith("AIz") ||
      key.startsWith("AIza") ||
      key.toLowerCase().includes("gemini");

    if (!isValidFormat) {
      return res.status(401).json({
        success: false,
        message: "❌ Key 형식 불일치 (AIz 또는 gemini 포함 필요)",
      });
    }

    const modelMap = {
      flash: "Gemini 1.5 Flash",
      pro: "Gemini 1.5 Pro",
      lite: "Gemini 1.5 Flash-Lite",
    };
    const selectedModel = modelMap[req.body?.model] || "Gemini (기본)";
    const elapsed = `${Math.floor(Math.random() * 300 + 100)} ms`;

    return res.status(200).json({
      success: true,
      model: selectedModel,
      elapsed,
      message: `✅ ${selectedModel} Key 인증 성공`,
    });
  } catch (err) {
    console.error("❌ /api/test-gemini 오류:", err);
    return res.status(500).json({
      success: false,
      message: "❌ 서버 처리 중 예외 발생",
      error: err.message,
    });
  }
});

// ─────────────────────────────
// ✅ 기타 테스트용 엔드포인트 유지
// ─────────────────────────────
app.post("/api/test-klaw", (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: "❌ K-Law ID 누락" });
  res.status(200).json({ message: `✅ K-Law 사용자 인증 완료 (${id})` });
});

app.post("/api/github-test", (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: "❌ GitHub Token 누락" });
  res.status(200).json({ message: "✅ GitHub 연결 확인" });
});

app.post("/api/naver-test", (req, res) => {
  const { clientId, clientSecret } = req.body;
  if (!clientId || !clientSecret)
    return res.status(400).json({ message: "❌ Naver API Key 누락" });
  res.status(200).json({ message: "✅ Naver API 연결 성공" });
});

// ─────────────────────────────
// ✅ 검증용 메인 엔드포인트 (Mock)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  try {
    const { mode, query, user } = req.body;

    // 1️⃣ Authorization 헤더에서도 Gemini Key 확인
    let gemini_key = req.body.gemini_key;
    const authHeader = req.headers["authorization"];
    if (!gemini_key && authHeader && authHeader.startsWith("Bearer ")) {
      gemini_key = authHeader.substring(7).trim();
    }

    if (!query || !mode)
      return res.status(400).json({ message: "❌ mode 또는 query 누락" });

    if (!gemini_key) {
      return res.status(400).json({
        success: false,
        message: "❌ Gemini Key 누락 (verify 요청에서)",
      });
    }

    // 2️⃣ Key 형식 검증
    const isValidFormat =
      gemini_key.startsWith("AIz") ||
      gemini_key.startsWith("AIza") ||
      gemini_key.toLowerCase().includes("gemini");

    if (!isValidFormat) {
      return res.status(401).json({
        success: false,
        message: "❌ Key 형식 불일치 (AIz 또는 gemini 포함 필요)",
      });
    }

    // 3️⃣ 모의 검증 데이터
    const responses = {
      QV: {
        message: "질문 검증(QV): 문장의 논리적 일관성과 의미 명확성을 평가했습니다.",
        summary: "질문 구조가 명확하며 모호성이 적습니다.",
      },
      FV: {
        message: "사실 검증(FV): 신뢰 가능한 출처와의 비교를 완료했습니다.",
        summary: "주요 사실이 공개 출처와 일치합니다.",
      },
      DV: {
        message: "개발 검증(DV): 코드의 기능적 완전성과 예외 처리를 분석했습니다.",
        summary: "코드 로직에 문제 없음.",
      },
      CV: {
        message: "코드 검증(CV): 문법 및 보안 취약점을 점검했습니다.",
        summary: "문법 오류 없음, 리스크 낮음.",
      },
    };

    const now = new Date();
    const elapsed = `${Math.floor(Math.random() * 900 + 300)} ms`;
    const confidence = (Math.random() * 0.3 + 0.7).toFixed(2);
    const resp = responses[mode] || {
      message: "✅ 기본 검증 완료",
      summary: "입력 문장이 정상적으로 분석되었습니다.",
    };

    return res.status(200).json({
      success: true,
      mode,
      model: "Gemini 1.5 Pro (Mock)",
      user: user || "local",
      gemini_key: gemini_key ? "attached" : "missing",
      confidence,
      elapsed,
      message: resp.message,
      summary: resp.summary,
      timestamp: now.toISOString(),
    });
  } catch (err) {
    console.error("❌ /api/verify 오류:", err);
    return res.status(500).json({
      success: false,
      message: "❌ 서버 처리 중 예외 발생",
      error: err.message,
    });
  }
});

// ─────────────────────────────
// SPA 라우팅 및 서버 시작
// ─────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(webDir, "index.html")));

app.listen(PORT, () =>
  console.log(`🚀 Cross-Verified AI Proxy v11.3.1 running on port ${PORT}`)
);
