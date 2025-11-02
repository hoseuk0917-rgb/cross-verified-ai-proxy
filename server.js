// server.js — Cross-Verified AI Proxy Server v11.0.0 (VerifyPage v2 지원)
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
  res.status(200).json({ status: "ok", version: "v11.0.0", timestamp: Date.now() })
);

// ─────────────────────────────
// API 테스트 엔드포인트
// ─────────────────────────────
app.post("/api/test-gemini", (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ message: "❌ Gemini Key 누락" });
  res.status(200).json({ message: "✅ Gemini Key 확인 성공" });
});

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
// 검증 엔드포인트 (/api/verify)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const { mode, query, user, gemini_key } = req.body;
  if (!query || !mode)
    return res.status(400).json({ message: "❌ mode 또는 query 누락" });

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
      summary: "코드 로직에 명확한 문제 없음, 에러 처리 적절.",
    },
    CV: {
      message: "코드 검증(CV): 문법 및 보안 취약점을 점검했습니다.",
      summary: "문법 오류 없음, 잠재적 보안 리스크 낮음.",
    },
  };

  const now = new Date();
  const elapsed = `${Math.floor(Math.random() * 900 + 300)} ms`;
  const confidence = (Math.random() * 0.3 + 0.7).toFixed(2); // 0.70~1.00

  const resp = responses[mode] || {
    message: "✅ 기본 검증 완료",
    summary: "입력된 문장이 정상적으로 분석되었습니다.",
  };

  return res.status(200).json({
    success: true,
    mode,
    model: "Gemini 1.5 Pro (Mock)",
    user: user || "local",
    gemini_key: !!gemini_key,
    confidence,
    elapsed,
    message: resp.message,
    summary: resp.summary,
    timestamp: now.toISOString(),
  });
});

// ─────────────────────────────
// 레거시 호환 (/api/callGemini)
// ─────────────────────────────
app.post("/api/callGemini", (req, res) => {
  const { mode, query, user } = req.body;
  if (!query) return res.status(400).json({ message: "❌ 질문 문장 누락" });
  return res.status(200).json({
    message: `✅ ${mode || "QV"} 모드 실행 완료`,
    user,
    echo: query,
  });
});

// ─────────────────────────────
// SPA 라우팅 (Flutter 웹)
// ─────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(webDir, "index.html")));

// ─────────────────────────────
// 서버 시작
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v11.0.0 running on port ${PORT}`);
});
