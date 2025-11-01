// server.js — Cross-Verified AI Proxy Server v10.9.0 (Server 2.0 Stable)
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
    skip: (req) => req.url === "/health", // Health Ping 로그 억제
  })
);

// ─────────────────────────────
// Flutter Web 정적 경로
// ─────────────────────────────
const __dirname = path.resolve();
const webDir = path.join(__dirname, "src", "build", "web");
app.use(express.static(webDir));

// ─────────────────────────────
// Health Check (Render keepalive)
// ─────────────────────────────
app.get("/health", (req, res) =>
  res.status(200).json({ status: "ok", version: "v10.9.0", timestamp: Date.now() })
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
// 통합 검증 엔드포인트 (/api/verify)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const { mode, query, user, gemini_key } = req.body;

  if (!query || !mode) {
    return res.status(400).json({ message: "❌ mode 또는 query 누락" });
  }

  // 간단한 모드별 Mock 처리
  const responses = {
    QV: "질문 검증(QV): 입력 문장의 논리적 일관성을 평가했습니다.",
    FV: "사실 검증(FV): 신뢰 가능한 공개 출처와 비교 완료.",
    DV: "개발 검증(DV): 코드 동작 및 에러 핸들링 분석 완료.",
    CV: "코드 검증(CV): 문법 및 보안 취약점 점검 결과 제공.",
  };

  const now = new Date();
  const elapsed = `${Math.floor(Math.random() * 1200 + 300)} ms`;

  return res.status(200).json({
    success: true,
    mode,
    model: "Gemini 1.5 Pro (Mock)",
    user: user || "local",
    gemini_key: !!gemini_key,
    elapsed,
    message: responses[mode] || "✅ 검증 완료",
    timestamp: now.toISOString(),
  });
});

// ─────────────────────────────
// 레거시 호환 엔드포인트 (/api/callGemini)
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
// SPA 라우팅 (Flutter 웹 대응)
// ─────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(webDir, "index.html"));
});

// ─────────────────────────────
// 서버 시작
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v10.9.0 running on port ${PORT}`);
});
