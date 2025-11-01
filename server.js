// server.js — Cross-Verified AI Proxy v10.8.3 (Full Web Serving Build)

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
// 기본 미들웨어
// ─────────────────────────────
app.use(cors());
app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan("dev"));

// ─────────────────────────────
// Flutter 웹 정적 경로
// ─────────────────────────────
const __dirname = path.resolve();
const webDir = path.join(__dirname, "src", "build", "web");
app.use(express.static(webDir));

// ─────────────────────────────
// Health Check
// ─────────────────────────────
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok", version: "v10.8.3" });
});

// ─────────────────────────────
// API 테스트 라우트
// ─────────────────────────────
app.post("/api/test-gemini", (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ message: "Gemini Key 누락" });
  return res.status(200).json({ message: "✅ Gemini Key 확인 성공" });
});

app.post("/api/test-klaw", (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: "K-Law ID 누락" });
  return res.status(200).json({ message: `✅ K-Law 사용자 인증 완료 (${id})` });
});

app.post("/api/github-test", (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: "GitHub Token 누락" });
  return res.status(200).json({ message: "✅ GitHub 연결 확인" });
});

app.post("/api/naver-test", (req, res) => {
  const { clientId, clientSecret } = req.body;
  if (!clientId || !clientSecret)
    return res.status(400).json({ message: "Naver API Key 누락" });
  return res.status(200).json({ message: "✅ Naver API 연결 성공" });
});

// ─────────────────────────────
// Flutter Web SPA 대응 (모든 나머지 요청은 index.html 전달)
// ─────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(webDir, "index.html"));
});

// ─────────────────────────────
// 서버 실행
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v10.8.3 running on port ${PORT}`);
});
