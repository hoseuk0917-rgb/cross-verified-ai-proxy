/**
 * Cross-Verified AI Proxy Server (Render Edition)
 * v8.6.5 Operational Secure Edition
 * by hoseuk0917-rgb
 */

import express from "express";
import cors from "cors";
import helmet from "helmet";
import crypto from "crypto";
import rateLimit from "express-rate-limit";

const app = express();

// ✅ Middleware
app.use(express.json({ limit: "1mb" }));
app.use(cors());
app.use(helmet());

// ✅ 환경변수 PORT (Render에서 자동 주입)
const PORT = process.env.PORT || 10000;

// ✅ 보안 키 (Render Environment Variables에서 설정해야 함)
const JWT_SECRET = process.env.JWT_SECRET || "default_jwt_secret";
const HMAC_SECRET = process.env.HMAC_SECRET || "default_hmac_secret";
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || "*";

// ✅ Rate Limiter (Render Free Tier 안전 범위)
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1분
  max: 30, // 분당 30회 제한
  message: "Too many requests from this IP. Please try again later.",
});
app.use(limiter);

// ✅ HMAC 검증 미들웨어
app.use((req, res, next) => {
  const signature = req.headers["x-app-signature"];
  if (!signature) return next();

  const body = JSON.stringify(req.body);
  const timestamp = req.headers["x-timestamp"] || "";
  const computed = crypto
    .createHmac("sha256", HMAC_SECRET)
    .update(body + timestamp)
    .digest("hex");

  if (signature !== computed) {
    console.warn("⚠️ Invalid HMAC signature detected.");
    return res.status(403).json({ error: "Invalid signature" });
  }
  next();
});

// ✅ 기본 라우트 (테스트용)
app.get("/", (req, res) => {
  res.send({
    message: "✅ Cross-Verified AI Proxy Server is running successfully.",
    version: "v8.6.5",
    timestamp: new Date().toISOString(),
  });
});

// ✅ Health Check (Render가 서버 정상 여부 확인)
app.get("/healthz", (req, res) => {
  res.status(200).send("OK");
});

// ✅ Proxy 테스트용 엔드포인트 (예시)
app.post("/api/verify", (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "No text provided" });

  res.json({
    verified: true,
    text,
    timestamp: new Date().toISOString(),
  });
});

// ✅ 서버 실행
app.listen(PORT, () => {
  console.log(`🚀 Proxy running on port ${PORT}`);
  console.log(`✅ Health check ready at /healthz`);
});
