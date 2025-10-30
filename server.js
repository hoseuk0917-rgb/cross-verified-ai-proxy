// server.js (v10.5.3)
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import bodyParser from "body-parser";
import cors from "cors";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import { verifyEngines } from "./engine/verification.js";
import { calculateTruthScore } from "./engine/truthscore.js";

dotenv.config();
const app = express();

// ------------------------------------------------------
// 📂 경로 설정
// ------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ------------------------------------------------------
// 🔧 미들웨어 설정
// ------------------------------------------------------
app.use(cors());
app.use(bodyParser.json());

// 요청 제한 완화 (Render HealthCheck 안정화)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 1000, // 허용 요청 수 확장
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "default-secret-key";

// ------------------------------------------------------
// 🩺 서버 헬스체크
// ------------------------------------------------------
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    version: "10.5.3",
    timestamp: new Date().toISOString(),
  });
});

// ------------------------------------------------------
// 🧩 Flutter 앱 연결 확인
// ------------------------------------------------------
app.get("/api/ping", (req, res) => {
  res.status(200).json({
    message: "✅ Proxy active and responding",
    version: "10.5.3",
    time: new Date().toISOString(),
  });
});

// ------------------------------------------------------
// 🔐 개발용 JWT 토큰 발급
// ------------------------------------------------------
app.post("/auth/dev-token", (req, res) => {
  const { email, name } = req.body;
  if (!email)
    return res.status(400).json({ success: false, error: "Missing email" });

  const token = jwt.sign({ email, name }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ success: true, token });
});

// ------------------------------------------------------
// 🧾 토큰 검증
// ------------------------------------------------------
app.get("/auth/verify", (req, res) => {
  const header = req.headers.authorization;
  if (!header)
    return res.status(401).json({ success: false, error: "Missing token" });

  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ success: true, user: decoded });
  } catch {
    res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
});

// ------------------------------------------------------
// 🤖 교차검증 + TruthScore 통합 엔드포인트
// ------------------------------------------------------
app.post("/proxy/fulltest", async (req, res) => {
  const header = req.headers.authorization;
  const token = header ? header.split(" ")[1] : null;

  if (!token)
    return res.status(401).json({ success: false, error: "Missing token" });

  try {
    jwt.verify(token, JWT_SECRET);
    const { query } = req.body;
    if (!query)
      return res.status(400).json({ success: false, error: "Missing query" });

    const engineResults = await verifyEngines(query);
    const scoreResult = calculateTruthScore(engineResults);

    res.json({
      success: true,
      query,
      timestamp: new Date().toISOString(),
      engines: engineResults,
      truthScore: scoreResult.truthScore,
      truthScoreBreakdown: scoreResult.breakdown,
    });
  } catch (err) {
    console.error("[Proxy Error]", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ------------------------------------------------------
// 🌐 Flutter Web 정적 빌드 서빙
// ------------------------------------------------------
app.use(express.static(path.join(__dirname, "build", "web")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "build", "web", "index.html"));
});

// ------------------------------------------------------
// 🚀 서버 실행
// ------------------------------------------------------
app.listen(PORT, () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
