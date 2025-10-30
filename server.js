// server.js (v10.4.2)
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import { verifyEngines } from "./engine/verification.js";
import { calculateTruthScore } from "./engine/truthscore.js";

dotenv.config();
const app = express();
app.use(cors());
app.use(bodyParser.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "default-secret-key";

// =======================
// Health check
// =======================
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    version: "10.4.2",
    timestamp: new Date().toISOString(),
  });
});

// =======================
// 토큰 발급 (개발용)
// =======================
app.post("/auth/dev-token", (req, res) => {
  const { email, name } = req.body;
  if (!email) return res.status(400).json({ success: false, error: "Missing email" });
  const token = jwt.sign({ email, name }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ success: true, token });
});

// =======================
// 토큰 검증
// =======================
app.get("/auth/verify", (req, res) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ success: false, error: "Missing token" });
  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ success: true, user: decoded });
  } catch {
    res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
});

// =======================
// 교차검증 + TruthScore 통합 엔드포인트
// =======================
app.post("/proxy/fulltest", async (req, res) => {
  const header = req.headers.authorization;
  const token = header ? header.split(" ")[1] : null;
  if (!token) return res.status(401).json({ success: false, error: "Missing token" });

  try {
    jwt.verify(token, JWT_SECRET);
    const { query } = req.body;
    if (!query) return res.status(400).json({ success: false, error: "Missing query" });

    const engineResults = await verifyEngines(query);
    const scoreResult = calculateTruthScore(engineResults);

    res.json({
      success: true,
      query,
      timestamp: new Date().toISOString(),
      engines: engineResults,
      truthScore: scoreResult.truthScore,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Proxy server running on port ${PORT}`);
});
