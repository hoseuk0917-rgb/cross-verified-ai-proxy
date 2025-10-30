/**
 * Cross-Verified AI Proxy Server v10.3.0
 * Basic Auth + JWT + Health endpoints
 */

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const rateLimit = require("express-rate-limit");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// ✅ Health Check
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    version: "10.3.0",
    timestamp: new Date().toISOString(),
  });
});

// ✅ Dev Token 발급 (테스트용)
app.post("/auth/dev-token", (req, res) => {
  const { email, name } = req.body;
  if (!email || !name) {
    return res.status(400).json({ success: false, error: "Missing email or name" });
  }

  try {
    const token = jwt.sign({ email, name }, process.env.JWT_SECRET || "default_secret", {
      expiresIn: "2h",
    });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ JWT 토큰 검증
app.get("/auth/verify", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ success: false, error: "Missing Authorization header" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "default_secret");
    res.json({ success: true, user: decoded });
  } catch (err) {
    res.status(401).json({ success: false, error: err.message });
  }
});

// ✅ 기본 라우트
app.get("/", (req, res) => {
  res.send("✅ Cross-Verified AI Proxy v10.3.0 running.");
});

// ✅ 404 핸들러
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
