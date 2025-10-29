/**
 * Cross-Verified AI Proxy Server v10.0.0
 * -------------------------------------
 * Features:
 * ✅ Express 기반 서버
 * ✅ Google OAuth 로그인 + JWT 발급
 * ✅ JWT 토큰 검증 미들웨어 (API 보호)
 * ✅ Gemini API 엔진
 * ✅ /api/verify/:engine, /api/verify/all 보호 적용
 */

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const path = require("path");
require("dotenv").config();

// -------------------------------
// 🔹 Express 초기 설정
// -------------------------------
const app = express();
app.use(cors());
app.use(bodyParser.json());

// -------------------------------
// 🔹 세션 & Passport 초기화
// -------------------------------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "session_secret_key",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// -------------------------------
// 🔹 Google OAuth 설정
// -------------------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:
        process.env.GOOGLE_CALLBACK_URL ||
        "https://cross-verified-ai-proxy.onrender.com/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      const user = {
        id: profile.id,
        displayName: profile.displayName,
        email: profile.emails[0].value,
      };
      return done(null, user);
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// -------------------------------
// 🔹 JWT 미들웨어
// -------------------------------
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token)
    return res.status(401).json({ success: false, error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwt_secret");
    req.user = decoded;
    next();
  } catch (error) {
    return res
      .status(403)
      .json({ success: false, error: "Invalid or expired token" });
  }
};

// -------------------------------
// 🔹 Health Check
// -------------------------------
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    version: "10.0.0",
    timestamp: new Date().toISOString(),
  });
});

// -------------------------------
// 🔹 Google OAuth 라우트
// -------------------------------
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/fail" }),
  (req, res) => {
    const user = req.user;
    const token = jwt.sign(
      { email: user.email, name: user.displayName },
      process.env.JWT_SECRET || "jwt_secret",
      { expiresIn: "2h" }
    );

    res.json({ success: true, token, user });
  }
);

app.get("/auth/fail", (req, res) =>
  res.status(401).json({ success: false, error: "Authentication failed" })
);

// JWT 검증 API
app.get("/auth/verify", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token)
    return res.status(401).json({ success: false, error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwt_secret");
    res.json({ success: true, user: decoded });
  } catch (error) {
    res.status(403).json({ success: false, error: "Invalid token" });
  }
});

// -------------------------------
// 🔹 Gemini 엔진 (샘플 버전)
// -------------------------------
const { callGemini } = require("./engine/gemini");

app.post("/api/gemini/generate", async (req, res) => {
  try {
    const { apiKey, model, prompt } = req.body;
    const result = await callGemini({ apiKey, model, prompt });
    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// -------------------------------
// 🔹 엔진 보호 구간 (/api/verify/*)
// -------------------------------
const verification = require("./engine/verification");

app.post("/api/verify/:engine", authMiddleware, async (req, res) => {
  try {
    const { engine } = req.params;
    const { query } = req.body;
    const result = await verification.verifySingleEngine(engine, query);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/api/verify/all", authMiddleware, async (req, res) => {
  try {
    const { query } = req.body;
    const result = await verification.verifyAllEngines(query);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// -------------------------------
// 🔹 서버 실행
// -------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
