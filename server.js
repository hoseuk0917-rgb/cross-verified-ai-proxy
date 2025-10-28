/**
 * Cross-Verified AI Proxy Server (Full Integrated Version)
 * Features:
 *  - Google OAuth 2.0 Authentication
 *  - Gemini 2.5 Flash/Pro API
 *  - TruthScore Engine
 *  - Cross Verification (CrossRef, OpenAlex, GDELT, Wikidata, Naver, K-Law, GitHub)
 *  - PostgreSQL Database Integration
 *  - CORS & Secure Session Handling
 */

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const axios = require("axios");
const cors = require("cors");
const { Pool } = require("pg");

// 엔진 로드
const geminiEngine = require("./engine/gemini");
const truthscoreEngine = require("./engine/truthscore");
const verificationEngine = require("./engine/verification");

// DB 연결
const pool = new Pool({
  connectionString: process.env.DATABASE_URL_INTERNAL,
  ssl: { rejectUnauthorized: false },
});

const app = express();
app.use(express.json());
app.use(cors({ origin: "*", credentials: true }));

// 세션 설정
app.use(
  session({
    secret: process.env.SESSION_SECRET || "cross-verified-ai",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// --- GOOGLE OAUTH 설정 ---
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => done(null, profile)
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/auth/failure",
    successRedirect: "/auth/success",
  })
);

app.get("/auth/success", (req, res) => {
  if (!req.user) return res.status(401).json({ success: false, message: "No user session" });
  res.json({
    success: true,
    user: {
      displayName: req.user.displayName,
      email: req.user.emails?.[0]?.value || "unknown",
    },
  });
});

app.get("/auth/failure", (req, res) =>
  res.status(401).json({ success: false, message: "Google login failed" })
);

// --- HEALTH CHECK ---
app.get(["/ping", "/health"], (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    version: "9.8.4",
    timestamp: new Date().toISOString(),
  });
});

// --- GEMINI 엔진 ---
app.post("/api/gemini/generate", async (req, res) => {
  try {
    const { apiKey, model, prompt } = req.body;
    const result = await geminiEngine.callGemini({ apiKey, model, prompt });
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- TRUTHSCORE 계산 ---
app.post("/api/truthscore/calculate", async (req, res) => {
  try {
    const { scores, weights } = req.body;
    const result = truthscoreEngine.calculate(scores, weights);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- 검증 엔진별 호출 ---
app.post("/api/verify/:engine", async (req, res) => {
  try {
    const { engine } = req.params;
    const { query } = req.body;
    const result = await verificationEngine.callEngine(engine, query);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- 다중 병렬 검증 ---
app.post("/api/verify/all", async (req, res) => {
  try {
    const { query } = req.body;
    const result = await verificationEngine.callAll(query);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// --- 기본 404 처리 ---
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// --- 서버 실행 ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
