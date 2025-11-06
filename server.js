// Cross-Verified AI Proxy — v13.5.0
// Render + Supabase + OAuth + Gemini 2.5 Flash/Pro Verification + Logs

import express from "express";
import session from "express-session";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import dotenv from "dotenv";
import cors from "cors";
import morgan from "morgan";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { createClient } from "@supabase/supabase-js";
import axios from "axios";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: (origin, callback) => {
    const allowed = process.env.ALLOWED_ORIGINS?.split(",") || [];
    if (!origin || allowed.includes(origin)) return callback(null, true);
    callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
}));
app.use(express.json());
app.use(morgan("dev"));

// ─────────────────────────────
// ✅ Supabase 연결
// ─────────────────────────────
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// ─────────────────────────────
// ✅ PostgreSQL 세션 스토어
// ─────────────────────────────
const PgStore = connectPgSimple(session);
const pgPool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(session({
  store: new PgStore({ pool: pgPool, tableName: "session_store" }),
  secret: process.env.SESSION_SECRET || "dev-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === "production", httpOnly: true, maxAge: 24 * 60 * 60 * 1000 },
}));

// ─────────────────────────────
// ✅ Passport (Google OAuth)
// ─────────────────────────────
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
  clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
},
async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    const whitelist = process.env.ADMIN_WHITELIST?.split(",") || [];
    if (!whitelist.includes(email)) return done(new Error("Unauthorized admin user"));
    await supabase.from("users").upsert([{ email, name: profile.displayName }], { onConflict: "email" });
    return done(null, { email, name: profile.displayName });
  } catch (err) { return done(err); }
}));
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));
app.use(passport.initialize());
app.use(passport.session());

// ─────────────────────────────
// ✅ OAuth Routes
// ─────────────────────────────
app.get("/auth/admin", passport.authenticate("google", { scope: ["email", "profile"] }));
app.get("/auth/admin/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  async (req, res) => {
    const { email, name } = req.user;
    await supabase.from("sessions").insert([{ email, name, provider: "google" }]);
    res.send(`<h2>✅ OAuth Login Success</h2><p>${name} (${email})</p>`);
  });
app.get("/auth/failure", (req, res) => res.status(401).send("❌ OAuth Failed"));

// ─────────────────────────────
// ✅ Gemini 2.5 Flash / Pro Test
// ─────────────────────────────
app.post("/api/test-gemini", async (req, res) => {
  try {
    const { key, query, mode = "flash" } = req.body;
    const model = mode === "pro" ? "gemini-2.5-pro" : "gemini-2.5-flash";
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
      { contents: [{ parts: [{ text: query || "테스트 요청" }] }] }
    );

    const resultText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "결과 없음";
    await supabase.from("verification_logs").insert([{ query, engine: model, result: resultText }]);
    res.json({ success: true, model, result: resultText.slice(0, 200), elapsed: `${response.headers["x-response-time"] || "?"} ms` });
  } catch (err) {
    console.error("❌ Gemini Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});
// ─────────────────────────────
// ✅ /api/verify — Gemini Flash & Pro 병렬 검증 통합 엔드포인트
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const { query, key } = req.body;
  if (!query || !key) {
    return res.status(400).json({ success: false, message: "❌ query 또는 key가 누락되었습니다." });
  }

  try {
    const start = Date.now();
    const models = ["gemini-2.5-flash", "gemini-2.5-pro"];

    // 병렬 실행
    const results = await Promise.allSettled(
      models.map(async (model) => {
        const response = await axios.post(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
          { contents: [{ parts: [{ text: query }] }] }
        );
        return {
          model,
          text: response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "",
        };
      })
    );

    // 결과 정리
    const merged = results
      .filter((r) => r.status === "fulfilled")
      .map((r) => r.value);
    const elapsed = `${Date.now() - start} ms`;

    // DB 기록
    await supabase.from("verification_logs").insert(
      merged.map((m) => ({
        query,
        engine: m.model,
        result: m.text,
        elapsed,
      }))
    );

    // 응답
    res.json({
      success: true,
      message: "✅ Gemini Flash & Pro 검증 완료 및 DB 저장됨",
      query,
      elapsed,
      models: merged.map((m) => m.model),
      preview: merged.map((m) => ({
        engine: m.model,
        result: m.text.slice(0, 150),
      })),
    });
  } catch (err) {
    console.error("❌ /api/verify error:", err.message);
    res.status(500).json({
      success: false,
      message: "❌ Gemini API 호출 실패",
      error: err.message,
    });
  }
});

// ─────────────────────────────
// ✅ /health — 서버 상태 확인
// ─────────────────────────────
app.get("/health", async (req, res) => {
  try {
    const { data, error } = await supabase.from("users").select("id").limit(1);
    res.status(200).json({
      status: "ok",
      db: error ? "partial" : "connected",
      timestamp: new Date().toISOString(),
    });
  } catch {
    res.status(200).json({
      status: "ok",
      db: "unverified",
      timestamp: new Date().toISOString(),
    });
  }
});

// ─────────────────────────────
// ✅ /api/test-db — DB 연결 테스트
// ─────────────────────────────
app.get("/api/test-db", async (req, res) => {
  try {
    const client = await pgPool.connect();
    const result = await client.query("SELECT NOW()");
    client.release();
    res.json({
      success: true,
      message: "✅ PostgreSQL 연결 성공",
      time: new Date(result.rows[0].now).toISOString(),
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "❌ PostgreSQL 연결 실패",
      error: err.message,
    });
  }
});

// ─────────────────────────────
// ✅ 서버 실행
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v13.5.0 running on port ${PORT}`);
  console.log(`🌐 Health: http://localhost:${PORT}/health`);
  console.log(`🧠 DB Test: http://localhost:${PORT}/api/test-db`);
  console.log(`🤖 Gemini Verify: POST /api/verify`);
});
