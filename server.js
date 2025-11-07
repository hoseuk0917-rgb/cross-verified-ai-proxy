// Cross-Verified AI Proxy — v13.8
// Render + Supabase + OAuth + Gemini Flash/Pro + K-Law API + Keyword Extraction + Local-First
// 🧩 Local-First Policy: DB 최소화 (keywords, verify logs → 앱 로컬 저장)
// 📡 XML→JSON 자동 변환, 핵심어 표시 강화

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
import xml2js from "xml2js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────
// ✅ Middleware 설정
// ─────────────────────────────
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
// ✅ PostgreSQL + 세션 설정
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
  cookie: { secure: false, httpOnly: true, maxAge: 86400000 },
}));

// ─────────────────────────────
// ✅ Supabase 연결 (OAuth 계정용 최소 테이블만)
// ─────────────────────────────
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// ─────────────────────────────
// ✅ Passport (Google OAuth)
// ─────────────────────────────
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
  clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    const whitelist = process.env.ADMIN_WHITELIST?.split(",") || [];
    if (!whitelist.includes(email))
      return done(new Error("Unauthorized admin user"));
    await supabase.from("users")
      .upsert([{ email, name: profile.displayName }], { onConflict: "email" });
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
// ✅ 핵심어 추출 (강화 버전 / Flash-Lite 기반)
// ─────────────────────────────
app.post("/api/extract-keywords", async (req, res) => {
  try {
    const { key, query } = req.body;
    if (!key || !query)
      return res.status(400).json({ success: false, message: "❌ key 또는 query 누락" });

    const model = "gemini-2.5-flash-lite";
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
      {
        contents: [
          { parts: [{ text: `문장에서 핵심 검색어 5개 이하로만 추출:\n"${query}"` }] }
        ]
      }
    );

    const raw = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    const clean = raw.replace(/[#*•`]/g, "").trim();
    const keywords = clean.split(/[,\s]+/).filter(t => t.length > 1);

    res.json({
      success: true,
      engine: model,
      keywords,
      display_keywords: keywords.join(", "),
      store_local: true,      // 앱 로컬에 캐싱
      cached: true,
      message: "✅ 핵심어 추출 성공 (앱 UI 표시 가능)"
    });
  } catch (err) {
    console.error("❌ /api/extract-keywords Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────
// ✅ K-Law API 프록시 라우트 연결
// ─────────────────────────────
import klawRouter from "./routes/klaw.js";
app.use("/proxy/klaw", klawRouter);
// ─────────────────────────────
// ✅ Adaptive Verify (Gemini Flash + Pro 병렬 검증 + 문장단위 신뢰도)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const { query, key, mode = "auto" } = req.body;
  if (!query || !key)
    return res.status(400).json({ success: false, message: "❌ query 또는 key 누락" });

  try {
    const start = Date.now();

    // 1️⃣ Pro 전용 모드
    if (mode === "pro-only") {
      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=${key}`,
        { contents: [{ parts: [{ text: query }] }] }
      );
      const text = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
      return res.json({
        success: true,
        message: "✅ Pro 모드 완료 (로컬 저장 필요)",
        text,
        store_local: true,
      });
    }

    // 2️⃣ Flash 전용 모드
    if (mode === "flash-only") {
      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${key}`,
        { contents: [{ parts: [{ text: query }] }] }
      );
      const text = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
      return res.json({
        success: true,
        message: "✅ Flash 모드 완료 (로컬 저장 필요)",
        text,
        store_local: true,
      });
    }

    // 3️⃣ Auto 모드 — Flash + Pro 병렬 검증
    const models = ["gemini-2.5-flash", "gemini-2.5-pro"];
    const results = await Promise.allSettled(
      models.map(async (m) => {
        const r = await axios.post(
          `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${key}`,
          { contents: [{ parts: [{ text: query }] }] }
        );
        return { model: m, text: r.data?.candidates?.[0]?.content?.parts?.[0]?.text || "" };
      })
    );

    const merged = results.filter(r => r.status === "fulfilled").map(r => r.value);
    const flashText = merged.find(m => m.model.includes("flash"))?.text || "";
    const proText = merged.find(m => m.model.includes("pro"))?.text || "";

    // 문장 단위 Confidence 계산
    const sentences = proText.split(/(?<=[.?!])\s+/).map(s => s.trim()).filter(Boolean);
    const partial = sentences.map((s, i) => {
      const normalized = s.toLowerCase().replace(/\s+/g, " ");
      const match = flashText.toLowerCase().includes(normalized.split(" ").slice(0, 5).join(" "));
      const confidence = match ? "high" : "medium";
      const icon = match ? "✔️" : "❓";
      return { id: i + 1, sentence: s, confidence, icon };
    });

    const avg = (partial.filter(p => p.confidence === "high").length / partial.length) || 0;
    const elapsed = `${Date.now() - start} ms`;

    res.json({
      success: true,
      message: "✅ Adaptive Verify 완료 (로컬 저장 필요)",
      query,
      mode,
      elapsed,
      summary_confidence: avg.toFixed(2),
      sentences: partial,
      store_local: true,
    });
  } catch (err) {
    console.error("❌ /api/verify Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────
// ✅ PostgreSQL 연결 테스트
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
    console.error("DB 연결 오류:", err.message);
    res.status(500).json({ success: false, message: "❌ PostgreSQL 연결 실패", error: err.message });
  }
});

// ─────────────────────────────
// ✅ Health Check
// ─────────────────────────────
app.get("/health", (req, res) =>
  res.status(200).json({ status: "ok", timestamp: new Date().toISOString() })
);
// ─────────────────────────────
// ✅ 서버 실행 (Health / Log 안내)
// ─────────────────────────────
app.listen(PORT, () => {
  console.log("─────────────────────────────");
  console.log(`🚀 Cross-Verified AI Proxy v13.8 (Local-First)`);
  console.log(`🌐 서버 실행 중: http://localhost:${PORT}`);
  console.log("─────────────────────────────");
  console.log(`🧠 DB Test: GET  → /api/test-db`);
  console.log(`🤖 Verify: POST → /api/verify`);
  console.log(`🔍 Keywords: POST → /api/extract-keywords`);
  console.log(`⚖️  K-Law Proxy: GET  → /proxy/klaw/search?target=law&type=JSON&query=자동차`);
  console.log(`💚 Health Check: GET  → /health`);
  console.log("─────────────────────────────");
});
