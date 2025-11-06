// Cross-Verified AI Proxy — v13.7.1 (Full Adaptive Verify Expansion)
// Render + Supabase + OAuth + Gemini Flash/Pro + Flash-Lite Keyword Extraction + Verify + DB Test + Sentence Confidence

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
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  },
}));

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
// ✅ Flash-Lite 핵심어 추출 및 보정 (/api/extract-keywords)
// ─────────────────────────────
app.post("/api/extract-keywords", async (req, res) => {
  try {
    const { key, query } = req.body;
    if (!key || !query)
      return res.status(400).json({ success: false, message: "❌ key 또는 query 누락" });

    const model = "gemini-2.5-flash-lite";
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
      { contents: [{ parts: [{ text: `다음 문장에서 핵심 검색어만 나열해줘:\n"${query}"` }] }] }
    );

    let raw = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    let clean = raw
      .replace(/[#*•`]/g, "")
      .replace(/(핵심|검색|구문|조건|설명)/g, "")
      .replace(/[^\w가-힣\s]/g, "")
      .replace(/\s+/g, " ")
      .trim();

    const hasOr = /(또는|or|,|\/)/i.test(query);
    const hasAnd = /(과|및|와|그리고)/i.test(query);
    const mode = hasOr ? "OR" : hasAnd ? "AND" : "AND";

    const tokens = clean.split(" ").filter((t) => t.length > 1);
    const commonPrefix = query.match(/\b(UAM|AI|SmartCity|스마트시티)\b/i);
    let expanded = clean;
    if (commonPrefix && tokens.length >= 2 && mode === "OR") {
      expanded = `${commonPrefix[0]} ${tokens[0]} OR ${commonPrefix[0]} ${tokens[1]}`;
    }

    const finalQuery =
      mode === "OR"
        ? expanded.replace(/\s+OR\s+/g, " OR ")
        : expanded.split(" ").join(" AND ");

    await supabase.from("keyword_logs").insert([
      { query, raw_keywords: raw, clean_keywords: clean, logic_keywords: finalQuery, mode, engine: model },
    ]);

    res.json({ success: true, engine: model, mode, raw: raw.trim(), clean, final: finalQuery });
  } catch (err) {
    console.error("❌ /api/extract-keywords Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────
// ✅ Gemini Flash / Pro 단일 테스트
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
    res.json({ success: true, model, result: resultText.slice(0, 200) });
  } catch (err) {
    console.error("❌ /api/test-gemini Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────
// ✅ Adaptive Verify (Flash + Pro / Pro-only / Flash-only)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const { query, key, mode = "auto" } = req.body;
  if (!query || !key)
    return res.status(400).json({ success: false, message: "❌ query 또는 key 누락" });

  try {
    const start = Date.now();

    // 1️⃣ Pro 전용
    if (mode === "pro-only") {
      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=${key}`,
        { contents: [{ parts: [{ text: query }] }] }
      );
      const text = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
      await supabase.from("verification_logs").insert([{ query, engine: "gemini-2.5-pro", result: text }]);
      return res.json({ success: true, message: "✅ Pro 모드 결과 저장 완료", text });
    }

    // 2️⃣ Flash 전용
    if (mode === "flash-only") {
      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${key}`,
        { contents: [{ parts: [{ text: query }] }] }
      );
      const text = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
      await supabase.from("verification_logs").insert([{ query, engine: "gemini-2.5-flash", result: text }]);
      return res.json({ success: true, message: "✅ Flash 모드 결과 저장 완료", text });
    }

    // 3️⃣ 기본 Auto (Flash + Pro 병렬 검증 + 문장단위 신뢰도)
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

    await supabase.from("verification_logs").insert(
      merged.map(m => ({ query, engine: m.model, result: m.text, elapsed, confidence: avg }))
    );
    await supabase.from("sentence_logs").insert(
      partial.map(p => ({ query, sentence: p.sentence, confidence: p.confidence, icon: p.icon }))
    );

    res.json({
      success: true,
      message: "✅ Adaptive Verify 완료 및 DB 저장됨",
      query,
      mode,
      elapsed,
      summary_confidence: avg.toFixed(2),
      sentences: partial,
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
// ✅ Health Check 및 서버 실행
// ─────────────────────────────
app.get("/health", (req, res) =>
  res.status(200).json({ status: "ok", timestamp: new Date().toISOString() })
);

app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v13.7.1 running on port ${PORT}`);
  console.log(`🌐 Health: http://localhost:${PORT}/health`);
  console.log(`🧠 DB Test: http://localhost:${PORT}/api/test-db`);
  console.log(`🔑 Keyword Extract: POST /api/extract-keywords`);
  console.log(`🤖 Verify: POST /api/verify`);
});

