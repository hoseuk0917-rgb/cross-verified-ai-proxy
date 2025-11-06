// ===============================================
// Cross-Verified AI Proxy v13.2.0 (Supabase + OAuth + SessionStore)
// ===============================================
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import morgan from "morgan";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import dotenv from "dotenv";
import axios from "axios";
import fetch from "node-fetch";
import { createClient } from "@supabase/supabase-js";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// ------------------------
// Core Middleware
// ------------------------
app.use(cors({ origin: "*", credentials: true }));
app.use(bodyParser.json());
app.use(morgan("dev"));

// ------------------------
// PostgreSQL & Supabase 설정
// ------------------------
const { Pool } = pg;
const PgSession = connectPgSimple(session);

const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pgPool.connect()
  .then(() => console.log("🟢 PostgreSQL (Supabase SessionStore) 연결 완료"))
  .catch(err => console.error("🔴 PostgreSQL 연결 실패:", err.message));

app.use(session({
  store: new PgSession({ pool: pgPool, tableName: "sessions" }),
  secret: process.env.SESSION_SECRET || "default_secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Render에서는 자동 HTTPS 적용됨
    maxAge: 24 * 60 * 60 * 1000, // 1일
  },
}));

// ------------------------
// Passport (Google OAuth Admin)
// ------------------------
app.use(passport.initialize());
app.use(passport.session());

passport.use("google-admin", new GoogleStrategy({
  clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
  clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
}, (accessToken, refreshToken, profile, done) => {
  if (process.env.ADMIN_WHITELIST?.split(",").includes(profile.emails[0].value)) {
    return done(null, profile);
  }
  return done(new Error("허용되지 않은 사용자 접근"), null);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ------------------------
// Supabase Client
// ------------------------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ------------------------
// Routes
// ------------------------

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", version: "v13.2.0", time: new Date().toISOString() });
});

// Google OAuth (Admin)
app.get("/auth/admin", passport.authenticate("google-admin", {
  scope: ["profile", "email"],
}));
app.get("/auth/admin/callback",
  passport.authenticate("google-admin", {
    failureRedirect: "/auth/fail",
    session: true,
  }),
  (req, res) => res.send(`<h2>✅ 로그인 성공</h2><p>${req.user.displayName}</p>`)
);
app.get("/auth/fail", (req, res) => res.status(401).send("❌ 로그인 실패"));

// Main verification endpoint
app.post("/api/verify", async (req, res) => {
  const { query, key } = req.body;
  if (!query) return res.status(400).json({ error: "Missing query" });

  try {
    const response = await axios.post(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + key,
      { contents: [{ parts: [{ text: query }] }] }
    );

    const resultText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "No result";
    await supabase.from("verification_logs").insert([
      { query, result: resultText, created_at: new Date() },
    ]);

    res.json({
      success: true,
      result: resultText,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Gemini API Error:", error.message);
    res.status(500).json({ error: "Internal verification error" });
  }
});

// ------------------------
// Start Server
// ------------------------
app.listen(port, () => {
  console.log(`🚀 Cross-Verified AI Proxy (v13.2.0) 실행 중 - 포트: ${port}`);
  console.log(`🌐 Health: http://localhost:${port}/api/health`);
  console.log(`🔑 OAuth Admin: ${process.env.GOOGLE_ADMIN_CALLBACK_URL}`);
});
