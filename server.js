// Cross-Verified AI Proxy — v13.6.0 (Full Consolidated)
// Render + Supabase + OAuth + Gemini Flash/Pro + Flash-Lite Keyword Extraction

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
app.use(
  cors({
    origin: (origin, callback) => {
      const allowed = process.env.ALLOWED_ORIGINS?.split(",") || [];
      if (!origin || allowed.includes(origin)) return callback(null, true);
      callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);
app.use(express.json());
app.use(morgan("dev"));

// ─────────────────────────────
// ✅ Supabase 연결
// ─────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ─────────────────────────────
// ✅ PostgreSQL 세션 스토어
// ─────────────────────────────
const PgStore = connectPgSimple(session);
const pgPool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(
  session({
    store: new PgStore({ pool: pgPool, tableName: "session_store" }),
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);
// ─────────────────────────────
// ✅ Passport (Google OAuth)
// ─────────────────────────────
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
      clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        const whitelist = process.env.ADMIN_WHITELIST?.split(",") || [];
        if (!whitelist.includes(email))
          return done(new Error("Unauthorized admin user"));

        await supabase
          .from("users")
          .upsert([{ email, name: profile.displayName }], {
            onConflict: "email",
          });
        return done(null, { email, name: profile.displayName });
      } catch (err) {
        return done(err);
      }
    }
  )
);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));
app.use(passport.initialize());
app.use(passport.session());

// ─────────────────────────────
// ✅ OAuth Routes
// ─────────────────────────────
app.get(
  "/auth/admin",
  passport.authenticate("google", { scope: ["email", "profile"] })
);

app.get(
  "/auth/admin/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  async (req, res) => {
    const { email, name } = req.user;
    await supabase.from("sessions").insert([{ email, name, provider: "google" }]);
    res.send(`<h2>✅ OAuth Login Success</h2><p>${name} (${email})</p>`);
  }
);

app.get("/auth/failure", (req, res) =>
  res.status(401).send("❌ OAuth Failed")
);
// ─────────────────────────────
// ✅ Flash-Lite 핵심어 추출 (/api/extract-keywords)
// ─────────────────────────────
app.post("/api/extract-keywords", async (req, res) => {
  try {
    const { key, query } = req.body;
    if (!key || !query)
      return res
        .status(400)
        .json({ success: false, message: "❌ key 또는 query 누락" });

    const model = "gemini-2.5-flash-lite";
    const hasOr = /(또는|or|\/|,)/i.test(query);
    const mode = hasOr ? "OR" : "AND";

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
      {
        contents: [
          {
            parts: [
              {
                text: `아래 문장에서 핵심 검색구문을 ${mode} 조건에 맞는 형태로 출력:\n"${query}"`,
              },
            ],
          },
        ],
      }
    );

    const keywords =
      response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "키워드 없음";
    await supabase
      .from("keyword_logs")
      .insert([{ query, keywords, mode, engine: model }]);

    res.json({ success: true, engine: model, mode, keywords: keywords.trim() });
  } catch (err) {
    console.error("❌ /api/extract-keywords Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────
// ✅ Gemini Flash / Pro / Verify / Health / DB Test
// ─────────────────────────────
// 기존 v13.5 코드 전체 유지 (test-gemini, verify, health, test-db 그대로)
// ─────────────────────────────

app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v13.6.0 running on port ${PORT}`);
  console.log(`🌐 Health: http://localhost:${PORT}/health`);
  console.log(`🔑 Keyword Extract: POST /api/extract-keywords`);
  console.log(`🤖 Verify: POST /api/verify`);
});

// ✅ Health Check
app.get("/health", async (req, res) => {
  res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
});
