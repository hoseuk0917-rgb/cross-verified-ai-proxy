// server.js (v13.4.0)
// Cross-Verified AI Proxy — Render + Supabase + OAuth + Health & DB Test

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
// ✅ Supabase 연결 설정
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
    store: new PgStore({ pool: pgPool, tableName: "sessions" }),
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
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
        if (!whitelist.includes(email)) {
          return done(new Error("Unauthorized admin user"));
        }

        // 세션 저장용 예시 (Supabase users 테이블 기록)
        const { error } = await supabase
          .from("users")
          .upsert([{ email, name: profile.displayName }], { onConflict: "email" });
        if (error) console.error("Supabase upsert error:", error.message);

        return done(null, profile);
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
// ✅ /health (Render용 고정)
// ─────────────────────────────
app.get("/health", async (req, res) => {
  try {
    const { data, error } = await supabase.from("verification_logs").select("id").limit(1);
    res.status(200).json({
      status: "ok",
      db: error ? "partial" : "connected",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(200).json({
      status: "ok",
      db: "unverified",
      timestamp: new Date().toISOString(),
    });
  }
});

// ─────────────────────────────
// ✅ /api/test-db (DB 연결 직접테스트)
// ─────────────────────────────
app.get("/api/test-db", async (req, res) => {
  try {
    const client = await pgPool.connect();
    const result = await client.query("SELECT NOW()");
    client.release();

    res.json({
      success: true,
      message: "✅ PostgreSQL 연결 성공",
      time: result.rows[0].now,
    });
  } catch (err) {
    console.error("DB 연결 오류:", err.message);
    res.status(500).json({
      success: false,
      message: "❌ PostgreSQL 연결 실패",
      error: err.message,
    });
  }
});

// ─────────────────────────────
// ✅ OAuth 라우팅
// ─────────────────────────────
app.get("/auth/admin", passport.authenticate("google", { scope: ["email", "profile"] }));

app.get(
  "/auth/admin/callback",
  passport.authenticate("google", {
    failureRedirect: "/auth/failure",
    session: true,
  }),
  (req, res) => {
    res.send(`<h2>✅ OAuth Login Success</h2><p>User: ${req.user.displayName}</p>`);
  }
);

app.get("/auth/failure", (req, res) => res.status(401).send("❌ OAuth Failed"));

// ─────────────────────────────
// ✅ 서버 실행
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy running on port ${PORT}`);
  console.log(`🌐 Health: http://localhost:${PORT}/health`);
  console.log(`🧠 DB Test: http://localhost:${PORT}/api/test-db`);
  console.log(`🔑 OAuth Callback: ${process.env.GOOGLE_ADMIN_CALLBACK_URL}`);
});
