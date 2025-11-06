// Cross-Verified AI Proxy — v13.4.1
// Render + Supabase + OAuth + Session + Health Test

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
        if (!whitelist.includes(email)) {
          console.warn(`🚫 Unauthorized admin attempt: ${email}`);
          return done(new Error("Unauthorized admin user"));
        }

        const { error } = await supabase
          .from("users")
          .upsert([{ email, name: profile.displayName }], { onConflict: "email" });

        if (error) console.error("⚠️ Supabase upsert error:", error.message);

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
// ✅ /auth/admin — OAuth 로그인 시작
// ─────────────────────────────
app.get("/auth/admin", passport.authenticate("google", { scope: ["email", "profile"] }));

// ─────────────────────────────
// ✅ /auth/admin/callback — 로그인 완료 후 Supabase에 세션 저장
// ─────────────────────────────
app.get(
  "/auth/admin/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  async (req, res) => {
    try {
      const { email, name } = req.user;

      // Supabase sessions 테이블 기록
      const { error } = await supabase
        .from("sessions")
        .insert([
          {
            email,
            name,
            login_time: new Date().toISOString(),
            provider: "google",
          },
        ]);

      if (error) {
        console.error("⚠️ Supabase session insert error:", error.message);
      }

      // 브라우저 / API 클라이언트 양쪽 대응
      if (req.headers.accept?.includes("application/json")) {
        res.json({
          success: true,
          message: "✅ OAuth 로그인 성공",
          user: { email, name },
          timestamp: new Date().toISOString(),
        });
      } else {
        res.send(
          `<h2>✅ OAuth Login Success</h2>
           <p>User: ${name}</p>
           <p>Email: ${email}</p>
           <small>${new Date().toLocaleString()}</small>`
        );
      }
    } catch (err) {
      console.error("❌ OAuth callback error:", err.message);
      res.status(500).json({ success: false, error: err.message });
    }
  }
);

app.get("/auth/failure", (req, res) =>
  res.status(401).send("❌ OAuth Login Failed — Unauthorized or invalid user")
);

// ─────────────────────────────
// ✅ /health — Render용 서버 상태 점검
// ─────────────────────────────
app.get("/health", async (req, res) => {
  try {
    const { error } = await supabase.from("verification_logs").select("id").limit(1);
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
// ✅ /api/test-db — PostgreSQL 직접 연결 점검
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
  console.log(`🚀 Cross-Verified AI Proxy v13.4.1 running on port ${PORT}`);
  console.log(`🌐 Health: http://localhost:${PORT}/health`);
  console.log(`🧠 DB Test: http://localhost:${PORT}/api/test-db`);
  console.log(`🔑 OAuth: /auth/admin → /auth/admin/callback`);
});
