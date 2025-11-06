// ============================================
// Cross-Verified AI Proxy v13.2.5
// (Render + Supabase IPv4 only + OAuth + Lazy Session + /health 고정)
// ============================================

import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import dotenv from "dotenv";
import morgan from "morgan";
import session from "express-session";
import pgSession from "connect-pg-simple";
import pg from "pg";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import pkg from "@supabase/supabase-js";
const { createClient } = pkg;

// ===========================
// ✅ 환경설정
// ===========================
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = process.env.APP_VERSION || "v13.2.5";

// ===========================
// ✅ 미들웨어
// ===========================
app.use(cors({ origin: "*", credentials: true }));
app.use(bodyParser.json({ limit: "5mb" }));
app.use(morgan("dev"));

// ===========================
// ✅ PostgreSQL 세션 스토어 (IPv4 + TLS + Lazy 모드)
// ===========================
pg.defaults.ssl = { rejectUnauthorized: false };
pg.defaults.host = "0.0.0.0"; // ✅ IPv4-only 강제

const PgSession = pgSession(session);
let pgStore;

try {
  pgStore = new PgSession({
    conString: process.env.SUPABASE_DB_URL,
    createTableIfMissing: false,
    ssl: { rejectUnauthorized: false },
  });

  app.use(
    session({
      store: pgStore,
      secret: process.env.SESSION_SECRET || "my-session-secret",
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        sameSite: "lax",
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30일
      },
    })
  );

  console.log("🟢 SessionStore 연결 (IPv4 only, TLS enabled)");
} catch (err) {
  console.error("🔴 SessionStore 초기화 실패:", err.message);
}

// ===========================
// ✅ Passport (Google OAuth)
// ===========================
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
      clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      const whitelist = (process.env.ADMIN_WHITELIST || "").split(",");
      if (whitelist.includes(profile.emails[0].value)) {
        return done(null, profile);
      } else {
        return done(null, false, { message: "허용되지 않은 관리자 계정" });
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use(passport.initialize());
app.use(passport.session());

// ===========================
// ✅ Supabase 연결
// ===========================
let supabase = null;
try {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
  );
  console.log(`🟢 Supabase 연결 완료: ${process.env.SUPABASE_URL}`);
} catch (err) {
  console.error("🔴 Supabase 연결 실패:", err.message);
}

// ===========================
// ✅ Health Check (/health 고정)
// ===========================
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    version: APP_VERSION,
    timestamp: new Date().toISOString(),
  });
});

// ===========================
// ✅ 기본 루트
// ===========================
app.get("/", (req, res) => {
  res.send(
    `<h2>🚀 Cross-Verified AI Proxy (${APP_VERSION})</h2><p>Server active at ${new Date().toISOString()}</p>`
  );
});

// ===========================
// ✅ 관리자 인증 라우트
// ===========================
app.get("/auth/admin", passport.authenticate("google", { scope: ["email", "profile"] }));

app.get(
  "/auth/admin/callback",
  passport.authenticate("google", {
    failureRedirect: "/auth/failure",
    successRedirect: "/admin/dashboard",
  })
);

app.get("/auth/failure", (req, res) => res.status(403).send("❌ 관리자 인증 실패"));

// ===========================
// ✅ 관리자 대시보드
// ===========================
app.get("/admin/dashboard", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).send("❌ 관리자 로그인이 필요합니다.");
  }

  try {
    const { data, error } = await supabase
      .from("verification_logs")
      .select("id, query, model, cross_score, elapsed, status, created_at")
      .order("id", { ascending: false })
      .limit(10);

    if (error) throw error;

    const rows = data
      .map(
        (r) => `<tr>
          <td>${r.id}</td>
          <td>${r.query?.slice(0, 40) || "-"}</td>
          <td>${r.model || "-"}</td>
          <td>${r.cross_score || "-"}</td>
          <td>${r.elapsed || "-"}</td>
          <td>${r.status || "-"}</td>
          <td>${r.created_at}</td>
        </tr>`
      )
      .join("");

    res.send(`
      <html><head><meta charset="utf-8">
      <title>Admin Dashboard</title>
      <style>
        body{font-family:Arial,sans-serif;padding:16px}
        table{border-collapse:collapse;width:100%}
        td,th{border:1px solid #ccc;padding:6px;text-align:center}
        th{background:#f5f5f5}
      </style></head>
      <body>
        <h2>✅ Cross-Verified Admin Dashboard</h2>
        <p>Logged in as <b>${req.user.displayName}</b> (${req.user.emails[0].value})</p>
        <table>
          <thead>
            <tr><th>ID</th><th>Query</th><th>Model</th><th>Score</th><th>Elapsed</th><th>Status</th><th>Created</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </body></html>
    `);
  } catch (err) {
    console.error("❌ Dashboard Error:", err.message);
    res.status(500).send("서버 오류 발생");
  }
});

// ===========================
// ✅ 서버 실행
// ===========================
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy (${APP_VERSION}) 실행 중 - 포트: ${PORT}`);
  console.log(`🌐 Health: http://localhost:${PORT}/health`);
  console.log(`🔑 OAuth Admin: ${process.env.GOOGLE_ADMIN_CALLBACK_URL}`);
});
