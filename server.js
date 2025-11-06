/**
 * Cross-Verified AI Proxy v12.6.1
 * Features:
 *  - Google OAuth 2.0 로그인 (관리자 대시보드)
 *  - Supabase DB 세션 및 로그 연동
 *  - Token 기반 관리자 접근 (/admin)
 *  - Render Health Check (/health) 통합 고정
 */

import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bodyParser from "body-parser";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import connectPgSimple from "connect-pg-simple";
import { createClient } from "@supabase/supabase-js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

//────────────────────────────
// 📦 Supabase 연결
//────────────────────────────
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const { Pool } = pkg;
const PgSession = connectPgSimple(session);
const pgPool = new Pool({
  connectionString: process.env.SUPABASE_DB_URL,
  ssl: { rejectUnauthorized: false },
});

//────────────────────────────
// 🧩 미들웨어 설정
//────────────────────────────
app.use(cors());
app.use(bodyParser.json());
app.use(
  session({
    store: new PgSession({
      pool: pgPool,
      tableName: "session",
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || "cross-verified-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 }, // 1시간
  })
);
app.use(passport.initialize());
app.use(passport.session());

//────────────────────────────
// 🔑 Passport Google OAuth 설정
//────────────────────────────
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
      clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      const email = profile.emails?.[0]?.value;
      if (email === process.env.ADMIN_WHITELIST) return done(null, profile);
      return done(null, false, { message: "Unauthorized" });
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

//────────────────────────────
// 🌐 OAuth 라우트
//────────────────────────────
app.get("/auth/admin", passport.authenticate("google", { scope: ["email", "profile"] }));

app.get(
  "/auth/admin/callback",
  passport.authenticate("google", {
    failureRedirect: "/auth/failure",
    successRedirect: "/admin",
  })
);

app.get("/auth/failure", (req, res) => res.status(403).send("❌ OAuth 인증 실패"));
app.get("/logout", (req, res) => req.logout(() => res.redirect("/")));

//────────────────────────────
// 🧠 관리자 페이지 (/admin)
//────────────────────────────
app.get("/admin", async (req, res) => {
  // ✅ 1단계: 토큰 인증 확인
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];
  if (token === process.env.ADMIN_SECRET) {
    const { data, error } = await supabase
      .from("verification_logs")
      .select("*")
      .order("id", { ascending: false })
      .limit(5);
    if (error) return res.status(500).send("DB 조회 오류");

    const rows = data
      .map(
        (r) => `
        <tr>
          <td>${r.id}</td>
          <td>${r.question?.slice(0, 40) || ""}</td>
          <td>${r.model_main || ""}</td>
          <td>${r.cross_score || ""}</td>
          <td>${r.elapsed || ""}</td>
          <td>${r.status || ""}</td>
          <td>${r.created_at || ""}</td>
        </tr>`
      )
      .join("");

    return res.send(`
      <!doctype html>
      <html><head><meta charset="utf-8"><title>Admin Dashboard</title>
      <style>body{font-family:Arial,Helvetica,sans-serif;padding:16px;background:#fafafa}
      table{border-collapse:collapse;width:100%}
      th,td{border:1px solid #ddd;padding:8px;text-align:left}
      th{background:#eee}</style></head><body>
      <h2>✅ Cross-Verified Admin Dashboard</h2>
      <table><thead><tr><th>ID</th><th>Query</th><th>Model</th><th>Score</th><th>Time</th><th>Status</th><th>Created</th></tr></thead>
      <tbody>${rows}</tbody></table>
      <p style="margin-top:20px;font-size:12px;color:#666;">Access via Bearer Token</p>
      </body></html>
    `);
  }

  // ✅ 2단계: OAuth 세션 인증
  if (req.isAuthenticated() && req.user) {
    const { data } = await supabase
      .from("verification_logs")
      .select("*")
      .order("id", { ascending: false })
      .limit(5);

    const rows = data
      .map(
        (r) => `
        <tr>
          <td>${r.id}</td>
          <td>${r.question?.slice(0, 40) || ""}</td>
          <td>${r.model_main || ""}</td>
          <td>${r.cross_score || ""}</td>
          <td>${r.elapsed || ""}</td>
          <td>${r.status || ""}</td>
          <td>${r.created_at || ""}</td>
        </tr>`
      )
      .join("");

    return res.send(`
      <!doctype html>
      <html><head><meta charset="utf-8"><title>Admin Dashboard</title></head>
      <body><h2>✅ OAuth 로그인 성공 (${req.user.emails[0].value})</h2>
      <table border="1" cellpadding="6"><tr><th>ID</th><th>Query</th><th>Model</th><th>Score</th><th>Time</th><th>Status</th><th>Created</th></tr>
      ${rows}</table></body></html>
    `);
  }

  res.status(401).send("Unauthorized: 로그인 필요");
});

//────────────────────────────
// 💓 통합 Health Check (/health 고정)
//────────────────────────────
app.get("/health", async (req, res) => {
  try {
    const { count, error } = await supabase
      .from("verification_logs")
      .select("*", { count: "exact", head: true });
    if (error) throw error;
    res.status(200).json({
      success: true,
      message: "✅ Proxy Server Healthy",
      version: process.env.APP_VERSION || "v12.6.1",
      supabase: { connected: true, rows: count ?? "unknown" },
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "❌ Health Check Failed",
      error: err.message,
    });
  }
});

//────────────────────────────
// 🧾 서버 실행
//────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy (v12.6.1) running on port ${PORT}`);
  console.log(`🌐 OAuth Login: ${process.env.GOOGLE_ADMIN_CALLBACK_URL}`);
  console.log(`💓 Health Check: /health`);
});
