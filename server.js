// server.js — Cross-Verified AI Proxy v12.5.1 (Persistent Session + Dual OAuth + Supabase Dashboard)
import express from "express";
import cors from "cors";
import passport from "passport";
import session from "express-session";
import pgSession from "connect-pg-simple";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// ----------------------------
// 기본 미들웨어
// ----------------------------
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());

// ----------------------------
// Supabase 연결
// ----------------------------
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
console.log("🌐 Supabase 연결 완료:", process.env.SUPABASE_URL);

// ----------------------------
// PostgreSQL 세션 스토어 연결 (connect-pg-simple)
// ----------------------------
const PgSession = pgSession(session);
const dbConnectionString =
  process.env.SUPABASE_DB_URL ||
  process.env.SUPABASE_URL.replace("https://", "postgres://") + "?sslmode=require";

app.use(
  session({
    store: new PgSession({
      conString: dbConnectionString,
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || "session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // HTTPS 전용 시 true로 변경
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ----------------------------
// Passport 설정 (Dual OAuth)
// ----------------------------

// 일반 사용자 로그인
passport.use(
  "user-google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      console.log("✅ 일반 사용자 로그인:", profile.emails[0].value);
      return done(null, profile);
    }
  )
);

// 관리자 로그인
passport.use(
  "admin-google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
      clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      const email = profile.emails[0].value.toLowerCase();
      const whitelist = process.env.ADMIN_WHITELIST?.toLowerCase();
      if (email === whitelist) {
        console.log("🛡️ 관리자 인증 성공:", email);
        return done(null, profile);
      } else {
        console.warn("🚫 관리자 인증 실패:", email);
        return done(null, false, { message: "Unauthorized" });
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ----------------------------
// 라우팅
// ----------------------------

app.get("/", (req, res) =>
  res.send("<h2>Cross-Verified AI Proxy Server (v12.5.1) — Persistent Session</h2>")
);

// ✅ 일반 사용자 OAuth
app.get("/auth/google", passport.authenticate("user-google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/callback",
  passport.authenticate("user-google", { failureRedirect: "/" }),
  (req, res) => res.send(`<h3>✅ 일반 로그인 완료 (${req.user.displayName})</h3>`)
);

// ✅ 관리자 OAuth
app.get("/auth/admin", passport.authenticate("admin-google", { scope: ["profile", "email"] }));
app.get(
  "/auth/admin/callback",
  passport.authenticate("admin-google", { failureRedirect: "/" }),
  (req, res) => res.redirect("/admin")
);

// ✅ 관리자 대시보드
app.get("/admin", async (req, res) => {
  if (!req.user) return res.status(401).send("Unauthorized: 로그인 필요");
  if (req.user.emails[0].value.toLowerCase() !== process.env.ADMIN_WHITELIST.toLowerCase())
    return res.status(403).send("Forbidden: 관리자만 접근 가능");

  const { data, error } = await supabase
    .from("verification_logs")
    .select("id, query, model, cross_score, elapsed, status, created_at")
    .order("id", { ascending: false })
    .limit(20);

  if (error) {
    console.error("❌ Supabase 조회 오류:", error.message);
    return res.status(500).send("DB 조회 실패");
  }

  const rows = data
    .map(
      (r) => `
        <tr>
          <td>${r.id}</td>
          <td>${r.query || "-"}</td>
          <td>${r.model || "-"}</td>
          <td>${r.cross_score ?? "-"}</td>
          <td>${r.elapsed ?? "-"}</td>
          <td>${r.status || "-"}</td>
          <td>${r.created_at}</td>
        </tr>`
    )
    .join("");

  res.send(`
    <html><head>
      <meta charset="utf-8" />
      <title>Admin Dashboard</title>
      <style>
        body { font-family: Arial; padding: 24px; background: #fafafa; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 6px; text-align: left; }
        th { background: #eee; }
      </style>
    </head>
    <body>
      <h2>🔐 Admin Dashboard (Supabase Persistent Session)</h2>
      <p>관리자: ${req.user.displayName} (${req.user.emails[0].value})</p>
      <table>
        <thead>
          <tr>
            <th>ID</th><th>Query</th><th>Model</th><th>CrossScore</th><th>Elapsed</th><th>Status</th><th>Created</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      <p style="margin-top:16px;font-size:13px;color:#666;">Generated at ${new Date().toISOString()}</p>
    </body></html>
  `);
});

// ----------------------------
// 서버 실행
// ----------------------------
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy (v12.5.1) 실행 중 - 포트: ${PORT}`);
});
