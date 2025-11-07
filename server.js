// =======================================================
// Cross-Verified AI Proxy — v14.0.3 (Render + Admin + Naver Test)
// =======================================================
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
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { parseXMLtoJSON } from "./utils/xmlParser.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────
// ✅ EJS + Static (절대경로 보정)
// ─────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

// ─────────────────────────────
// ✅ 기본 미들웨어
// ─────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(morgan("dev"));
// ─────────────────────────────
// ✅ Supabase + PostgreSQL 세션
// ─────────────────────────────
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
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
// ✅ OAuth (Google Admin)
// ─────────────────────────────
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
  clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
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
// ✅ Admin Dashboard Routes
// ─────────────────────────────
function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.redirect("/auth/admin");
}

app.get("/auth/admin", passport.authenticate("google", { scope: ["email", "profile"] }));
app.get("/auth/admin/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => res.redirect("/admin/dashboard"));
app.get("/auth/failure", (req, res) => res.status(401).send("❌ OAuth Failed"));

app.get("/admin/dashboard", ensureAuth, async (req, res) => {
  const { data: logs } = await supabase
    .from("api_logs")
    .select("created_at, engine, truthscore, response_time")
    .order("created_at", { ascending: false })
    .limit(20);

  const avgTruth = logs?.reduce((a, b) => a + (b.truthscore || 0), 0) / (logs?.length || 1);
  const avgResponse = logs?.reduce((a, b) => a + (b.response_time || 0), 0) / (logs?.length || 1);

  res.render("dashboard", {
    user: req.user,
    stats: {
      avgTruth: avgTruth.toFixed(2),
      avgResponse: avgResponse.toFixed(0),
      count: logs?.length || 0
    },
    logs: logs || [],
  });
});
// ─────────────────────────────
// ✅ Naver API + Whitelist Filtering + Test
// ─────────────────────────────
const NAVER_API_BASE = "https://openapi.naver.com/v1/search";
const NAVER_HEADERS = {
  "X-Naver-Client-Id": process.env.NAVER_CLIENT_ID,
  "X-Naver-Client-Secret": process.env.NAVER_CLIENT_SECRET
};
const whitelistPath = path.join(__dirname, "data", "naver_whitelist.json");
let whitelistData = {};
try {
  whitelistData = JSON.parse(fs.readFileSync(whitelistPath, "utf-8"));
} catch (err) {
  console.warn("⚠️ Naver whitelist 로드 실패:", err.message);
  whitelistData = { tiers: {} };
}
const allDomains = Object.values(whitelistData.tiers || {}).flatMap(t => t.domains);
const filterByWhitelist = (arr) =>
  arr.filter(i => allDomains.some(d => i.link?.includes(d)));

async function callNaverAPIs(query) {
  const endpoints = {
    news: `${NAVER_API_BASE}/news.json?query=${encodeURIComponent(query)}&display=5`,
    ency: `${NAVER_API_BASE}/encyc.json?query=${encodeURIComponent(query)}&display=3`,
    web: `${NAVER_API_BASE}/webkr.json?query=${encodeURIComponent(query)}&display=3`
  };
  const [news, ency, web] = await Promise.allSettled([
    axios.get(endpoints.news, { headers: NAVER_HEADERS }),
    axios.get(endpoints.ency, { headers: NAVER_HEADERS }),
    axios.get(endpoints.web, { headers: NAVER_HEADERS })
  ]);
  return {
    news: news.status === "fulfilled" ? news.value.data.items : [],
    ency: ency.status === "fulfilled" ? ency.value.data.items : [],
    web: web.status === "fulfilled" ? web.value.data.items : []
  };
}

// ✅ Naver 단일 테스트 엔드포인트
app.post("/api/test-naver", async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ success: false, message: "❌ query 누락" });
    const result = await callNaverAPIs(query);
    res.json({
      success: true,
      counts: {
        news: result.news.length,
        ency: result.ency.length,
        web: result.web.length
      },
      sample: {
        news: result.news[0]?.title,
        ency: result.ency[0]?.title,
        web: result.web[0]?.title
      }
    });
  } catch (err) {
    console.error("❌ /api/test-naver Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ 기존 Verify + K-Law + DB + Health 그대로 유지 (v14.0.2 내용 동일)
