// =======================================================
// Cross-Verified AI Proxy — v14.0.4 (Render + Admin + Naver + Verify + K-Law)
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

// ✅ EJS + Static (절대경로 보정)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

// ✅ 미들웨어
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(morgan("dev"));

// ✅ Supabase + PostgreSQL 세션
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

// ✅ OAuth (Google Admin)
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

// ✅ Admin Dashboard
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
    stats: { avgTruth: avgTruth.toFixed(2), avgResponse: avgResponse.toFixed(0), count: logs?.length || 0 },
    logs: logs || [],
  });
});

// ✅ Naver API + Whitelist
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
const filterByWhitelist = (arr) => arr.filter(i => allDomains.some(d => i.link?.includes(d)));
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
// ✅ Verify 엔진 통합 (Gemini + Naver + Whitelist)
app.post("/api/verify", async (req, res) => {
  const { query, key } = req.body;
  if (!query || !key)
    return res.status(400).json({ success: false, message: "❌ query 또는 key 누락" });

  try {
    const start = Date.now();
    const models = ["gemini-2.5-flash", "gemini-2.5-pro"];
    const geminiResults = await Promise.allSettled(
      models.map(async (m) => {
        const r = await axios.post(
          `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${key}`,
          { contents: [{ parts: [{ text: query }] }] }
        );
        return { model: m, text: r.data?.candidates?.[0]?.content?.parts?.[0]?.text || "" };
      })
    );

    const merged = geminiResults.filter(r => r.status === "fulfilled").map(r => r.value);
    const flashText = merged.find(m => m.model.includes("flash"))?.text || "";
    const proText = merged.find(m => m.model.includes("pro"))?.text || "";

    const naverResults = await callNaverAPIs(query);
    const filteredNaver = {
      news: filterByWhitelist(naverResults.news),
      ency: naverResults.ency,
      web: filterByWhitelist(naverResults.web)
    };

    const sentences = proText.split(/(?<=[.?!])\s+/).map(s => s.trim()).filter(Boolean);
    const partial = sentences.map((s, i) => {
      const normalized = s.toLowerCase().replace(/\s+/g, " ");
      const match = flashText.toLowerCase().includes(normalized.split(" ").slice(0, 5).join(" "));
      const confidence = match ? "high" : "medium";
      return { id: i + 1, sentence: s, confidence, icon: match ? "✔️" : "❓" };
    });

    const truthWeights = { news: 0.9, ency: 1.0, web: 0.7 };
    const naverScore =
      (filteredNaver.news.length * truthWeights.news +
        filteredNaver.ency.length * truthWeights.ency +
        filteredNaver.web.length * truthWeights.web) /
      (filteredNaver.news.length + filteredNaver.ency.length + filteredNaver.web.length || 1);

    const avg = (partial.filter(p => p.confidence === "high").length / partial.length) || 0;
    const finalTruth = ((avg + naverScore) / 2).toFixed(2);
    const elapsed = `${Date.now() - start} ms`;

    res.json({
      success: true,
      message: "✅ Adaptive Verify + Naver Whitelist 완료",
      query,
      truthscore: finalTruth,
      naver: {
        counts: {
          news: filteredNaver.news.length,
          ency: filteredNaver.ency.length,
          web: filteredNaver.web.length
        }
      },
      summary_confidence: avg.toFixed(2),
      elapsed,
      store_local: true,
    });
  } catch (err) {
    console.error("❌ /api/verify Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ K-Law (법령정보 API)
app.post("/api/klaw", async (req, res) => {
  try {
    const { oc, target, query, type = "XML", mobile = true } = req.body;
    if (!oc || !target)
      return res.status(400).json({ success: false, message: "❌ OC 또는 target 누락" });

    const baseUrl = "https://www.law.go.kr/DRF/lawSearch.do";
    const params = new URLSearchParams({
      OC: oc,
      target,
      type,
      mobileYn: mobile ? "Y" : "N",
      query: query || "",
      display: 20,
      page: 1
    });

    const response = await axios.get(`${baseUrl}?${params}`, { responseType: "text" });
    const contentType = response.headers["content-type"] || "";
    let parsed;

    if (contentType.includes("xml")) parsed = parseXMLtoJSON(response.data);
    else if (contentType.includes("json")) parsed = JSON.parse(response.data);
    else parsed = { raw: response.data };

    res.json({ success: true, target, format: type, parsed, source_url: `${baseUrl}?${params}` });
  } catch (err) {
    console.error("❌ /api/klaw Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ PostgreSQL 연결 테스트
app.get("/api/test-db", async (req, res) => {
  try {
    const client = await pgPool.connect();
    const result = await client.query("SELECT NOW()");
    client.release();
    res.json({ success: true, message: "✅ PostgreSQL 연결 성공", time: new Date(result.rows[0].now).toISOString() });
  } catch (err) {
    res.status(500).json({ success: false, message: "❌ PostgreSQL 연결 실패", error: err.message });
  }
});

// ✅ Health Check & Server Start
app.get("/health", (_, res) =>
  res.status(200).json({ status: "ok", version: "v14.0.4", timestamp: new Date().toISOString() })
);
const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log(`🚀 Cross-Verified AI Proxy v14.0.4 running on port ${port}`);
  console.log(`🌐 Health: http://localhost:${port}/health`);
});
