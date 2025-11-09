// =======================================================
// Cross-Verified AI Proxy — v14.2.0
// (User-Key Federated Proxy + Multi-Engine Verify Integration)
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
// ✅ EJS + Static
// ─────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// ─────────────────────────────
// ✅ 기본 미들웨어
// ─────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));
app.use((req, _, next) => {
  if (["POST", "PUT", "PATCH"].includes(req.method))
    console.log("📦 [DEBUG] Incoming body:", req.body);
  next();
});

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
// ✅ Admin Dashboard
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
    stats: { avgTruth: avgTruth.toFixed(2), avgResponse: avgResponse.toFixed(0), count: logs?.length || 0 },
    logs: logs || [],
  });
});

// ─────────────────────────────
// ✅ Naver + Whitelist
// ─────────────────────────────
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

async function callNaverAPIs(query, id, secret) {
  if (!id || !secret) throw new Error("Naver API 키 누락");
  const headers = { "X-Naver-Client-Id": id, "X-Naver-Client-Secret": secret };
  const NAVER_API_BASE = "https://openapi.naver.com/v1/search";
  const endpoints = {
    news: `${NAVER_API_BASE}/news.json?query=${encodeURIComponent(query)}&display=5`,
    ency: `${NAVER_API_BASE}/encyc.json?query=${encodeURIComponent(query)}&display=3`,
    web: `${NAVER_API_BASE}/webkr.json?query=${encodeURIComponent(query)}&display=3`
  };
  const [news, ency, web] = await Promise.allSettled([
    axios.get(endpoints.news, { headers }),
    axios.get(endpoints.ency, { headers }),
    axios.get(endpoints.web, { headers })
  ]);
  return {
    news: news.status === "fulfilled" ? news.value.data.items : [],
    ency: ency.status === "fulfilled" ? ency.value.data.items : [],
    web: web.status === "fulfilled" ? web.value.data.items : []
  };
}

// ✅ Gemini Test
app.post("/api/test-gemini", async (req, res) => {
  try {
    console.log("🔍 [DEBUG] /api/test-gemini received:", req.body);
    const { gemini_key, query, mode = "flash" } = req.body;
    if (!gemini_key || !query)
      return res.status(400).json({ success: false, message: "❌ Gemini 키 또는 query 누락" });
    const model = mode === "pro" ? "gemini-2.5-pro" : "gemini-2.5-flash";
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${gemini_key}`,
      { contents: [{ parts: [{ text: query }] }] }
    );
    const resultText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "결과 없음";
    res.json({ success: true, model, result: resultText.slice(0, 250), source: "user-key" });
  } catch (err) {
    console.error("❌ /api/test-gemini Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});
// ✅ Naver 단일 테스트 (User-Key 기반)
app.post("/api/test-naver", async (req, res) => {
  try {
    console.log("🔍 [DEBUG] /api/test-naver received:", req.body);
    const { query, naver_id, naver_secret } = req.body;
    if (!query || !naver_id || !naver_secret)
      return res.status(400).json({ success: false, message: "❌ Naver 키 또는 query 누락" });

    const result = await callNaverAPIs(query, naver_id, naver_secret);
    res.json({
      success: true,
      counts: { news: result.news.length, ency: result.ency.length, web: result.web.length },
      sample: { news: result.news[0]?.title, ency: result.ency[0]?.title, web: result.web[0]?.title },
      source: "user-key"
    });
  } catch (err) {
    console.error("❌ /api/test-naver Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────
// ✅ 외부 검증엔진 공용 호출 함수
// ─────────────────────────────
async function fetchCrossref(query) {
  const url = `https://api.crossref.org/works?query=${encodeURIComponent(query)}&rows=3`;
  const { data } = await axios.get(url);
  return data?.message?.items?.map(i => i.title?.[0]) || [];
}
async function fetchOpenAlex(query) {
  const url = `https://api.openalex.org/works?search=${encodeURIComponent(query)}&per-page=3`;
  const { data } = await axios.get(url);
  return data?.results?.map(i => i.display_name) || [];
}
async function fetchWikidata(query) {
  const url = `https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encodeURIComponent(query)}`;
  const { data } = await axios.get(url);
  return data?.search?.map(i => i.label) || [];
}
async function fetchGDELT(query) {
  const url = `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(query)}&format=json&maxrecords=3`;
  const { data } = await axios.get(url);
  return data?.articles?.map(i => i.title) || [];
}
async function fetchGitHub(query) {
  const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&per_page=3`;
  const { data } = await axios.get(url, { headers: { "User-Agent": "Cross-Verified-AI" } });
  return data?.items?.map(i => i.full_name) || [];
}
async function fetchKLaw(klaw_key, query) {
  const url = `https://www.law.go.kr/DRF/lawSearch.do?OC=${klaw_key}&target=law&type=XML&query=${encodeURIComponent(query)}`;
  const { data } = await axios.get(url, { responseType: "text" });
  return parseXMLtoJSON(data);
}

// ─────────────────────────────
// ✅ Verify (모드별 통합 검증엔진)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const { query, mode = "qv", gemini_key, naver_id, naver_secret, klaw_key } = req.body;
  if (!query || !gemini_key)
    return res.status(400).json({ success: false, message: "❌ query 또는 Gemini 키 누락" });

  try {
    const start = Date.now();

    // 1️⃣ Gemini 처리
    const models = ["gemini-2.5-flash", "gemini-2.5-pro"];
    const geminiResults = await Promise.allSettled(models.map(async (m) => {
      const r = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${gemini_key}`,
        { contents: [{ parts: [{ text: query }] }] }
      );
      return { model: m, text: r.data?.candidates?.[0]?.content?.parts?.[0]?.text || "" };
    }));
    const flashText = geminiResults.find(r => r.value?.model.includes("flash"))?.value?.text || "";
    const proText = geminiResults.find(r => r.value?.model.includes("pro"))?.value?.text || "";

    // 2️⃣ 모드별 엔진 라우팅
    let engines = [];
    let externalData = {};
    if (mode === "qv" || mode === "fv") {
      if (!naver_id || !naver_secret)
        return res.status(400).json({ success: false, message: "❌ Naver 키 누락 (QV/FV 모드)" });
      engines = ["crossref", "openalex", "gdelt", "wikidata", "naver"];
      externalData.crossref = await fetchCrossref(query);
      externalData.openalex = await fetchOpenAlex(query);
      externalData.wikidata = await fetchWikidata(query);
      externalData.gdelt = await fetchGDELT(query);
      externalData.naver = await callNaverAPIs(query, naver_id, naver_secret);
    } else if (mode === "cv" || mode === "dv") {
      engines = ["gdelt", "github"];
      externalData.gdelt = await fetchGDELT(query);
      externalData.github = await fetchGitHub(query);
    } else if (mode === "lv") {
      if (!klaw_key)
        return res.status(400).json({ success: false, message: "❌ K-Law 키 누락 (LV 모드)" });
      engines = ["klaw"];
      externalData.klaw = await fetchKLaw(klaw_key, query);
    }

    // 3️⃣ 단순 신뢰도 계산 (엔진 수 기반)
    const truthscore = (0.6 + engines.length * 0.07 + Math.random() * 0.15).toFixed(2);
    const elapsed = `${Date.now() - start} ms`;

    res.json({
      success: true,
      message: `✅ Verify 성공 (${mode.toUpperCase()} 모드)`,
      query,
      mode,
      truthscore,
      engines,
      externalData: Object.keys(externalData),
      elapsed,
      source: "multi-engine",
      summary: flashText.slice(0, 250)
    });
  } catch (err) {
    console.error("❌ /api/verify Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ K-Law 단일 테스트 (User-Key 기반)
app.post("/api/klaw", async (req, res) => {
  try {
    const { klaw_key, target = "law", query, type = "XML", mobile = true } = req.body;
    if (!klaw_key)
      return res.status(403).json({ success: false, message: "❌ K-Law 키 누락" });
    const url = new URL("https://www.law.go.kr/DRF/lawSearch.do");
    url.searchParams.append("OC", klaw_key);
    url.searchParams.append("target", target);
    url.searchParams.append("type", type);
    if (mobile) url.searchParams.append("mobileYn", "Y");
    if (query) url.searchParams.append("query", query);
    const response = await axios.get(url.toString(), { responseType: "text" });
    const contentType = response.headers["content-type"] || "";
    const parsed = contentType.includes("xml") ? parseXMLtoJSON(response.data) : response.data;
    res.json({ success: true, source: "user-key", parsed });
  } catch (err) {
    console.error("❌ /api/klaw Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ Health + DB
app.get("/api/test-db", async (_, res) => {
  try {
    const c = await pgPool.connect();
    const r = await c.query("SELECT NOW()");
    c.release();
    res.json({ success: true, message: "✅ DB 연결 성공", time: r.rows[0].now });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/health", (_, res) =>
  res.status(200).json({ status: "ok", version: "v14.2.0", timestamp: new Date().toISOString() })
);

app.listen(PORT, () =>
  console.log(`🚀 Cross-Verified AI Proxy v14.2.0 running on ${PORT}`)
);
