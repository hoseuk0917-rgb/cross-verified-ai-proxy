// =======================================================
// Cross-Verified AI Proxy — v15.0.4 (Full Extended + DV/CV 독립검증)
// =======================================================
process.on("unhandledRejection", r => console.error("⚠️ Unhandled:", r));
process.on("uncaughtException", e => console.error("💥 Crash:", e));

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
import xml2js from "xml2js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import ejs from "ejs";
import nodemailer from "nodemailer";
import { google } from "googleapis";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const DEBUG = process.env.DEBUG_MODE === "true";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "8mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));
if (DEBUG) console.log("🧩 Debug mode enabled");

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
// ✅ 공통 유틸리티
// ─────────────────────────────
async function parseXMLtoJSON(xml) {
  return new Promise((resolve, reject) => {
    xml2js.parseString(xml, { explicitArray: false }, (err, res) =>
      err ? reject(err) : resolve(res)
    );
  });
}
function expDecay(days) { return Math.exp(-days / 90); } // Rₜ = e^(-Δt/90)

// ─────────────────────────────
// ✅ Gmail OAuth2 Mailer
// ─────────────────────────────
const oAuth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  process.env.GMAIL_REDIRECT_URI
);
oAuth2Client.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });
async function sendAdminNotice(subject, html) {
  try {
    const accessToken = await oAuth2Client.getAccessToken();
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        type: "OAuth2",
        user: process.env.GMAIL_USER,
        clientId: process.env.GMAIL_CLIENT_ID,
        clientSecret: process.env.GMAIL_CLIENT_SECRET,
        refreshToken: process.env.GMAIL_REFRESH_TOKEN,
        accessToken
      }
    });
    await transporter.sendMail({
      from: `"Cross-Verified Notifier" <${process.env.GMAIL_USER}>`,
      to: process.env.ADMIN_EMAIL,
      subject, html
    });
  } catch (err) { console.error("❌ Mail fail:", err.message); }
}
let failCount = 0;
async function handleEngineFail(engine, query, error) {
  failCount++;
  await supabase.from("engine_fails").insert([{ engine, query, error, created_at: new Date() }]);
  if (failCount >= 3) {
    await sendAdminNotice("⚠️ Engine Fail-Grace", `<p>마지막 엔진: ${engine}<br>${error}</p>`);
    failCount = 0;
  }
}

// ─────────────────────────────
// ✅ OAuth / Naver / External Engines
// ─────────────────────────────
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
  clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
}, async (_, __, profile, done) => {
  const email = profile.emails?.[0]?.value;
  const allow = process.env.ADMIN_WHITELIST?.split(",") || [];
  if (!allow.includes(email)) return done(new Error("Unauthorized"));
  await supabase.from("users").upsert([{ email, name: profile.displayName }], { onConflict: "email" });
  done(null, { email, name: profile.displayName });
}));
passport.serializeUser((u, d) => d(null, u));
passport.deserializeUser((u, d) => d(null, u));
app.use(passport.initialize());
app.use(passport.session());
function ensureAuth(req, res, next) { if (req.isAuthenticated()) return next(); res.redirect("/auth/admin"); }
app.get("/auth/admin", passport.authenticate("google", { scope: ["email", "profile"] }));
app.get("/auth/admin/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  (_, res) => res.redirect("/admin/dashboard"));
app.get("/auth/failure", (_, res) => res.status(401).send("❌ OAuth Failed"));
// ─────────────────────────────
// ✅ Naver Whitelist Tier System
// ─────────────────────────────
const whitelistPath = path.join(__dirname, "data", "naver_whitelist.json");
let whitelistData = {};
try {
  whitelistData = JSON.parse(fs.readFileSync(whitelistPath, "utf-8"));
} catch {
  whitelistData = { tiers: {} };
  if (DEBUG) console.warn("⚠️ whitelist not found, using empty");
}
const tierWeights = Object.entries(whitelistData.tiers || {}).map(([k, v]) => ({
  tier: k,
  weight: v.weight || 1,
  domains: v.domains || [],
}));

function filterByWhitelist(items = []) {
  const scored = [];
  for (const i of items) {
    const link = i.originallink || i.link || "";
    let maxW = 0;
    for (const t of tierWeights)
      if (t.domains.some((d) => link.includes(d)))
        maxW = Math.max(maxW, t.weight);
    if (maxW > 0) scored.push({ ...i, weight: maxW });
  }
  return scored.sort((a, b) => b.weight - a.weight);
}

async function callNaver(query, id, secret) {
  if (!id || !secret) throw new Error("Naver 키 누락");
  const base = "https://openapi.naver.com/v1/search";
  const headers = {
    "X-Naver-Client-Id": id,
    "X-Naver-Client-Secret": secret,
  };
  const endpoints = {
    news: `${base}/news.json?query=${encodeURIComponent(query)}&display=5`,
    web: `${base}/webkr.json?query=${encodeURIComponent(query)}&display=5`,
    ency: `${base}/encyc.json?query=${encodeURIComponent(query)}&display=3`,
  };
  const results = {};
  for (const [key, url] of Object.entries(endpoints)) {
    for (let i = 0; i < 2; i++) {
      try {
        const r = await axios.get(url, { headers, timeout: 6000 });
        results[key] = filterByWhitelist(r.data.items || []);
        break;
      } catch (err) {
        if (i === 1) {
          await handleEngineFail("naver", query, err.message);
          results[key] = [];
        }
      }
    }
  }
  return results;
}

// ─────────────────────────────
// ✅ External Engines + Fail-Grace Wrapper
// ─────────────────────────────
async function safeFetch(name, fn, q) {
  for (let i = 0; i < 2; i++) {
    try {
      return await fn(q);
    } catch (err) {
      if (i === 1) {
        await handleEngineFail(name, q, err.message);
        return [];
      }
    }
  }
}

async function fetchCrossref(q) {
  const { data } = await axios.get(
    `https://api.crossref.org/works?query=${encodeURIComponent(q)}&rows=3`
  );
  return data?.message?.items?.map((i) => i.title?.[0]) || [];
}
async function fetchOpenAlex(q) {
  const { data } = await axios.get(
    `https://api.openalex.org/works?search=${encodeURIComponent(q)}&per-page=3`
  );
  return data?.results?.map((i) => i.display_name) || [];
}
async function fetchWikidata(q) {
  const { data } = await axios.get(
    `https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encodeURIComponent(q)}`
  );
  return data?.search?.map((i) => i.label) || [];
}
async function fetchGDELT(q) {
  const { data } = await axios.get(
    `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q)}&format=json&maxrecords=3`
  );
  return data?.articles?.map((i) => ({
    title: i.title,
    date: i.seendate,
  })) || [];
}
async function fetchGitHub(q) {
  const { data } = await axios.get(
    `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&per_page=3`,
    { headers: { "User-Agent": "CrossVerifiedAI" } }
  );
  return data?.items?.map((i) => ({
    name: i.full_name,
    stars: i.stargazers_count,
    forks: i.forks_count,
    updated: i.updated_at,
  })) || [];
}
async function fetchKLaw(k, q) {
  const { data } = await axios.get(
    `https://www.law.go.kr/DRF/lawSearch.do?OC=${k}&target=law&type=XML&query=${encodeURIComponent(q)}`,
    { responseType: "text" }
  );
  return parseXMLtoJSON(data);
}

// ─────────────────────────────
// ✅ 시의성 (Rₜ, GDELT 기반) + 유효성 (Vᵣ, GitHub 기반)
// ─────────────────────────────
function calcRecencyScore(gdeltItems = []) {
  if (!gdeltItems.length) return 0.5;
  const now = new Date();
  const scores = gdeltItems.map((a) => {
    const diffDays = (now - new Date(a.date)) / (1000 * 60 * 60 * 24);
    return expDecay(diffDays);
  });
  const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
  return Math.min(1, Math.max(0, avg));
}

function calcValidityScore(gitItems = []) {
  if (!gitItems.length) return 0.5;
  const norm = gitItems.map((r) => {
    const stars = Math.min(r.stars || 0, 5000) / 5000;
    const forks = Math.min(r.forks || 0, 1000) / 1000;
    const freshness =
      1 - Math.min((new Date() - new Date(r.updated)) / (1000 * 60 * 60 * 24 * 365), 1);
    return 0.5 * stars + 0.3 * forks + 0.2 * freshness;
  });
  return norm.reduce((a, b) => a + b, 0) / norm.length;
}

// ─────────────────────────────
// ✅ Gemini 안정화 요청기 (v1 + Soft Retry + Timeout)
// ─────────────────────────────
async function fetchGemini(url, body) {
  for (let i = 0; i < 2; i++) {
    try {
      const res = await axios.post(url, body, { timeout: 20000 });
      const text = res.data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (text) return text;
    } catch (err) {
      if (i === 1) throw err;
    }
  }
  return "";
}
// ─────────────────────────────
// ✅ Weight + History Update
// ─────────────────────────────
async function updateWeight(engine, truth, time) {
  try {
    const { data: prev } = await supabase
      .from("engine_stats")
      .select("*")
      .eq("engine_name", engine)
      .single();
    const λ = 0.8;
    const prevTruth = prev?.avg_truth || 0.7;
    const prevResp = prev?.avg_response || 1000;
    const newTruth = prevTruth * λ + truth * (1 - λ);
    const newResp = prevResp * λ + time * (1 - λ);
    await supabase.from("engine_stats").upsert([
      {
        engine_name: engine,
        avg_truth: newTruth,
        avg_response: newResp,
        total_runs: (prev?.total_runs || 0) + 1,
        updated_at: new Date(),
      },
    ]);
  } catch (e) {
    if (DEBUG) console.warn("⚠️ Weight update fail:", e.message);
  }
}

// ─────────────────────────────
// ✅ Verify Core (QV, FV, DV, CV, LV)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const { query, mode, gemini_key, naver_id, naver_secret, klaw_key, user_answer } = req.body;
  if (!query || !gemini_key)
    return res.status(400).json({ success: false, message: "❌ query 또는 Gemini 키 누락" });

  const engines = [];
  const external = {};
  const start = Date.now();
  let partial_scores = {};
  let truthscore = 0.0;

  try {
    switch (mode) {
      // ── 개발검증(DV) / 코드검증(CV) ──
      case "dv":
      case "cv":
        engines.push("gdelt", "github");
        [external.gdelt, external.github] = await Promise.all([
          safeFetch("gdelt", fetchGDELT, query),
          safeFetch("github", fetchGitHub, query),
        ]);
        partial_scores.recency = calcRecencyScore(external.gdelt);
        partial_scores.validity = calcValidityScore(external.github);
        break;

      // ── 법령검증(LV) ──
      case "lv":
        engines.push("klaw");
        external.klaw = await fetchKLaw(klaw_key, query);
        break;

      // ── 기본검증(QV/FV) ──
      default:
        engines.push("crossref", "openalex", "wikidata", "gdelt");
        [external.crossref, external.openalex, external.wikidata, external.gdelt] = await Promise.all([
          safeFetch("crossref", fetchCrossref, query),
          safeFetch("openalex", fetchOpenAlex, query),
          safeFetch("wikidata", fetchWikidata, query),
          safeFetch("gdelt", fetchGDELT, query),
        ]);
        if (naver_id && naver_secret) {
          external.naver = await callNaver(query, naver_id, naver_secret);
          engines.push("naver");
        }
    }

    // ── Gemini 요청 단계 (Flash → Pro) ──
    const flashPrompt = `[${mode.toUpperCase()}] ${query}\n참조자료: ${JSON.stringify(external).slice(0, 800)}`;
    const flash = await fetchGemini(
      `https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=${gemini_key}`,
      { contents: [{ parts: [{ text: flashPrompt }] }] }
    );

    const verifyPrompt = `검증모드:${mode}\n${user_answer || query}\n${flash}`;
    const verify = await fetchGemini(
      `https://generativelanguage.googleapis.com/v1/models/gemini-2.5-pro:generateContent?key=${gemini_key}`,
      { contents: [{ parts: [{ text: verifyPrompt }] }] }
    );

    // ── TruthScore 계산 (시의성·유효성 독립판정식 반영) ──
    const elapsed = Date.now() - start;
    const Rₜ = partial_scores.recency ?? 0.7; // GDELT
    const Vᵣ = partial_scores.validity ?? 0.7; // GitHub
    let hybrid = 0.7;
    if (mode === "dv" || mode === "cv") hybrid = 0.5 * Rₜ + 0.5 * Vᵣ;
    else if (mode === "lv") hybrid = 0.65;
    truthscore = Math.min(0.97, 0.6 + 0.4 * hybrid);

    // ── 로그 및 DB 반영 ──
    for (const e of engines) await updateWeight(e, truthscore, elapsed);
    await supabase.from("verify_logs").insert([
      {
        query,
        mode,
        truthscore,
        elapsed,
        partial_scores: JSON.stringify(partial_scores),
        engines: JSON.stringify(engines),
        created_at: new Date(),
      },
    ]);

    res.json({
      success: true,
      mode,
      truthscore: truthscore.toFixed(3),
      elapsed,
      engines,
      partial_scores,
      flash_summary: flash.slice(0, 250),
      verify_summary: verify.slice(0, 350),
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    console.error("❌ Verify Error:", e.message);
    await supabase.from("verify_logs").insert([
      { query, mode, error: e.message, created_at: new Date() },
    ]);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─────────────────────────────
// ✅ Health / DB / Server Start
// ─────────────────────────────
app.get("/api/test-db", async (_, res) => {
  try {
    const c = await pgPool.connect();
    const r = await c.query("SELECT NOW()");
    c.release();
    res.json({ success: true, message: "✅ DB 연결 성공", time: r.rows[0].now });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get("/health", (_, res) =>
  res.status(200).json({ status: "ok", version: "v15.0.4", timestamp: new Date().toISOString() })
);

app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v15.0.4 running on port ${PORT}`);
});
