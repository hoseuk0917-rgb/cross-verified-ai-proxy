// =======================================================
// Cross-Verified AI Proxy — v13.8.5 (Naver Integrated)
// Render + Supabase + OAuth + Gemini Flash/Pro + Fast-XML
// + Naver Web/News/Ency Integration + Local-First Caching
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
import { parseXMLtoJSON } from "./utils/xmlParser.js";   // ✅ fast-xml-parser 단일화 버전 사용

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
// ✅ Supabase 연결 (계정/Key용 최소 테이블만)
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
app.use(session({
  store: new PgStore({ pool: pgPool, tableName: "session_store" }),
  secret: process.env.SESSION_SECRET || "dev-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  },
}));

// ─────────────────────────────
// ✅ Passport (Google OAuth)
// ─────────────────────────────
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
  clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    const whitelist = process.env.ADMIN_WHITELIST?.split(",") || [];
    if (!whitelist.includes(email))
      return done(new Error("Unauthorized admin user"));
    await supabase.from("users")
      .upsert([{ email, name: profile.displayName }], { onConflict: "email" });
    return done(null, { email, name: profile.displayName });
  } catch (err) { return done(err); }
}));
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));
app.use(passport.initialize());
app.use(passport.session());

// ─────────────────────────────
// ✅ OAuth Routes
// ─────────────────────────────
app.get("/auth/admin", passport.authenticate("google", { scope: ["email", "profile"] }));
app.get("/auth/admin/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  async (req, res) => {
    const { email, name } = req.user;
    await supabase.from("sessions").insert([{ email, name, provider: "google" }]);
    res.send(`<h2>✅ OAuth Login Success</h2><p>${name} (${email})</p>`);
  });
app.get("/auth/failure", (req, res) => res.status(401).send("❌ OAuth Failed"));
// ─────────────────────────────
// ✅ Flash-Lite 핵심어 추출
// ─────────────────────────────
app.post("/api/extract-keywords", async (req, res) => {
  try {
    const { key, query } = req.body;
    if (!key || !query)
      return res.status(400).json({ success: false, message: "❌ key 또는 query 누락" });

    const model = "gemini-2.5-flash-lite";
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
      { contents: [{ parts: [{ text: `다음 문장에서 핵심 검색어만 나열해줘:\n"${query}"` }] }] }
    );

    let raw = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    let clean = raw.replace(/[#*•`]/g, "")
      .replace(/(핵심|검색|구문|조건|설명)/g, "")
      .replace(/[^\w가-힣\s]/g, "")
      .replace(/\s+/g, " ")
      .trim();

    const hasOr = /(또는|or|,|\/)/i.test(query);
    const hasAnd = /(과|및|와|그리고)/i.test(query);
    const mode = hasOr ? "OR" : hasAnd ? "AND" : "AND";
    const tokens = clean.split(" ").filter(t => t.length > 1);
    const commonPrefix = query.match(/\b(UAM|AI|SmartCity|스마트시티)\b/i);
    let expanded = clean;
    if (commonPrefix && tokens.length >= 2 && mode === "OR")
      expanded = `${commonPrefix[0]} ${tokens[0]} OR ${commonPrefix[0]} ${tokens[1]}`;

    const finalQuery = (mode === "OR")
      ? expanded.replace(/\s+OR\s+/g, " OR ")
      : expanded.split(" ").join(" AND ");

    res.json({
      success: true,
      engine: model,
      mode,
      raw: raw.trim(),
      clean,
      final: finalQuery,
      cached: true,
      store_local: true,
    });
  } catch (err) {
    console.error("❌ /api/extract-keywords Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────
// ✅ Gemini Flash / Pro 단일 테스트
// ─────────────────────────────
app.post("/api/test-gemini", async (req, res) => {
  try {
    const { key, query, mode = "flash" } = req.body;
    const model = mode === "pro" ? "gemini-2.5-pro" : "gemini-2.5-flash";
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
      { contents: [{ parts: [{ text: query || "테스트 요청" }] }] }
    );
    const resultText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "결과 없음";
    res.json({ success: true, model, result: resultText.slice(0, 200), store_local: true });
  } catch (err) {
    console.error("❌ /api/test-gemini Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────
// ✅ Naver Search API (뉴스/백과/웹 통합)
// ─────────────────────────────
const NAVER_API_BASE = "https://openapi.naver.com/v1/search";
const NAVER_HEADERS = {
  "X-Naver-Client-Id": process.env.NAVER_CLIENT_ID,
  "X-Naver-Client-Secret": process.env.NAVER_CLIENT_SECRET
};
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
// ─────────────────────────────
// ✅ Adaptive Verify (Gemini Flash + Pro + Naver Sources)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const { query, key, mode = "auto" } = req.body;
  if (!query || !key)
    return res.status(400).json({ success: false, message: "❌ query 또는 key 누락" });

  try {
    const start = Date.now();

    // 1️⃣ Gemini 병렬 (Flash + Pro)
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

    // 2️⃣ Naver API 호출 (뉴스, 백과, 웹)
    const naverResults = await callNaverAPIs(query);

    // 3️⃣ 문장 단위 신뢰도 계산
    const sentences = proText.split(/(?<=[.?!])\s+/).map(s => s.trim()).filter(Boolean);
    const partial = sentences.map((s, i) => {
      const normalized = s.toLowerCase().replace(/\s+/g, " ");
      const match = flashText.toLowerCase().includes(normalized.split(" ").slice(0, 5).join(" "));
      const confidence = match ? "high" : "medium";
      const icon = match ? "✔️" : "❓";
      return { id: i + 1, sentence: s, confidence, icon };
    });

    // 4️⃣ TruthScore 계산 (Naver 가중치 반영)
    const truthWeights = { news: 0.9, ency: 1.0, web: 0.7 };
    const naverScore =
      (naverResults.news.length * truthWeights.news +
        naverResults.ency.length * truthWeights.ency +
        naverResults.web.length * truthWeights.web) /
      (naverResults.news.length + naverResults.ency.length + naverResults.web.length || 1);

    const avg = (partial.filter(p => p.confidence === "high").length / partial.length) || 0;
    const finalTruth = ((avg + naverScore) / 2).toFixed(2);
    const elapsed = `${Date.now() - start} ms`;

    // 5️⃣ 응답
    res.json({
      success: true,
      message: "✅ Adaptive Verify + Naver 통합 완료",
      query,
      mode,
      elapsed,
      truthscore: finalTruth,
      gemini: {
        flashText: flashText.slice(0, 400),
        proText: proText.slice(0, 400)
      },
      naver: {
        counts: {
          news: naverResults.news.length,
          ency: naverResults.ency.length,
          web: naverResults.web.length
        }
      },
      summary_confidence: avg.toFixed(2),
      store_local: true,
    });
  } catch (err) {
    console.error("❌ /api/verify Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────
// ✅ TruthScore 시각화 기준 (UI 참고용)
// ─────────────────────────────
const TRUTH_ICONS = {
  high: "🟢",
  reliable: "🟡",
  low: "🟠",
  unreliable: "🔴",
  encyclopedia: "📘",
  web: "🌐"
};
// ─────────────────────────────
// ✅ K-Law (법령정보 통합 API) — fast-xml-parser 기반
// ─────────────────────────────
app.post("/api/klaw", async (req, res) => {
  try {
    const { oc, target, query, type = "JSON", mobile = true, display = 20, page = 1 } = req.body;
    if (!oc || !target)
      return res.status(400).json({ success: false, message: "❌ OC 또는 target 누락" });

    const baseUrl = "https://www.law.go.kr/DRF/lawSearch.do";
    const url = new URL(baseUrl);
    url.searchParams.append("OC", oc);
    url.searchParams.append("target", target);
    url.searchParams.append("type", type.toUpperCase());
    if (mobile) url.searchParams.append("mobileYn", "Y");
    if (query) url.searchParams.append("query", query);
    url.searchParams.append("display", display);
    url.searchParams.append("page", page);

    const response = await axios.get(url.toString(), { responseType: "text" });
    const contentType = response.headers["content-type"] || "";
    let data;

    if (contentType.includes("xml") || type.toUpperCase() === "XML") {
      data = parseXMLtoJSON(response.data);
    } else if (contentType.includes("json") || type.toUpperCase() === "JSON") {
      data = typeof response.data === "string" ? JSON.parse(response.data) : response.data;
    } else {
      data = { raw: response.data };
    }

    res.json({
      success: true,
      target,
      format: type.toUpperCase(),
      source_url: url.toString(),
      parsed: data,
    });
  } catch (err) {
    console.error("❌ /api/klaw Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────
// ✅ PostgreSQL 연결 테스트
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
// ✅ Health Check
// ─────────────────────────────
app.get("/health", (req, res) =>
  res.status(200).json({
    status: "ok",
    timestamp: new Date().toISOString(),
  })
);

// ─────────────────────────────
// ✅ 서버 실행
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v13.8.5 (Naver Integrated) running on port ${PORT}`);
  console.log(`🌐 Health: http://localhost:${PORT}/health`);
  console.log(`🧠 DB Test: http://localhost:${PORT}/api/test-db`);
  console.log(`🔑 Keyword Extract: POST /api/extract-keywords`);
  console.log(`🤖 Verify: POST /api/verify`);
  console.log(`⚖️ K-Law API: POST /api/klaw`);
});
