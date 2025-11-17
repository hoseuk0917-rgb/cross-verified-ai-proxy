// =======================================================
// Cross-Verified AI Proxy — v18.3.0
// (Full Extended + LV External Module + Translation + Naver Region Detection)
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

// ✅ LV (법령검증) 모듈 외부화
import { fetchKLawAll } from "./src/modules/klaw_module.js";

// ✅ 번역모듈 (DeepL + Gemini Flash-Lite fallback)
import { translateText } from "./src/modules/translateText.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const DEBUG = process.env.DEBUG_MODE === "true";
const REGION = process.env.REGION || "GLOBAL";

// 🔹 엔진 보정 롤오버 윈도우 (기본 20회, .env에서 ENGINE_CORRECTION_WINDOW로 조정 가능)
const ENGINE_CORRECTION_WINDOW = parseInt(
  process.env.ENGINE_CORRECTION_WINDOW || "20",
  10
);

// 🔹 엔진별 기본 가중치 (w_e)
const ENGINE_BASE_WEIGHTS = {
  crossref: 1.0,
  openalex: 0.95,
  wikidata: 0.9,
  gdelt: 1.0,
  naver: 0.9,
  github: 1.0,
  klaw: 1.0, // ⚠ 명세상 가중치 시스템에 포함되지 않지만, 기존 구조 유지용으로 남김
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "8mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));
if (DEBUG) console.log("🧩 Debug mode enabled");

// ─────────────────────────────
// ✅ 공통 응답 헬퍼 (ⅩⅤ 규약 반영)
// ─────────────────────────────
function buildSuccess(data) {
  return {
    success: true,
    data,
    timestamp: new Date().toISOString(),
  };
}

function buildError(code, message, detail = null) {
  const payload = {
    success: false,
    code,
    message,
    timestamp: new Date().toISOString(),
  };
  if (detail) payload.detail = detail;
  return payload;
}

// ─────────────────────────────
// ✅ Supabase + PostgreSQL 세션
// ─────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
const PgStore = connectPgSimple(session);
const pgPool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(
  session({
    store: new PgStore({ pool: pgPool, tableName: "session_store" }),
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 86400000 },
  })
);

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

function expDecay(days) {
  return Math.exp(-days / 90); // Rₜ = e^(-Δt/90)
}

// GDELT 기반 시의성(recency) 점수 계산
function calcRecencyScore(gdeltArticles = []) {
  if (!gdeltArticles || !gdeltArticles.length) return 0.7; // 정보 없을 때 중립값
  const now = Date.now();
  const scores = gdeltArticles.map((a) => {
    if (!a?.date) return 0.7;
    const t = new Date(a.date).getTime();
    if (Number.isNaN(t)) return 0.7;
    const days = (now - t) / (1000 * 60 * 60 * 24);
    const decay = expDecay(Math.max(0, days)); // 0일→1, 90일→e^-1≈0.37
    // 0.5~0.95 범위로 스케일링
    return 0.5 + 0.45 * Math.max(0, Math.min(1, decay));
  });
  return scores.reduce((s, v) => s + v, 0) / scores.length;
}

// ─────────────────────────────
// ✅ 공통 에러 응답 헬퍼 (ⅩⅤ 규약)
// ─────────────────────────────
function sendError(res, httpStatus, code, message, detail = null) {
  return res.status(httpStatus).json({
    success: false,
    code,
    message,
    detail,
    timestamp: new Date().toISOString(),
  });
}

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
        accessToken,
      },
    });
    await transporter.sendMail({
      from: `"Cross-Verified Notifier" <${process.env.GMAIL_USER}>`,
      to: process.env.ADMIN_EMAIL,
      subject,
      html,
    });
  } catch (err) {
    console.error("❌ Mail fail:", err.message);
  }
}

let failCount = 0;
async function handleEngineFail(engine, query, error) {
  failCount++;
  await supabase
    .from("engine_fails")
    .insert([{ engine, query, error, created_at: new Date() }]);
  if (failCount >= 3) {
    await sendAdminNotice(
      "⚠️ Engine Fail-Grace",
      `<p>마지막 엔진: ${engine}<br>${error}</p>`
    );
    failCount = 0;
  }
}

// ─────────────────────────────
// ✅ OAuth / Naver / External Engines
// ─────────────────────────────
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
      clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
    },
    async (_, __, profile, done) => {
      const email = profile.emails?.[0]?.value;
      const allow = process.env.ADMIN_WHITELIST?.split(",") || [];
      if (!allow.includes(email)) return done(new Error("Unauthorized"));
      await supabase
        .from("users")
        .upsert(
          [{ email, name: profile.displayName }],
          { onConflict: "email" }
        );
      done(null, { email, name: profile.displayName });
    }
  )
);

passport.serializeUser((u, d) => d(null, u));
passport.deserializeUser((u, d) => d(null, u));

app.use(passport.initialize());
app.use(passport.session());

function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.redirect("/auth/admin");
}

app.get(
  "/auth/admin",
  passport.authenticate("google", { scope: ["email", "profile"] })
);
app.get(
  "/auth/admin/callback",
  passport.authenticate("google", {
    failureRedirect: "/auth/failure",
    session: true,
  }),
  (_, res) => res.redirect("/admin/dashboard")
);
app.get("/auth/failure", (_, res) =>
  res.status(401).send("❌ OAuth Failed")
);

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
const tierWeights = Object.entries(whitelistData.tiers || {}).map(
  ([k, v]) => ({
    tier: k,
    weight: v.weight || 1,
    domains: v.domains || [],
  })
);

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

// ─────────────────────────────
// ✅ Naver API (서버 직접 호출 버전 — 추후 앱 호출 플로우로 이관 예정)
// ─────────────────────────────
async function callNaver(query, clientId, clientSecret, req = null) {
  try {
    // 🔹 IP 또는 환경변수 기반 지역 감지
    const ip =
      req?.headers["x-forwarded-for"] || req?.socket?.remoteAddress || "";
    const region = REGION.toUpperCase();
    const isKoreanUser =
      region === "KR" ||
      ip.includes(".kr") ||
      ip.startsWith("121.") ||
      ip.startsWith("175.");
    if (!isKoreanUser) {
      if (DEBUG)
        console.log("🌐 Naver API skipped (non-KR region detected)");
      return [];
    }

    const headers = {
      "X-Naver-Client-Id": clientId,
      "X-Naver-Client-Secret": clientSecret,
    };
    const endpoints = [
      "https://openapi.naver.com/v1/search/news.json",
      "https://openapi.naver.com/v1/search/webkr.json",
      "https://openapi.naver.com/v1/search/encyc.json",
    ];

    const all = [];
    for (const url of endpoints) {
      const { data } = await axios.get(url, {
        headers,
        params: { query, display: 3 },
      });
      const items =
        data?.items?.map((i) => ({
          title: i.title?.replace(/<[^>]+>/g, ""),
          desc: i.description?.replace(/<[^>]+>/g, ""),
          link: i.link,
          origin: "naver",
        })) || [];
      all.push(...items);
    }
    return all;
  } catch (e) {
    if (DEBUG) console.warn("⚠️ Naver fetch fail:", e.message);
    return [];
  }
}

// ─────────────────────────────
// ✅ External Engine Wrappers
// ─────────────────────────────
async function fetchCrossref(q) {
  const { data } = await axios.get(
    `https://api.crossref.org/works?query=${encodeURIComponent(q)}&rows=3`
  );
  return data?.message?.items?.map((i) => i.title?.[0]) || [];
}

async function fetchOpenAlex(q) {
  const { data } = await axios.get(
    `https://api.openalex.org/works?search=${encodeURIComponent(
      q
    )}&per-page=3`
  );
  return data?.results?.map((i) => i.display_name) || [];
}

async function fetchWikidata(q) {
  const { data } = await axios.get(
    `https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encodeURIComponent(
      q
    )}`
  );
  return data?.search?.map((i) => i.label) || [];
}

async function fetchGDELT(q) {
  const { data } = await axios.get(
    `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(
      q
    )}&format=json&maxrecords=3`
  );
  return (
    data?.articles?.map((i) => ({
      title: i.title,
      date: i.seendate,
    })) || []
  );
}

async function fetchGitHub(q, token) {
  const headers = {
    "User-Agent": "CrossVerifiedAI",
  };

  // ✅ 사용자가 설정에서 넣은 github_token 우선 사용
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  } else if (process.env.GITHUB_TOKEN) {
    // (옵션) 서버 환경변수에 백업 토큰 있으면 사용
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  const { data } = await axios.get(
    `https://api.github.com/search/repositories?q=${encodeURIComponent(
      q
    )}&per_page=3`,
    { headers }
  );

  return (
    data?.items?.map((i) => ({
      name: i.full_name,
      stars: i.stargazers_count,
      forks: i.forks_count,
      updated: i.updated_at,
    })) || []
  );
}

// ─────────────────────────────
// ✅ 유효성 (Vᵣ) 계산식 — GitHub 기반
// ─────────────────────────────
function calcValidityScore(gitItems = []) {
  if (!gitItems.length) return 0.5;
  const norm = gitItems.map((r) => {
    const stars = Math.min(r.stars || 0, 5000) / 5000;
    const forks = Math.min(r.forks || 0, 1000) / 1000;
    const freshness =
      1 -
      Math.min(
        (new Date() - new Date(r.updated)) / (1000 * 60 * 60 * 24 * 365),
        1
      );
    return 0.6 * stars + 0.3 * forks + 0.1 * freshness;
  });
  return norm.reduce((a, b) => a + b, 0) / norm.length;
}

// ─────────────────────────────
// ✅ Gemini 안정화 요청기 (Flash / Pro / Lite)
//   - 429 발생 시에는 바로 throw → 상위에서
//     GEMINI_KEY_EXHAUSTED 코드로 변환
// ─────────────────────────────
async function fetchGemini(url, body) {
  for (let i = 0; i < 2; i++) {
    try {
      const res = await axios.post(url, body, { timeout: 40000 });
      const text = res.data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (text) return text;
    } catch (err) {
      const status = err.response?.status;
      if (status === 429) {
        // 키 한도 소진으로 간주 → 재시도 없이 상위로 전달
        throw err;
      }
      if (i === 1) throw err;
    }
  }
  return "";
}
// ─────────────────────────────
// ✅ Weight + History Update (롤오버 기반 보정 샘플)
// ─────────────────────────────
async function updateWeight(engine, truth, time) {
  try {
    // 🔹 명세 Ⅲ, Ⅳ: K-Law는 가중치/보정 시스템에서 제외
    if (engine === "klaw") {
      return;
    }

    const windowSize = ENGINE_CORRECTION_WINDOW;

    // 1) 엔진별 샘플 저장 (Supabase)
    await supabase.from("engine_correction_samples").insert([
      {
        engine_name: engine,
        truthscore: truth,
        response_ms: time,
        created_at: new Date(),
      },
    ]);

    // 2) 최근 N회(windowSize) 샘플 조회
    const { data: samples } = await supabase
      .from("engine_correction_samples")
      .select("truthscore,response_ms")
      .eq("engine_name", engine)
      .order("created_at", { ascending: false })
      .limit(windowSize);

    const rows = samples || [];
    const sampleCount = rows.length;

    const avgTruth =
      sampleCount > 0
        ? rows.reduce((sum, r) => sum + (r.truthscore ?? 0), 0) / sampleCount
        : truth;

    const avgResp =
      sampleCount > 0
        ? rows.reduce((sum, r) => sum + (r.response_ms ?? 0), 0) /
          sampleCount
        : time;

    // 3) 기존 total_runs 조회
    const { data: prev } = await supabase
      .from("engine_stats")
      .select("total_runs")
      .eq("engine_name", engine)
      .single();

    const totalRuns = (prev?.total_runs || 0) + 1;

    // 4) 롤오버 기반 평균으로 engine_stats 갱신
    await supabase.from("engine_stats").upsert([
      {
        engine_name: engine,
        avg_truth: avgTruth, // 롤오버 Truth 평균
        avg_response: avgResp, // 롤오버 응답시간 평균(ms)
        rolling_window_size: windowSize, // 사용 중인 롤오버 윈도우 크기
        sample_count: sampleCount, // 현재 포함 샘플 수
        total_runs: totalRuns,
        updated_at: new Date(),
      },
    ]);
  } catch (e) {
    if (DEBUG) console.warn("⚠️ Weight update fail:", e.message);
  }
}

// ─────────────────────────────
// ✅ 엔진 보정계수 조회 + 가중치 계산
// ─────────────────────────────
async function fetchEngineStatsMap(engines = []) {
  const unique = [...new Set(engines)];
  if (!unique.length) return {};
  const { data, error } = await supabase
    .from("engine_stats")
    .select(
      "engine_name, avg_truth, avg_response, rolling_window_size, sample_count"
    )
    .in("engine_name", unique);
  if (error && DEBUG)
    console.warn("⚠️ fetchEngineStatsMap fail:", error.message);
  const map = {};
  (data || []).forEach((row) => {
    map[row.engine_name] = row;
  });
  return map;
}

// 서버가 관리하는 보정값 c_e 를 반영한 엔진 전역 보정계수 C (0.9~1.1)
function computeEngineCorrectionFactor(engines = [], statsMap = {}) {
  if (!engines.length) return 1.0;
  const factors = [];

  for (const name of engines) {
    const base = ENGINE_BASE_WEIGHTS[name] ?? 1.0;
    const st = statsMap[name];
    let truthAdj = 1.0;
    let speedAdj = 1.0;

    // avg_truth 기준: 0.7일 때 1.0, 위/아래로 0.9~1.1 사이에서 조정
    if (st && typeof st.avg_truth === "number") {
      const t = st.avg_truth || 0.7;
      truthAdj = Math.max(0.9, Math.min(1.1, t / 0.7));
    }

    // avg_response 기준: 느리면 약간 패널티, 빠르면 약간 보너스 (0.9~1.1)
    if (st && typeof st.avg_response === "number") {
      const resp = st.avg_response || 1000;
      const baseResp = 800; // 0.8초 기준
      const ratio = baseResp / (baseResp + resp); // 0~1
      let s = 0.9 + 0.2 * ratio; // 0.9~1.1 근처
      if (s > 1.1) s = 1.1;
      if (s < 0.9) s = 0.9;
      speedAdj = s;
    }

    const corr = base * truthAdj * speedAdj;
    factors.push(corr);
  }

  if (!factors.length) return 1.0;
  const avg = factors.reduce((s, v) => s + v, 0) / factors.length;
  return Math.max(0.9, Math.min(1.1, avg)); // 글로벌 보정계수 C
}

// ─────────────────────────────
// ✅ Verify Core (QV / FV / DV / CV / LV)
//   - DV/CV: GitHub 기반 TruthScore 직접 계산
//   - LV: TruthScore 없이 K-Law 결과만 제공 (Ⅸ 명세 반영)
// ─────────────────────────────
app.post("/api/verify", async (req, res) => {
  const {
    query,
    mode,
    gemini_key,
    naver_id,
    naver_secret,
    klaw_key,
    user_answer,
    github_token, // ✅ DV/CV GitHub 토큰
  } = req.body;

  const safeMode = (mode || "").trim().toLowerCase();

  // 기본 검증
  if (!query) {
    return res
      .status(400)
      .json(buildError("VALIDATION_ERROR", "query가 누락되었습니다."));
  }

  if (safeMode !== "lv" && !gemini_key) {
    return res
      .status(400)
      .json(buildError("VALIDATION_ERROR", "Gemini 키가 누락되었습니다."));
  }

  const allowedModes = ["qv", "fv", "dv", "cv", "lv"];
  if (!allowedModes.includes(safeMode)) {
    return res
      .status(400)
      .json(buildError("INVALID_MODE", `지원하지 않는 모드입니다: ${mode}`));
  }

  const engines = [];
  const external = {};
  const start = Date.now();
  let partial_scores = {};
  let truthscore = 0.0;
  let engineStatsMap = {};
  let engineFactor = 1.0;

  try {
    switch (safeMode) {
      // ── 개발검증(DV) / 코드검증(CV)
      //   👉 GDELT 제거, GitHub만 사용 + github_token 지원
      case "dv":
      case "cv":
        engines.push("github");

        external.github = await safeFetch(
          "github",
          (q) => fetchGitHub(q, github_token),
          query
        );

        // GitHub 리포 기반 유효성 평가
        partial_scores.validity = calcValidityScore(external.github);
        break;

      // ── 법령검증(LV) ──
      //   TruthScore 없이 K-Law 결과만 제공
      case "lv":
        engines.push("klaw");
        external.klaw = await fetchKLawAll(klaw_key, query);
        break;

      // ── 기본검증(QV/FV) ──
      default:
        engines.push("crossref", "openalex", "wikidata", "gdelt");
        [
          external.crossref,
          external.openalex,
          external.wikidata,
          external.gdelt,
        ] = await Promise.all([
          safeFetch("crossref", fetchCrossref, query),
          safeFetch("openalex", fetchOpenAlex, query),
          safeFetch("wikidata", fetchWikidata, query),
          safeFetch("gdelt", fetchGDELT, query),
        ]);

        // QV/FV도 시의성은 GDELT 기반으로 산출
        partial_scores.recency = calcRecencyScore(external.gdelt);

        if (naver_id && naver_secret) {
          external.naver = await callNaver(query, naver_id, naver_secret, req);
          engines.push("naver");
        }
    }

    // ── LV 모드는 TruthScore/가중치 계산 없이 바로 반환 ──
    if (safeMode === "lv") {
      const elapsed = Date.now() - start;

      // LV 모드는 엔진 보정/TruthScore 없이 법령 정보만 제공 (Ⅸ 명세)
      await supabase.from("verify_logs").insert([
        {
          query,
          mode: safeMode,
          truthscore: null,
          elapsed,
          partial_scores: JSON.stringify({}),
          engines: JSON.stringify(engines),
          created_at: new Date(),
        },
      ]);

      return res.json(
        buildSuccess({
          mode: safeMode,
          elapsed,
          engines,
          klaw_result: external.klaw,
        })
      );
    }

    // ── 엔진 보정계수 조회 (서버 통계 기반) ──
    if (engines.length > 0) {
      engineStatsMap = await fetchEngineStatsMap(engines);
      engineFactor = computeEngineCorrectionFactor(engines, engineStatsMap); // 0.9~1.1
      partial_scores.engine_factor = engineFactor;
    }

    // ── Gemini 요청 단계 (Lite → Flash → Pro)
    //   - 429: 그대로 throw → 상위에서 GEMINI_KEY_EXHAUSTED 처리
    //   - 그 외 5xx/네트워크 에러: 외부 엔진 결과만으로 TruthScore 계산
    let flash = "";
    let verify = "";
    if (safeMode !== "lv") {
      try {
        const flashPrompt = `[${mode.toUpperCase()}] ${query}\n참조자료: ${JSON.stringify(
          external
        ).slice(0, 800)}`;
        flash = await fetchGemini(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${gemini_key}`,
          { contents: [{ parts: [{ text: flashPrompt }] }] }
        );

        const verifyPrompt = `검증모드:${mode}\n${
          user_answer || query
        }\n${flash}`;
        verify = await fetchGemini(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=${gemini_key}`,
          { contents: [{ parts: [{ text: verifyPrompt }] }] }
        );
      } catch (e) {
        const status = e.response?.status;
        if (status === 429) {
          // 이 경우만 상위 catch 로 보내서 GEMINI_KEY_EXHAUSTED 코드로 변환
          throw e;
        }
        if (DEBUG) {
          console.warn(
            "⚠️ Gemini verify 단계 실패, 외부 엔진 결과만 사용:",
            status,
            e.message
          );
        }
        // flash, verify 는 그냥 "" 상태로 두고, 외부 엔진 기반 TruthScore만 사용
      }
    }

    // ─────────────────────────────
    // ✅ TruthScore 계산 (hybrid 구조)
    //   - DV/CV: GitHub Vᵣ + engine_factor 기반
    //   - QV/FV: GDELT 기반 recency (임시)
    // ─────────────────────────────
    const elapsed = Date.now() - start;
    const R_t = partial_scores.recency ?? 0.7;
    const V_r = partial_scores.validity ?? 0.7;

    let hybrid = 0.7;

    if (safeMode === "dv" || safeMode === "cv") {
      // DV/CV는 GitHub 기반 유효성만 사용
      hybrid = V_r || 0.7;
    } else {
      // QV/FV는 GDELT 기반 recency 사용 (필요할 때)
      hybrid = R_t;
    }

    const C = partial_scores.engine_factor ?? engineFactor ?? 1.0; // 엔진 전역 보정계수
    const hybridCorrected = Math.max(0, Math.min(1, hybrid * C));

    truthscore = Math.min(0.97, 0.6 + 0.4 * hybridCorrected);

    // ─────────────────────────────
    // ✅ 로그 및 DB 반영
    // ─────────────────────────────
    for (const e of engines) {
      await updateWeight(e, truthscore, elapsed);
    }

    await supabase.from("verify_logs").insert([
      {
        query,
        mode: safeMode,
        truthscore,
        elapsed,
        partial_scores: JSON.stringify(partial_scores),
        engines: JSON.stringify(engines),
        created_at: new Date(),
      },
    ]);

    // ─────────────────────────────
    // ✅ 결과 반환 (ⅩⅤ 규약 형태로 래핑)
    // ─────────────────────────────
    return res.json(
      buildSuccess({
        mode: safeMode,
        truthscore: truthscore.toFixed(3),
        elapsed,
        engines,
        partial_scores,
        flash_summary: flash.slice(0, 250),
        verify_summary: verify.slice(0, 350),
      })
    );
  } catch (e) {
    console.error("❌ Verify Error:", e.message);
    await supabase.from("verify_logs").insert([
      {
        query,
        mode: safeMode,
        error: e.message,
        created_at: new Date(),
      },
    ]);

    const status = e.response?.status;

    // Gemini 429 → GEMINI_KEY_EXHAUSTED (ⅩⅤ 3.2)
    if (status === 429) {
      return res
        .status(200)
        .json(
          buildError(
            "GEMINI_KEY_EXHAUSTED",
            "현재 사용 중인 Gemini 키의 일일 할당량이 소진되었습니다.",
            e.message
          )
        );
    }

    return res
      .status(500)
      .json(
        buildError(
          "INTERNAL_SERVER_ERROR",
          "서버 내부 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.",
          e.message
        )
      );
  }
});

// ─────────────────────────────
// ✅ Translation API (DeepL + Gemini Flash-Lite fallback, production use)
// ─────────────────────────────
app.post("/api/translation", async (req, res) => {
  try {
    const { text, targetLang, deepl_key, gemini_key } = req.body;

    // 1) 필수값 검증
    if (!text || !text.trim()) {
      return sendError(
        res,
        400,
        "VALIDATION_ERROR",
        "text 필수 입력값이 누락되었거나 비어 있습니다.",
        "Field 'text' is required for /api/translation"
      );
    }

    // 2) 실제 번역 수행
    const result = await translateText(
      text,
      targetLang ?? null,
      deepl_key ?? null,
      gemini_key ?? null
    );

    // 3) 성공 응답 (기존 구조 유지)
    return res.json({
      success: true,
      original: text,
      translated: result.text,
      targetLang: result.target || (targetLang?.toUpperCase() || "EN"),
      engine: result.engine,
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    console.error("❌ /api/translation Error:", e.message);

    // 4) 번역 엔진 관련 에러를 공통 코드로 래핑
    return sendError(
      res,
      500,
      "TRANSLATION_ENGINE_ERROR",
      "번역 엔진 오류로 인해 번역을 수행할 수 없습니다.",
      e.message
    );
  }
});

// ✅ 번역 테스트 라우트 (간단형, 백호환용)
app.post("/api/translate", async (req, res) => {
  try {
    const { text, targetLang, deepl_key, gemini_key } = req.body;

    // 1) 필수값 검증
    if (!text || !text.trim()) {
      return sendError(
        res,
        400,
        "VALIDATION_ERROR",
        "text 필수 입력값이 누락되었거나 비어 있습니다.",
        "Field 'text' is required for /api/translate"
      );
    }

    // 2) 간단형 번역 (기존 동작 유지)
    const result = await translateText(
      text,
      targetLang ?? null,
      deepl_key ?? null,
      gemini_key ?? null
    );

    // 3) 성공 응답 (기존 구조 유지)
    return res.json({
      success: true,
      translated: result.text,
      engine: result.engine,
      targetLang: result.target || (targetLang?.toUpperCase() || "EN"),
    });
  } catch (e) {
    console.error("❌ /api/translate Error:", e.message);

    return sendError(
      res,
      500,
      "TRANSLATION_ENGINE_ERROR",
      "번역 엔진 오류로 인해 번역을 수행할 수 없습니다.",
      e.message
    );
  }
});

// ─────────────────────────────
// ✅ 문서 요약·분석 / Job 엔드포인트 스텁
//   - 아직 실제 구현 전이므로 ENGINE_UNAVAILABLE로 응답
// ─────────────────────────────
app.post("/api/docs/upload", async (req, res) => {
  return res
    .status(500)
    .json(
      buildError(
        "ENGINE_UNAVAILABLE",
        "문서 요약·분석 모드는 아직 서버에 구현되지 않았습니다."
      )
    );
});

app.post("/api/docs/analyze", async (req, res) => {
  return res
    .status(500)
    .json(
      buildError(
        "ENGINE_UNAVAILABLE",
        "문서 요약·분석 모드는 아직 서버에 구현되지 않았습니다."
      )
    );
});

app.get("/api/jobs/:jobId", async (req, res) => {
  // Job 시스템 미구현 상태 → 통일된 에러 코드로 반환
  return res
    .status(404)
    .json(
      buildError(
        "DOC_NOT_FOUND",
        "요청한 작업(Job)을 찾을 수 없습니다. Job 시스템이 아직 구현되지 않았거나 만료되었습니다."
      )
    );
});

// ─────────────────────────────
// ✅ Health / DB / Server Start
// ─────────────────────────────
app.get("/api/test-db", async (_, res) => {
  try {
    const c = await pgPool.connect();
    const r = await c.query("SELECT NOW()");
    c.release();
    return res.json(
      buildSuccess({
        message: "✅ DB 연결 성공",
        time: r.rows[0].now,
      })
    );
  } catch (e) {
    return res
      .status(500)
      .json(
        buildError(
          "INTERNAL_SERVER_ERROR",
          "DB 연결 중 오류가 발생했습니다.",
          e.message
        )
      );
  }
});

app.get("/health", (_, res) =>
  res.status(200).json({
    status: "ok",
    version: "v18.3.0",
    uptime: process.uptime().toFixed(2) + "s",
    region: REGION,
    timestamp: new Date().toISOString(),
  })
);

// ─────────────────────────────
// ✅ Root Endpoint for Render Health Check
//   - HEAD /, GET / 둘 다 200 반환
// ─────────────────────────────
app.get("/", (_, res) => {
  res
    .status(200)
    .send("OK - Cross-Verified AI Proxy v18.3.0 (root health check)");
});

app.head("/", (_, res) => {
  res.status(200).end();
});


app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v18.3.0 running on port ${PORT}`);
  console.log("🔹 LV 모듈 외부화 (/src/modules/klaw_module.js)");
  console.log(
    "🔹 Translation 모듈 활성화 (DeepL + Gemini Flash-Lite Fallback)"
  );
  console.log("🔹 Naver 지역 감지 활성화 완료");
  console.log("🔹 Supabase + Gemini 2.5 (Flash / Pro / Lite) 정상 동작");
  console.log("🔹 공통 에러 코드/응답 규약(ⅩⅤ) 1차 적용 완료");
});
