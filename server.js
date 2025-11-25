// =======================================================
// Cross-Verified AI Proxy — v18.4.0-pre
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

// 🔹 외부 엔진 / Gemini 공통 HTTP 타임아웃 (ms)
//    - 기본 45000ms, Render 환경변수 HTTP_TIMEOUT_MS 로 조정 가능
const HTTP_TIMEOUT_MS = parseInt(
  process.env.HTTP_TIMEOUT_MS || "45000",
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

// ✅ EJS 뷰 엔진 설정 (어드민 페이지용)
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
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
    (_, res) => res.redirect("/admin/ui")
);
app.get("/auth/failure", (_, res) =>
  res.status(401).send("❌ OAuth Failed")
);

// ─────────────────────────────
// ✅ Naver Whitelist Tier System
// ─────────────────────────────
const whitelistPath = path.join(__dirname, "config", "naver_whitelist.json");
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

// 🔹 Naver 링크의 도메인을 기준으로 티어/가중치 찾기
function resolveNaverTier(link) {
  try {
    const url = new URL(link);
    let host = url.hostname || "";
    host = host.replace(/^www\./, "");

    for (const t of tierWeights) {
      const domains = t.domains || [];
      const matched = domains.some((d) => {
        const dd = String(d || "").replace(/^www\./, "");
        // exact match 또는 서브도메인 매칭
        return host === dd || host.endsWith(`.${dd}`);
      });
      if (matched) {
        return { tier: t.tier, weight: t.weight ?? 1 };
      }
    }
  } catch (e) {
    if (DEBUG) console.warn("⚠️ resolveNaverTier fail:", e.message);
  }

  // 매칭 안 되면 기본값
  return { tier: null, weight: 1 };
}


// ─────────────────────────────
// ✅ External Engines + Fail-Grace Wrapper
// ─────────────────────────────
// metrics 옵션: { [engineName]: { response_ms: number } } 형태로 응답시간 누적
async function safeFetch(name, fn, q, metrics) {
  for (let i = 0; i < 2; i++) {
    const t0 = Date.now();
    try {
      const result = await fn(q);
      const elapsed = Date.now() - t0;

      if (metrics && typeof metrics === "object") {
        metrics[name] = metrics[name] || {};
        // 여러 번 부를 수도 있으니 간단히 평균으로 누적
        metrics[name].response_ms =
          typeof metrics[name].response_ms === "number"
            ? (metrics[name].response_ms + elapsed) / 2
            : elapsed;
      }

      return result;
    } catch (err) {
      if (i === 1) {
        await handleEngineFail(name, q, err.message);
        return [];
      }
    }
  }
}

async function safeFetchTimed(name, fn, q) {
  const start = Date.now();
  const result = await safeFetch(name, fn, q);
  const ms = Date.now() - start;
  return { result, ms };
}

// ─────────────────────────────
// ✅ Naver API (서버 직접 호출, 리전 제한 없음)
//   - clientId / clientSecret 은 요청 바디에서 받은 값을 그대로 사용
// ─────────────────────────────
async function callNaver(query, clientId, clientSecret) {
  try {
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

    // 🔹 AND 조건 비슷하게 만들기 위한 핵심어 토큰
    const tokens = String(query || "")
      .split(/\s+/)
      .map((t) => t.trim())
      .filter((t) => t.length > 1);

    // 토큰이 3개 이상이면 최소 2개 이상 매칭, 그보다 적으면 전부 매칭
    const requiredHits =
      tokens.length >= 3 ? tokens.length - 1 : tokens.length;

    for (const url of endpoints) {
      const { data } = await axios.get(url, {
  headers,
  params: { query, display: 3 },
  timeout: HTTP_TIMEOUT_MS,   // ✅ 추가
});

            let items =
        data?.items?.map((i) => {
          const cleanTitle = i.title?.replace(/<[^>]+>/g, "") || "";
          const cleanDesc = i.description?.replace(/<[^>]+>/g, "") || "";
          const link = i.link;

          // 🔹 도메인 기반 티어 계산
          const tierInfo = resolveNaverTier(link);

          return {
            title: cleanTitle,
            desc: cleanDesc,
            link,
            origin: "naver",
            tier: tierInfo.tier,
            tier_weight: tierInfo.weight,
          };
        }) || [];

      // 🔹 제목/요약에 핵심어가 거의 안 들어간 결과는 필터링
      if (tokens.length > 0) {
        items = items.filter((it) => {
          const text = `${it.title || ""} ${it.desc || ""}`.toLowerCase();
          let hit = 0;
          for (const tk of tokens) {
            if (text.includes(tk.toLowerCase())) hit++;
          }
          // 예: 토큰 3개 → 최소 2개 이상 포함
          return hit >= requiredHits;
        });
      }

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
    `https://api.crossref.org/works?query=${encodeURIComponent(q)}&rows=3`,
    { timeout: HTTP_TIMEOUT_MS }                    // ✅ 추가
  );
  return data?.message?.items?.map((i) => i.title?.[0]) || [];
}

async function fetchOpenAlex(q) {
  const { data } = await axios.get(
    `https://api.openalex.org/works?search=${encodeURIComponent(
      q
    )}&per-page=3`,
    { timeout: HTTP_TIMEOUT_MS }                    // ✅ 추가
  );
  return data?.results?.map((i) => i.display_name) || [];
}

async function fetchWikidata(q) {
  const { data } = await axios.get(
    `https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encodeURIComponent(
      q
    )}`,
    { timeout: HTTP_TIMEOUT_MS }                    // ✅ 추가
  );
  return data?.search?.map((i) => i.label) || [];
}

// 🔹 GDELT 뉴스 기반 시의성 엔진
async function fetchGDELT(q) {
  const { data } = await axios.get(
    `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(
      q
    )}&format=json&maxrecords=3`,
    { timeout: HTTP_TIMEOUT_MS }                    // ✅ 추가
  );
  return (
    data?.articles?.map((i) => ({
      title: i.title,
      date: i.seendate,
    })) || []
  );
}

// 🔹 GitHub 리포 검색 엔진 (DV/CV용)
async function fetchGitHub(q, token) {
  const headers = {
    "User-Agent": "CrossVerifiedAI",
  };

  if (!token) {
    throw new Error("GITHUB_TOKEN_REQUIRED");
  }
  headers.Authorization = `Bearer ${token}`;

  const { data } = await axios.get(
    `https://api.github.com/search/repositories?q=${encodeURIComponent(
      q
    )}&per_page=3`,
    {
      headers,
      timeout: HTTP_TIMEOUT_MS,                     // ✅ 추가
    }
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
// ✅ Gemini 호출 공통 유틸
//   - URL: 모델 엔드포인트 (flash / pro / flash-lite 등)
//   - payload: { contents: [...] } 형식
//   - 반환: text(string)
// ─────────────────────────────
async function fetchGemini(url, payload) {
  const { data } = await axios.post(url, payload, {
    timeout: HTTP_TIMEOUT_MS,                       // ✅ 추가
  });

  const text =
    data?.candidates?.[0]?.content?.parts
      ?.map((p) => p.text || "")
      .join("\n") || "";

  return text;
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
// ✅ DV/CV 일치도(Consistency) 계산 — Gemini Pro 기반
//   - 입력: mode, query, user_answer, github 메타데이터, gemini_key
//   - 출력: 0.0 ~ 1.0 사이 consistency 값 (실패 시 0.7)
// ─────────────────────────────
async function calcConsistencyFromGemini(
  mode,
  query,
  user_answer,
  githubData,
  gemini_key
) {
  try {
    const baseText =
      user_answer && user_answer.trim().length > 0
        ? `질문:\n${query}\n\n검증 대상 내용(요약 또는 코드):\n${user_answer}`
        : `질문:\n${query}`;

    const prompt = `
당신은 코드/설계 내용과 GitHub 리포지토리 정보를 비교하여 일치도를 평가하는 엔진입니다.

다음 두 가지 정보를 바탕으로, 0과 1 사이의 일치도 점수 "consistency"를 계산하세요.

1) 검증 대상 내용 (${mode.toUpperCase()} 모드):
${baseText}

2) GitHub 리포지토리 메타데이터 목록 (JSON):
${JSON.stringify(githubData).slice(0, 2500)}

- 리포지토리의 설명, 이름, 주제와 검증 대상 내용이 얼마나 관련 있는지,
- 구현 난이도/범위가 비슷한지,
- 명백히 다른 스택/도메인인지 등을 고려하세요.

반드시 아래 JSON 형식만 출력하세요. 다른 설명은 절대 쓰지 마세요.

{"consistency":0.0}
`;

    const text = await fetchGemini(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=${gemini_key}`,
      { contents: [{ parts: [{ text: prompt }] }] }
    );

    const trimmed = (text || "").trim();
    const jsonMatch = trimmed.match(/\{[\s\S]*\}/);
    const jsonText = jsonMatch ? jsonMatch[0] : trimmed;

    let parsed;
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      return 0.7;
    }

    let c = Number(parsed.consistency);
    if (Number.isNaN(c)) return 0.7;
    if (c < 0) c = 0;
    if (c > 1) c = 1;
    return c;
  } catch (e) {
    if (DEBUG) console.warn("⚠️ calcConsistencyFromGemini fail:", e.message);
    return 0.7;
  }
}


// ─────────────────────────────
// ✅ DV/CV용 GitHub 검색쿼리 생성기 (Gemini Flash 기반)
//   - 입력: mode, query, user_answer, gemini_key
//   - 출력: ["express helmet security best practice", ...] 형태 배열
// ─────────────────────────────
async function buildGithubQueriesFromGemini(
  mode,
  query,
  user_answer,
  gemini_key
) {
  try {
    const baseText =
      user_answer && user_answer.trim().length > 0
        ? `질문:\n${query}\n\n검증 대상 내용(요약 또는 코드):\n${user_answer}`
        : `질문:\n${query}`;

    const prompt = `
당신은 GitHub 검색 쿼리를 설계하는 보조 엔진입니다.
아래 내용을 바탕으로, "관련성이 높은 GitHub 리포지토리를 찾기 좋은 검색어" 1~3개만 생성하세요.

${baseText}

출력 형식은 반드시 다음 JSON 형식만 사용하세요 (설명 금지):

{"queries":["검색어1","검색어2","검색어3"]}
`;

    const text = await fetchGemini(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${gemini_key}`,
      { contents: [{ parts: [{ text: prompt }] }] }
    );

    const trimmed = (text || "").trim();

    // 코드블록 안에 JSON이 들어오는 경우도 대비
    const jsonMatch = trimmed.match(/\{[\s\S]*\}/);
    const jsonText = jsonMatch ? jsonMatch[0] : trimmed;

    let parsed;
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      // 파싱 실패하면 그냥 원래 query 하나만 사용
      return [query];
    }

    const arr = Array.isArray(parsed.queries) ? parsed.queries : [];
    const cleaned = arr
      .map((s) => String(s).trim())
      .filter((s) => s.length > 0);

    return cleaned.length > 0 ? cleaned : [query];
  } catch (e) {
    if (DEBUG) {
      console.warn("⚠️ buildGithubQueriesFromGemini fail:", e.message);
    }
    // 실패 시 fallback: 기존처럼 query 하나만 사용
    return [query];
  }
}
// ✅ Weight + History Update (롤오버 기반 보정 샘플 + cₑ 계산)
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
    const { data: samples, error: sampleErr } = await supabase
      .from("engine_correction_samples")
      .select("truthscore,response_ms")
      .eq("engine_name", engine)
      .order("created_at", { ascending: false })
      .limit(windowSize);

    if (sampleErr && DEBUG) {
      console.warn("⚠️ engine_correction_samples select fail:", sampleErr.message);
    }

    const rows = samples || [];
const sampleCount = rows.length;

const avgTruth =
  sampleCount > 0
    ? rows.reduce((sum, r) => sum + (r.truthscore ?? 0), 0) / sampleCount
    : truth;

const avgResp =
  sampleCount > 0
    ? rows.reduce((sum, r) => sum + (r.response_ms ?? 0), 0) / sampleCount
    : time;

    // 3) 기존 total_runs, override_ce 조회
    const { data: prev, error: prevErr } = await supabase
      .from("engine_stats")
      .select("total_runs, override_ce")
      .eq("engine_name", engine)
      .single();

    if (prevErr && DEBUG && prevErr.code !== "PGRST116") {
      // PGRST116 = row not found
      console.warn("⚠️ engine_stats select fail:", prevErr.message);
    }

    const totalRuns = (prev?.total_runs || 0) + 1;

    // 4) avgTruth / avgResp 기반 자동 보정계수(auto_ce) 계산 (0.9~1.1)
    const targetTruth = 0.7; // 기준 Truth
    let truthAdj = avgTruth / targetTruth;
    if (truthAdj < 0.9) truthAdj = 0.9;
    if (truthAdj > 1.1) truthAdj = 1.1;

    const baseResp = 800; // 0.8초 기준
    const ratio = baseResp / (baseResp + avgResp); // 0~1
    let speedAdj = 0.9 + 0.2 * ratio; // 0.9~1.1 근처
    if (speedAdj < 0.9) speedAdj = 0.9;
    if (speedAdj > 1.1) speedAdj = 1.1;

    const auto_ce = Math.max(0.9, Math.min(1.1, truthAdj * speedAdj));

    // 5) override_ce가 있으면 그 값을, 없으면 auto_ce를 effective_ce로 사용
    const override_ce =
      typeof prev?.override_ce === "number" ? prev.override_ce : null;
    const effective_ce =
      typeof override_ce === "number" && Number.isFinite(override_ce)
        ? override_ce
        : auto_ce;

    // 6) engine_stats 갱신 (Ⅲ, Ⅳ 명세 반영)
    await supabase.from("engine_stats").upsert([
      {
        engine_name: engine,
        avg_truth: avgTruth,
        avg_response: avgResp,
        rolling_window_size: windowSize,
        sample_count: sampleCount,
        total_runs: totalRuns,
        auto_ce,
        override_ce,
        effective_ce,
        updated_at: new Date(),
      },
    ]);
  } catch (e) {
    if (DEBUG) console.warn("⚠️ Weight update fail:", e.message);
  }
}

// ─────────────────────────────
// ✅ QV/FV용 검색어 전처리기
//    - 간단 한국어 정규화 + Gemini Flash 기반 핵심어 추출
//    - 결과: 한국어/영어 코어 쿼리 반환
// ─────────────────────────────
function normalizeKoreanQuestion(raw) {
  if (!raw) return "";
  let s = String(raw);

  // 1) 물음표 앞부분만 사용 (질문 꼬리 제거)
  const qIdx = s.indexOf("?");
  if (qIdx !== -1) s = s.slice(0, qIdx);

  // 2) 자주 쓰는 질문형 꼬리 제거
  s = s.replace(
    /(은|는|이|가)?\s*(무엇인가요|무엇인가|뭐야|뭐냐|어디야|어디인가요|어디지|어느 정도야|얼마야|얼마인가요|얼마 정도야)\s*$/u,
    ""
  );

  // 3) 공백 정리
  s = s.replace(/\s+/g, " ").trim();
  return s;
}

// 🔹 Naver 검색용 AND 쿼리 빌더
//    예) "2025 한국 인구" → "+2025 +한국 +인구"
function buildNaverAndQuery(baseKo) {
  if (!baseKo) return "";

  const tokens = baseKo
    .split(/\s+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  if (!tokens.length) return baseKo;

  // 한 글자(조사 등)는 그대로 두고, 나머지는 +키워드로 변환
  return tokens
    .map((t) => (t.length <= 1 ? t : `+${t}`))
    .join(" ");
}

async function buildEngineQueriesForQVFV(query, gemini_key) {
  // 기본값: 한국어는 간단 정규화, 영어는 아직 비어 있음
  const baseKo = normalizeKoreanQuestion(query);
  let qKo = baseKo;
  let qEn = "";

  // 혹시라도 gemini_key가 없으면 그냥 원래 query 사용
  if (!gemini_key) {
    return {
      q_ko: qKo || query,
      q_en: query,
    };
  }

  try {
    const prompt = `
아래 사용자의 질의를 보고, 검색 엔진용 핵심 검색어를 뽑으세요.

요구사항:
- korean: 네이버/한국어 검색엔진용 핵심어 (2~6단어, 조사/어미/존댓말 제거)
- english: Crossref/OpenAlex/Wikidata/GDELT용 영어 키워드 (2~8단어의 간단한 구문)
- 질의가 영어라면 korean은 비워두거나 원 문장을 그대로 둘 수 있습니다.
- 질의가 한국어라면 english는 자연스러운 영어 표현으로 옮기세요.

사용자 질의:
${query}

반드시 아래 JSON 형식 **그대로**만 출력하세요. 설명 텍스트는 절대 쓰지 마세요.

{"korean":"서울 인구","english":"population of Seoul"}
`;

    const text = await fetchGemini(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${gemini_key}`,
      { contents: [{ parts: [{ text: prompt }] }] }
    );

    const trimmed = (text || "").trim();
    const jsonMatch = trimmed.match(/\{[\s\S]*\}/);
    const jsonText = jsonMatch ? jsonMatch[0] : trimmed;

    let parsed = null;
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      parsed = null;
    }

    if (parsed && typeof parsed === "object") {
      if (typeof parsed.korean === "string" && parsed.korean.trim()) {
        qKo = parsed.korean.trim();
      }
      if (typeof parsed.english === "string" && parsed.english.trim()) {
        qEn = parsed.english.trim();
      }
    }
  } catch (e) {
    if (DEBUG) {
      console.warn("⚠️ buildEngineQueriesForQVFV fail:", e.message);
    }
  }

  // 최종 fallback: 비어 있으면 원래 query 사용
  return {
    q_ko: qKo || query,
    q_en: qEn || query,
  };
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
      "engine_name, avg_truth, avg_response, rolling_window_size, sample_count, auto_ce, override_ce, effective_ce"
    )
    .in("engine_name", unique);

  if (error && DEBUG) {
    console.warn("⚠️ fetchEngineStatsMap fail:", error.message);
  }

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
    // K-Law는 보정 시스템에서 제외 (명세 Ⅲ, Ⅳ)
    if (name === "klaw") continue;

    const base = ENGINE_BASE_WEIGHTS[name] ?? 1.0;
    const st = statsMap[name];

    // 1) per-engine cₑ 선택: effective_ce → auto_ce → 1.0
    let ce = 1.0;
    if (st) {
      if (typeof st.effective_ce === "number") {
        ce = st.effective_ce;
      } else if (typeof st.auto_ce === "number") {
        ce = st.auto_ce;
      }
    }

    // 0.9~1.1 범위로 클램핑
    if (ce < 0.9) ce = 0.9;
    if (ce > 1.1) ce = 1.1;

    // 2) wₑ(eff) = wₑ(0) × cₑ
    const wEff = base * ce;
    factors.push(wEff);
  }

  if (!factors.length) return 1.0;
  const avg = factors.reduce((s, v) => s + v, 0) / factors.length;

  // 글로벌 보정계수 C (0.9~1.1)
  return Math.max(0.9, Math.min(1.1, avg));
}


// ─────────────────────────────
// ✅ Verify Core (QV / FV / DV / CV / LV)
//   - DV/CV: GitHub 기반 TruthScore 직접 계산 (Gemini→GitHub)
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
    github_token,     // ✅ DV/CV GitHub 토큰
    gemini_model,     // ✅ QV/FV에서만 Flash/Pro 토글용
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
  // QV/FV 모드는 네이버 옵션 해제 → 항상 Naver 엔진 사용
  if ((safeMode === "qv" || safeMode === "fv") && (!naver_id || !naver_secret)) {
    return res
      .status(400)
      .json(
        buildError(
          "VALIDATION_ERROR",
          "QV/FV 모드에서는 Naver client id / secret이 필요합니다."
        )
      );
  }

  // 🔹 QV/FV용 Gemini 모델 토글 (Flash / Pro)
  // - 클라이언트에서 gemini_model: "flash" | "pro" | undefined 로 보냄
  // - QV/FV에서만 토글, DV/CV는 항상 Pro 고정
    const geminiModelRaw = (gemini_model || "").toString().trim().toLowerCase();
  let verifyModel = null; // 기본값: 모드별로 아래에서 설정

  if (safeMode === "qv" || safeMode === "fv") {
    if (geminiModelRaw === "flash") {
      verifyModel = "gemini-2.5-flash";
    } else {
      // gemini_model이 "pro"이거나 없으면 Pro 사용
      verifyModel = "gemini-2.5-pro";
    }
  } else if (safeMode === "dv" || safeMode === "cv") {
    // DV/CV는 항상 Pro 고정
    verifyModel = "gemini-2.5-pro";
  }

    const engines = [];
  const external = {};
  const start = Date.now();
  let partial_scores = {};
  let truthscore = 0.0;
  let engineStatsMap = {};
  let engineFactor = 1.0;
  const engineTimes = {}; // ⭐ 엔진별 응답시간(ms) 기록용
 const engineMetrics = {}; // 🔹 엔진별 응답시간 기록용

  try {
    // ─────────────────────────────
    // ① 모드별 외부엔진 호출 (DV/CV/QV/FV/LV)
    // ─────────────────────────────
    switch (safeMode) {
      // ── 개발검증(DV) / 코드검증(CV)
      //   👉 Gemini Flash로 GitHub 검색어를 먼저 만들고,
      //      그 검색어들로 GitHub 리포를 찾은 뒤 유효성(Vᵣ) 계산
         case "dv":
    case "cv": {
      // 🔹 DV/CV에서는 github_token이 반드시 필요
      if (!github_token) {
        return res
          .status(400)
          .json(
            buildError(
              "VALIDATION_ERROR",
              "DV/CV 모드에서는 github_token이 필요합니다."
            )
          );
      }

      engines.push("github");

      // 🔹 CV일 때만 user_answer를 GitHub 쿼리/일치도에 사용
      const answerText =
        safeMode === "cv" &&
        user_answer &&
        user_answer.trim().length > 0
          ? user_answer
          : "";

      // 1단계: Gemini Flash를 사용해서 GitHub 검색용 쿼리 생성
      const ghQueries = await buildGithubQueriesFromGemini(
        safeMode,
        query,
        answerText,   // ⬅️ DV는 "", CV는 user_answer
        gemini_key
      );

      // 2단계: 생성된 쿼리들로 GitHub 검색 수행
      external.github = [];
            external.github = [];
      let githubMsTotal = 0;

      for (const ghq of ghQueries) {
        const { result, ms } = await safeFetchTimed(
          "github",
          (q) => fetchGitHub(q, github_token),
          ghq
        );
        githubMsTotal += ms;
        if (Array.isArray(result) && result.length > 0) {
          external.github.push(...result);
        }
      }

      // ⭐ 이번 요청에서 GitHub 엔진에 실제로 걸린 시간(ms)
      engineTimes.github = githubMsTotal;


      // GitHub 리포 기반 유효성 평가 (Vᵣ)
      partial_scores.validity = calcValidityScore(external.github);
      // (옵션) 나중에 UI에서 보여주고 싶으면 쿼리들도 같이 내려줌
      partial_scores.github_queries = ghQueries;

      // GitHub 메타데이터와 검증 대상 내용 간 일치도(Consistency) 평가
      partial_scores.consistency = await calcConsistencyFromGemini(
        safeMode,
        query,
        answerText,   // ⬅️ DV: 질문 기준, CV: 질문 + user_answer 기준
        external.github,
        gemini_key
      );
      break;
    }


      // ── 법령검증(LV) ──
      //   TruthScore 없이 K-Law 결과만 제공
      case "lv": {
  engines.push("klaw");
  external.klaw = await fetchKLawAll(klaw_key, query);

  // 🔹 선택적 Flash-Lite 요약 (gemini_key가 있을 때만)
  let lvSummary = null;

  if (gemini_key) {
    const prompt = `
너는 대한민국 항공·교통 법령 및 판례를 요약해주는 엔진이다.

[사용자 질의]
${query}

[아래는 K-Law API에서 가져온 JSON 응답이다.]
이 JSON 안에 포함된 관련 법령·판례를 확인하고, 질의에 답하는 데 중요한 내용만 뽑아서 요약해라.

요약 지침:
- 한국어로 3~7개의 bullet로 정리
- 각 bullet은
  - 관련 법령/조문 제목 또는 사건명
  - 핵심 내용 (의무, 금지, 허용, 절차 등)
  - UAM 운항/운영과의 연관성을 짧게 포함
- 불필요한 부연 설명, 서론/결론 문장은 넣지 말 것.

[K-Law JSON 응답 요약본]
${JSON.stringify(external.klaw).slice(0, 6000)}
    `.trim();

    try {
      lvSummary = await fetchGemini(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=${gemini_key}`,
        { contents: [{ parts: [{ text: prompt }] }] }
      );
    } catch (e) {
      if (DEBUG) {
        console.warn("⚠️ LV Flash-Lite summary fail:", e.message);
      }
      lvSummary = null;
    }
  }

  // safeMode === "lv" 블록에서 같이 내려주기 위해
  partial_scores.lv_summary = lvSummary || null;
  break;
}


      // ── 기본검증(QV/FV) ──
            default: {
        // QV/FV 모드에서는 4개 검증엔진 + Naver를 항상 동시 호출
        engines.push("crossref", "openalex", "wikidata", "gdelt", "naver");

        // 1단계: Gemini Flash로 엔진 공통 핵심 검색어 생성
        const { q_ko, q_en } = await buildEngineQueriesForQVFV(
          query,
          gemini_key
        );

        // 🔹 Naver용 AND 강화 쿼리 생성
        const naverQuery = buildNaverAndQuery(q_ko);

        // 디버깅 / UI용: 어떤 쿼리를 썼는지 기록
        partial_scores.engine_queries = {
          crossref: q_en,
          openalex: q_en,
          wikidata: q_en,
          gdelt: q_en,
          naver: naverQuery,
        };


        // 2단계: 엔진별로 적합한 쿼리 사용
                const [
          crossrefPack,
          openalexPack,
          wikidataPack,
          gdeltPack,
          naverPack,
        ] = await Promise.all([
          // 영문 검색 위주 엔진
          safeFetchTimed("crossref", fetchCrossref, q_en),
          safeFetchTimed("openalex", fetchOpenAlex, q_en),
          safeFetchTimed("wikidata", fetchWikidata, q_en),
          safeFetchTimed("gdelt", fetchGDELT, q_en),
          // 네이버는 한국어 쿼리 사용
          safeFetchTimed(
            "naver",
            (q) => callNaver(q, naver_id, naver_secret),
            naverQuery
          ),
        ]);

        external.crossref = crossrefPack.result;
        external.openalex = openalexPack.result;
        external.wikidata = wikidataPack.result;
        external.gdelt = gdeltPack.result;
        external.naver = naverPack.result;

        // ⭐ 엔진별 응답시간(ms)을 기록
        engineTimes.crossref = crossrefPack.ms;
        engineTimes.openalex = openalexPack.ms;
        engineTimes.wikidata = wikidataPack.ms;
        engineTimes.gdelt = gdeltPack.ms;
        engineTimes.naver = naverPack.ms;

        // QV/FV도 시의성은 GDELT 기반으로 산출
        partial_scores.recency = calcRecencyScore(external.gdelt);

        // 🔹 Naver 호출 + 티어 기반 가중치 산출 (항상 시도, 결과 없으면 스킵)
        if (Array.isArray(external.naver) && external.naver.length > 0) {
          const weights = external.naver
            .map((item) =>
              typeof item.tier_weight === "number" ? item.tier_weight : 1
            )
            .filter((w) => Number.isFinite(w) && w > 0);

          if (weights.length > 0) {
            // 티어 설정 평균 → 0.9~1.05로 클램핑
            const avgTierWeight =
              weights.reduce((s, v) => s + v, 0) / weights.length;

            const tierFactor = Math.max(0.9, Math.min(1.05, avgTierWeight));
            partial_scores.naver_tier_factor = tierFactor;
          }
        }

        break;
      }
} // 🔹 switch (safeMode) 닫기

    // ─────────────────────────────
    // ② LV 모드는 TruthScore/가중치 계산 없이 바로 반환
    // ─────────────────────────────
   if (safeMode === "lv") {
  const elapsed = Date.now() - start;

  // LV 모드는 엔진 보정/TruthScore 없이 법령 정보 + 선택적 요약만 제공 (Ⅸ 명세)
  await supabase.from("verification_logs").insert([
    {
      query,
      mode: safeMode,
      truthscore: null,
      elapsed,
      // 🔹 여기서 lv_summary 들어간 partial_scores를 그대로 저장
      partial_scores: JSON.stringify(partial_scores || {}),
      engines: JSON.stringify(engines),
      gemini_model: null,   // ✅ LV는 TruthScore 계산용 Gemini 모델 없음
      created_at: new Date(),
    },
  ]);

  return res.json(
    buildSuccess({
      mode: safeMode,
      elapsed,
      engines,
      klaw_result: external.klaw,
      // 🔹 Flash-Lite 요약본을 함께 내려줌 (없으면 null)
      lv_summary: partial_scores.lv_summary || null,
    })
  );
}

    // ─────────────────────────────
    // ③ 엔진 보정계수 조회 (서버 통계 기반)
    // ─────────────────────────────
    if (engines.length > 0) {
      engineStatsMap = await fetchEngineStatsMap(engines);
      engineFactor = computeEngineCorrectionFactor(engines, engineStatsMap); // 0.9~1.1
      partial_scores.engine_factor = engineFactor;
    }

        // ─────────────────────────────
    // ④ Gemini 요청 단계 (Flash → Pro)
    //   - Flash: 1차 요약/설명용
    //   - Pro: 의미블록/부분 TruthScore/종합 TruthScore/엔진보정 JSON 한 번에 계산
    // ─────────────────────────────
    let flash = "";
    let verify = "";
    let verifyMeta = null; // Pro 결과(JSON)를 파싱한 메타 정보 저장

    try {
      // 4-1) Flash: 외부엔진 결과를 붙여서 1차 응답 생성
      const flashPrompt = `[${mode.toUpperCase()}] ${query}\n참조자료: ${JSON.stringify(
        external
      ).slice(0, 800)}`;
      flash = await fetchGemini(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${gemini_key}`,
        { contents: [{ parts: [{ text: flashPrompt }] }] }
      );

      // 🔹 CV일 때만 user_answer를 검증 대상으로 사용
      const coreText =
        safeMode === "cv" &&
        user_answer &&
        user_answer.trim().length > 0
          ? user_answer
          : query;

      // Pro에 넘길 입력 패키지 (너무 길어지지 않게 슬라이스)
      const verifyInput = {
        mode: safeMode,
        query,
        core_text: coreText,
        external,
        partial_scores,
      };

      const verifyPrompt = `
당신은 "Cross-Verified AI" 시스템의 메타 검증 엔진입니다.

목표:
- 하나의 요청으로 아래 네 가지를 모두 수행합니다.
  1) 검증 대상 텍스트(core_text)를 의미 단위 블록으로 나누기
  2) 각 블록을 외부 검증엔진 결과(external)와 비교하여 부분별 TruthScore(0~1) 계산
  3) 전체 문장/코드에 대한 종합 TruthScore(0~1 구간, raw) 계산
  4) 각 검증엔진별로 이번 질의에 대한 국소 보정값(0.9~1.1) 제안

[입력 JSON]
${JSON.stringify(verifyInput).slice(0, 6000)}

입력 필드 설명(요약):
- mode: "qv" | "fv" | "dv" | "cv" 중 하나
- query: 사용자가 입력한 질문 또는 사실 문장
- core_text:
    - QV/FV: 주로 query 기반 핵심 주장/내용
    - DV: "어떤 개발 과제를 하려는지"에 대한 설명
    - CV: 실제 검증 대상 코드/설계 또는 요약
- external: crossref / openalex / wikidata / gdelt / naver / github / klaw 등 외부 엔진 결과
- partial_scores: 서버에서 미리 계산된 전역 스코어
    (예: recency, validity, consistency, engine_factor, naver_tier_factor 등)

[작업 지침]

1. 의미 단위 분할
   - core_text를 의미적으로 자연스러운 2~8개 블록으로 분할하십시오.
   - 각 블록은 하나의 주장, 기능, 단계, 조건 등을 기준으로 나누고,
     너무 잘게 쪼개지 말고 한 문장 또는 밀접한 1~3문장 정도로 묶습니다.

2. 블록별 TruthScore(block_truthscore, 0~1)
   - 각 블록에 대해 external 안의 증거들과 비교하여 0~1 사이 점수를 매기십시오.
   - 기준:
     - 0.90~1.00: 강하게 뒷받침됨 (여러 엔진에서 일관되게 지지)
     - 0.70~0.89: 대체로 타당 (직접적인 증거는 일부지만, 방향성 일치)
     - 0.40~0.69: 불확실 / 부분적으로만 지지 (간접적이거나 단편적인 근거)
     - 0.10~0.39: 근거 부족 또는 논쟁적 (명확한 지지가 없거나 모순 가능성)
     - 0.00~0.09: 명백히 잘못되었거나 반대 증거 존재
   - 각 블록마다 어떤 엔진이 지지(support) / 충돌(conflict)하는지 기록하십시오.

3. 종합 TruthScore(overall_truthscore_raw, 0~1)
   - 블록별 점수와 partial_scores(recency, validity, consistency 등)를 종합하여
     0~1 사이의 overall_truthscore_raw를 계산하십시오.
   - 이 값은 "순수 0~1 척도"이며, 서버에서는
     truthscore = 0.6 + 0.4 * overall_truthscore_raw
     와 같은 방식으로 0.6~0.97 범위로 변환하여 사용할 수 있습니다.
   - overall_truthscore_raw가 1에 가까울수록 전체 내용이 매우 잘 뒷받침됨을 의미합니다.

4. 엔진별 보정 제안(engine_adjust)
   - external과 partial_scores를 참고하여,
     이번 질의에서 각 엔진의 신뢰도를 0.9~1.1 범위로 제안하십시오.
   - 키: "crossref", "openalex", "wikidata", "gdelt", "naver", "github"
   - 값:
     - 1.0 = 중립
     - 1.02~1.08: 이번 질의에서는 특히 품질이 좋음
     - 0.92~0.98: 품질/일관성이 떨어지므로 약간 낮게
   - 해당 엔진 데이터가 거의 없거나 의미가 없으면 1.0 근처로 설정하십시오.

5. 설명은 한국어로 간단하게 작성하세요.
   - block별 comment, overall.summary는 한국어 1~3문장 정도로 충분합니다.

[출력 형식]
반드시 아래 JSON 형식 **그대로**만 출력하고, 추가 텍스트를 절대 넣지 마십시오.

{
  "blocks": [
    {
      "id": 1,
      "text": "이 블록에 해당하는 텍스트",
      "block_truthscore": 0.85,
      "evidence": {
        "support": ["crossref","naver"],
        "conflict": ["wikidata"]
      },
      "comment": "이 블록에 이런 점수를 준 이유를 한국어로 한두 문장 설명"
    }
  ],
  "overall": {
    "overall_truthscore_raw": 0.82,
    "summary": "전체적으로 어떤 부분은 잘 뒷받침되고, 어떤 부분은 불확실한지 한국어로 2~3문장 설명"
  },
  "engine_adjust": {
    "crossref": 1.03,
    "openalex": 1.00,
    "wikidata": 0.97,
    "gdelt": 1.05,
    "naver": 0.99,
    "github": 1.04
  }
}
`;

            verify = await fetchGemini(
        `https://generativelanguage.googleapis.com/v1beta/models/${verifyModel}:generateContent?key=${gemini_key}`,
        { contents: [{ parts: [{ text: verifyPrompt }] }] }
      );

      // Pro 결과(JSON) 파싱 시도
      try {
        const trimmed = (verify || "").trim();
        const jsonMatch = trimmed.match(/\{[\s\S]*\}/);
        const jsonText = jsonMatch ? jsonMatch[0] : trimmed;
        verifyMeta = JSON.parse(jsonText);
      } catch {
        verifyMeta = null;
        if (DEBUG) {
          console.warn("⚠️ verifyMeta JSON parse fail");
        }
      }
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
      // flash, verifyMeta 는 없는 상태로 두고,
      // 외부 엔진 기반 TruthScore만 사용
    }

    // ⑤ TruthScore 계산용 보조 값 정리 ------------------------
    // Gemini 메타 점수 G (0~1), 없으면 0.7 중립값
    const G = (() => {
      const v =
        verifyMeta &&
        typeof verifyMeta.overall?.overall_truthscore_raw === "number"
          ? verifyMeta.overall.overall_truthscore_raw
          : 0.7;
      return Math.max(0, Math.min(1, v));
    })();

    // QV/FV: GDELT 기반 시의성 Rₜ, 그 외 모드는 1.0
    const R_t =
      (safeMode === "qv" || safeMode === "fv") &&
      typeof partial_scores.recency === "number"
        ? Math.max(0, Math.min(1, partial_scores.recency))
        : 1.0;

    // DV/CV: GitHub 유효성 Vᵣ, 없으면 0.7 중립값
    const V_r =
      (safeMode === "dv" || safeMode === "cv") &&
      typeof partial_scores.validity === "number"
        ? Math.max(0, Math.min(1, partial_scores.validity))
        : 0.7;

    // QV/FV: Naver 티어 팩터 N (0.9~1.05), 없으면 1.0
    const N =
      (safeMode === "qv" || safeMode === "fv") &&
      typeof partial_scores.naver_tier_factor === "number"
        ? Math.max(0.9, Math.min(1.05, partial_scores.naver_tier_factor))
        : 1.0;

    // 엔진 전역 보정계수 C (0.9~1.1)
    const C =
      typeof engineFactor === "number" && Number.isFinite(engineFactor)
        ? Math.max(0.9, Math.min(1.1, engineFactor))
        : 1.0;

        let hybrid;

    if (safeMode === "dv" || safeMode === "cv") {
      // DV/CV:
      // - G (Gemini 종합 스코어)가 주 신뢰도
      // - Vᵣ(GitHub 유효성)는 보조 신뢰도
      const combined = 0.7 * G + 0.3 * V_r; // 0~1 범위
      const rawHybrid = combined * C;
      hybrid = Math.max(0, Math.min(1, rawHybrid));
    } else {
      // QV/FV:
      // - GDELT 시의성 Rₜ
      // - Naver 티어 팩터 N
      // - 엔진 보정 C
      // - Gemini 종합 스코어 G
      const rawHybrid = R_t * N * G * C;
      hybrid = Math.max(0, Math.min(1, rawHybrid));
    }

    // 최종 TruthScore (0.6 ~ 0.97 범위)
    truthscore = Math.min(0.97, 0.6 + 0.4 * hybrid);

    // 요청당 경과 시간(ms)
    const elapsed = Date.now() - start;

    // ⭐ Pro 메타(JSON)에서 엔진별 보정 제안 맵 추출 (없으면 빈 객체)
    const perEngineAdjust =
      verifyMeta && typeof verifyMeta.engine_adjust === "object"
        ? verifyMeta.engine_adjust
        : {};

    // (옵션) partial_scores에도 넣어 두면 로그에서 같이 볼 수 있음
    partial_scores.engine_adjust = perEngineAdjust;

    // ─────────────────────────────
    // ⑥ 로그 및 DB 반영
    // ─────────────────────────────
    await Promise.all(
      engines.map((eName) => {
        // 이번 요청에서 이 엔진에 적용할 truth 샘플
        const adj =
          typeof perEngineAdjust[eName] === "number" &&
          Number.isFinite(perEngineAdjust[eName])
            ? perEngineAdjust[eName]
            : 1.0;

        const engineTruth = truthscore * adj;

        // per-engine 응답시간이 있으면 사용, 없으면 전체 elapsed 사용
        const engineMs =
          typeof engineTimes[eName] === "number" && engineTimes[eName] > 0
            ? engineTimes[eName]
            : elapsed;

        return updateWeight(eName, engineTruth, engineMs);
      })
    );

    await supabase.from("verification_logs").insert([
  {
    query,
    mode: safeMode,
    truthscore,
    elapsed,
    partial_scores: JSON.stringify(partial_scores),
    engines: JSON.stringify(engines),
    gemini_model: verifyModel,
    created_at: new Date(),
  },
]);

    // ─────────────────────────────
    // ⑦ 결과 반환 (ⅩⅤ 규약 형태로 래핑)
    // ─────────────────────────────
    const normalizedPartial = { ...partial_scores };

    if (safeMode === "dv" || safeMode === "cv") {
      // DV/CV 모드에서 명세 기본 필드 보장
      normalizedPartial.validity =
        typeof partial_scores.validity === "number"
          ? partial_scores.validity
          : 0.7;

      normalizedPartial.engine_factor =
        typeof partial_scores.engine_factor === "number"
          ? partial_scores.engine_factor
          : C;
    }

  const payload = {
      mode: safeMode,
      truthscore: truthscore.toFixed(3),
      elapsed,
      engines,
      partial_scores: normalizedPartial,
      flash_summary: flash.slice(0, 250),
      verify_raw: verify.slice(0, 350),
      gemini_verify_model: verifyModel, // ✅ 이번 요청에서 TruthScore 계산에 사용된 모델
    };


    // 🔹 DV/CV 모드에서는 GitHub 검색 결과도 같이 내려줌
    if (safeMode === "dv" || safeMode === "cv") {
      payload.github_repos = external.github ?? [];
    }

    // 🔹 QV/FV 모드에서는 Naver 검색 결과도 같이 내려줌
    if ((safeMode === "qv" || safeMode === "fv") && external.naver) {
      payload.naver_results = external.naver;
    }

    return res.json(buildSuccess(payload));
    } catch (e) {
    console.error("❌ Verify Error:", e.message);
    await supabase.from("verification_logs").insert([
  {
    query,
    mode: safeMode,
    error: e.message,
    gemini_model: verifyModel || null,
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

    // 3) 성공 응답 (ⅩⅤ 규약: buildSuccess 사용)
    return res.json(
      buildSuccess({
        translated: result.text,
        engine: result.engine,
        targetLang: result.target || (targetLang?.toUpperCase() || "EN"),
      })
    );
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
// ✅ 문서 요약·분석 / Job 엔드포인트 (v18.4.0-pre)
//   - 서버는 "텍스트 chunk"만 처리 (파일 분할은 앱에서 수행)
//   - 비동기 Job/DB는 사용하지 않고, 요청당 동기 처리만 수행
// ─────────────────────────────

const DOC_MAX_CHARS = 24000; // chunk당 최대 처리 글자 수 (초과분은 잘라서 사용)

app.post("/api/docs/upload", async (req, res) => {
  // ⚠ 현재 설계에서는 파일 자체를 서버에 저장하지 않음
  //    → 앱에서 파일을 페이지/범위별 텍스트 chunk로 쪼개서 /api/docs/analyze로 직접 보내는 구조
  return res
    .status(400)
    .json(
      buildError(
        "DOC_UPLOAD_NOT_SUPPORTED",
        "현재 버전에서는 파일 업로드 대신 /api/docs/analyze로 텍스트 chunk만 전송해 주세요."
      )
    );
});

/*
  /api/docs/analyze — 문서 요약·번역 공통 엔드포인트

  📌 공통 파라미터
  - mode: "chunk" | "final"
    - "chunk" : 페이지 일부/범위 단위로 잘라서 보낼 때
    - "final" : 사용자가 마지막에 모은 텍스트(예: chunk 요약들 합친 것, 또는 전체 요약본)를 보낼 때
  - task: "summary" | "translate" | ["summary","translate"]
    - summary   : Gemini Flash로 요약
    - translate : DeepL / Gemini로 번역
    - 둘 다     : 먼저 요약, 그 결과를 번역 (final 모드에서)

  - text: 분석/요약/번역할 텍스트 (필수)

  📌 chunk 모드 추가 파라미터 (선택)
  - chunk_index: 현재 chunk 번호 (1-based)
  - total_chunks: 전체 chunk 개수
  - page_range: { from: number, to: number }  // 이 chunk가 커버하는 페이지 범위

  📌 번역용 파라미터
  - source_lang: 원문 언어 (옵션, "auto" 권장)
  - target_lang: 타겟 언어 (예: "EN","KO")
  - deepl_key  : 사용자 DeepL API 키
  - gemini_key : Gemini 키 (요약 + 번역 fallback용)
*/
app.post("/api/docs/analyze", async (req, res) => {
  try {
    const {
      mode,
      task,
      text,
      chunk_index,
      total_chunks,
      page_range,
      source_lang,
      target_lang,
      deepl_key,
      gemini_key,
    } = req.body;

    const safeMode = (mode || "chunk").toString().toLowerCase();
    if (!["chunk", "final"].includes(safeMode)) {
      return sendError(
        res,
        400,
        "DOC_MODE_INVALID",
        `지원하지 않는 mode 입니다: ${mode}`
      );
    }

    // task: "summary" | "translate" | ["summary","translate"]
    let tasks = [];
    if (Array.isArray(task)) {
      tasks = task.map((t) => t.toString().toLowerCase());
    } else if (typeof task === "string" && task.trim()) {
      tasks = [task.toLowerCase()];
    }

    // task를 안 보내면 기본값은 "summary"
    if (!tasks.length) {
      tasks = ["summary"];
    }

    const wantsSummary = tasks.includes("summary");
    const wantsTranslate = tasks.includes("translate");

    if (!wantsSummary && !wantsTranslate) {
      return sendError(
        res,
        400,
        "DOC_TASK_INVALID",
        "task에는 최소한 'summary' 또는 'translate' 중 하나가 포함되어야 합니다."
      );
    }

    if (!text || !text.trim()) {
      return sendError(
        res,
        400,
        "VALIDATION_ERROR",
        "text 필수 입력값이 누락되었거나 비어 있습니다."
      );
    }

    // 길이 제한 처리
    const rawText = text.toString();
    const safeText = rawText.slice(0, DOC_MAX_CHARS);

    if (rawText.length > DOC_MAX_CHARS && DEBUG) {
      console.warn(
        `ℹ️ /api/docs/analyze: 입력 텍스트가 ${DOC_MAX_CHARS}자를 초과하여 잘렸습니다. (원본: ${rawText.length}자)`
      );
    }

    // 요약 요청인데 Gemini 키 없음
    if (wantsSummary && !gemini_key) {
      return sendError(
        res,
        400,
        "DOC_SUMMARY_REQUIRES_GEMINI",
        "요약(summary)을 수행하려면 gemini_key가 필요합니다."
      );
    }

    // 번역 요청인데 DeepL/Gemini 둘 다 없음
    if (wantsTranslate && !deepl_key && !gemini_key) {
      return sendError(
        res,
        400,
        "DOC_TRANSLATE_REQUIRES_ENGINE",
        "번역(translate)을 수행하려면 deepl_key 또는 gemini_key 중 하나가 필요합니다."
      );
    }

    let summaryResult = null;
    let translateResult = null;

    // ─────────────────────────────
    // 1) 요약 (Gemini 2.5 Flash)
    // ─────────────────────────────
    if (wantsSummary && gemini_key) {
      const modeLabel =
        safeMode === "chunk" ? "부분(chunk) 요약" : "최종 요약";

      const pageInfo =
        page_range && page_range.from && page_range.to
          ? `페이지 범위: ${page_range.from}~${page_range.to}p`
          : "";

      const chunkInfo =
        safeMode === "chunk" && total_chunks
          ? `chunk: ${chunk_index ?? "?"}/${total_chunks}`
          : "";

      const prompt = `
너는 긴 기술/학술 문서를 요약하는 보조 엔진이다.

[메타 정보]
- 요약 타입: ${modeLabel}
- ${chunkInfo}
- ${pageInfo}

[요약 지침]
- 한국어로 5~10문장 정도로 핵심만 요약한다.
- 중요한 정의, 수치, 조건, 예외는 최대한 보존한다.
- 이 텍스트에서만 알 수 있는 내용 위주로 정리한다.
- 다른 chunk 내용은 모른다고 가정한다.

[원문 텍스트]
${safeText}
      `.trim();

      const summaryText = await fetchGemini(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${gemini_key}`,
        { contents: [{ parts: [{ text: prompt }] }] }
      );

      summaryResult = (summaryText || "").trim();
    }

    // ─────────────────────────────
    // 2) 번역 (DeepL 우선, 없으면 Gemini)
    // ─────────────────────────────
    if (wantsTranslate && (deepl_key || gemini_key)) {
      const baseForTranslate =
        // final 모드에서 summary+translate 같이 요청 → 요약 결과를 번역
        safeMode === "final" && wantsSummary && summaryResult
          ? summaryResult
          : safeText;

      const tr = await translateText(
        baseForTranslate,
        target_lang ?? null,      // null이면 모듈이 기본값(보통 EN) 선택
        deepl_key ?? null,
        gemini_key ?? null
      );

      translateResult = {
        text: tr.text,
        engine: tr.engine,
        targetLang:
          tr.target || (target_lang ? String(target_lang).toUpperCase() : null),
      };
    }

    // ─────────────────────────────
    // 3) 응답 페이로드 구성
    // ─────────────────────────────
    const payload =
      safeMode === "chunk"
        ? {
            mode: "doc-chunk",
            chunk_index: chunk_index ?? null,
            total_chunks: total_chunks ?? null,
            page_range: page_range || null,
            summary: summaryResult,
            translation: translateResult,
            used_chars: safeText.length,
          }
        : {
            mode: "doc-final",
            summary: summaryResult,
            translation: translateResult,
            used_chars: safeText.length,
          };

    return res.json(buildSuccess(payload));
  } catch (e) {
    console.error("❌ /api/docs/analyze Error:", e.message);
    return sendError(
      res,
      500,
      "DOC_ANALYZE_ERROR",
      "문서 요약·분석 처리 중 오류가 발생했습니다.",
      e.message
    );
  }
});

// ─────────────────────────────
// ✅ Job 조회 (미구현 스텁 유지)
// ─────────────────────────────
app.get("/api/jobs/:jobId", async (req, res) => {
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
// ✅ Admin API (간단 JSON 대시보드)
// ─────────────────────────────

// 관리자 대시보드 (간단 상태 확인용)
app.get("/admin/dashboard", ensureAuth, async (req, res) => {
  return res.json(
    buildSuccess({
      message: "Admin dashboard is alive",
      user: req.user || null,
      region: REGION,
      http_timeout_ms: HTTP_TIMEOUT_MS,
    })
  );
});

// 엔진 통계 조회
app.get("/admin/engine-stats", ensureAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("engine_stats")
      .select("*")
      .order("engine_name", { ascending: true });

    if (error) {
      return sendError(
        res,
        500,
        "ENGINE_STATS_ERROR",
        "엔진 통계 조회 중 오류가 발생했습니다.",
        error.message
      );
    }

    return res.json(
      buildSuccess({
        engine_stats: data || [],
      })
    );
  } catch (e) {
    return sendError(
      res,
      500,
      "ENGINE_STATS_ERROR",
      "엔진 통계 조회 중 알 수 없는 오류가 발생했습니다.",
      e.message
    );
  }
});

// 엔진 보정값 수동 조정 (override_ce 설정/초기화)
app.post("/admin/engine-stats/override", ensureAuth, async (req, res) => {
  try {
    const { engine_name, override_ce, action } = req.body;

    if (!engine_name) {
      return sendError(
        res,
        400,
        "VALIDATION_ERROR",
        "engine_name이 누락되었습니다."
      );
    }

    // 1) 기존 엔진 상태 조회 (auto_ce 가져오기)
    const { data: prev, error } = await supabase
      .from("engine_stats")
      .select("engine_name, auto_ce")
      .eq("engine_name", engine_name)
      .single();

    if (error || !prev) {
      return sendError(
        res,
        404,
        "ENGINE_NOT_FOUND",
        `engine_stats에 해당 엔진이 존재하지 않습니다: ${engine_name}`,
        error?.message
      );
    }

    const auto_ce =
      typeof prev.auto_ce === "number" && Number.isFinite(prev.auto_ce)
        ? prev.auto_ce
        : 1.0;

    let newOverride = null;
    let newEffective = auto_ce;

    // 2) action 이 clear 가 아니면 override 값 파싱
    if (action !== "clear") {
      const num = parseFloat(override_ce);
      if (!Number.isFinite(num)) {
        return sendError(
          res,
          400,
          "VALIDATION_ERROR",
          "override_ce는 숫자여야 합니다."
        );
      }

      // 안전 범위: 0.5 ~ 1.5 (실제 권장: 0.9~1.1)
      let v = num;
      if (v < 0.5) v = 0.5;
      if (v > 1.5) v = 1.5;

      newOverride = v;
      newEffective = v;
    } else {
      // action === "clear" → override 제거, auto_ce로 복귀
      newOverride = null;
      newEffective = auto_ce;
    }

    // 3) engine_stats 업데이트
    const { error: updErr } = await supabase
      .from("engine_stats")
      .update({
        override_ce: newOverride,
        effective_ce: newEffective,
        updated_at: new Date(),
      })
      .eq("engine_name", engine_name);

    if (updErr) {
      return sendError(
        res,
        500,
        "ENGINE_OVERRIDE_UPDATE_ERROR",
        "엔진 보정값 업데이트 중 오류가 발생했습니다.",
        updErr.message
      );
    }

    return res.redirect("/admin/ui");
  } catch (e) {
    console.error("❌ /admin/engine-stats/override Error:", e.message);
    return sendError(
      res,
      500,
      "ENGINE_OVERRIDE_UPDATE_ERROR",
      "엔진 보정값 업데이트 중 알 수 없는 오류가 발생했습니다.",
      e.message
    );
  }
});

// Naver 화이트리스트 조회
app.get("/admin/naver-whitelist", ensureAuth, async (req, res) => {
  return res.json(
    buildSuccess({
      whitelist: whitelistData || { tiers: {} },
    })
  );
});

// Naver 도메인 tier 테스트용 (어드민)
app.get("/admin/naver-test-domain", ensureAuth, (req, res) => {
  const { link } = req.query;
  if (!link) {
    return sendError(
      res,
      400,
      "VALIDATION_ERROR",
      "querystring에 link가 필요합니다. 예: /admin/naver-test-domain?link=https://news.naver.com"
    );
  }
  const info = resolveNaverTier(link);
  return res.json(
    buildSuccess({
      link,
      tier: info.tier,
      weight: info.weight,
    })
  );
});

// ─────────────────────────────
// ✅ Admin UI (EJS 대시보드 화면)
// ─────────────────────────────
app.get("/admin/ui", ensureAuth, async (req, res) => {
  try {
    // 엔진 통계 조회
    const { data: engineStats, error } = await supabase
      .from("engine_stats")
      .select("*")
      .order("engine_name", { ascending: true });

    if (error) {
      console.warn("⚠️ engine_stats query error:", error.message);
    }

    // 화이트리스트 요약 (티어별 도메인 개수)
    const tiers = (whitelistData && whitelistData.tiers) || {};
    const whitelistSummary = Object.entries(tiers).map(([tier, info]) => ({
      tier,
      weight: info?.weight ?? 1,
      domainCount: Array.isArray(info?.domains) ? info.domains.length : 0,
    }));

    res.render("admin-dashboard", {
  user: req.user || null,
  region: REGION,
  httpTimeoutMs: HTTP_TIMEOUT_MS,
  engineStats: engineStats || [],
  whitelistSummary,
  baseWeights: ENGINE_BASE_WEIGHTS,   // ⬅️ 추가
});
  } catch (e) {
    console.error("❌ Admin UI error:", e.message);
    res.status(500).send("Admin UI error");
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
    version: "v18.4.0-pre",
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
  console.log(`🚀 Cross-Verified AI Proxy v18.4.0-pre running on port ${PORT}`);
  console.log("🔹 LV 모듈 외부화 (/src/modules/klaw_module.js)");
  console.log(
    "🔹 Translation 모듈 활성화 (DeepL + Gemini Flash-Lite Fallback)"
  );
    console.log("🔹 Naver 서버 직접 호출 (Region 제한 해제)");
  console.log("🔹 Supabase + Gemini 2.5 (Flash / Pro / Lite) 정상 동작");
  console.log("🔹 공통 에러 코드/응답 규약(ⅩⅤ) 1차 적용 완료");
});
