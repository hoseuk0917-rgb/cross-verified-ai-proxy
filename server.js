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

const isProd = process.env.NODE_ENV === "production";
const DEBUG = process.env.DEBUG === "true";

const app = express();

const PORT = parseInt(process.env.PORT || "10000", 10);
const REGION =
  process.env.RENDER_REGION ||
  process.env.FLY_REGION ||
  process.env.AWS_REGION ||
  process.env.REGION ||
  "unknown";


// ✅ 여기서 먼저 풀/스토어 준비
const pgPool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false, // 로컬이면 false 권장
});

const PgStore = connectPgSimple(session);

const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || "cva.sid";
const SESSION_SAMESITE_RAW = (process.env.SESSION_SAMESITE || "lax").toLowerCase();
const SESSION_SAMESITE = (["lax", "none", "strict"].includes(SESSION_SAMESITE_RAW))
  ? SESSION_SAMESITE_RAW
  : "lax";
const SESSION_SECURE = (SESSION_SAMESITE === "none") ? true : isProd;
const SESSION_DOMAIN = process.env.SESSION_DOMAIN || undefined;

// ✅ 운영이면 secret 강제(권장)
if (isProd && !process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required in production");
}

app.use(
  session({
    name: SESSION_COOKIE_NAME,

    // ✅ Postgres 세션 스토어 연결
    store: new PgStore({
  pool: pgPool,
  tableName: "session_store",
  createTableIfMissing: !isProd, // ✅ 운영은 false 권장
}),

    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    proxy: true,

    cookie: {
      httpOnly: true,
      maxAge: 86400000,
      secure: SESSION_SECURE,
      sameSite: SESSION_SAMESITE,
      ...(SESSION_DOMAIN ? { domain: SESSION_DOMAIN } : {}),
    },
  })
);

// ✅ 운영에서 “로그인 사용자만” 허용하려면 true
const REQUIRE_USER_AUTH = process.env.REQUIRE_USER_AUTH === "true";

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

// 🔹 (옵션) Flash 프롬프트에 붙일 external 길이 (기본 800 → 넉넉히 4000 권장)
const FLASH_REF_CHARS = parseInt(process.env.FLASH_REF_CHARS || "4000", 10);

// 🔹 (옵션) Pro(verify) 입력 JSON 길이 (기본 6000 → 넉넉히 12000 권장)
const VERIFY_INPUT_CHARS = parseInt(process.env.VERIFY_INPUT_CHARS || "12000", 10);

// 🔹 (옵션) DB에 저장할 Gemini 원문 텍스트 제한 (미설정이면 “무제한”)
const MAX_LOG_TEXT_CHARS = process.env.MAX_LOG_TEXT_CHARS
  ? parseInt(process.env.MAX_LOG_TEXT_CHARS, 10)
  : null;


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
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // 모바일 앱/서버투서버처럼 Origin이 없는 경우 허용
    if (!origin) return cb(null, true);

    // 등록된 origin만 허용
    if (CORS_ORIGINS.includes(origin)) return cb(null, true);

    return cb(new Error("CORS_NOT_ALLOWED"), false);
  },
  credentials: true,
}));

app.use(express.json({ limit: "8mb" }));
app.use(express.urlencoded({ extended: true }));
// ✅ Morgan: Render 헬스체크/Flutter SW 요청 로그 스킵
// ✅ Morgan: Render 헬스체크/노이즈 요청 로그 스킵 (더 강력 버전)
function getBasePath(req) {
  const u = (req.originalUrl || req.url || "").toString();
  return u.split("?")[0] || "";
}

function shouldSkipMorgan(req) {
  const p = getBasePath(req);

  // health/root
  if (p === "/health" || p === "/") return true;

  // flutter/pwa noise
  if (p === "/flutter_service_worker.js") return true;
  if (p === "/manifest.json") return true;
  if (p === "/favicon.ico") return true;

  // (선택) admin/ui가 너무 시끄러우면 켜기
  // if (p.startsWith("/admin/ui")) return true;

  // CORS preflight
  if (req.method === "OPTIONS") return true;

  return false;
}

app.use(
  morgan(DEBUG ? "dev" : "combined", {
    skip: (req, res) => shouldSkipMorgan(req),
  })
);

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

function maybeTruncateText(s) {
  if (s == null) return s;
  const str = String(s);
  if (!MAX_LOG_TEXT_CHARS || !Number.isFinite(MAX_LOG_TEXT_CHARS)) return str;
  if (MAX_LOG_TEXT_CHARS <= 0) return str;
  return str.length > MAX_LOG_TEXT_CHARS ? str.slice(0, MAX_LOG_TEXT_CHARS) : str;
}

function safeSourcesForDB(obj, maxLen = 20000) {
  try {
    let s = JSON.stringify(obj);
    if (s.length <= maxLen) return s;

    // 1) 크기 줄이기: 큰 텍스트/덩어리 제거
    const slim = {
      meta: obj?.meta || null,
      external: obj?.external ? { ...obj.external } : {},
      partial_scores: obj?.partial_scores ? { ...obj.partial_scores } : {},
      verify_meta: obj?.verify_meta || null,
    };

    // (옵션 저장) flash/verify 원문은 가장 무거움 → 제거
    if (slim.partial_scores) {
      delete slim.partial_scores.flash_text;
      delete slim.partial_scores.verify_text;
    }

    // verify_meta가 크면 최소 필드만 유지
    if (slim.verify_meta && typeof slim.verify_meta === "object") {
      const vm = slim.verify_meta;
      slim.verify_meta = {
        overall: vm?.overall ?? null,
        engine_adjust: vm?.engine_adjust ?? null,
        blocks: Array.isArray(vm?.blocks) ? vm.blocks.slice(0, 8) : null,
      };
    }


    // external 배열은 상한 축소
    const cut = (v, n) => (Array.isArray(v) ? v.slice(0, n) : v);
    if (slim.external) {
      slim.external.naver = cut(slim.external.naver, 8);
      slim.external.gdelt = cut(slim.external.gdelt, 8);
      slim.external.crossref = cut(slim.external.crossref, 8);
      slim.external.openalex = cut(slim.external.openalex, 8);
      slim.external.wikidata = cut(slim.external.wikidata, 8);
      slim.external.github = cut(slim.external.github, 8);

      // klaw는 객체/배열이 큰 경우가 많아서 최종 단계에서 제거 후보
      // (LV에서는 anyhow klaw_result를 응답으로 주니까, 로그에는 축약해도 됨)
    }

    s = JSON.stringify(slim);
    if (s.length <= maxLen) return s;

    // 2) 그래도 크면 가장 큰 덩어리(klaw) 제거하고 플래그만 남김
    if (slim.external && slim.external.klaw) {
      slim.external.klaw = { truncated: true };
      s = JSON.stringify(slim);
      if (s.length <= maxLen) return s;
    }

    // 3) 마지막 안전망: 깨진 JSON로 저장하지 말고, "정상 JSON" 최소 형태로 저장
    return JSON.stringify({ truncated: true, reason: "sources_too_large" });
  } catch (e) {
    return JSON.stringify({ truncated: true, reason: "sources_stringify_fail" });
  }
}

// ─────────────────────────────
// ✅ Supabase + PostgreSQL 세션
// ─────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

function getBearerToken(req) {
  const h = req.headers?.authorization || req.headers?.Authorization;
  if (!h) return null;
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function toPseudoEmail(token) {
  // Bearer localtest 같은 값도 users 테이블에 박히게 “가짜 이메일”로 통일
  const safe = String(token || "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 60) || "anon";
  return `${safe}@local.test`;
}

async function getSupabaseAuthUser(req) {
  const token = getBearerToken(req);
  if (!token) return null;

  const { data, error } = await supabase.auth.getUser(token);
  if (error) return null;
  return data?.user || null;
}

function isUuid(v) {
  return typeof v === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
}

// user_id > user_email 기반 users 테이블에서 id 조회/생성 > DEFAULT_USER_ID
// user_id > user_email 기반 users 테이블에서 id 조회/생성 > DEFAULT_USER_ID
async function resolveLogUserId({ user_id, user_email, user_name, auth_user, bearer_token }) {
  // ✅ 1) Supabase JWT로 검증된 사용자면 그 정보를 최우선 사용 (body 값은 위조 가능)
  if (auth_user?.email) {
    user_email = auth_user.email;
    user_name =
      auth_user.user_metadata?.full_name ||
      auth_user.user_metadata?.name ||
      user_name ||
      null;

    // body user_id는 무시(다른 사람 id로 저장 방지)
    user_id = null;
  }

  // ✅ 2) (레거시) 서버가 uuid user_id를 직접 받는 경우만 허용
  if (isUuid(user_id)) return user_id;

  // ✅ 3) auth_user가 없을 때도 Bearer 토큰을 "로그 식별"로 활용 (localtest 등)
  // - 토큰이 UUID면 그대로 user_id로 인정
  // - 토큰이 이메일이면 user_email로 사용
  // - 그 외면 pseudo email로 변환해서 users에 upsert/lookup
  if (!auth_user && bearer_token) {
    const t = String(bearer_token).trim();
    if (t) {
      if (isUuid(t)) return t;
      if (!user_email) {
        user_email = t.includes("@") ? t : toPseudoEmail(t);
      }
    }
  }

  // ✅ 4) email로 users 테이블에서 id upsert/lookup
  const email = (user_email || "").toString().trim().toLowerCase();
  if (email) {
    await supabase
      .from("users")
      .upsert([{ email, name: user_name || null }], { onConflict: "email" });

    const { data, error } = await supabase
      .from("users")
      .select("id")
      .eq("email", email)
      .single();

    if (!error && data?.id) return data.id;
  }

  // ✅ 5) DEFAULT_USER_ID (UUID) fallback
  const def = process.env.DEFAULT_USER_ID;
  if (isUuid(def)) return def;

  return null;
}

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

function parseGdeltSeenDate(seen) {
  const s = String(seen || "").trim();

  // GDELT seendate: YYYYMMDDHHMMSS 형태 대응
  const m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/);
  if (m) {
    const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
    return Number.isNaN(d.getTime()) ? null : d;
  }

  // ISO/일반 날짜 문자열 fallback
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
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
    const at = await oAuth2Client.getAccessToken();
    const accessToken = typeof at === "string" ? at : at?.token;

    if (!accessToken) {
      throw new Error("GMAIL_ACCESS_TOKEN_EMPTY");
    }

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        type: "OAuth2",
        user: process.env.GMAIL_USER,
        clientId: process.env.GMAIL_CLIENT_ID,
        clientSecret: process.env.GMAIL_CLIENT_SECRET,
        refreshToken: process.env.GMAIL_REFRESH_TOKEN,
        accessToken, // ✅ string 보장
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

// ✅ Naver 타입별 가중치(필요시 조정)
const NAVER_TYPE_WEIGHTS = {
  news: 1.0,
  web: 0.9,
  encyc: 1.05,
};

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

// 🔹 (옵션) Naver 다중 쿼리 호출 제한
const NAVER_MULTI_MAX_QUERIES = parseInt(process.env.NAVER_MULTI_MAX_QUERIES || "3", 10);
const NAVER_MULTI_MAX_ITEMS = parseInt(process.env.NAVER_MULTI_MAX_ITEMS || "18", 10);

// 🔹 결과 중복 제거(링크 기준)
function dedupeByLink(items = []) {
  const seen = new Set();
  const out = [];
  for (const it of items) {
    const key = (it?.link || "").toString().trim();
    if (!key) continue;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(it);
  }
  return out;
}

// ─────────────────────────────
// ✅ External Engines + Fail-Grace Wrapper
// ─────────────────────────────
async function safeFetch(name, fn, q) {
  for (let i = 0; i < 2; i++) {
    try {
      return await fn(q);
    } catch (err) {
      // ✅ 인증/설정 오류 같은 '치명(fatal)'은 fail-grace 하지 말고 즉시 중단
      if (err?._fatal) {
        await handleEngineFail(name, q, err.message);
        throw err;
      }

      if (i === 1) {
        await handleEngineFail(name, q, err.message);
        return [];
      }
    }
  }
}

function ensureMetric(engineMetrics, name) {
  if (!engineMetrics[name]) {
    engineMetrics[name] = { calls: 0, ms_total: 0, ms_avg: null, ms_last: null };
  }
  return engineMetrics[name];
}

function recordTime(timesObj, name, ms) {
  if (!timesObj || typeof timesObj !== "object") return;
  timesObj[name] = (timesObj[name] || 0) + ms; // 누적
}

function recordMetric(metricsObj, name, ms) {
  if (!metricsObj || typeof metricsObj !== "object") return;
  const m = ensureMetric(metricsObj, name);
  m.calls += 1;
  m.ms_total += ms;
  m.ms_last = ms;
  m.ms_avg = Math.round((m.ms_total / m.calls) * 10) / 10;
}


async function safeFetchTimed(name, fn, q, engineTimes, engineMetrics) {
  const start = Date.now();
  const result = await safeFetch(name, fn, q);
  const ms = Date.now() - start;

  // ✅ 엔진별 총 소요시간 누적 (ms)
  if (engineTimes && typeof engineTimes === "object") {
    engineTimes[name] = (engineTimes[name] || 0) + ms;
  }

  // ✅ 어드민/디버그용 메트릭 누적 (calls, avg, total, last)
  if (engineMetrics && typeof engineMetrics === "object") {
    const m = ensureMetric(engineMetrics, name);
    m.calls += 1;
    m.ms_total += ms;
    m.ms_last = ms;
    m.ms_avg = Math.round((m.ms_total / m.calls) * 10) / 10; // 소수 1자리
  }

  return { result, ms };
}


// ─────────────────────────────
// ✅ Naver API (서버 직접 호출, 리전 제한 없음)
//   - clientId / clientSecret 은 요청 바디에서 받은 값을 그대로 사용
// ─────────────────────────────
function sanitizeNaverQuery(q) {
  return String(q || "")
    .replace(/[+]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeNaverToken(t) {
  let s = String(t || "").trim();
  s = s.replace(/^\++/, "");
  // 구두점 제거 (유니코드 문자/숫자만 남김)
  s = s.replace(/[^\p{L}\p{N}]+/gu, "");

  // 아주 단순 조사/어미 제거(끝에 붙은 1글자 조사만) - 과도한 필터링 방지
  const particles = ["은", "는", "이", "가", "을", "를", "의", "도", "만"];
  for (const p of particles) {
    if (s.length > 2 && s.endsWith(p)) {
      s = s.slice(0, -p.length);
      break;
    }
  }
  return s;
}

async function callNaver(query, clientId, clientSecret) {
  const q = sanitizeNaverQuery(query);

  const headers = {
    "X-Naver-Client-Id": clientId,
    "X-Naver-Client-Secret": clientSecret,
  };

  const endpoints = [
    { type: "news",  url: "https://openapi.naver.com/v1/search/news.json" },
    { type: "web",   url: "https://openapi.naver.com/v1/search/webkr.json" },
    { type: "encyc", url: "https://openapi.naver.com/v1/search/encyc.json" },
  ];

  // 🔹 AND 비슷한 필터용 토큰(너무 빡세면 결과 0 나옴 → 완화)
  const tokens = q
    .split(/\s+/)
    .map(normalizeNaverToken)
    .filter((t) => t.length > 1);

  const requiredHits = tokens.length <= 2 ? 1 : (tokens.length - 1);

  const all = [];
  let lastErr = null;

  for (const ep of endpoints) {
    try {
      const { data } = await axios.get(ep.url, {
        headers,
        params: { query: q, display: 3 },
        timeout: HTTP_TIMEOUT_MS,
      });

      let items =
        data?.items?.map((i) => {
          const cleanTitle = i.title?.replace(/<[^>]+>/g, "") || "";
          const cleanDesc = i.description?.replace(/<[^>]+>/g, "") || "";
          const link = i.link;

          const tierInfo = resolveNaverTier(link);
          const typeWeight = NAVER_TYPE_WEIGHTS[ep.type] ?? 1;

          return {
            title: cleanTitle,
            desc: cleanDesc,
            link,
            origin: "naver",
            naver_type: ep.type,
            tier: tierInfo.tier,
            tier_weight: tierInfo.weight,
            type_weight: typeWeight,
          };
        }) || [];

      // 🔹 제목/요약 토큰 필터(완화된 requiredHits 사용)
      if (tokens.length > 0) {
        items = items.filter((it) => {
          const text = `${it.title || ""} ${it.desc || ""}`.toLowerCase();
          let hit = 0;
          for (const tk of tokens) {
            if (text.includes(tk.toLowerCase())) hit++;
          }
          return hit >= requiredHits;
        });
      }

      all.push(...items);
    } catch (e) {
      lastErr = e;
      const s = e?.response?.status;

      // ✅ BAD 키(401/403)는 즉시 "치명 오류"로 중단시켜야 함
      if (s === 401 || s === 403) {
        const err = new Error("NAVER_AUTH_ERROR");
        err.code = "NAVER_AUTH_ERROR";
        err.httpStatus = 401;
        err.detail = { status: s };
        err._fatal = true;
        throw err;
      }

      // 다른 에러는 일단 다음 endpoint 시도 (news만 죽고 web은 살 수 있음)
      if (DEBUG) console.warn("⚠️ Naver endpoint fail:", ep.type, s, e.message);
    }
  }

  // 3개 endpoint를 다 돌렸는데도 결과 0이고 에러가 있었다면 상위로 올려서 fail-grace/로그가 가능하게
  if (!all.length && lastErr) {
    throw lastErr;
  }

  return all;
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
    `https://api.openalex.org/works?search=${encodeURIComponent(q)}&per_page=3`,
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
    `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q)}&format=json&maxrecords=3`,
    { timeout: HTTP_TIMEOUT_MS }
  );

  return (
    data?.articles?.map((i) => {
      const d = parseGdeltSeenDate(i.seendate);
      return { title: i.title, date: d ? d.toISOString() : null };
    }) || []
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
// ✅ Gemini 호출 공통 유틸 (빈문자 방지 + 원인 로그 + fallback 지원용)
// ─────────────────────────────
function extractGeminiText(data) {
  const parts = data?.candidates?.[0]?.content?.parts;
  if (!Array.isArray(parts)) return "";
  return parts.map((p) => (p?.text ? String(p.text) : "")).join("\n");
}

function geminiErrMessage(e) {
  const status = e?.response?.status;
  const apiMsg =
    e?.response?.data?.error?.message ||
    e?.response?.data?.message ||
    null;
  return `[status=${status ?? "?"}] ${apiMsg || e?.message || "Unknown Gemini error"}`;
}

// ✅ url: generateContent endpoint
// ✅ payload: { contents:[{parts:[{text:"..."}]}] }
// ✅ opts: { label?:string, minChars?:number }
async function fetchGemini(url, payload, opts = {}) {
  const label = opts.label || "gemini";
  const minChars = Number.isFinite(opts.minChars) ? opts.minChars : 1;

  try {
    const { data } = await axios.post(url, payload, { timeout: HTTP_TIMEOUT_MS });

    const text = extractGeminiText(data);

    // ✅ 후보가 없거나 텍스트가 비면 "실패"로 처리 (fallback이 작동하도록 throw)
    if ((text || "").trim().length < minChars) {
      const finishReason = data?.candidates?.[0]?.finishReason;
      const blockReason = data?.promptFeedback?.blockReason;
      const err = new Error(
        `${label}: GEMINI_EMPTY_TEXT (finish=${finishReason || "?"}, block=${blockReason || "?"})`
      );
      err._gemini_empty = true;
      throw err;
    }

    return text;
  } catch (e) {
    // ✅ DEBUG가 꺼져 있어도 원인 파악 가능하게 항상 로그
    console.error("❌ Gemini call failed:", label, geminiErrMessage(e));
    throw e;
  }
}


// ─────────────────────────────
// ✅ 유효성 (Vᵣ) 계산식 — GitHub 기반
// ─────────────────────────────
function calcValidityScore(gitItems = []) {
  if (!gitItems.length) return 0.5;

  const norm = gitItems.map((r) => {
    const stars = Math.min(r.stars || 0, 5000) / 5000;
    const forks = Math.min(r.forks || 0, 1000) / 1000;
    const upd = new Date(r.updated);
const freshness = isNaN(upd.getTime())
  ? 0.5
  : 1 - Math.min((Date.now() - upd.getTime()) / (1000 * 60 * 60 * 24 * 365), 1);
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

// ✅ engine_correction_samples: 엔진별 최근 N개만 남기기 (ID 기반 트림)
const TRIM_BATCH = 200; // 한 번에 지울 최대 개수(안전용)

async function trimEngineCorrectionSamples(engine, windowSize) {
  if (!windowSize || windowSize <= 0) return;

  while (true) {
    // 최신 windowSize개는 보존, 그 이후 것들을 range로 잡아서 배치 삭제
    const { data: oldRows, error: selErr } = await supabase
      .from("engine_correction_samples")
      .select("id")
      .eq("engine_name", engine)
      .order("created_at", { ascending: false })
      .order("id", { ascending: false }) // created_at 동률 대비
      .range(windowSize, windowSize + TRIM_BATCH - 1);

    if (selErr) {
      if (DEBUG) console.warn("⚠️ trim select fail:", selErr.message);
      break;
    }

    if (!oldRows || oldRows.length === 0) break;

    const idsToDelete = oldRows.map(r => r.id).filter(v => v != null);
    if (!idsToDelete.length) break;

    const { error: delErr } = await supabase
      .from("engine_correction_samples")
      .delete()
      .in("id", idsToDelete);

    if (delErr) {
      if (DEBUG) console.warn("⚠️ trim delete fail:", delErr.message);
      break;
    }
  }
}

// ✅ Weight + History Update (정확히 N개 롤오버 유지 + cₑ 계산)
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

    // ✅ 2) 엔진별 최근 N개만 유지 (ID 기반 삭제)
    await trimEngineCorrectionSamples(engine, windowSize);

    // 3) 최근 N회(windowSize) 샘플 조회 (정렬 안정화)
    const { data: samples, error: sampleErr } = await supabase
      .from("engine_correction_samples")
      .select("id, truthscore, response_ms")
      .eq("engine_name", engine)
      .order("created_at", { ascending: false })
      .order("id", { ascending: false })
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

    // 4) 기존 total_runs, override_ce 조회
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

// 5) avgTruth 기반 자동 보정계수(auto_ce) 계산 (0.9~1.1)
//    ✅ 응답시간(avgResp)은 모니터링(저장)만 하고, 신뢰도 보정에는 반영하지 않음
const targetTruth = 0.7; // 기준 Truth
let truthAdj = avgTruth / targetTruth;
if (truthAdj < 0.9) truthAdj = 0.9;
if (truthAdj > 1.1) truthAdj = 1.1;

const auto_ce = Math.max(0.9, Math.min(1.1, truthAdj));
;

    // 6) override_ce가 있으면 그 값을, 없으면 auto_ce를 effective_ce로 사용
    const override_ce =
      typeof prev?.override_ce === "number" ? prev.override_ce : null;

    const effective_ce =
      typeof override_ce === "number" && Number.isFinite(override_ce)
        ? override_ce
        : auto_ce;

    // 7) engine_stats 갱신 (Ⅲ, Ⅳ 명세 반영)
    await supabase.from("engine_stats").upsert([
      {
        engine_name: engine,
        avg_truth: avgTruth,
        avg_response: avgResp,
        rolling_window_size: windowSize,
        sample_count: sampleCount, // ✅ 이제 진짜로 "최대 N" 유지됨
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
  return String(raw).replace(/\s+/g, " ").trim();
}

function splitIntoTwoParts(text) {
  const t = String(text || "").replace(/\s+/g, " ").trim();
  if (!t) return ["", ""];
  if (t.length < 40) return [t, ""]; // 너무 짧으면 2개로 억지 복제하지 않음

  const mid = Math.floor(t.length / 2);

  // 중간 근처에서 공백 기준으로 자연스럽게 자르기
  let cut = t.lastIndexOf(" ", mid);
  if (cut < 10) cut = t.indexOf(" ", mid);
  if (cut < 10) cut = mid;

  const a = t.slice(0, cut).trim();
  const b = t.slice(cut).trim();
  if (!a || !b) return [t, t]; // 결과가 비면 복제

  return [a, b];
}

function buildNaverAndQuery(baseKo) {
  return String(baseKo || "")
    .replace(/[+]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

const QVFV_MAX_BLOCKS = parseInt(process.env.QVFV_MAX_BLOCKS || "5", 10);
const BLOCK_NAVER_MAX_QUERIES = parseInt(process.env.BLOCK_NAVER_MAX_QUERIES || "2", 10);
const BLOCK_NAVER_MAX_ITEMS = parseInt(process.env.BLOCK_NAVER_MAX_ITEMS || "6", 10);

async function preprocessQVFVOneShot({ mode, query, core_text, gemini_key, modelName }) {
  // mode: "qv" | "fv"
  // QV: 답변 생성 + 답변 기준 블록/쿼리 생성
  // FV: core_text(사실문장) 기준 블록/쿼리 생성 (답변 생성 X)

  const baseCore = (core_text || query || "").toString().trim();

 const prompt = `
너는 Cross-Verified AI의 "전처리 엔진"이다.
목표: (QV) 답변 생성 + 의미블록 분해 + 블록별 외부검증 엔진 쿼리 생성을 한 번에 수행한다.

[입력]
- mode: ${mode}                // "qv" | "fv"
- user_query: ${query}
- core_text(FV에서만 사용): ${mode === "fv" ? baseCore : "(QV에서는 무시)"}

[절대 규칙 — 위반하면 실패]
1) 출력은 JSON 1개만. (설명/접두어/접미어/코드블록/마크다운/줄바꿈 코멘트 모두 금지)
2) JSON은 반드시 double quote(")만 사용하고, trailing comma 금지.
3) blocks는 반드시 1~${QVFV_MAX_BLOCKS}개.
4) block.text는 "검증 대상 텍스트"에서 문장을 그대로 복사해서 사용(의역/요약/새 주장 추가 금지).
5) naver 쿼리에는 '+'를 절대 포함하지 말 것.

[QV 규칙]
- 질문에 대해 최선의 한국어 답변(answer_ko)을 6~10문장으로 작성한다.
- 웹검색/브라우징/실시간 조회를 했다고 주장하지 말라.
- 확실하지 않은 고유명사/수치/날짜는 단정하지 말고 '불확실'로 표시한다.

[FV 규칙]
- answer_ko는 반드시 "" (빈 문자열).
- 검증 대상 텍스트는 core_text(없으면 user_query) 그대로.

[blocks 규칙]
- 각 블록은 "주장/수치/조건" 단위로 1~2문장씩 묶는다.
- 각 block.text는 30~260자 내로 유지(너무 짧거나 너무 길면 실패).
- id는 1부터 순서대로.

[engine_queries 규칙]
- crossref/openalex: 영어 키워드/짧은 구문(2~10단어, 90자 이내)
- wikidata: 한국어 엔티티/명사 중심(2~8단어, 50자 이내)
- gdelt: 영어 boolean 쿼리(AND/OR 괄호 허용, 120자 이내)
- naver: 한국어 짧은 키워드열 배열 1~${BLOCK_NAVER_MAX_QUERIES}개 (각 원소 30자 이내, '+' 금지)

[출력 JSON 스키마]
{
  "answer_ko": "...",          // FV는 ""
  "korean_core": "...",
  "english_core": "...",
  "blocks": [
    {
      "id": 1,
      "text": "...",
      "engine_queries": {
        "crossref": "...",
        "openalex": "...",
        "wikidata": "...",
        "gdelt": "...",
        "naver": ["...", "..."]
      }
    }
  ]
}
`.trim();


  const text = await fetchGemini(
    `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${gemini_key}`,
    { contents: [{ parts: [{ text: prompt }] }] }
  );

  const trimmed = (text || "").trim();
  const jsonMatch = trimmed.match(/\{[\s\S]*\}/);
  const jsonText = jsonMatch ? jsonMatch[0] : trimmed;

  let parsed = null;
  try { parsed = JSON.parse(jsonText); } catch { parsed = null; }

  const answer_ko = String(parsed?.answer_ko || "").trim();
  const korean_core = String(parsed?.korean_core || "").trim() || normalizeKoreanQuestion(baseCore);
  const english_core = String(parsed?.english_core || "").trim() || String(query || "").trim();

   let blocksRaw = Array.isArray(parsed?.blocks) ? parsed.blocks : [];

  let blocks = blocksRaw.slice(0, QVFV_MAX_BLOCKS).map((b, idx) => {
    const eq = b?.engine_queries || {};
    const naverArr = Array.isArray(eq.naver) ? eq.naver : (typeof eq.naver === "string" ? [eq.naver] : []);
    return {
      id: Number.isFinite(Number(b?.id)) ? Number(b.id) : (idx + 1),
      text: String(b?.text || "").trim(),
      engine_queries: {
        crossref: String(eq.crossref || "").trim() || english_core,
        openalex: String(eq.openalex || "").trim() || english_core,
        wikidata: String(eq.wikidata || "").trim() || korean_core,
        gdelt: String(eq.gdelt || "").trim() || english_core,
        naver: naverArr.map(s => String(s).trim()).filter(Boolean).slice(0, BLOCK_NAVER_MAX_QUERIES),
      },
    };
  }).filter(b => b.text);

 // ✅ 최종 안전망: 0개면 base 텍스트로 1개 생성
if (blocks.length === 0) {
  const seedText =
    (mode === "qv")
      ? (answer_ko || baseCore || "")
      : (baseCore || "");

  const t1 = String(seedText || "").trim();

  blocks = [
    {
      id: 1,
      text: t1,
      engine_queries: {
        crossref: english_core,
        openalex: english_core,
        wikidata: korean_core,
        gdelt: english_core,
        naver: [korean_core],
      },
    },
  ].filter((b) => b.text);
}

  return {
    answer_ko: (mode === "qv" ? (answer_ko || "") : ""),
    korean_core,
    english_core,
    blocks, // ✅ 여기서 항상 2개 이상이 되도록 보장됨
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

  let num = 0;
  let den = 0;

  for (const name of engines) {
    if (name === "klaw") continue;

    const base = Number(ENGINE_BASE_WEIGHTS[name] ?? 1.0);
    if (!Number.isFinite(base) || base <= 0) continue;

    const st = statsMap[name];

    let ce = 1.0;
    if (st) {
      if (typeof st.effective_ce === "number") ce = st.effective_ce;
      else if (typeof st.auto_ce === "number") ce = st.auto_ce;
    }

    ce = Math.max(0.9, Math.min(1.1, ce));

    num += base * ce;
    den += base;
  }

  if (den <= 0) return 1.0;

  const C = num / den;
  return Math.max(0.9, Math.min(1.1, C));
}

  


// ─────────────────────────────
// ✅ Verify Core (QV / FV / DV / CV / LV)
//   - DV/CV: GitHub 기반 TruthScore 직접 계산 (Gemini→GitHub)
//   - LV: TruthScore 없이 K-Law 결과만 제공 (Ⅸ 명세 반영)
// ─────────────────────────────

app.post("/api/verify", async (req, res) => {
let logUserId = null;   // ✅ 요청마다 독립
  let authUser = null;    // ✅ 요청마다 독립
 const {
  query,
  mode,
  gemini_key,
  naver_id,
  naver_secret,
  klaw_key,
  user_answer,
  github_token,
  gemini_model,

  // ✅ FV에서 "사실 문장"을 query와 분리해서 보내고 싶을 때 사용
  core_text,

  user_id,
  user_email,
  user_name,
} = req.body;

const safeMode = (mode || "").trim().toLowerCase();

// ✅ FV 검증 대상(사실 문장) 우선 입력값
const userCoreText = (core_text || "").toString().trim();

  // 기본 검증
  if (!query) {
    return res
      .status(400)
      .json(buildError("VALIDATION_ERROR", "query가 누락되었습니다."));
  }

  const allowedModes = ["qv", "fv", "dv", "cv", "lv"];
if (!allowedModes.includes(safeMode)) {
  return res
    .status(400)
    .json(buildError("INVALID_MODE", `지원하지 않는 모드입니다: ${mode}`));
}

// ✅ 모드가 확정된 다음에 키 검증
if (safeMode !== "lv" && !gemini_key) {
  return res
    .status(400)
    .json(buildError("VALIDATION_ERROR", "Gemini 키가 누락되었습니다."));
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

// ✅ LV는 klaw_key 필수
if (safeMode === "lv" && !klaw_key) {
  return res.status(400).json(
    buildError("VALIDATION_ERROR", "LV 모드에서는 klaw_key가 필요합니다.")
  );
}

// ✅ DV/CV는 github_token 필수
if ((safeMode === "dv" || safeMode === "cv") && !github_token) {
  return res.status(400).json(
    buildError("VALIDATION_ERROR", "DV/CV 모드에서는 github_token이 필요합니다.")
  );
}

  // 🔹 QV/FV용 Gemini 모델 토글 (Flash / Pro)
  // - 클라이언트에서 gemini_model: "flash" | "pro" | undefined 로 보냄
  // - QV/FV에서만 토글, DV/CV는 항상 Pro 고정
    const geminiModelRaw = (gemini_model || "").toString().trim().toLowerCase();
let verifyModel = null;        // 요청에서 "의도한" verify 모델
let verifyModelUsed = null;    // ✅ 실제로 성공한 verify 모델(에러 캐치에서도 써야 하므로 바깥 스코프)

if (safeMode === "qv" || safeMode === "fv") {
  if (geminiModelRaw === "flash") {
    verifyModel = "gemini-2.5-flash";
  } else {
    verifyModel = "gemini-2.5-pro";
  }
} else if (safeMode === "dv" || safeMode === "cv") {
  verifyModel = "gemini-2.5-pro";
}

// ✅ 기본값은 "의도한 모델"로 세팅 (fallback 성공 시 아래에서 덮어씀)
verifyModelUsed = verifyModel;

    const engines = [];
  const external = {};
  const start = Date.now();
  let partial_scores = {};
  let truthscore = 0.0;
  let engineStatsMap = {};
  let engineFactor = 1.0;

  // ✅ 엔진/LLM 시간·메트릭 누적용 객체
  const engineTimes = {};
  const engineMetrics = {};
  const geminiTimes = {};
  const geminiMetrics = {};

  // ✅ QV/FV 2-call 구조용: 전처리 결과(답변/블록/증거)를 요청 스코프에 보관
  let qvfvPre = null;                 
  let qvfvBlocksForVerifyFull = null; // [{id,text,queries,evidence...}, ...]
  let qvfvPreDone = false;            // 전처리 성공 여부

  try {
  // ✅ 추가: verification_logs.user_id NOT NULL 대응
  authUser = await getSupabaseAuthUser(req);

// ✅ 운영모드: 로그인 토큰 없으면 차단
if (REQUIRE_USER_AUTH && !authUser) {
  return res.status(401).json(buildError("UNAUTHORIZED", "로그인이 필요합니다. (Authorization: Bearer <token>)"));
}

logUserId = await resolveLogUserId({
  user_id,
  user_email,
  user_name,
  auth_user: authUser,
  bearer_token: getBearerToken(req), // ✅ 추가: Bearer localtest 같은 값도 로그 식별에 사용
});

if (!logUserId) {
  return res.status(400).json(
    buildError(
      "VALIDATION_ERROR",
      "로그 식별자(user) 확정 실패: Authorization Bearer 토큰 또는 DEFAULT_USER_ID가 필요합니다."
    )
  );
}

// ─────────────────────────────
// ① 모드별 외부엔진 호출 (DV/CV/QV/FV/LV)
// ─────────────────────────────
switch (safeMode) {
  case "qv":
  case "fv": {
    engines.push("crossref", "openalex", "wikidata", "gdelt", "naver");

    const preprocessModel =
      geminiModelRaw === "flash" ? "gemini-2.5-flash" : "gemini-2.5-pro";

    const qvfvBaseText = (safeMode === "fv" && userCoreText) ? userCoreText : query;

    // ✅ QV/FV 전처리 원샷 (답변+블록+블록별 쿼리)
    try {
      const t_pre = Date.now();
      const pre = await preprocessQVFVOneShot({
        mode: safeMode,
        query,
        core_text: qvfvBaseText,
        gemini_key,
        modelName: preprocessModel,
      });
      const ms_pre = Date.now() - t_pre;
      recordTime(geminiTimes, "qvfv_preprocess_ms", ms_pre);
      recordMetric(geminiMetrics, "qvfv_preprocess", ms_pre);

      qvfvPre = pre;
      qvfvPreDone = true;

      partial_scores.qvfv_pre = {
        korean_core: pre.korean_core,
        english_core: pre.english_core,
        blocks_count: pre.blocks.length,
      };
      partial_scores.qv_answer = safeMode === "qv" ? pre.answer_ko : null;
    } catch (e) {
      qvfvPre = null;
      qvfvPreDone = false;
      if (DEBUG) console.warn("⚠️ QV/FV preprocess one-shot fail:", e.message);
    }

 // ✅ 전처리 실패 fallback
if (!qvfvPre) {
  const baseCore = qvfvBaseText || query || "";
  const [t1, t2] = splitIntoTwoParts(baseCore);

  qvfvPre = {
    answer_ko: "",
    korean_core: normalizeKoreanQuestion(baseCore),
    english_core: String(baseCore).trim(),
    blocks: [
      {
        id: 1,
        text: t1,
        engine_queries: {
          crossref: String(baseCore).trim(),
          openalex: String(baseCore).trim(),
          wikidata: normalizeKoreanQuestion(baseCore),
          gdelt: String(baseCore).trim(),
          naver: [normalizeKoreanQuestion(baseCore)],
        },
      },
      {
        id: 2,
        text: t2,
        engine_queries: {
          crossref: String(baseCore).trim(),
          openalex: String(baseCore).trim(),
          wikidata: normalizeKoreanQuestion(baseCore),
          gdelt: String(baseCore).trim(),
          naver: [normalizeKoreanQuestion(baseCore)],
        },
      },
    ].filter((b) => b.text),
  };
}


    // ✅ 블록별 엔진 호출 → verify에 넣을 “블록+증거” 패키지 구성
    external.crossref = [];
    external.openalex = [];
    external.wikidata = [];
    external.gdelt = [];
    external.naver = [];

    const blocksForVerify = [];
const naverQueriesUsed = []; // ✅ 실제로 호출한 naver 쿼리 기록용(중복제거해서 로그에 저장)


    for (const b of qvfvPre.blocks || []) {
      const eq = b.engine_queries || {};
      const qCrossref = eq.crossref || qvfvPre.english_core || query;
      const qOpenalex = eq.openalex || qvfvPre.english_core || query;
      const qWikidata = eq.wikidata || qvfvPre.korean_core || query;
      const qGdelt = eq.gdelt || qvfvPre.english_core || query;

      let naverQueries = Array.isArray(eq.naver) ? eq.naver : [];
      naverQueries = naverQueries
        .map((q) => buildNaverAndQuery(q))
        .filter(Boolean)
        .slice(0, BLOCK_NAVER_MAX_QUERIES);

      if (!naverQueries.length) {
        naverQueries = [buildNaverAndQuery(qvfvPre.korean_core || query)].filter(Boolean);
      }

naverQueriesUsed.push(...naverQueries); // ✅ 이번 블록에서 실제 호출한 쿼리 저장


      const [crPack, oaPack, wdPack, gdPack] = await Promise.all([
        safeFetchTimed("crossref", fetchCrossref, qCrossref, engineTimes, engineMetrics),
        safeFetchTimed("openalex", fetchOpenAlex, qOpenalex, engineTimes, engineMetrics),
        safeFetchTimed("wikidata", fetchWikidata, qWikidata, engineTimes, engineMetrics),
        safeFetchTimed("gdelt", fetchGDELT, qGdelt, engineTimes, engineMetrics),
      ]);

      let naverItems = [];
      for (const nq of naverQueries) {
        const { result } = await safeFetchTimed(
          "naver",
          (qq) => callNaver(qq, naver_id, naver_secret),
          nq,
          engineTimes,
          engineMetrics
        );
        if (Array.isArray(result) && result.length) naverItems.push(...result);
      }
      naverItems = dedupeByLink(naverItems).slice(0, BLOCK_NAVER_MAX_ITEMS);

      external.crossref.push(...(crPack.result || []));
      external.openalex.push(...(oaPack.result || []));
      external.wikidata.push(...(wdPack.result || []));
      external.gdelt.push(...(gdPack.result || []));
      external.naver.push(...(naverItems || []));

      blocksForVerify.push({
        id: b.id,
        text: b.text,
        queries: { crossref: qCrossref, openalex: qOpenalex, wikidata: qWikidata, gdelt: qGdelt, naver: naverQueries },
        evidence: {
          crossref: crPack.result || [],
          openalex: oaPack.result || [],
          wikidata: wdPack.result || [],
          gdelt: gdPack.result || [],
          naver: naverItems || [],
        },
      });
    }

    external.naver = dedupeByLink(external.naver).slice(0, NAVER_MULTI_MAX_ITEMS);
    qvfvBlocksForVerifyFull = blocksForVerify;

// ✅ 실제 호출된 naver 쿼리 로그 저장(중복 제거)
partial_scores.engine_queries = partial_scores.engine_queries || {};
partial_scores.engine_queries.naver = [...new Set(
  (naverQueriesUsed || [])
    .map((q) => buildNaverAndQuery(q))
    .filter(Boolean)
)].slice(0, 12);


    partial_scores.blocks_for_verify = blocksForVerify.map((x) => ({
      id: x.id,
      text: String(x.text || "").slice(0, 400),
      queries: x.queries,
      evidence_counts: {
        crossref: (x.evidence?.crossref || []).length,
        openalex: (x.evidence?.openalex || []).length,
        wikidata: (x.evidence?.wikidata || []).length,
        gdelt: (x.evidence?.gdelt || []).length,
        naver: (x.evidence?.naver || []).length,
      },
    }));

    partial_scores.recency = calcRecencyScore(external.gdelt);

    // naver tier × type factor
    if (Array.isArray(external.naver) && external.naver.length > 0) {
      const weights = external.naver
        .map((item) => {
          const tw = (typeof item.tier_weight === "number" && Number.isFinite(item.tier_weight)) ? item.tier_weight : 1;
          const vw = (typeof item.type_weight === "number" && Number.isFinite(item.type_weight)) ? item.type_weight : 1;
          return tw * vw;
        })
        .filter((w) => Number.isFinite(w) && w > 0);

      if (weights.length > 0) {
        const avg = weights.reduce((s, v) => s + v, 0) / weights.length;
        partial_scores.naver_tier_factor = Math.max(0.9, Math.min(1.05, avg));
      }
    }

    break;
  }

  case "dv":
  case "cv": {
    engines.push("github");
    external.github = [];

    const answerText =
      (safeMode === "cv" && user_answer && user_answer.trim().length > 0)
        ? user_answer
        : query;

    // ✅ GitHub 쿼리 생성 (Gemini)
    const t_q = Date.now();
    const ghQueries = await buildGithubQueriesFromGemini(
      safeMode, query, answerText, gemini_key
    );
    const ms_q = Date.now() - t_q;
    recordTime(geminiTimes, "github_query_builder_ms", ms_q);
    recordMetric(geminiMetrics, "github_query_builder", ms_q);

    // ✅ GitHub 검색(최대 3쿼리)
    for (const q of (ghQueries || []).slice(0, 3)) {
      const { result } = await safeFetchTimed(
        "github",
        (qq) => fetchGitHub(qq, github_token),
        q,
        engineTimes,
        engineMetrics
      );
      if (Array.isArray(result) && result.length) external.github.push(...result);
    }

    external.github = (external.github || []).slice(0, 12);

    partial_scores.validity = calcValidityScore(external.github);
    partial_scores.github_queries = ghQueries;

    // ✅ consistency (Gemini Pro)
    const t_cons = Date.now();
    partial_scores.consistency = await calcConsistencyFromGemini(
      safeMode,
      query,
      answerText,
      external.github,
      gemini_key
    );
    const ms_cons = Date.now() - t_cons;
    recordTime(geminiTimes, "consistency_ms", ms_cons);
    recordMetric(geminiMetrics, "consistency", ms_cons);

    break;
  }

  case "lv": {
    engines.push("klaw");
    external.klaw = await fetchKLawAll(klaw_key, query);

    let lvSummary = null;
    if (gemini_key) {
      const prompt = `
너는 대한민국 항공·교통 법령 및 판례를 요약해주는 엔진이다.
[사용자 질의]
${query}

[아래는 K-Law API에서 가져온 JSON 응답이다.]
이 JSON 안에 포함된 관련 법령·판례를 확인하고 질의에 답하는 데 중요한 내용만 요약해라.

- 한국어로 3~7개의 bullet
- 법령/조문 또는 사건명 + 핵심(의무/금지/절차) + UAM 연관성
- 서론/결론 금지

[K-Law JSON]
${JSON.stringify(external.klaw).slice(0, 6000)}
      `.trim();

      try {
        const t_lv = Date.now();
        lvSummary = await fetchGemini(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=${gemini_key}`,
          { contents: [{ parts: [{ text: prompt }] }] }
        );
        const ms_lv = Date.now() - t_lv;
        recordTime(geminiTimes, "lv_flash_lite_summary_ms", ms_lv);
        recordMetric(geminiMetrics, "lv_flash_lite_summary", ms_lv);
      } catch (e) {
        if (DEBUG) console.warn("⚠️ LV Flash-Lite summary fail:", e.message);
        lvSummary = null;
      }
    }

    partial_scores.lv_summary = lvSummary || null;
    break;
  }

  default: {
    // 여기까지 오면 allowedModes 검증에서 이미 걸러짐
    break;
  }
}


partial_scores.engine_times = engineTimes;
partial_scores.engine_metrics = engineMetrics;
partial_scores.gemini_times = geminiTimes;
partial_scores.gemini_metrics = geminiMetrics;


    // ─────────────────────────────
    // ② LV 모드는 TruthScore/가중치 계산 없이 바로 반환
    // ─────────────────────────────
   if (safeMode === "lv") {
  const elapsed = Date.now() - start;

// ✅ LV도 Gemini 총합(ms) 계산 (Flash-Lite 요약 등 포함)
partial_scores.gemini_total_ms = Object.values(geminiTimes)
  .filter((v) => typeof v === "number" && Number.isFinite(v))
  .reduce((s, v) => s + v, 0);

// sources(text)에 서버 메타/부분점수 등을 JSON으로 저장(필요한 만큼만)
const sourcesText = safeSourcesForDB(
  {
    meta: { mode: safeMode },
    external,
    partial_scores,
  },
  20000
);

await supabase.from("verification_logs").insert([
  {
    user_id: logUserId,
    question: query,          // ✅ 대표 질문
    query: query,             // ✅ (스키마에 있으니 같이)
    truth_score: null,        // ✅ LV는 TruthScore 없음
    summary: partial_scores.lv_summary || null,
    cross_score: null,
    adjusted_score: null,
    status: safeMode,         // ✅ mode 컬럼이 없으니 status에 mode 저장
    engines,                  // ✅ jsonb (stringify 금지)
    keywords: null,           // ✅ 필요하면 배열 넣기
    elapsed: String(elapsed), // ✅ text 컬럼
    model_main: partial_scores.lv_summary ? "gemini-2.5-flash-lite" : null,
    model_eval: null,
    sources: sourcesText,
    gemini_model: null,
    error: null,
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
    //   - QV/FV: 전처리에서 이미 답변/블록 생성 → 여기서는 검증(verify)만 수행
    //   - DV/CV: external을 포함한 요약(flash) + 검증(verify)
    // ─────────────────────────────
let flash = "";
let verify = "";
let verifyMeta = null;

// ✅ 여기서는 "선언(let)" 하지 말고, 필요하면 값만 리셋
verifyModelUsed = verifyModel;

// flash(답변/요약) 단계에서 실제 사용한 모델을 로그에 남기기 위함
let answerModelUsed = "gemini-2.5-flash";

    if (safeMode === "qv" || safeMode === "fv") {
      // QV/FV는 gemini_model 토글을 그대로 사용
      answerModelUsed =
        geminiModelRaw === "flash" ? "gemini-2.5-flash" : "gemini-2.5-pro";
    }

    try {
      // 4-1) Flash 단계
      if (safeMode === "qv") {
  flash = (partial_scores.qv_answer || "").toString();

  // 전처리 실패 시: 여기서라도 답변 생성
  if (!flash.trim()) {
    const flashPrompt = `[QV] ${query}\n한국어로 6~10문장으로 답변만 작성하세요.`;
    const t_flash = Date.now();
    flash = await fetchGemini(
      `https://generativelanguage.googleapis.com/v1beta/models/${answerModelUsed}:generateContent?key=${gemini_key}`,
      { contents: [{ parts: [{ text: flashPrompt }] }] }
    );
    const ms_flash = Date.now() - t_flash;
    recordTime(geminiTimes, "flash_ms", ms_flash);
    recordMetric(geminiMetrics, "flash", ms_flash);
  }
}
 else if (safeMode === "fv") {
        // ✅ FV: 검증 대상은 사용자가 준 사실 문장(core_text)이므로 별도 flash 불필요
        flash = "";
      } else {
        // ✅ DV/CV: external을 포함한 1차 요약/설명 생성 (기존 로직 유지)
        const flashPrompt =
          `[${safeMode.toUpperCase()}] ${query}\n` +
          `참조자료:\n${JSON.stringify(external).slice(0, FLASH_REF_CHARS)}`;

        const t_flash = Date.now();
        flash = await fetchGemini(
          `https://generativelanguage.googleapis.com/v1beta/models/${answerModelUsed}:generateContent?key=${gemini_key}`,
          { contents: [{ parts: [{ text: flashPrompt }] }] }
        );
        const ms_flash = Date.now() - t_flash;
        recordTime(geminiTimes, "flash_ms", ms_flash);
        recordMetric(geminiMetrics, "flash", ms_flash);
      }

      // 4-2) verify 입력 패키지 구성
      const blocksForVerify =
        (safeMode === "qv" || safeMode === "fv") &&
        Array.isArray(qvfvBlocksForVerifyFull)
          ? qvfvBlocksForVerifyFull
          : [];

      const coreText =
        safeMode === "qv"
          ? flash && flash.trim().length > 0
            ? flash
            : qvfvPre?.korean_core || query
          : safeMode === "fv"
          ? userCoreText || query
          : safeMode === "cv" && user_answer && user_answer.trim().length > 0
          ? user_answer
          : query;

      const verifyInput = {
        mode: safeMode,
        query,
        core_text: coreText,
        blocks: blocksForVerify, // ✅ QV/FV: 전처리 블록 + 증거
        external,
        partial_scores,
      };

      const verifyPrompt = `
당신은 "Cross-Verified AI" 시스템의 메타 검증 엔진입니다.

목표:
- 하나의 요청으로 아래 작업을 모두 수행합니다.
  1) (필요한 경우에만) core_text를 의미 단위 블록으로 나누기
  2) 각 블록을 외부 검증엔진 결과 및 blocks[i].evidence와 비교하여 부분 TruthScore(0~1) 계산
  3) 전체 문장/코드에 대한 종합 TruthScore(0~1 구간, raw) 계산
  4) 각 검증엔진별로 이번 질의에 대한 국소 보정값(0.9~1.1) 제안

[입력 JSON]
${JSON.stringify(verifyInput).slice(0, VERIFY_INPUT_CHARS)}

입력 필드 설명(요약):
- mode: "qv" | "fv" | "dv" | "cv" 중 하나
- query: 사용자가 입력한 질문 또는 사실 문장
- core_text:
    - QV: Gemini가 생성한 "답변" (검증 대상)
    - FV: 사용자가 입력한 "사실 문장" (검증 대상)
    - DV: "어떤 개발 과제를 하려는지"에 대한 설명
    - CV: 실제 검증 대상 코드/설계 또는 요약
- blocks:
    - QV/FV: 전처리 단계에서 이미 생성된 의미 블록 배열
      (각 요소는 id, text, queries, evidence(crossref/openalex/wikidata/gdelt/naver) 를 포함)
    - DV/CV: 서버에서 비워둘 수 있음([])
- external: crossref / openalex / wikidata / gdelt / naver / github / klaw 등 외부 엔진 결과
- partial_scores: 서버에서 미리 계산된 전역 스코어
    (예: recency, validity, consistency, engine_factor, naver_tier_factor 등)

[작업 지침]

1. 블록 사용 규칙
   - blocks 배열이 "비어있지 않은 경우"(QV/FV):
     - blocks[i]를 그대로 사용하고, 절대 재분해/병합/삭제하지 마세요.
     - 각 blocks[i].text가 이미 의미 단위로 분리된 상태입니다.
     - 각 blocks[i].evidence 안의 엔진별 결과를 근거로 block_truthscore를 계산하세요.
   - blocks 배열이 "비어있는 경우"(주로 DV/CV):
     - core_text를 의미적으로 자연스러운 2~8개 블록으로 직접 분할해도 좋습니다.
     - 이때 evidence는 external 전체를 참고하여 간접적으로 판단합니다.

2. 블록별 TruthScore(block_truthscore, 0~1)
   - 각 블록에 대해 외부 증거와 비교하여 0~1 사이 점수를 매기십시오.
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
     truthscore = overall_truthscore_raw
     와 같이 0~1 범위 그대로 사용합니다.
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
`.trim();

      // ✅ verify는 모델 실패/빈문자 발생이 있어서 fallback 시도
const verifyPayload = { contents: [{ parts: [{ text: verifyPrompt }] }] };

// 1순위: verifyModel, 2순위: flash, 3순위: flash-lite
const verifyModelCandidates = [
  verifyModel,
  "gemini-2.5-flash",
  "gemini-2.5-flash-lite",
].filter((v, i, a) => v && a.indexOf(v) === i);

let lastVerifyErr = null;

const t_verify = Date.now();
try {
  for (const m of verifyModelCandidates) {
    try {
      verify = await fetchGemini(
        `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${gemini_key}`,
        verifyPayload,
        { label: `verify:${m}`, minChars: 20 } // ✅ 너무 짧은 텍스트(빈문자)도 실패로 처리
      );
      verifyModelUsed = m; // ✅ 실제 성공 모델 기록
      break;
    } catch (e) {
      const status = e?.response?.status;
// ✅ NAVER 인증 오류는 여기서도 401로 매핑 (외부엔진 수집 단계에서 터지는 케이스)
if (e?.code === "NAVER_AUTH_ERROR") {
  return res
    .status(e.httpStatus || 401)
    .json(
      buildError(
        "NAVER_AUTH_ERROR",
        "Naver client id / secret 인증에 실패했습니다. (올바른 키인지 확인하세요)",
        e.detail || e.message
      )
    );
}
      if (status === 429) throw e; // ✅ 쿼터 소진은 즉시 상위로
      lastVerifyErr = e;
      // 다음 후보 모델로 계속 진행
    }
  }
} finally {
  const ms_verify = Date.now() - t_verify;
  recordTime(geminiTimes, "verify_ms", ms_verify);
  recordMetric(geminiMetrics, "verify", ms_verify);
}

// ✅ 끝까지 실패했으면 기존 정책대로: verifyMeta 없이 외부엔진 기반으로만 진행
if (!verify || !verify.trim()) {
  verifyMeta = null;
  if (DEBUG) console.warn("⚠️ verify failed on all models:", lastVerifyErr?.message || "unknown");
} else {
  // ✅ Pro 결과(JSON) 파싱 시도
  try {
    const trimmed = (verify || "").trim();
    const jsonMatch = trimmed.match(/\{[\s\S]*\}/);
    const jsonText = jsonMatch ? jsonMatch[0] : trimmed;
    verifyMeta = JSON.parse(jsonText);
  } catch {
    verifyMeta = null;
    if (DEBUG) console.warn("⚠️ verifyMeta JSON parse fail");
  }
}
    } catch (e) {
      const status = e.response?.status;
// ✅ NAVER 인증 오류는 401로 즉시 반환
if (e?.code === "NAVER_AUTH_ERROR") {
  return res
    .status(e.httpStatus || 401)
    .json(
      buildError(
        "NAVER_AUTH_ERROR",
        "Naver client id / secret 인증에 실패했습니다. (올바른 키인지 확인하세요)",
        e.detail || e.message
      )
    );
}

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
    truthscore = hybrid; // 0~1

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
    const adjRaw =
      typeof perEngineAdjust?.[eName] === "number" &&
      Number.isFinite(perEngineAdjust[eName])
        ? perEngineAdjust[eName]
        : 1.0;

    // ✅ 명세 범위(0.9~1.1)로 제한
    const adj = Math.max(0.9, Math.min(1.1, adjRaw));

    // ✅ truth는 0~1로 고정 (0.97*1.1 같은 케이스 방지)
    const engineTruth = Math.max(0, Math.min(1, hybrid * adj));

    // per-engine 응답시간이 있으면 사용, 없으면 전체 elapsed 사용
    const engineMs =
      typeof engineTimes[eName] === "number" && engineTimes[eName] > 0
        ? engineTimes[eName]
        : elapsed;

    return updateWeight(eName, engineTruth, engineMs);
  })
);

// ✅ Gemini 총합(ms) — 모든 Gemini 단계 완료 후 계산
partial_scores.gemini_total_ms = Object.values(geminiTimes)
  .filter((v) => typeof v === "number" && Number.isFinite(v))
  .reduce((s, v) => s + v, 0);

const STORE_GEMINI_TEXT = process.env.STORE_GEMINI_TEXT === "true";

// 길이/메타만 남기기(가볍고 유용)
partial_scores.flash_len = (flash || "").length;
partial_scores.verify_len = (verify || "").length;

// 원문 저장은 옵션
if (STORE_GEMINI_TEXT) {
  partial_scores.flash_text = maybeTruncateText(flash);
  partial_scores.verify_text = maybeTruncateText(verify);
}

    // 요약(summary) 필드: Pro 메타 요약 우선, 없으면 flash 일부라도
const summaryText =
  (verifyMeta && typeof verifyMeta.overall?.summary === "string" && verifyMeta.overall.summary.trim())
    ? verifyMeta.overall.summary.trim()
    : (flash || "").slice(0, 2000) || null;

// keywords는 선택: QV/FV는 naverQuery 토큰, DV/CV는 github_queries 등
const keywordsForLog =
  (safeMode === "dv" || safeMode === "cv")
    ? (Array.isArray(partial_scores.github_queries) ? partial_scores.github_queries.slice(0, 12) : null)
    : (safeMode === "qv" || safeMode === "fv")
     ? (() => {
    const nq = partial_scores.engine_queries?.naver;
    const txt = Array.isArray(nq) ? nq.join(" ") : String(nq || query);
    return txt;
  })()
          .replace(/\+/g, "")
          .split(/\s+/)
          .filter(Boolean)
          .slice(0, 12)
      : null;

const sourcesText = safeSourcesForDB(
  {
    meta: { mode: safeMode },
    external,
    partial_scores,
    verify_meta: verifyMeta || null,
  },
  20000
);

await supabase.from("verification_logs").insert([
  {
    user_id: logUserId,
    question: query,
    query: query,

    truth_score: Number(truthscore),     // ✅ double precision
    summary: summaryText,

    cross_score: Number(G),              // ✅ raw(0~1)
    adjusted_score: Number(hybrid),      // ✅ adjusted(0~1)

    status: safeMode,                    // ✅ mode 컬럼 없으니 여기 저장
    engines,                             // ✅ jsonb
    keywords: keywordsForLog,            // ✅ array(text[])
    elapsed: String(elapsed),            // ✅ text

    model_main: answerModelUsed,  // ✅ QV/FV 토글 반영 (또는 기본 flash)
model_eval: verifyModelUsed,  // ✅ 실제 성공한 verify 모델
sources: sourcesText,

gemini_model: verifyModelUsed, // ✅ 실제 성공한 verify 모델
error: null,
created_at: new Date(),
  },
]);

// ─────────────────────────────
// ⑦ 결과 반환 (ⅩⅤ 규약 형태로 래핑)
// ─────────────────────────────
const truthscore_pct = Math.round(truthscore * 10000) / 100; // 2 decimals
const truthscore_text = `${truthscore_pct.toFixed(2)}%`;

// ✅ normalizedPartial이 따로 없으니 일단 동일하게 사용
const normalizedPartial = partial_scores;

const payload = {
  mode: safeMode,
  truthscore: truthscore_text,
  truthscore_pct,
  truthscore_01: Number(truthscore.toFixed(4)),
  elapsed,
  engines,
  partial_scores: normalizedPartial,
  flash_summary: flash,
  verify_raw: verify,
  gemini_verify_model: verifyModelUsed, // ✅ 실제로 성공한 모델
  engine_times: engineTimes,
  engine_metrics: engineMetrics,
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

  try {
    const fallbackUserId = logUserId || process.env.DEFAULT_USER_ID;
    if (fallbackUserId) {
      await supabase.from("verification_logs").insert([
  {
    user_id: logUserId || process.env.DEFAULT_USER_ID, // logUserId 없으면 DEFAULT 필요
    question: query || null,
    query: query || null,

    truth_score: null,
    summary: null,
    cross_score: null,
    adjusted_score: null,

    status: safeMode || null,
    engines: engines || null,
    keywords: null,
    elapsed: null,

    model_main: "gemini-2.5-flash",
    model_eval: verifyModelUsed || verifyModel || null,
    sources: null,

    gemini_model: verifyModelUsed || verifyModel || null,
    error: e.message,
    created_at: new Date(),
  },
]);
 }
  } catch (logErr) {
    console.error("❌ verification_logs insert failed:", logErr.message);
  }

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

    // ✅ 최근 요청(verification_logs)에서 engine_metrics 읽기
    const { data: recentLogsRaw, error: logsErr } = await supabase
  .from("verification_logs")
  .select("created_at, question, truth_score, cross_score, adjusted_score, status, engines, keywords, elapsed, model_main, model_eval, sources, gemini_model, error")
  .order("created_at", { ascending: false })
  .limit(10);

const recentLogs = (recentLogsRaw || []).map((r) => {
  let src = r.sources;
  if (typeof src === "string") {
    try { src = JSON.parse(src); } catch { src = {}; }
  }
  if (!src || typeof src !== "object") src = {};

  const ps = (src && typeof src.partial_scores === "object") ? src.partial_scores : {};

  // (기존 EJS 호환용으로 query/mode 같은 키를 억지로 만들어 주고 싶으면)
  return {
    ...r,
    query: r.question,              // ✅ 기존 template이 r.query를 쓰면 깨져서
    mode: r.status,                // ✅ 기존 template이 r.mode를 쓰면 깨져서
    partial_scores_obj: ps,         // ✅ 기존 로직 유지
    sources_obj: src,
  };
});

    const lastRequest = recentLogs[0] || null;
    const em = lastRequest?.partial_scores_obj?.engine_metrics || {};
    const et = lastRequest?.partial_scores_obj?.engine_times || {};
const gm = lastRequest?.partial_scores_obj?.gemini_metrics || {};
const gt = lastRequest?.partial_scores_obj?.gemini_times || {};

    const lastEngineMetricsRows = Object.entries(em).map(([engine, m]) => ({
      engine,
      calls: m?.calls ?? 0,
      ms_total: m?.ms_total ?? 0,
      ms_avg: m?.ms_avg ?? null,
      ms_last: m?.ms_last ?? null,
    }));

    const lastEngineTimesRows = Object.entries(et).map(([engine, ms]) => ({
      engine,
      ms,
    }));

   return res.render("admin-dashboard", {
      user: req.user || null,
      region: REGION,
      httpTimeoutMs: HTTP_TIMEOUT_MS,
      engineStats: engineStats || [],
      whitelistSummary,
      baseWeights: ENGINE_BASE_WEIGHTS,

      // ✅ 추가
      recentLogs,
      lastRequest,

      // ✅ EJS에서 쓰는 원본 객체(네가 만든 EJS 기준)
      lastEngineMetrics: em,
      lastEngineTimes: et,
 
 lastGeminiMetrics: gm,
  lastGeminiTimes: gt,

      // (선택) rows가 필요하면 유지
      lastEngineMetricsRows,
      lastEngineTimesRows,
    });
  } catch (e) {
    console.error("❌ /admin/ui Error:", e.message);
    return res.status(500).send("Admin UI error");
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
    .send("OK - Cross-Verified AI Proxy v18.4.0-pre (root health check)");
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
