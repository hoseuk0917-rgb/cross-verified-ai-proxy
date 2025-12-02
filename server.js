// =======================================================
// Cross-Verified AI Proxy — v18.4.0-pre
// (Full Extended + LV External Module + Translation + Naver Region Detection)
// =======================================================

process.on("unhandledRejection", (r) => {
  const msg = r?.message || String(r);
  console.error("⚠️ Unhandled:", msg);
  if (!isProd && r?.stack) console.error(r.stack);
});

process.on("uncaughtException", (e) => {
  const msg = e?.message || String(e);
  console.error("💥 Crash:", msg);
  if (!isProd && e?.stack) console.error(e.stack);
});

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
import crypto from "crypto";              // ✅ ADD: 암호화/키ID/UUID
import "express-async-errors";

// ✅ LV (법령검증) 모듈 외부화
import { fetchKLawAll } from "./src/modules/klaw_module.js";

// ✅ 번역모듈 (DeepL + Gemini Flash-Lite fallback)
import { translateText } from "./src/modules/translateText.js";

// ─────────────────────────────
// ✅ Timeout / retry / timebox utils
// ─────────────────────────────
const HTTP_TIMEOUT_MS = parseInt(process.env.HTTP_TIMEOUT_MS || "12000", 10);
const ENGINE_TIMEBOX_MS = parseInt(process.env.ENGINE_TIMEBOX_MS || "25000", 10); // 엔진 1개 상한
const GEMINI_TIMEOUT_MS = parseInt(process.env.GEMINI_TIMEOUT_MS || "45000", 10); // Gemini는 더 길게

const ENGINE_RETRY_MAX = parseInt(process.env.ENGINE_RETRY_MAX || "1", 10); // 0~1 권장
const ENGINE_RETRY_BASE_MS = parseInt(process.env.ENGINE_RETRY_BASE_MS || "350", 10);

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function withTimebox(promiseFactory, ms, label = "timebox") {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);

  try {
    // promiseFactory는 ({signal})을 받아서 axios/fetch에 signal을 넘길 수 있어야 함
    return await promiseFactory({ signal: ctrl.signal });
  } catch (e) {
    // ✅ Node/axios 취소 케이스까지 TIMEBOX_TIMEOUT으로 통일
    const isAbort =
      e?.name === "AbortError" ||
      e?.name === "CanceledError" ||
      e?.code === "ERR_CANCELED" ||
      /aborted|canceled|cancelled/i.test(String(e?.message || ""));

    if (isAbort) {
      const err = new Error(`${label} timeout (${ms}ms)`);
      err.code = "TIMEBOX_TIMEOUT";
      throw err;
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// 재시도: 네트워크/5xx/타임아웃류만 제한적으로
function isRetryable(err) {
  const code = String(err?.code || "");
  const msg = String(err?.message || "");
  const status = err?.response?.status;

  if (code.includes("TIMEOUT") || code === "ECONNABORTED") return true;
  if (msg.includes("timeout")) return true;
  if (status && status >= 500) return true; // 5xx
  if (code === "ENOTFOUND" || code === "ECONNRESET" || code === "EAI_AGAIN") return true;
  return false;
}

async function withRetry(fn, { maxRetries, baseMs, label }) {
  let attempt = 0;
  let lastErr = null;

  while (attempt <= maxRetries) {
    try {
      return await fn(attempt);
    } catch (e) {
      lastErr = e;
      if (attempt >= maxRetries || !isRetryable(e)) break;

      const backoff = baseMs * Math.pow(2, attempt);
      console.warn(`⚠️ retryable error in ${label} (attempt=${attempt + 1}/${maxRetries + 1}):`, e?.message || e);
      await sleep(backoff);
      attempt++;
    }
  }
  throw lastErr;
}

dotenv.config();

const isProd = process.env.NODE_ENV === "production";

// ─────────────────────────────
// ✅ LOG REDACTION (PROD safe)
// ─────────────────────────────
const LOG_REDACT = String(process.env.LOG_REDACT || (isProd ? "1" : "0")) === "1";
const LOG_REDACT_MAX_STR = parseInt(process.env.LOG_REDACT_MAX_STR || "6000", 10);

const SENSITIVE_KEY_RE =
  /(authorization|cookie|set-cookie|x-admin-token|x-api-key|api[-_]?key|secret|token|password|session|gemini|openai|naver|supabase|service[_-]?key|client_secret|refresh_token|access_token)/i;

function maskToken(t) {
  const s = String(t || "");
  if (s.length <= 10) return "***";
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

function redactText(input) {
  let s = String(input ?? "");
  if (!s) return s;

  // 너무 긴 로그는 잘라서 메모리/노이즈 방지
  if (s.length > LOG_REDACT_MAX_STR) s = s.slice(0, LOG_REDACT_MAX_STR) + "…(truncated)";

  // Bearer 토큰
  s = s.replace(/Bearer\s+([A-Za-z0-9\-._~+/]+=*)/gi, (_, t) => `Bearer ${maskToken(t)}`);

  // Google API key (AIza…)
  s = s.replace(/AIza[0-9A-Za-z\-_]{20,}/g, (m) => maskToken(m));

  // OpenAI 스타일 sk- 키(혹시 있을 때)
  s = s.replace(/\bsk-[A-Za-z0-9]{10,}\b/g, (m) => maskToken(m));

  // query/body 형태 key=... / token=... / secret=...
  s = s.replace(
    /\b(key|api_key|apikey|token|secret|password|session|naver_secret|gemini_key|supabase_service_key)\b\s*=\s*([^\s&]+)/gi,
    (_, k, v) => `${k}=${maskToken(v)}`
  );

  // JSON "key":"value"
  s = s.replace(
    /"((?:api[_-]?key|token|secret|password|authorization|cookie|gemini[_-]?key|naver[_-]?secret|supabase[_-]?service[_-]?key))"\s*:\s*"([^"]+)"/gi,
    (_, k, v) => `"${k}":"${maskToken(v)}"`
  );

  return s;
}

function redactAny(x, depth = 0) {
  if (!LOG_REDACT) return x;
  if (x == null) return x;

  if (typeof x === "string") return redactText(x);

  if (x instanceof Error) {
    // 에러는 stack/message에 민감정보 섞이는 경우가 있어서 문자열로 안전하게 출력
    const msg = redactText(x.message || "");
    const st = redactText(x.stack || "");
    return `${x.name}: ${msg}${st ? `\n${st}` : ""}`;
  }

  if (typeof x !== "object") return x;

  if (depth >= 4) return "[Object]";

  if (Array.isArray(x)) return x.slice(0, 50).map((v) => redactAny(v, depth + 1));

  const out = {};
  const keys = Object.keys(x).slice(0, 80);
  for (const k of keys) {
    if (SENSITIVE_KEY_RE.test(k)) out[k] = "***";
    else out[k] = redactAny(x[k], depth + 1);
  }
  return out;
}

function installConsoleRedactor() {
  if (!LOG_REDACT) return;

  const wrap = (fn) => (...args) => fn(...args.map((a) => redactAny(a)));
  console.log = wrap(console.log.bind(console));
  console.info = wrap(console.info.bind(console));
  console.warn = wrap(console.warn.bind(console));
  console.error = wrap(console.error.bind(console));
  console.debug = wrap(console.debug.bind(console));

  console.log("✅ LOG_REDACT enabled");
}

installConsoleRedactor();

const DEBUG = !isProd && process.env.DEBUG === "true";

// ✅ ADD: Secrets 암호화(서버 마스터키) + Pacific 리셋 TZ
const SETTINGS_ENC_KEY_B64 = (process.env.SETTINGS_ENC_KEY_B64 || "").trim(); // base64(32bytes)
const GEMINI_RESET_TZ = process.env.GEMINI_RESET_TZ || "America/Los_Angeles"; // 태평양 시간(PT)
const PACIFIC_INFO_TTL_MS = parseInt(process.env.PACIFIC_INFO_TTL_MS || "300000", 10); // 5분 캐시
const GEMINI_KEYRING_MAX = parseInt(process.env.GEMINI_KEYRING_MAX || "10", 10);

const app = express();

app.disable("x-powered-by");

// ✅ 기본 노출 최소화
app.disable("x-powered-by");

// trust proxy는 세션보다 위에서, 운영일 때만
if (isProd) app.set("trust proxy", 1);


const PORT = parseInt(process.env.PORT || "10000", 10);
const REGION =
  process.env.RENDER_REGION ||
  process.env.FLY_REGION ||
  process.env.AWS_REGION ||
  process.env.REGION ||
  "unknown";

function pickDatabaseUrl() {
  const candidates = [
    ["SUPABASE_DATABASE_URL", process.env.SUPABASE_DATABASE_URL],
    ["DATABASE_URL", process.env.DATABASE_URL],
    ["DATABASE_URL_INTERNAL", process.env.DATABASE_URL_INTERNAL],
  ];

  const found = candidates.find(([, v]) => String(v ?? "").trim().length > 0);
  const source = found?.[0] || "";
  const raw = found?.[1] || "";
  const u = String(raw).trim();

  if (!u) {
    throw new Error("No database URL provided. Set SUPABASE_DATABASE_URL (recommended) or DATABASE_URL.");
  }

  if (!/^postgres(ql)?:\/\//i.test(u)) {
    throw new Error(`${source || "DATABASE_URL"} must start with postgres:// or postgresql://`);
  }
  if (/^postgres(ql)?:\/\/https?:\/\//i.test(u)) {
    throw new Error(`${source || "DATABASE_URL"} is malformed (contains https:// after protocol)`);
  }
  if (u.includes("onrender.com")) {
    throw new Error(`${source || "DATABASE_URL"} must be a Postgres URL (Supabase), not a Render app URL`);
  }

  // ✅ Render Postgres 호스트 차단 (dpg-xxx...render.com 등)
  try {
    const host = new URL(u).hostname || "";
    if (host.includes("render.com") || host.includes("postgres.render.com")) {
      throw new Error(`${source || "DATABASE_URL"} points to Render Postgres. Use SUPABASE_DATABASE_URL instead.`);
    }
  } catch {}

  return { url: u, source };
}

const { url: DB_URL, source: DB_URL_SOURCE } = pickDatabaseUrl();

// ✅ 부팅 로그(비밀값 노출 없이: host만)
try {
  const host = new URL(DB_URL).hostname || "unknown";
  if (!isProd) {
    console.log(`✅ DB URL selected via ${DB_URL_SOURCE || "DATABASE_URL"} (host=${host})`);
  } else {
    console.log(`✅ DB URL selected via ${DB_URL_SOURCE || "DATABASE_URL"}`);
  }
} catch {
  console.log(`✅ DB URL selected via ${DB_URL_SOURCE || "DATABASE_URL"}`);
}

// ✅ 여기서 먼저 풀/스토어 준비
const useSsl =
  process.env.PGSSL === "false"
    ? false
    : { rejectUnauthorized: false }; // Supabase/Pooler면 로컬도 SSL 필요한 경우 많음

const pgPool = new pg.Pool({
  connectionString: DB_URL,
  ssl: useSsl,
  max: parseInt(process.env.PGPOOL_MAX || "5", 10),
  idleTimeoutMillis: parseInt(process.env.PGPOOL_IDLE_MS || "10000", 10),
  connectionTimeoutMillis: parseInt(process.env.PGPOOL_CONN_MS || "10000", 10),
  keepAlive: true,
});


// ✅ 중요: Pool 'error' 이벤트 핸들러 없으면 프로세스가 죽을 수 있음
pgPool.on("error", (err) => {
  console.error("⚠️ PG POOL ERROR (idle client):", err.code || "", err.message);
});

const PgStore = connectPgSimple(session);
const sessionStore = new PgStore({
  pool: pgPool,
  schemaName: "public",
  tableName: "session_store",
  createTableIfMissing: !isProd,     // ✅ DEV에서는 자동생성 허용, PROD는 고정
  pruneSessionInterval: 60 * 10,
});

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
    store: sessionStore,

    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,

    cookie: {
      httpOnly: true,
      maxAge: (parseInt(process.env.SESSION_TTL_DAYS || "14", 10) * 24 * 60 * 60 * 1000),
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

// 🔹 Gemini 전용 타임아웃 (ms) — 외부엔진(HTTP_TIMEOUT_MS)과 분리
// - Pro는 오래 걸릴 수 있어 기본을 더 길게
// - verify 단계는 입력이 커서 더 길게
const GEMINI_TIMEOUT_PRO_MS = parseInt(
  process.env.GEMINI_TIMEOUT_PRO_MS || process.env.GEMINI_TIMEOUT_MS || "70000",
  10
);

const GEMINI_TIMEOUT_FLASH_MS = parseInt(
  process.env.GEMINI_TIMEOUT_FLASH_MS || process.env.GEMINI_TIMEOUT_MS || "35000",
  10
);

const GEMINI_TIMEOUT_FLASH_LITE_MS = parseInt(
  process.env.GEMINI_TIMEOUT_FLASH_LITE_MS || process.env.GEMINI_TIMEOUT_MS || "30000",
  10
);

const GEMINI_TIMEOUT_VERIFY_PRO_MS = parseInt(
  process.env.GEMINI_TIMEOUT_VERIFY_PRO_MS || "90000",
  10
);

const GEMINI_TIMEOUT_VERIFY_FLASH_MS = parseInt(
  process.env.GEMINI_TIMEOUT_VERIFY_FLASH_MS || "45000",
  10
);

const GEMINI_TIMEOUT_VERIFY_FLASH_LITE_MS = parseInt(
  process.env.GEMINI_TIMEOUT_VERIFY_FLASH_LITE_MS || "35000",
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

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // curl/서버-서버
    if (CORS_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, false); // 에러 던지지 않음(불필요한 500 방지)
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Admin-Token"],
  exposedHeaders: ["Retry-After"],
  maxAge: 86400,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ─────────────────────────────
// ✅ Safe request logging (morgan)
// ─────────────────────────────
function redactUrl(u) {
  const s = String(u || "");
  const idx = s.indexOf("?");
  if (idx < 0) return s;
  const base = s.slice(0, idx);
  const qs = s.slice(idx + 1);

  // token/key/secret 류 쿼리값만 마스킹
  const masked = qs.replace(
    /(^|&)(token|key|api_key|apikey|secret|password|session|auth)=([^&]*)/gi,
    (_, p, k, v) => `${p}${k}=${maskToken(v)}`
  );
  return `${base}?${masked}`;
}

// ✅ Safe request logging (morgan)
morgan.token("safe-url", (req) => redactUrl(req.originalUrl || req.url));
morgan.token("user", (req) => (req.user?.email || req.user?.id || req.user?.sub || "-"));

// ✅ morgan middleware mount (single)
const MORGAN_ENABLED = String(process.env.MORGAN_ENABLED || "true").toLowerCase() !== "false";

if (MORGAN_ENABLED) {
  console.log(`✅ Morgan enabled (NODE_ENV=${process.env.NODE_ENV || "unknown"})`);
  app.use(
    morgan(":remote-addr :user :method :safe-url :status :res[content-length] - :response-time ms", {
      // Render 로그에 확실히 남게 console.log로 강제
      stream: { write: (msg) => console.log(msg.trimEnd()) },
      skip: (req) => {
      const p = req.originalUrl || req.url || "";
      if (p.startsWith("/health")) return true;
       // ✅ 디버깅 중에는 test-db도 로그 보이게 (필요하면 다시 true로)
       // if (p.startsWith("/api/test-db")) return true;
       return false;
      },
    })
  );
}

// ─────────────────────────────
// ✅ (추가) CORS 에러를 JSON으로 정리해서 반환
//   - cors가 next(err)를 호출하면, "바로 다음" 에러핸들러가 잡음
// ─────────────────────────────
app.use((err, req, res, next) => {
  if (err && err.message === "CORS_NOT_ALLOWED") {
    return res.status(403).json(
      buildError(
        "CORS_NOT_ALLOWED",
        "허용되지 않은 Origin입니다.",
        { origin: req.headers?.origin || null }
      )
    );
  }
  return next(err);
});

const BODY_JSON_LIMIT = process.env.BODY_JSON_LIMIT || "4mb";
const BODY_URLENC_LIMIT = process.env.BODY_URLENC_LIMIT || BODY_JSON_LIMIT;

app.use(express.json({ limit: BODY_JSON_LIMIT }));
app.use(express.urlencoded({ extended: true, limit: BODY_URLENC_LIMIT }));

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

// ─────────────────────────────
// ✅ Basic rate-limit + payload guards (no deps)
// ─────────────────────────────
const VERIFY_RATE_LIMIT_PER_MIN = parseInt(
  process.env.VERIFY_RATE_LIMIT_PER_MIN || (isProd ? "30" : "300"),
  10
);
const VERIFY_RATE_LIMIT_WINDOW_MS = parseInt(
  process.env.VERIFY_RATE_LIMIT_WINDOW_MS || "60000",
  10
);

const VERIFY_MAX_QUERY_CHARS = parseInt(process.env.VERIFY_MAX_QUERY_CHARS || "2000", 10);
const VERIFY_MAX_CORE_TEXT_CHARS = parseInt(process.env.VERIFY_MAX_CORE_TEXT_CHARS || "4000", 10);
const VERIFY_MAX_USER_ANSWER_CHARS = parseInt(process.env.VERIFY_MAX_USER_ANSWER_CHARS || "8000", 10);

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return String(xf).split(",")[0].trim();
  return req.ip || req.socket?.remoteAddress || "unknown";
}

function hash16(s) {
  try {
    return crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 16);
  } catch {
    return "";
  }
}

function makeFixedWindowLimiter({ windowMs, max, keyFn, name }) {
  const hits = new Map();
  const cleanupMs = Math.max(windowMs, 60_000);

  const t = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits.entries()) {
      if (!v || now > v.resetAt + windowMs) hits.delete(k);
    }
  }, cleanupMs);
  if (t && typeof t.unref === "function") t.unref();

  return (req, res, next) => {
    if (!Number.isFinite(max) || max <= 0) return next();

    const key = keyFn(req);
    const now = Date.now();
    let rec = hits.get(key);

    if (!rec || now > rec.resetAt) {
      rec = { count: 0, resetAt: now + windowMs };
      hits.set(key, rec);
    }

    rec.count++;

    if (rec.count > max) {
      const retryAfterSec = Math.max(1, Math.ceil((rec.resetAt - now) / 1000));
      res.setHeader("Retry-After", String(retryAfterSec));
      return res.status(429).json(
        buildError("RATE_LIMITED", "요청이 너무 많습니다. 잠시 후 다시 시도하세요.", {
          scope: name,
          retry_after_sec: retryAfterSec,
        })
      );
    }

    return next();
  };
}

const verifyRateLimit = makeFixedWindowLimiter({
  windowMs: VERIFY_RATE_LIMIT_WINDOW_MS,
  max: VERIFY_RATE_LIMIT_PER_MIN,
  name: "verify",
  keyFn: (req) => {
    const ip = getClientIp(req);
    const auth = String(req.headers.authorization || "");
    const tok = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    const t = tok ? hash16(tok) : "";
    return t ? `${ip}|t:${t}` : ip;
  },
});

function enforceVerifyPayloadLimits(req, res, next) {
  const b = req.body || {};

  const q = String(b.query ?? "");
  const core = String(b.core_text ?? "");
  const ua = String(b.user_answer ?? "");

  if (q.length > VERIFY_MAX_QUERY_CHARS) {
    return res.status(413).json(
      buildError("PAYLOAD_TOO_LARGE", `query가 너무 깁니다. (max ${VERIFY_MAX_QUERY_CHARS} chars)`)
    );
  }
  if (core.length > VERIFY_MAX_CORE_TEXT_CHARS) {
    return res.status(413).json(
      buildError("PAYLOAD_TOO_LARGE", `core_text가 너무 깁니다. (max ${VERIFY_MAX_CORE_TEXT_CHARS} chars)`)
    );
  }
  if (ua.length > VERIFY_MAX_USER_ANSWER_CHARS) {
    return res.status(413).json(
      buildError("PAYLOAD_TOO_LARGE", `user_answer가 너무 깁니다. (max ${VERIFY_MAX_USER_ANSWER_CHARS} chars)`)
    );
  }

  return next();
}

function requireVerifyAuth(req, res, next) {
  if (!isProd) return next();

  const auth = String(req.headers.authorization || "");
  const tok = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  // 운영에서 localtest 같은 디버그 토큰 차단
  if (tok && tok.toLowerCase() === "localtest") {
    return res.status(401).json(buildError("UNAUTHORIZED", "Invalid token"));
  }

  // 토큰 있으면 통과
  if (tok) return next();

  // 세션 로그인(패스포트) 통과
  if (req.user) return next();

  return res.status(401).json(buildError("UNAUTHORIZED", "Authorization required"));
}

// ─────────────────────────────
// ✅ PROD key_uuid 정책: 기본 무시(안전) / 필요 시 admin만 허용
// KEY_UUID_PROD_POLICY: ignore | reject | admin_only
//  - ignore: 운영에서 key_uuid 들어오면 삭제하고 진행(권장)
//  - reject: 운영에서 key_uuid 들어오면 403
//  - admin_only: 운영에서 key_uuid는 x-admin-token(=DIAG_TOKEN or DEV_ADMIN_TOKEN) 있을 때만 허용
// ─────────────────────────────
const KEY_UUID_PROD_POLICY = String(process.env.KEY_UUID_PROD_POLICY || "ignore").toLowerCase();

function isAdminOverride(req) {
  const tok = String(req.headers["x-admin-token"] || "");
  const adminTok = process.env.DIAG_TOKEN || process.env.DEV_ADMIN_TOKEN || "";
  return !!adminTok && tok && tok === adminTok;
}

function guardProdKeyUuid(req, res, next) {
  if (!isProd) return next();

  const hasKeyUuid = !!(req.body?.key_uuid || req.body?.keyUuid);
  if (!hasKeyUuid) return next();

  if (KEY_UUID_PROD_POLICY === "ignore") {
    delete req.body.key_uuid;
    delete req.body.keyUuid;
    return next();
  }

  if (KEY_UUID_PROD_POLICY === "admin_only") {
    if (isAdminOverride(req)) return next();
    return res.status(403).json(buildError("FORBIDDEN", "key_uuid is admin-only in production"));
  }

  // reject
  return res.status(403).json(buildError("FORBIDDEN", "key_uuid is not allowed in production"));
}

// admin 라우트: (1) x-admin-token(DEV_ADMIN_TOKEN) 이거나 (2) 기존 ensureAuth 통과면 허용
function ensureAuthOrAdminToken(req, res, next) {
  // (선택) isAdminOverride가 있으면 우선 허용
  if (typeof isAdminOverride === "function" && isAdminOverride(req)) return next();

  // x-admin-token(DEV_ADMIN_TOKEN or DIAG_TOKEN)으로 우회 허용
  const tok = String(req.headers["x-admin-token"] || "");
  const adminTok = process.env.DEV_ADMIN_TOKEN || process.env.DIAG_TOKEN || "";
  if (adminTok && tok === adminTok) return next();

  // 그 외는 기존 세션 인증 흐름
  return ensureAuth(req, res, next);
}

// ─────────────────────────────
// ✅ PROD: dev/admin route guard
// ─────────────────────────────
const ALLOW_DEV_ROUTES_IN_PROD = String(process.env.ALLOW_DEV_ROUTES_IN_PROD || "0") === "1";

function requireAdminToken(req, res, next) {
  const tok = String(req.headers["x-admin-token"] || "");
  const adminTok = process.env.DEV_ADMIN_TOKEN || process.env.DIAG_TOKEN || "";
  if (!adminTok || tok !== adminTok) {
    return res.status(403).json(buildError("FORBIDDEN", "Admin token required"));
  }
  return next();
}

function blockDevRoutesInProd(req, res, next) {
  if (!isProd) return next();
  if (ALLOW_DEV_ROUTES_IN_PROD) return next();

  // 운영에서 /api/dev/* 는 기본 차단
  if (req.path && req.path.startsWith("/api/dev")) {
    return res.status(404).json(buildError("NOT_FOUND", "Not found"));
  }
  return next();
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
// ✅ (추가) Gemini verifyInput 안전 직렬화 (slice로 JSON 깨지는 것 방지)
// ─────────────────────────────
function safeVerifyInputForGemini(input, maxLen) {
  const limit = Number.isFinite(maxLen) ? maxLen : 12000;

  const tryStr = (obj) => {
    try {
      const s = JSON.stringify(obj);
      return s.length <= limit ? s : null;
    } catch {
      return null;
    }
  };

  // 0) 원본 그대로 시도
  let s0 = tryStr(input);
  if (s0) return s0;

  // 1) blocks evidence를 가볍게 (naver는 title/link만)
  const slimBlocks = Array.isArray(input?.blocks)
    ? input.blocks.map((b) => {
        const ev = b?.evidence || {};
        const cutArr = (v, n) => (Array.isArray(v) ? v.slice(0, n) : []);
        const slimNaver = cutArr(
  ev.naver,
  Math.min(3, (Number.isFinite(BLOCK_NAVER_EVIDENCE_TOPK) ? BLOCK_NAVER_EVIDENCE_TOPK : 3))
).map((x) => ({
          title: x?.title || null,
          link: x?.link || null,
          naver_type: x?.naver_type || null,
          tier: x?.tier || null,
        }));

        return {
          id: b?.id ?? null,
          text: (String(b?.text || "")).slice(0, 320),
          queries: b?.queries || null,
          evidence: {
          crossref: cutArr(ev.crossref, Math.min(3, (Number.isFinite(BLOCK_EVIDENCE_TOPK) ? BLOCK_EVIDENCE_TOPK : 3))),
          openalex: cutArr(ev.openalex, Math.min(3, (Number.isFinite(BLOCK_EVIDENCE_TOPK) ? BLOCK_EVIDENCE_TOPK : 3))),
           wikidata: cutArr(ev.wikidata, 5),
           gdelt: cutArr(ev.gdelt, Math.min(3, (Number.isFinite(BLOCK_EVIDENCE_TOPK) ? BLOCK_EVIDENCE_TOPK : 3))),
            naver: slimNaver,
          },
        };
      })
    : [];

  const slim1 = {
    mode: input?.mode,
    query: input?.query,
    core_text: input?.core_text ? String(input.core_text).slice(0, 2000) : "",
    blocks: slimBlocks,
    external: { truncated: true },
    partial_scores: input?.partial_scores
      ? {
          recency: input.partial_scores.recency ?? null,
          validity: input.partial_scores.validity ?? null,
          consistency: input.partial_scores.consistency ?? null,
          engine_factor: input.partial_scores.engine_factor ?? null,
          naver_tier_factor: input.partial_scores.naver_tier_factor ?? null,
          engines_used: input.partial_scores.engines_used ?? null,
          engine_results: input.partial_scores.engine_results ?? null,
        }
      : {},
  };

  let s1 = tryStr(slim1);
  if (s1) return s1;

  // 2) 마지막 안전망
  const slimmer = {
    mode: slim1.mode,
    query: slim1.query,
    core_text: slim1.core_text,
    blocks: slimBlocks.slice(0, 3),
    partial_scores: slim1.partial_scores,
    external: { truncated: true, reason: "too_large" },
  };

  let s2 = tryStr(slimmer);
  if (s2) return s2;

  // 3) 진짜 최종: 최소 JSON
  return JSON.stringify({
    mode: input?.mode || null,
    query: input?.query || null,
    core_text: input?.core_text ? String(input.core_text).slice(0, 1500) : "",
    truncated: true,
  });
}

// ─────────────────────────────
// ✅ Supabase + PostgreSQL 세션
// ─────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ✅ ADD: Pacific(PT) 날짜/다음 자정(리셋) UTC 시각 — DB로 정확 계산 + 캐시
let _pacificCache = { fetchedAt: 0, pt_date: null, next_reset_utc: null };

async function getPacificResetInfoCached() {
  const now = Date.now();
  if (_pacificCache.pt_date && (now - _pacificCache.fetchedAt) < PACIFIC_INFO_TTL_MS) {
    return { pt_date: _pacificCache.pt_date, next_reset_utc: _pacificCache.next_reset_utc };
  }

  // PT 자정은 DST 때문에 JS만으로 정확히 만들기 빡세서 Postgres tz로 계산
  const sql = `
    select
      (now() at time zone $1)::date::text as pt_date,
      (
        (date_trunc('day', now() at time zone $1) + interval '1 day')
        at time zone $1
      ) as next_reset_utc
  `;
  const r = await pgPool.query(sql, [GEMINI_RESET_TZ]);

  const pt_date = r.rows?.[0]?.pt_date || null;
  const next_reset_utc = r.rows?.[0]?.next_reset_utc
    ? new Date(r.rows[0].next_reset_utc).toISOString()
    : null;

  _pacificCache = { fetchedAt: now, pt_date, next_reset_utc };
  return { pt_date, next_reset_utc };
}

// ─────────────────────────────
// ✅ ADD: Secret Encrypt/Decrypt (AES-256-GCM)
// ─────────────────────────────
function _getEncKey() {
  if (!SETTINGS_ENC_KEY_B64) {
    const err = new Error("SETTINGS_ENC_KEY_B64 is required");
    err.code = "SETTINGS_ENC_KEY_MISSING";
    err.httpStatus = 500;
    err.publicMessage = "서버 암호화 키(SETTINGS_ENC_KEY_B64)가 설정되지 않았습니다.";
    err._fatal = true;
    throw err;
  }

  const key = Buffer.from(SETTINGS_ENC_KEY_B64, "base64");
  if (key.length !== 32) {
    const err = new Error("SETTINGS_ENC_KEY_B64 must be 32 bytes base64");
    err.code = "SETTINGS_ENC_KEY_INVALID";
    err.httpStatus = 500;
    err.publicMessage = "서버 암호화 키(SETTINGS_ENC_KEY_B64) 형식이 올바르지 않습니다. (base64 32bytes)";
    err._fatal = true;
    throw err;
  }
  return key;
}

function encryptSecret(plaintext) {
  const key = _getEncKey();
  const iv = crypto.randomBytes(12); // GCM 권장 12 bytes
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    v: 1,
    alg: "A256GCM",
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ct: ct.toString("base64"),
  };
}

function decryptSecret(enc) {
  if (!enc || typeof enc !== "object") return null;
  const key = _getEncKey();

  const iv = Buffer.from(enc.iv || "", "base64");
  const tag = Buffer.from(enc.tag || "", "base64");
  const ct = Buffer.from(enc.ct || "", "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf8");
}

// ─────────────────────────────
// ✅ ADD: user_secrets CRUD
// ─────────────────────────────
const USER_SECRETS_PROVIDER = process.env.USER_SECRETS_PROVIDER || "supabase";

async function loadUserSecretsRow(userId) {
  const { data, error } = await supabase
    .from("user_secrets")
    .select("user_id, secrets")
    .eq("user_id", userId)
    .single();

  if (error) {
    // row 없음(PGRST116)이면 빈 객체로 처리
    if (error.code === "PGRST116") return { user_id: userId, secrets: {} };
    throw error;
  }
  return { user_id: data.user_id, secrets: data.secrets || {} };
}

async function upsertUserSecretsRow(userId, secrets) {
  const now = new Date().toISOString();

  const provider = process.env.USER_SECRETS_PROVIDER || "supabase";
  const encVer = Number.parseInt(process.env.USER_SECRETS_ENC_VER || "1", 10);

  // ✅ created_at / iv NOT NULL 대응: 기존 row 있으면 값 유지, 없으면 생성
  let exists = false;
  let iv = null;
  let createdAt = null;

  {
    const { data, error } = await supabase
      .from("user_secrets")
      .select("user_id, iv, created_at")
      .eq("user_id", userId)
      .single();

    if (!error && data?.user_id) {
      exists = true;
      iv = data.iv ?? null;
      createdAt = data.created_at ?? null;
    }

    // row 없음이면 PGRST116 → 새로 만들면 됨
    if (error && error.code !== "PGRST116") throw error;
  }

  // ✅ iv 없으면 생성 (uuid/text 타입이면 OK)
  if (!iv) iv = crypto.randomUUID();

  const payload = {
    user_id: userId,
    provider,        // ✅ NOT NULL
    enc_ver: encVer, // ✅ NOT NULL
    iv,              // ✅ NOT NULL
    secrets,
    updated_at: now,
  };

  // created_at NOT NULL 스키마 대비(없을 때만)
  if (!exists || !createdAt) payload.created_at = now;

  const { error: upErr } = await supabase
    .from("user_secrets")
    .upsert([payload], { onConflict: "user_id" });

  if (upErr) throw upErr;
}

// ─────────────────────────────
// ✅ ADD: Gemini Keyring + Rotation State (PT 자정 리셋)
//   secrets.gemini = { keyring:{keys:[{id,label,enc}], state:{active_id, exhausted_ids:{[id]:pt_date}, last_reset_pt_date}}, updated_at }
// ─────────────────────────────
function _ensureGeminiSecretsShape(secrets) {
  if (!secrets || typeof secrets !== "object") secrets = {};
  if (!secrets.gemini || typeof secrets.gemini !== "object") secrets.gemini = {};
  if (!secrets.gemini.keyring || typeof secrets.gemini.keyring !== "object") {
    secrets.gemini.keyring = { keys: [], state: { active_id: null, exhausted_ids: {}, last_reset_pt_date: null } };
  }
  if (!Array.isArray(secrets.gemini.keyring.keys)) secrets.gemini.keyring.keys = [];
  if (!secrets.gemini.keyring.state || typeof secrets.gemini.keyring.state !== "object") {
    secrets.gemini.keyring.state = { active_id: null, exhausted_ids: {}, last_reset_pt_date: null };
  }
  if (!secrets.gemini.keyring.state.exhausted_ids || typeof secrets.gemini.keyring.state.exhausted_ids !== "object") {
    secrets.gemini.keyring.state.exhausted_ids = {};
  }
  return secrets;
}

// ─────────────────────────────
// Per-user Integration Secrets (Naver / K-Law / GitHub / DeepL)
// secrets.integrations = {
//   naver:  { id_enc, secret_enc },
//   klaw:   { key_enc },
//   github: { token_enc },
//   deepl:  { key_enc },
// }
// ─────────────────────────────
function _ensureIntegrationsSecretsShape(secrets) {
  if (!secrets || typeof secrets !== "object") secrets = {};
  if (!secrets.integrations || typeof secrets.integrations !== "object") secrets.integrations = {};
  const it = secrets.integrations;

  if (!it.naver || typeof it.naver !== "object") it.naver = {};
  if (!it.klaw || typeof it.klaw !== "object") it.klaw = {};
  if (!it.github || typeof it.github !== "object") it.github = {};
  if (!it.deepl || typeof it.deepl !== "object") it.deepl = {};

  return secrets;
}

function _setEncOrClear(obj, field, value) {
  if (value === undefined) return; // 요청에 없으면 변경하지 않음
  const t = String(value ?? "").trim();
  if (!t) {
    delete obj[field]; // 빈 문자열/NULL => 삭제(초기화)
    return;
  }
  obj[field] = encryptSecret(t);
}

function _getDec(obj, field) {
  const v = decryptSecret(obj?.[field]);
  const t = String(v ?? "").trim();
  return t || null;
}

function applyIntegrationsSecretPatch(secrets, patch = {}) {
  secrets = _ensureIntegrationsSecretsShape(secrets);
  const it = secrets.integrations;

  _setEncOrClear(it.naver, "id_enc", patch.naver_id);
  _setEncOrClear(it.naver, "secret_enc", patch.naver_secret);

  _setEncOrClear(it.klaw, "key_enc", patch.klaw_key);

  _setEncOrClear(it.github, "token_enc", patch.github_token);

  _setEncOrClear(it.deepl, "key_enc", patch.deepl_key);

  return secrets;
}

function decryptIntegrationsSecrets(secrets) {
  secrets = _ensureIntegrationsSecretsShape(secrets);
  const it = secrets.integrations;

  return {
    naver_id: _getDec(it.naver, "id_enc"),
    naver_secret: _getDec(it.naver, "secret_enc"),
    klaw_key: _getDec(it.klaw, "key_enc"),
    github_token: _getDec(it.github, "token_enc"),
    deepl_key: _getDec(it.deepl, "key_enc"),
  };
}

function _rotateKeyId(keys, currentId) {
  if (!keys.length) return null;
  const idx = keys.findIndex(k => k.id === currentId);
  const next = (idx >= 0) ? (idx + 1) % keys.length : 0;
  return keys[next]?.id || keys[0]?.id || null;
}

async function ensureGeminiResetIfNeeded(userId, secrets) {
  const pac = await getPacificResetInfoCached();
  const pt_date_now = pac.pt_date;

  const state = secrets?.gemini?.keyring?.state || {};
  const last = state.last_reset_pt_date;

  // PT 날짜가 바뀌면 "소진표시(exhausted)" 전부 해제
  if (pt_date_now && last && last !== pt_date_now) {
    state.exhausted_ids = {};
    state.last_reset_pt_date = pt_date_now;
    secrets.gemini.keyring.state = state;
    await upsertUserSecretsRow(userId, secrets);
  }

  // 최초면 last_reset_pt_date 세팅
  if (pt_date_now && !state.last_reset_pt_date) {
    state.last_reset_pt_date = pt_date_now;
    secrets.gemini.keyring.state = state;
    await upsertUserSecretsRow(userId, secrets);
  }

  return pac;
}

function pickGeminiKeyCandidate(secrets) {
  const kr = secrets?.gemini?.keyring;
  const keys = Array.isArray(kr?.keys) ? kr.keys : [];
  const state = kr?.state || {};
  const exhausted = state.exhausted_ids || {};

  if (!keys.length) return { keyId: null, enc: null, keysCount: 0 };

  const activeId = state.active_id || keys[0]?.id || null;
  const idxRaw = keys.findIndex((k) => k.id === activeId);
  const startIdx = idxRaw >= 0 ? idxRaw : 0;

  for (let offset = 0; offset < keys.length; offset++) {
    const k = keys[(startIdx + offset) % keys.length];
    if (k && k.id && k.enc && !exhausted[k.id]) {
      return { keyId: k.id, enc: k.enc, keysCount: keys.length };
    }
  }

  return { keyId: null, enc: null, keysCount: keys.length };
}

async function setGeminiActiveId(userId, secrets, keyId) {
  if (!keyId) return;
  secrets.gemini.keyring.state.active_id = keyId;
  await upsertUserSecretsRow(userId, secrets);
}

async function markGeminiKeyExhausted(userId, secrets, keyId, pt_date_now) {
  if (!keyId) return;
  secrets.gemini.keyring.state.exhausted_ids[keyId] = pt_date_now || "unknown";
  // 다음 후보를 active로 밀어둠(다음 호출이 바로 다른 키로 가게)
  const keys = secrets.gemini.keyring.keys || [];
  secrets.gemini.keyring.state.active_id = _rotateKeyId(keys, keyId);
  await upsertUserSecretsRow(userId, secrets);
}

async function getGeminiKeyFromDB(userId) {
  const row = await loadUserSecretsRow(userId);
  let secrets = _ensureGeminiSecretsShape(row.secrets);

  const pac = await ensureGeminiResetIfNeeded(userId, secrets);
  const pt_date_now = pac.pt_date;

  const keys = Array.isArray(secrets?.gemini?.keyring?.keys) ? secrets.gemini.keyring.keys : [];
  const keysCount = keys.length;

  // 키가 아예 없으면 즉시 종료
  if (!keysCount) {
    const err = new Error("GEMINI_KEYRING_EMPTY_OR_EXHAUSTED");
    err.code = "GEMINI_KEY_EXHAUSTED";
    err.httpStatus = 200;
    err.detail = { keysCount: 0, pt_date: pt_date_now, next_reset_utc: pac.next_reset_utc };
    throw err;
  }

  // ✅ 핵심: “현재 후보 키 복호화 실패”는 ‘전체 소진’이 아니라 ‘해당 키만 탈락’ → 다음 키로 계속
  const tried = new Set();

  for (let i = 0; i < keysCount; i++) {
    const cand = pickGeminiKeyCandidate(secrets);
    if (!cand.keyId || !cand.enc) break;

    // 무한루프 방지
    if (tried.has(cand.keyId)) break;
    tried.add(cand.keyId);

        let keyPlain = null;
    try {
      keyPlain = decryptSecret(cand.enc);
    } catch (err) {
      // ✅ 서버 마스터키 누락/불량 같은 "치명 오류"는 exhausted 처리하지 말고 즉시 중단
      if (err?._fatal) throw err;
      keyPlain = null;
    }

    if (keyPlain && keyPlain.trim()) {
      await setGeminiActiveId(userId, secrets, cand.keyId);
      return {
        gemini_key: keyPlain.trim(),
        key_id: cand.keyId,
        pt_date: pt_date_now,
        next_reset_utc: pac.next_reset_utc,
      };
    }

    // 복호화 실패/빈키 → 해당 키만 exhausted 처리 후 다음 키로 진행
    await markGeminiKeyExhausted(userId, secrets, cand.keyId, pt_date_now);
  }

  // 여기까지 왔으면 “진짜로” 쓸 키가 없음
  const err = new Error("GEMINI_KEYRING_EMPTY_OR_EXHAUSTED");
  err.code = "GEMINI_KEY_EXHAUSTED";
  err.httpStatus = 200;
  err.detail = { keysCount, pt_date: pt_date_now, next_reset_utc: pac.next_reset_utc };
  throw err;
}

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
  .upsert(
    [{ email, name: user_name || null, updated_at: new Date().toISOString() }],
    { onConflict: "email" }
  );

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
  if (!Array.isArray(gdeltArticles) || gdeltArticles.length === 0) return null;
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

function clamp01(x) {
  if (!Number.isFinite(x)) return 0;
  return Math.max(0, Math.min(1, x));
}

function expDecayDays(days, tauDays = 90) {
  return Math.exp(-days / tauDays);
}

function parseNaverPubDate(pubDate) {
  if (!pubDate) return null;
  const t = new Date(pubDate).getTime();
  return Number.isNaN(t) ? null : t;
}

function scoreFromDateMs(tMs, tauDays = 90) {
  if (!tMs) return null;
  const now = Date.now();
  const days = (now - tMs) / (1000 * 60 * 60 * 24);
  const decay = expDecayDays(Math.max(0, days), tauDays);
  // 0.5~0.95 범위
  return 0.5 + 0.45 * clamp01(decay);
}

function calcNewsRecencyScore(gdeltArticles = [], naverItems = []) {
  const scores = [];

  // GDELT: 아예 없으면 제외(중립 유지)
  if (Array.isArray(gdeltArticles) && gdeltArticles.length > 0) {
    const g = calcRecencyScore(gdeltArticles);
    if (Number.isFinite(g)) scores.push(g);
  }

  // NAVER news pubDate 기반
  if (Array.isArray(naverItems) && naverItems.length > 0) {
    const nScores = naverItems
      .filter((it) => it?.naver_type === "news" && it?.pubDate)
      .map((it) => scoreFromDateMs(parseNaverPubDate(it.pubDate), 90))
      .filter(Number.isFinite);

    if (nScores.length > 0) {
      scores.push(nScores.reduce((a, b) => a + b, 0) / nScores.length);
    }
  }

  // 뉴스 신호가 아예 없으면 “중립(약하게만)”로
  return scores.length > 0
    ? scores.reduce((a, b) => a + b, 0) / scores.length
    : 0.95;
}

function extractPaperYear(x) {
  // 문자열에서 연도 추출: "2023 - title" 형태 포함
  if (typeof x === "string") {
    const m = x.match(/\b(19|20)\d{2}\b/);
    return m ? Number(m[0]) : null;
  }
  // 혹시 객체로 바꾼 경우 대비
  if (x && typeof x === "object") {
    const y = x.year || x.publication_year || null;
    return Number.isFinite(Number(y)) ? Number(y) : null;
  }
  return null;
}

// 논문은 “연도”만으로 약하게(0.85~1.0) 반영
function calcPaperRecencyScore(papers = []) {
  const nowY = new Date().getFullYear();

  const years = (Array.isArray(papers) ? papers : [])
    .map(extractPaperYear)
    .filter((y) => Number.isFinite(y) && y >= 1900 && y <= nowY + 1);

  if (!years.length) return 0.95;

  // 최근 논문 쪽을 더 반영(최신값 기준)
  const bestY = Math.max(...years);
  const age = Math.max(0, nowY - bestY);

  // 0y=1.0, 8y≈0.905, 16y≈0.87 (약하게만)
  const decay = Math.exp(-age / 8);
  return 0.85 + 0.15 * clamp01(decay);
}

// DV/CV용 GitHub updated 기반(0.8~1.0 정도로)
function calcGithubRecencyScore(repos = []) {
  const ts = (Array.isArray(repos) ? repos : [])
    .map((r) => (r?.updated ? new Date(r.updated).getTime() : null))
    .filter((t) => t && !Number.isNaN(t));

  if (!ts.length) return 0.95;

  const newest = Math.max(...ts);
  const days = Math.max(0, (Date.now() - newest) / (1000 * 60 * 60 * 24));

  // 코드 생태계는 180일 정도를 기준으로 완만하게 감쇠
  const decay = expDecayDays(days, 180);
  return 0.8 + 0.2 * clamp01(decay);
}

function calcCompositeRecency({ mode, gdelt = [], naver = [], crossref = [], openalex = [], github = [] }) {
  const news = calcNewsRecencyScore(gdelt, naver);
  const paper = calcPaperRecencyScore([...(crossref || []), ...(openalex || [])]);
  const code = calcGithubRecencyScore(github);

  // ✅ “약하게” 반영 기본값(ENV로 조절 가능)
  const qvfvNewsW = Number(process.env.RECENCY_QVFV_NEWS_W ?? "0.12");
  const qvfvPaperW = Number(process.env.RECENCY_QVFV_PAPER_W ?? "0.08");
  const qvfvFloor = Number(process.env.RECENCY_QVFV_FLOOR ?? "0.90");

  const dvcvCodeW = Number(process.env.RECENCY_DVCV_CODE_W ?? "0.25");
  const dvcvPaperW = Number(process.env.RECENCY_DVCV_PAPER_W ?? "0.05");
  const dvcvNewsW = Number(process.env.RECENCY_DVCV_NEWS_W ?? "0.05");
  const dvcvFloor = Number(process.env.RECENCY_DVCV_FLOOR ?? "0.85");

  let wNews = 0, wPaper = 0, wCode = 0, floor = 0.9;

  if (mode === "dv" || mode === "cv") {
    wNews = dvcvNewsW; wPaper = dvcvPaperW; wCode = dvcvCodeW; floor = dvcvFloor;
  } else {
    wNews = qvfvNewsW; wPaper = qvfvPaperW; wCode = 0; floor = qvfvFloor;
  }

  // 1 - 가중치*(1-점수) 형태(“약하게” 깎임)
  const overall =
    1
    - wNews * (1 - news)
    - wPaper * (1 - paper)
    - wCode * (1 - code);

  const clamped = Math.max(floor, clamp01(overall));

  return {
    overall: clamped,
    detail: {
      news_recency: news,
      paper_recency: paper,
      code_recency: code,
      weights: { wNews, wPaper, wCode, floor },
    },
  };
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

// ─────────────────────────────
// ✅ DEV ONLY: seed secrets into user_secrets (encrypted via encryptSecret)
//   보호: header "x-admin-token" must match process.env.DEV_ADMIN_TOKEN
// ─────────────────────────────
const DEV_ADMIN_TOKEN = process.env.DEV_ADMIN_TOKEN || null;

// ─────────────────────────────
// ✅ DIAG 보호(운영 노출 최소화)
// - PROD에서는 기본적으로 test/diag 엔드포인트를 숨김(404)
// - 필요 시 헤더 x-admin-token 으로만 접근 가능
// - 토큰은 DIAG_TOKEN 우선, 없으면 DEV_ADMIN_TOKEN 재사용
// ─────────────────────────────
const DIAG_TOKEN = process.env.DIAG_TOKEN || DEV_ADMIN_TOKEN || null;

function isDiagAuthorized(req) {
  const tok = String(req.headers["x-admin-token"] || "");
  return !!DIAG_TOKEN && tok && tok === DIAG_TOKEN;
}

function requireDiag(req, res, next) {
  if (process.env.NODE_ENV !== "production") return next();
  if (isDiagAuthorized(req)) return next();
  return res.status(404).json(buildError("NOT_FOUND", "Not available"));
}

app.use(blockDevRoutesInProd);

// ✅ PROD에서는 dev seed endpoint 차단
if (process.env.NODE_ENV === "production") {
  app.post("/api/dev/seed-secrets", (req, res) =>
    res.status(404).json(buildError("NOT_FOUND", "Not available"))
  );
} else {
app.post("/api/dev/seed-secrets", async (req, res) => {
  try {
    const admin = String(req.headers["x-admin-token"] || "");
    if (!DEV_ADMIN_TOKEN || admin !== DEV_ADMIN_TOKEN) {
      return res.status(401).json(buildError("UNAUTHORIZED", "Invalid admin token"));
    }

    const {
      user_id,
      // integrations
      naver_id,
      naver_secret,
      klaw_key,
      github_token,
      deepl_key,
      // (옵션) gemini keyring도 같이 넣고 싶으면
      gemini_keys,
      action,
    } = req.body || {};

    const uid = String(user_id || "").trim();
    if (!uid) {
      return res.status(400).json(buildError("VALIDATION_ERROR", "user_id is required"));
    }

    const row = await loadUserSecretsRow(uid);
    let secrets = _ensureIntegrationsSecretsShape(_ensureGeminiSecretsShape(row.secrets));

    // ✅ integrations 암호화 저장(빈 문자열이면 삭제)
    secrets = applyIntegrationsSecretPatch(secrets, {
      naver_id,
      naver_secret,
      klaw_key,
      github_token,
      deepl_key,
    });

    // ✅ (옵션) gemini keyring도 seed
    const hasGeminiPayload =
      (Array.isArray(gemini_keys) && gemini_keys.length > 0) ||
      (typeof gemini_keys === "string" && String(gemini_keys).trim());

    if (hasGeminiPayload) {
      let normalized = [];
      let arr = [];
      if (Array.isArray(gemini_keys)) arr = gemini_keys;
      else arr = [String(gemini_keys).trim()];

      normalized = arr
        .map((x) => {
          if (typeof x === "string") return { key: x.trim(), label: null };
          if (x && typeof x === "object")
            return { key: String(x.key || x.k || "").trim(), label: x.label ? String(x.label).trim() : null };
          return { key: "", label: null };
        })
        .filter((x) => x.key);

      if (!normalized.length) {
        return res.status(400).json(buildError("VALIDATION_ERROR", "gemini_keys is empty"));
      }

      const mode = String(action || "replace").toLowerCase(); // replace | append
      let keys = Array.isArray(secrets.gemini.keyring.keys) ? secrets.gemini.keyring.keys : [];

      if (mode === "append") {
        const newOnes = normalized.map((x) => ({
          id: crypto.randomUUID(),
          label: x.label,
          enc: encryptSecret(x.key),
          created_at: new Date().toISOString(),
        }));
        keys = [...keys, ...newOnes].slice(0, GEMINI_KEYRING_MAX);
      } else {
        keys = normalized.map((x) => ({
          id: crypto.randomUUID(),
          label: x.label,
          enc: encryptSecret(x.key),
          created_at: new Date().toISOString(),
        }));
      }

      const pac = await getPacificResetInfoCached();
      secrets.gemini.keyring.keys = keys;
      secrets.gemini.keyring.state = secrets.gemini.keyring.state || {};
      secrets.gemini.keyring.state.active_id = keys[0]?.id || null;
      secrets.gemini.keyring.state.exhausted_ids = {};
      secrets.gemini.keyring.state.last_reset_pt_date = pac.pt_date;
    }

    await upsertUserSecretsRow(uid, secrets);

    const it = secrets.integrations || {};
    return res.json(
      buildSuccess({
        seeded: true,
        user_id: uid,
        has_naver: !!(it.naver?.id_enc && it.naver?.secret_enc),
        has_klaw: !!it.klaw?.key_enc,
        has_github: !!it.github?.token_enc,
        has_deepl: !!it.deepl?.key_enc,
        gemini_key_count: (secrets?.gemini?.keyring?.keys || []).length,
      })
    );
  } catch (e) {
    console.error("❌ /api/dev/seed-secrets Error:", e.message);
    return res.status(500).json(buildError("SEED_ERROR", "seed failed", e.message));
  }
});
}

// ─────────────────────────────
// ✅ ADD: Settings Save (Gemini Keyring encrypted in DB)
//   - 앱 설정창에서 호출
//   - Authorization: Bearer <supabase jwt> 권장
// ─────────────────────────────
app.post("/api/settings/save", async (req, res) => {
  try {
    const authUser = await getSupabaseAuthUser(req);

    // ✅ 운영(또는 REQUIRE_USER_AUTH=true)이면 settings 저장은 반드시 로그인 필요
    if ((isProd || REQUIRE_USER_AUTH) && !authUser) {
      return res.status(401).json(buildError("UNAUTHORIZED", "로그인이 필요합니다. (Authorization: Bearer <token>)"));
    }

    const userId = await resolveLogUserId({
      user_id: null,
      user_email: authUser?.email || null,
      user_name: authUser?.user_metadata?.full_name || authUser?.user_metadata?.name || null,
      auth_user: authUser || null,
      bearer_token: getBearerToken(req),
    });

    if (!userId) {
      return res.status(400).json(buildError("VALIDATION_ERROR", "userId 해결 실패"));
    }

    const {
      gemini_keys,
      action,

      // ✅ NEW: 다른 엔진 키도 같이 저장
      naver_id,
      naver_secret,
      klaw_key,
      github_token,
      deepl_key,
    } = req.body;

    const hasOtherPayload =
      naver_id !== undefined ||
      naver_secret !== undefined ||
      klaw_key !== undefined ||
      github_token !== undefined ||
      deepl_key !== undefined;

    const hasGeminiPayload =
      (Array.isArray(gemini_keys) && gemini_keys.length > 0) ||
      (typeof gemini_keys === "string" && gemini_keys.trim());

    // Gemini 입력 정규화 (있을 때만)
    let normalized = [];
    if (hasGeminiPayload) {
      let arr = [];
      if (Array.isArray(gemini_keys)) arr = gemini_keys;
      else if (typeof gemini_keys === "string" && gemini_keys.trim()) arr = [gemini_keys.trim()];

      normalized = arr
        .map((x) => {
          if (typeof x === "string") return { key: x.trim(), label: null };
          if (x && typeof x === "object")
            return {
              key: String(x.key || x.k || "").trim(),
              label: x.label ? String(x.label).trim() : null,
            };
          return { key: "", label: null };
        })
        .filter((x) => x.key);
    }

    if (!hasGeminiPayload && !hasOtherPayload) {
      return res.status(400).json(buildError("VALIDATION_ERROR", "저장할 설정이 없습니다."));
    }
    if (hasGeminiPayload && !normalized.length) {
      return res.status(400).json(buildError("VALIDATION_ERROR", "gemini_keys가 비어 있습니다."));
    }

    const row = await loadUserSecretsRow(userId);
    let secrets = _ensureIntegrationsSecretsShape(_ensureGeminiSecretsShape(row.secrets));

    // ✅ NEW: 기타 키 저장(암호화). 빈 문자열이면 삭제
    secrets = applyIntegrationsSecretPatch(secrets, {
      naver_id,
      naver_secret,
      klaw_key,
      github_token,
      deepl_key,
    });

    // ✅ Gemini keyring 저장은 gemini_keys가 들어왔을 때만
    let keys = Array.isArray(secrets.gemini.keyring.keys) ? secrets.gemini.keyring.keys : [];
    let pac = null;

    if (hasGeminiPayload) {
      const mode = String(action || "replace").toLowerCase(); // replace | append

      if (mode === "append") {
        const newOnes = normalized.map((x) => ({
          id: crypto.randomUUID(),
          label: x.label,
          enc: encryptSecret(x.key),
          created_at: new Date().toISOString(),
        }));
        keys = [...keys, ...newOnes].slice(0, GEMINI_KEYRING_MAX);
      } else {
        keys = normalized.map((x) => ({
          id: crypto.randomUUID(),
          label: x.label,
          enc: encryptSecret(x.key),
          created_at: new Date().toISOString(),
        }));
      }

      pac = await getPacificResetInfoCached();
      secrets.gemini.keyring.keys = keys;
      secrets.gemini.keyring.state = secrets.gemini.keyring.state || {};
      secrets.gemini.keyring.state.active_id = keys[0]?.id || null;
      secrets.gemini.keyring.state.exhausted_ids = {};
      secrets.gemini.keyring.state.last_reset_pt_date = pac.pt_date;
    }

    await upsertUserSecretsRow(userId, secrets);

    const it = secrets.integrations || {};

    return res.json(
      buildSuccess({
        saved: true,
        key_count: (secrets?.gemini?.keyring?.keys || []).length,
        pt_date: pac?.pt_date || null,
        next_reset_utc: pac?.next_reset_utc || null,

        has_naver: !!(it.naver?.id_enc && it.naver?.secret_enc),
        has_klaw: !!it.klaw?.key_enc,
        has_github: !!it.github?.token_enc,
        has_deepl: !!it.deepl?.key_enc,
      })
    );
  } catch (e) {
    console.error("❌ /api/settings/save Error:", e.message);
    return res.status(500).json(buildError("SETTINGS_SAVE_ERROR", "설정 저장 실패", e.message));
  }
});

// ✅ ADD: Gemini reset/keyring status (앱 ping용)
app.get("/api/settings/gemini/status", async (req, res) => {
  try {
    const authUser = await getSupabaseAuthUser(req);
    if (!authUser) {
      return res.status(401).json(buildError("UNAUTHORIZED", "로그인이 필요합니다."));
    }

    const userId = await resolveLogUserId({
      user_id: null,
      user_email: authUser.email,
      user_name: authUser.user_metadata?.full_name || authUser.user_metadata?.name || null,
      auth_user: authUser,
      bearer_token: getBearerToken(req),
    });

    const pac = await getPacificResetInfoCached();
    const row = await loadUserSecretsRow(userId);
    const secrets = _ensureGeminiSecretsShape(row.secrets);

    await ensureGeminiResetIfNeeded(userId, secrets);

    const keys = secrets.gemini.keyring.keys || [];
    const state = secrets.gemini.keyring.state || {};
    const exhaustedIds = state.exhausted_ids || {};

    return res.json(buildSuccess({
      pt_date: pac.pt_date,
      next_reset_utc: pac.next_reset_utc,
      key_count: keys.length,
      active_id: state.active_id || null,
      exhausted_count: Object.keys(exhaustedIds).length,
      exhausted_ids: exhaustedIds,
    }));
  } catch (e) {
    console.error("❌ /api/settings/gemini/status Error:", e.message);
    return res.status(500).json(buildError("GEMINI_STATUS_ERROR", "상태 조회 실패", e.message));
  }
});

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
// ✅ Naver Whitelist Tier System (v11.5.0 + bias_penalty)
// ─────────────────────────────
const whitelistPath = path.join(__dirname, "config", "naver_whitelist.json");
let _NAVER_WL_CACHE = { mtimeMs: 0, json: null };

function _stripWww(host) {
  return String(host || "").trim().toLowerCase().replace(/^www\./, "");
}

function _hostFromUrlish(urlish) {
  try {
    if (!urlish) return "";
    const s = String(urlish).trim();
    if (!s) return "";
    if (!s.includes("://")) return _stripWww(s);
    const u = new URL(s);
    return _stripWww(u.hostname);
  } catch {
    return _stripWww(urlish);
  }
}

function hostLooksOfficial(host) {
  if (!host) return false;
  const h = host.toLowerCase();
  return (
    h.endsWith(".go.kr") ||
    h.endsWith(".ac.kr") ||
    h.endsWith(".re.kr") ||
    h.endsWith(".or.kr") ||
    h.endsWith(".gov") ||
    h.endsWith(".edu")
  );
}

// ✅ exact match or subdomain match ONLY (evilchosun.com 같은 오탐 방지)
function _hostMatchesDomain(host, domain) {
  host = _stripWww(host);
  domain = _stripWww(domain);
  if (!host || !domain) return false;
  if (host === domain) return true;
  return host.endsWith("." + domain);
}

function loadNaverWhitelist() {
  try {
    const st = fs.statSync(whitelistPath);
    if (_NAVER_WL_CACHE.json && _NAVER_WL_CACHE.mtimeMs === st.mtimeMs) return _NAVER_WL_CACHE.json;

    const raw = fs.readFileSync(whitelistPath, "utf-8");
    const json = JSON.parse(raw);

    if (!json?.tiers || typeof json.tiers !== "object") {
      throw new Error("naver_whitelist.json missing 'tiers'");
    }

    _NAVER_WL_CACHE = { mtimeMs: st.mtimeMs, json };
    return json;
  } catch (e) {
    if (DEBUG) console.warn("⚠️ whitelist load failed:", e.message);
    return null;
  }
}

function _applyBiasPenalty(host, baseWeight, wl) {
  try {
    const bp = wl?.bias_penalty;
    if (!bp?.criteria || !bp?.sources) return { weight: baseWeight, penalties: [] };

    const penalties = [];
    let delta = 0;

    for (const [dom, flags] of Object.entries(bp.sources)) {
      if (!_hostMatchesDomain(host, dom)) continue;
      for (const f of (flags || [])) {
        const p = Number(bp.criteria[f] ?? 0);
        if (p) {
          delta += p; // 보통 음수
          penalties.push({ domain: dom, flag: f, delta: p });
        }
      }
    }

    return { weight: Math.max(0.1, baseWeight + delta), penalties };
  } catch {
    return { weight: baseWeight, penalties: [] };
  }
}

// ✅ Naver 타입별 가중치(필요시 조정)
const NAVER_TYPE_WEIGHTS = {
  news: 1.0,
  web: 0.9,
  encyc: 1.05,
};

// 🔹 (originallink/URL/host) 기준 티어/가중치(+bias_penalty) 찾기
function resolveNaverTier(urlOrHost) {
  const wl = loadNaverWhitelist();
  const host = _hostFromUrlish(urlOrHost);

  if (!wl || !host) return { tier: null, weight: 1, host, match_domain: null, bias_penalties: [] };

  const order = ["tier1", "tier2", "tier3", "tier4", "tier5"];
  for (const t of order) {
    const tierObj = wl.tiers?.[t];
    const domains = Array.isArray(tierObj?.domains) ? tierObj.domains : [];
    for (const d of domains) {
      if (_hostMatchesDomain(host, d)) {
        const base = Number(tierObj?.weight ?? 1);
        const bp = _applyBiasPenalty(host, base, wl);
        return {
          tier: t,
          weight: bp.weight,
          base_weight: base,
          host,
          match_domain: d,
          bias_penalties: bp.penalties,
        };
      }
    }
  }

  // tier 매칭은 없지만 bias source로 걸려있을 수도 있으니 penalty만 반영
  const bp = _applyBiasPenalty(host, 1, wl);
  return { tier: null, weight: bp.weight, base_weight: 1, host, match_domain: null, bias_penalties: bp.penalties };
}

// 🔹 (옵션) Naver 다중 쿼리 호출 제한
const NAVER_MULTI_MAX_QUERIES = parseInt(process.env.NAVER_MULTI_MAX_QUERIES || "3", 10);
const NAVER_MULTI_MAX_ITEMS = parseInt(process.env.NAVER_MULTI_MAX_ITEMS || "18", 10);

// 🔹 결과 중복 제거(링크 기준)
function uniqStrings(arr, max = 50) {
  const out = [];
  const seen = new Set();
  for (const v of (arr || [])) {
    const s = String(v || "").trim();
    if (!s) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= max) break;
  }
  return out;
}

function dedupeByLink(items = []) {
  const out = [];
  const seen = new Set();
  for (const it of (items || [])) {
    const key = String(it?.source_url || it?.link || "").trim();
    if (!key) continue;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(it);
  }
  return out;
}

// ✅ “쿼리 없으면 제외” + “calls 없으면 제외” + “results 0이면 제외”
function computeEnginesUsed({ enginesRequested, partial_scores, engineMetrics }) {
  const q = partial_scores?.engine_queries || {};
  const r = partial_scores?.engine_results || {};

  const used = [];
  const excluded = {};

  const hasQuery = (eng) => {
    const v = q?.[eng];
    if (Array.isArray(v)) return v.some((s) => String(s || "").trim().length > 0);
    if (typeof v === "string") return v.trim().length > 0;
    return false;
  };

  const callsOf = (eng) => {
    const c = engineMetrics?.[eng]?.calls;
    return (typeof c === "number" && Number.isFinite(c)) ? c : 0;
  };

  const resultsOf = (eng) => {
    const n = r?.[eng];
    return (typeof n === "number" && Number.isFinite(n)) ? n : 0;
  };

  for (const eng of (enginesRequested || [])) {
    if (!hasQuery(eng)) {
      excluded[eng] = { reason: "no_query" };
      continue;
    }
    if (callsOf(eng) <= 0) {
      excluded[eng] = { reason: "no_calls" };
      continue;
    }
    if (resultsOf(eng) <= 0) {
      excluded[eng] = { reason: "no_results" };
      continue;
    }
    used.push(eng);
  }

  return { used, excluded };
}

function engineQueriesPresent(q) {
  if (Array.isArray(q)) {
    return q.some((v) => String(v || "").trim().length > 0);
  }
  if (typeof q === "string") {
    return q.trim().length > 0;
  }
  return false;
}

// ─────────────────────────────
// ✅ External Engines + Fail-Grace Wrapper
// ─────────────────────────────
async function safeFetch(name, fn, q) {
  // ENGINE_RETRY_MAX=1 이면 총 2회 시도(기존과 동일)
  const attempts = Math.max(1, (parseInt(process.env.ENGINE_RETRY_MAX || String(ENGINE_RETRY_MAX || 1), 10) || 1) + 1);
  const baseMs = parseInt(process.env.ENGINE_RETRY_BASE_MS || String(ENGINE_RETRY_BASE_MS || 350), 10) || 350;

  for (let i = 0; i < attempts; i++) {
    try {
      // ✅ 엔진별 상한(Timebox) + Abort signal 전달
      // fn은 (q, {signal}) 형태면 signal을 axios/fetch에 넘길 수 있음(권장)
      // fn이 (q)만 받아도 JS는 추가 인자를 무시하므로 호환됨
      return await withTimebox(
        ({ signal }) => fn(q, { signal }),
        ENGINE_TIMEBOX_MS,
        name
      );
    } catch (err) {
      // ✅ 치명 오류는 즉시 중단
      if (err?._fatal) {
        await handleEngineFail(name, q, err.message);
        throw err;
      }

      const status = err?.response?.status;
      const code = err?.code || err?.name;

      const isTimeout =
        code === "TIMEBOX_TIMEOUT" || code === "ECONNABORTED" || code === "ERR_CANCELED";
      const isRetryableStatus =
        status === 408 || status === 429 || (typeof status === "number" && status >= 500);

      const shouldRetry = i < attempts - 1 && (isTimeout || isRetryableStatus || !status);

      if (!shouldRetry) {
        await handleEngineFail(name, q, err.message);
        return [];
      }

      if (DEBUG) {
        console.warn(`⚠️ ${name} retry (${i + 1}/${attempts}) :`, err?.message || err);
      }
      await sleep(baseMs * Math.pow(2, i)); // simple backoff
    }
  }

  // 논리상 도달하지 않지만 안전망
  await handleEngineFail(name, q, "unknown");
  return [];
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
//   - clientId / clientSecret은 (override 허용 시 body 우선) 없으면 vault(DB)에서 복호화해 사용
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

async function callNaver(query, clientId, clientSecret, ctx = {}) {
  const signal = ctx?.signal;
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
        signal,
      });

      let items =
        data?.items?.map((i) => {
          const cleanTitle = i.title?.replace(/<[^>]+>/g, "") || "";
          const cleanDesc = i.description?.replace(/<[^>]+>/g, "") || "";
          const link = i.link;

          const source_url = i.originallink || i.link; // ✅ news는 originallink가 진짜 출처
          const tierInfo = resolveNaverTier(source_url);
          const typeWeight = NAVER_TYPE_WEIGHTS[ep.type] ?? 1;

          // ✅ (패치) 화이트리스트에 없더라도 "공식 성격" 도메인이면 소프트 폴백으로 티어 부여
          let tier = tierInfo.tier;
          let tier_weight = tierInfo.weight;
          let whitelisted = !!tier;
          let inferred = false;

          if (!tier && hostLooksOfficial(tierInfo.host)) {
            tier = "tier2";
            tier_weight = 0.9;
            whitelisted = true;
            inferred = true;
          }

          return {
            title: cleanTitle,
            desc: cleanDesc,
            link,
            source_url,
            origin: "naver",
            naver_type: ep.type,

            // ✅ news만 pubDate가 옴
            pubDate: ep.type === "news" ? (i.pubDate || null) : null,

            // ✅ domain 판정은 항상 source_url(=originallink) 기준
            source_host: tierInfo.host || null,
            match_domain: tierInfo.match_domain || null,
            whitelisted,

            tier,
            tier_weight,
            type_weight: typeWeight,

            ...(inferred ? { _whitelist_inferred: true } : {}),
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
  err.publicMessage = "Naver client id / secret 인증에 실패했습니다. (올바른 키인지 확인하세요)";
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
async function fetchCrossref(q, ctx = {}) {
  const signal = ctx?.signal;
  const { data } = await axios.get(
    `https://api.crossref.org/works?query=${encodeURIComponent(q)}&rows=3`,
    { timeout: HTTP_TIMEOUT_MS, signal }
  );

  const items = data?.message?.items || [];
  return items
    .map((i) => {
      const title = i.title?.[0] || "";
      const year =
        i.issued?.["date-parts"]?.[0]?.[0] ||
        i["published-online"]?.["date-parts"]?.[0]?.[0] ||
        i["published-print"]?.["date-parts"]?.[0]?.[0] ||
        i.created?.["date-parts"]?.[0]?.[0] ||
        null;

      if (!title) return null;
      return year ? `${year} - ${title}` : title; // ✅ 문자열 포맷으로 연도 포함
    })
    .filter(Boolean);
}

async function fetchOpenAlex(q, ctx = {}) {
  const signal = ctx?.signal;
  const { data } = await axios.get(
    `https://api.openalex.org/works?search=${encodeURIComponent(q)}&per_page=3`,
    { timeout: HTTP_TIMEOUT_MS, signal }
  );

  const results = data?.results || [];
  return results
    .map((i) => {
      const title = i.display_name || "";
      const year = i.publication_year || null;
      if (!title) return null;
      return year ? `${year} - ${title}` : title; // ✅ 문자열 포맷으로 연도 포함
    })
    .filter(Boolean);
}

async function fetchWikidata(q, ctx = {}) {
  const signal = ctx?.signal;
  const { data } = await axios.get(
    `https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encodeURIComponent(
      q
    )}`,
    { timeout: HTTP_TIMEOUT_MS, signal }
  );
  return data?.search?.map((i) => i.label) || [];
}

// 🔹 GDELT 뉴스 기반 시의성 엔진
async function fetchGDELT(q, ctx = {}) {
  const signal = ctx?.signal;
  const { data } = await axios.get(
    `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q)}&format=json&maxrecords=3`,
    { timeout: HTTP_TIMEOUT_MS, signal }
  );

  return (
    data?.articles?.map((i) => {
      const d = parseGdeltSeenDate(i.seendate);
      return { title: i.title, date: d ? d.toISOString() : null };
    }) || []
  );
}

// 🔹 GitHub 리포 검색 엔진 (DV/CV용)
async function fetchGitHub(q, token, ctx = {}) {
  const signal = ctx?.signal;
  const headers = {
    "User-Agent": "CrossVerifiedAI",
  };

  if (!token) {
    throw new Error("GITHUB_TOKEN_REQUIRED");
  }
  headers.Authorization = `Bearer ${token}`;

  let data;
try {
  const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&per_page=3`;

  const resp = await axios.get(url, { headers, timeout: HTTP_TIMEOUT_MS, signal });

  data = resp.data;
} catch (e) {
  const s = e?.response?.status;

  // ✅ GitHub 토큰 불량/만료/권한없음 → 즉시 치명 오류로 중단
  if (s === 401 || s === 403) {
    const err = new Error("GITHUB_AUTH_ERROR");
    err.code = "GITHUB_AUTH_ERROR";
    err.httpStatus = 401;
    err.detail = { status: s };
    err.publicMessage = "GitHub token 인증에 실패했습니다. (토큰 만료/권한/형식 확인)";
    err._fatal = true;
    throw err;
  }

  throw e;
}

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

function getGeminiTimeoutMs(model, opts = {}) {
  const forced = opts?.timeoutMs;
  if (typeof forced === "number" && Number.isFinite(forced) && forced > 0) return forced;

  const m = String(model || "");
  const label = String(opts?.label || "");
  const isVerify = label.startsWith("verify:") || label.includes("verify:");

  if (isVerify) {
    if (m.includes("pro")) return GEMINI_TIMEOUT_VERIFY_PRO_MS;
    if (m.includes("flash-lite")) return GEMINI_TIMEOUT_VERIFY_FLASH_LITE_MS;
    return GEMINI_TIMEOUT_VERIFY_FLASH_MS;
  }

  if (m.includes("pro")) return GEMINI_TIMEOUT_PRO_MS;
  if (m.includes("flash-lite")) return GEMINI_TIMEOUT_FLASH_LITE_MS;
  return GEMINI_TIMEOUT_FLASH_MS;
}

// ✅ ADD: "model + key"로 직접 호출하는 raw
async function fetchGeminiRaw({ model, gemini_key, payload, opts = {} }) {
  const label = opts.label || `gemini:${model}`;
  const minChars = Number.isFinite(opts.minChars) ? opts.minChars : 1;

  // ✅ key를 URL(query)에 두지 말고 헤더로 (키 노출 리스크↓)
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

  const timeoutMs = getGeminiTimeoutMs(model, opts);

  const apiKey = String(gemini_key || "").trim();
  if (!apiKey) {
    const err = new Error(`${label}: GEMINI_KEY_MISSING`);
    err.code = "GEMINI_KEY_MISSING";
    throw err;
  }

  const maxRetries = Number.isFinite(opts.maxRetries) ? opts.maxRetries : ENGINE_RETRY_MAX;
  const baseMs = Number.isFinite(opts.retryBaseMs) ? opts.retryBaseMs : ENGINE_RETRY_BASE_MS;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const { data } = await withTimebox(
        ({ signal }) =>
          axios.post(url, payload, {
            timeout: timeoutMs,
            signal,
            headers: {
              "Content-Type": "application/json",
              ...(opts.headers || {}),
              "x-goog-api-key": apiKey,
            },
          }),
        timeoutMs,
        label
      );

      const text = extractGeminiText(data);
      if ((text || "").trim().length < minChars) {
        const finishReason = data?.candidates?.[0]?.finishReason;
        const blockReason = data?.promptFeedback?.blockReason;
        const err = new Error(
          `${label}: GEMINI_EMPTY_TEXT (finish=${finishReason || "?"}, block=${blockReason || "?"})`
        );
        err._gemini_empty = true;
        throw err; // ✅ 빈 텍스트는 retry하지 않음
      }

      return text;
    } catch (e) {
      const status = e?.response?.status;
      const code = e?.code || e?.name;

      // ✅ 인증/권한/요청형식 오류는 retry 금지 (rotating wrapper가 처리)
      if (status === 400 || status === 401 || status === 403 || status === 404) throw e;
      if (e?._gemini_empty) throw e;

      const isTimeout =
        code === "TIMEBOX_TIMEOUT" || code === "ECONNABORTED" || code === "ERR_CANCELED";
      const isRetryableStatus =
        status === 408 || status === 429 || (typeof status === "number" && status >= 500);

      const shouldRetry = attempt < maxRetries && (isTimeout || isRetryableStatus || !status);

      if (shouldRetry) {
        if (DEBUG) {
          console.warn(
            `⚠️ retryable error in ${label} (attempt=${attempt + 1}/${maxRetries + 1}):`,
            e?.message || e
          );
        }
        await sleep(baseMs * Math.pow(2, attempt)); // 간단 백오프
        continue;
      }

      throw e;
    }
  }
}

// ✅ ADD: Rotation wrapper
// - 우선순위: (1) 요청에서 gemini_key(keyHint) 왔으면 1회 시도 → (401/403/429)면 DB 키링으로
// - DB 키링은 (429/401/403)면 해당 key_id를 exhausted로 기록하고 다음 키로 자동교체
async function fetchGeminiRotating({ userId, keyHint, model, payload, opts = {} }) {
  const hint = String(keyHint || "").trim();

  // 0) hint key 1회 시도(옵션)
  if (hint) {
    try {
      return await fetchGeminiRaw({
        model,
        gemini_key: hint,
        payload,
        opts,
      });
    } catch (e) {
      const status = e?.response?.status;

      // ✅ hint 키가 불량(401/403) OR quota(429)면 DB 키링으로 넘어간다
      if (status === 429 || status === 401 || status === 403) {
        // 계속 진행(키링 시도)
      } else {
        console.error(
          "❌ Gemini call failed:",
          opts.label || `gemini:${model}`,
          geminiErrMessage(e)
        );
        throw e;
      }
    }
  }

  // hint가 없거나, hint가 quota/auth로 실패했는데 userId도 없으면 로테이션 불가
  if (!userId) {
    const err = new Error("GEMINI_USERID_REQUIRED_FOR_ROTATION");
    err.code = "GEMINI_KEY_EXHAUSTED";
    err.httpStatus = 200;
    err.detail = { reason: "userId_missing_or_unauthed" };
    throw err;
  }

  // 1) DB 키링에서 키를 뽑아가며 시도
  let lastErr = null;

  for (let attempt = 0; attempt < GEMINI_KEYRING_MAX; attempt++) {
    const kctx = await getGeminiKeyFromDB(userId); // {gemini_key, key_id, pt_date, next_reset_utc}

    try {
      const out = await fetchGeminiRaw({
        model,
        gemini_key: kctx.gemini_key,
        payload,
        opts: {
          ...opts,
          label: (opts.label || `gemini:${model}`) + `#${kctx.key_id}`,
        },
      });
      return out;
    } catch (e) {
      lastErr = e;
      const status = e?.response?.status;

      // ✅ 429(쿼터) 뿐 아니라 401/403(키 무효)도 해당 키를 탈락 처리하고 다음 키로
      if (status === 429 || status === 401 || status === 403) {
        try {
          const row = await loadUserSecretsRow(userId);
          const secrets = _ensureGeminiSecretsShape(row.secrets);
          await markGeminiKeyExhausted(userId, secrets, kctx.key_id, kctx.pt_date);
        } catch {}
        continue;
      }

      console.error(
        "❌ Gemini call failed:",
        opts.label || `gemini:${model}`,
        geminiErrMessage(e)
      );
      throw e;
    }
  }

  // 2) 여기까지 오면 키를 다 써버림
  const pac = await getPacificResetInfoCached();
  const err = new Error("GEMINI_ALL_KEYS_EXHAUSTED");
  err.code = "GEMINI_KEY_EXHAUSTED";
  err.httpStatus = 200;
  err.detail = {
    pt_date: pac.pt_date,
    next_reset_utc: pac.next_reset_utc,
    last_error: lastErr ? geminiErrMessage(lastErr) : null,
  };
  err._gemini_all_exhausted = true;
  throw err;
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
  gemini_key,
  userId // ✅ ADD
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

    const text = await fetchGeminiRotating({
  userId,                 // ✅ 아래에서 함수 시그니처를 userId 받게 바꿀 거라 여기선 임시
  keyHint: gemini_key,
  model: "gemini-2.5-pro",
  payload: { contents: [{ parts: [{ text: prompt }] }] },
});

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
  gemini_key,
  userId
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
`.trim();

    const text = await fetchGeminiRotating({
      userId,
      keyHint: gemini_key,
      model: "gemini-2.5-flash",
      payload: { contents: [{ parts: [{ text: prompt }] }] },
    });

    const trimmed = (text || "").trim();
    const jsonMatch = trimmed.match(/\{[\s\S]*\}/);
    const jsonText = jsonMatch ? jsonMatch[0] : trimmed;

    let parsed;
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      return [query];
    }

    const arr = Array.isArray(parsed.queries) ? parsed.queries : [];
    const cleaned = arr
      .map((s) => String(s).trim())
      .filter((s) => s.length > 0);

    return cleaned.length > 0 ? cleaned : [query];
  } catch (e) {
    if (DEBUG) console.warn("⚠️ buildGithubQueriesFromGemini fail:", e.message);
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

// ─────────────────────────────
// ✅ (추가) 블록 텍스트 상한 클립 (verify 흔들림 방지)
// ─────────────────────────────
function clipBlockText(s, max = 260) {
  const t = String(s || "").replace(/\s+/g, " ").trim();
  if (!t) return "";
  return t.length > max ? t.slice(0, max).trim() : t;
}

function buildNaverAndQuery(baseKo) {
  return String(baseKo || "")
    .replace(/[+]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function normSpace(s) {
  return String(s || "").replace(/\s+/g, " ").trim();
}

function limitChars(s, n) {
  const t = normSpace(s);
  if (!t) return "";
  return t.length > n ? t.slice(0, n).trim() : t;
}

function fallbackNaverQueryFromText(seed) {
  // '+' 금지 규칙도 반영
  const q = limitChars(buildNaverAndQuery(seed), 30);
  return q ? [q] : [];
}

const QVFV_MAX_BLOCKS = parseInt(process.env.QVFV_MAX_BLOCKS || "5", 10);
const BLOCK_NAVER_MAX_QUERIES = parseInt(process.env.BLOCK_NAVER_MAX_QUERIES || "2", 10);
const BLOCK_NAVER_MAX_ITEMS = parseInt(process.env.BLOCK_NAVER_MAX_ITEMS || "6", 10);

// ─────────────────────────────
// ✅ (패치) evidence 채택 규칙 (화이트리스트 + 타입 필터 + 관련도 + 상위 K)
// ─────────────────────────────
const BLOCK_EVIDENCE_TOPK = parseInt(process.env.BLOCK_EVIDENCE_TOPK || "3", 10); // 블록당 엔진별 evidence 상위 K
const BLOCK_NAVER_EVIDENCE_TOPK = parseInt(
  process.env.BLOCK_NAVER_EVIDENCE_TOPK || String(BLOCK_EVIDENCE_TOPK),
  10
); // 블록당 naver evidence 상위 K
const NAVER_RELEVANCE_MIN = parseFloat(process.env.NAVER_RELEVANCE_MIN || "0.1"); // 0~1

function topArr(arr, k) {
  const n = Number.isFinite(k) && k > 0 ? k : 3;
  return Array.isArray(arr) ? arr.slice(0, n) : [];
}

// ─────────────────────────────
// ✅ (패치) 숫자 블록이면: 선택된 근거 URL을 열어 "숫자 포함 발췌(evidence_text)" 생성
//   - 특정 사이트 하드코딩 없이 동작
//   - 선택된 TOPK URL만, 숫자 블록일 때만 fetch
// ─────────────────────────────
const NAVER_NUMERIC_FETCH = (process.env.NAVER_NUMERIC_FETCH ?? "true").toLowerCase() !== "false";
// ✅ 숫자/단위 감지 (숫자 발췌 패치용)
function hasNumberLike(text) {
  const s = String(text || "");
  return (
    /\d/.test(s) ||
    /%|퍼센트|만\s*명|명|대|원|달러|억원|조원|km|m\/s|GHz|MHz/.test(s)
  );
}

const NAVER_FETCH_TIMEOUT_MS = parseInt(process.env.NAVER_FETCH_TIMEOUT_MS || "5000", 10);
const EVIDENCE_EXCERPT_CHARS = parseInt(process.env.EVIDENCE_EXCERPT_CHARS || "700", 10);
const NAVER_NUMERIC_FETCH_MAX = parseInt(process.env.NAVER_NUMERIC_FETCH_MAX || "8", 10);

function isSafeExternalHttpUrl(u) {
  try {
    const url = new URL(u);
    const protoOk = url.protocol === "http:" || url.protocol === "https:";
    if (!protoOk) return false;

    const h = (url.hostname || "").toLowerCase();
    if (!h) return false;
    if (h === "localhost" || h.endsWith(".localhost")) return false;

    // basic private-range guards (SSRF 최소 방지)
    if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
      if (/^(10\.|127\.|169\.254\.|192\.168\.)/.test(h)) return false;
      if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(h)) return false;
    }
    if (h.startsWith("::1") || h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) return false;

    return true;
  } catch {
    return false;
  }
}

function stripHtmlToText(html) {
  return (html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;?/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function makeNumberTokens(blockText) {
  const raw = (String(blockText || "").match(/[\d][\d,\.]*/g) || []).filter(Boolean);
  const cleaned = raw.map((s) => s.replace(/,/g, "")).filter(Boolean);
  // 원문(콤마 포함) + 콤마 제거 버전 둘 다
  return Array.from(new Set([...raw, ...cleaned]));
}

function extractExcerptContainingNumbers(pageText, blockText, maxChars = 700) {
  const t = String(pageText || "");
  if (!t) return null;

  const tokens = makeNumberTokens(blockText);
  for (const num of tokens) {
    const idx = t.indexOf(num);
    if (idx >= 0) {
      const start = Math.max(0, idx - Math.floor(maxChars * 0.4));
      const end = Math.min(t.length, idx + Math.floor(maxChars * 0.6));
      return t.slice(start, end).trim();
    }
  }

  // 숫자가 그대로 안 맞으면 키워드(최대 6개)로라도 발췌
  const kw = String(blockText || "")
    .split(/\s+/)
    .map((w) => w.trim())
    .filter((w) => w.length >= 2)
    .slice(0, 6);

  for (const k of kw) {
    const idx = t.indexOf(k);
    if (idx >= 0) {
      const start = Math.max(0, idx - Math.floor(maxChars * 0.4));
      const end = Math.min(t.length, idx + Math.floor(maxChars * 0.6));
      return t.slice(start, end).trim();
    }
  }

  return null;
}

async function fetchReadableText(url, timeoutMs = 5000, ctx = {}) {
  const signal = ctx?.signal;
  try {
    const r = await axios.get(url, {
      timeout: timeoutMs,
      signal,
      maxContentLength: 1024 * 1024,
      maxBodyLength: 1024 * 1024,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; CrossVerifiedAI/1.0)"
      }
    });
    return stripHtmlToText(r.data);
  } catch {
    return null;
  }
}

function isTimeSensitiveText(text) {
  const s = String(text || "");

  // ✅ 상대/실시간/속보성 키워드
  if (/(최근|요즘|오늘|어제|내일|현재|지금|최신|업데이트|발표|논란|속보|실시간|뉴스)/.test(s)) return true;

  // ✅ 명시적 “날짜/기간” (연도 단독은 제외)
  if (/(\d{4}[.\-\/]\d{1,2}[.\-\/]\d{1,2}|\d{1,2}\s*월\s*\d{1,2}\s*일|\d{4}\s*년\s*\d{1,2}\s*월|지난\s*(주|달|해|년)|이번\s*(주|달|해)|작년|올해|내년)/.test(s)) return true;

  // ✅ 시세/가격류 (연도 없어도 시의성 필요)
  return /(가격|시세|환율|주가|금리|기준금리|랭킹|순위)/.test(s);
}

function extractKeywords(text, max = 12) {
  const s = String(text || "")
    .replace(/<[^>]+>/g, " ")
    .replace(/[+]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!s) return [];

  // 한글(2자+), 영문(3자+), 숫자(2자+) 토큰 추출
  const raw = s.match(/[가-힣]{2,}|[A-Za-z]{3,}|\d{2,}/g) || [];
  const stop = new Set([
    "그리고","하지만","또한","대한","관련","대한민국","한국","사용자","질문","블록","내용",
    "the","and","for","with","from","that","this","are","was","were","has","have"
  ]);

  const out = [];
  const seen = new Set();
  for (const t of raw) {
    const w = t.trim();
    if (!w) continue;
    if (stop.has(w)) continue;
    if (seen.has(w)) continue;
    seen.add(w);
    out.push(w);
    if (out.length >= max) break;
  }
  return out;
}

function keywordHitRatio(haystack, keywords) {
  const text = String(haystack || "").toLowerCase();
  const ks = Array.isArray(keywords) ? keywords : [];
  if (!ks.length) return 0;

  let hit = 0;
  for (const k of ks) {
    const kk = String(k || "").toLowerCase();
    if (!kk) continue;
    if (text.includes(kk)) hit++;
  }
  return hit / ks.length; // 0~1
}

function pickTopNaverEvidenceForVerify({
  items,
  query,
  blockText,
  naverQueries,
  allowNews,
  topK,
  minRelevance,
}) {
  const list = Array.isArray(items) ? items : [];
  const K = Number.isFinite(topK) && topK > 0 ? topK : 3;
  const minRel = Number.isFinite(minRelevance) ? minRelevance : 0.15;

  const kw = extractKeywords([query, blockText, ...(naverQueries || [])].join(" "), 14);
  const needNum = hasNumberLike(blockText) || hasNumberLike(query);

  const scored = [];
  for (const it of list) {
    const isWhitelisted = !!it?.tier; // ✅ 화이트리스트 밖은 evidence 제외(표시는 OK)
    if (!isWhitelisted) continue;

    if (!allowNews && it?.naver_type === "news") continue; // ✅ 시사성 질문에서만 news 허용

    const text = `${it?.title || ""} ${it?.desc || ""}`;
    const rel = keywordHitRatio(text, kw);

    if (rel < minRel) continue; // ✅ 무관한 결과(의대/비트코인 등) evidence에서 제외

    const baseW =
      (typeof it?.tier_weight === "number" && Number.isFinite(it.tier_weight) ? it.tier_weight : 1) *
      (typeof it?.type_weight === "number" && Number.isFinite(it.type_weight) ? it.type_weight : 1);

    const hasNum = hasNumberLike(text);
    const numFactor = needNum ? (hasNum ? 1.15 : 0.8) : 1.0;

    // 최종 점수: (도메인/타입 가중치) × 관련도 × (수치근거 우선)
    const score = baseW * (0.6 + 0.4 * rel) * numFactor;

    scored.push({ it, score });
  }

  scored.sort((a, b) => b.score - a.score);

  return scored.slice(0, K).map((x) => x.it);
}

async function preprocessQVFVOneShot({ mode, query, core_text, gemini_key, modelName, userId }) {
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

  const text = await fetchGeminiRotating({
    userId,
    keyHint: gemini_key,
    model: modelName || "gemini-2.5-flash",
    payload: { contents: [{ parts: [{ text: prompt }] }] },
  });

  const trimmed = (text || "").trim();
  const jsonMatch = trimmed.match(/\{[\s\S]*\}/);
  const jsonText = jsonMatch ? jsonMatch[0] : trimmed;

  let parsed = null;
  try { parsed = JSON.parse(jsonText); } catch { parsed = null; }

  const answer_ko = String(parsed?.answer_ko || "").trim();
  const korean_core = String(parsed?.korean_core || "").trim() || normalizeKoreanQuestion(baseCore);
  const english_core = String(parsed?.english_core || "").trim() || String(query || "").trim();

   let blocksRaw = Array.isArray(parsed?.blocks) ? parsed.blocks : [];

let blocks = blocksRaw
  .slice(0, QVFV_MAX_BLOCKS)
  .map((b, idx) => {
    const eq = b?.engine_queries || {};

    // ✅ engine query 기본값/길이제한 강제
    const crossrefQ = limitChars(eq.crossref || english_core, 90);
    const openalexQ = limitChars(eq.openalex || english_core, 90);
    const wikidataQ = limitChars(eq.wikidata || korean_core, 50);
    const gdeltQ    = limitChars(eq.gdelt   || english_core, 120);

    // ✅ naver는 배열/문자열 모두 수용 + '+' 제거 + 30자 제한
    let naverArr = Array.isArray(eq.naver)
      ? eq.naver
      : (typeof eq.naver === "string" ? [eq.naver] : []);

    naverArr = naverArr
      .map((s) => limitChars(buildNaverAndQuery(s), 30))
      .filter(Boolean)
      .slice(0, BLOCK_NAVER_MAX_QUERIES);

    // ✅ 핵심: 전처리 결과가 비어도 naver 쿼리 1개는 보장
    // (block.text → korean_core 순으로 seed)
    if (naverArr.length === 0) {
      const seed = String(b?.text || "").trim() || korean_core;
      naverArr = fallbackNaverQueryFromText(seed).slice(0, BLOCK_NAVER_MAX_QUERIES);
    }

    const text = clipBlockText(String(b?.text || "").trim(), 260);

    return {
      id: Number.isFinite(Number(b?.id)) ? Number(b.id) : (idx + 1),
      text,
      engine_queries: {
        crossref: crossrefQ,
        openalex: openalexQ,
        wikidata: wikidataQ,
        gdelt: gdeltQ,
        naver: naverArr,
      },
    };
  })
  .filter((b) => b.text);

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
app.post("/api/verify", verifyRateLimit, enforceVerifyPayloadLimits, requireVerifyAuth, guardProdKeyUuid, async (req, res) => {
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
  return res
    .status(401)
    .json(buildError("UNAUTHORIZED", "로그인이 필요합니다. (Authorization: Bearer <token>)"));
}

logUserId = await resolveLogUserId({
  user_id,
  user_email,
  user_name,
  auth_user: authUser,
  bearer_token: getBearerToken(req), // ✅ Bearer localtest 같은 값도 로그 식별에 사용
});

if (!logUserId) {
  return res.status(400).json(
    buildError(
      "VALIDATION_ERROR",
      "로그 식별자(user) 확정 실패: Authorization Bearer 토큰 또는 DEFAULT_USER_ID가 필요합니다."
    )
  );
}

// ✅ per-user vault에서 Naver / K-Law / GitHub / DeepL 키 복호화
const secretsRow = await loadUserSecretsRow(logUserId);
let userSecrets = _ensureIntegrationsSecretsShape(_ensureGeminiSecretsShape(secretsRow.secrets));
const vault = decryptIntegrationsSecrets(userSecrets);

const naverIdFinal = (naver_id && String(naver_id).trim()) || vault.naver_id;
const naverSecretFinal = (naver_secret && String(naver_secret).trim()) || vault.naver_secret;
const klawKeyFinal = (klaw_key && String(klaw_key).trim()) || vault.klaw_key;
const githubTokenFinal = (github_token && String(github_token).trim()) || vault.github_token;

const geminiKeysCount = (userSecrets?.gemini?.keyring?.keys || []).length;

// ✅ 모드별 필수키 검증(body → vault 순서)
if ((safeMode === "qv" || safeMode === "fv") && (!naverIdFinal || !naverSecretFinal)) {
  return res.status(400).json(
    buildError(
      "VALIDATION_ERROR",
      "QV/FV 모드에서는 Naver client id / secret이 필요합니다. (설정 저장 또는 body 포함)"
    )
  );
}

if (safeMode === "lv" && !klawKeyFinal) {
  return res
    .status(400)
    .json(buildError("VALIDATION_ERROR", "LV 모드에서는 klaw_key가 필요합니다. (설정 저장 또는 body 포함)"));
}

if ((safeMode === "dv" || safeMode === "cv") && !githubTokenFinal) {
  return res.status(400).json(
    buildError("VALIDATION_ERROR", "DV/CV 모드에서는 github_token이 필요합니다. (설정 저장 또는 body 포함)")
  );
}

if (!logUserId) {
  return res.status(400).json(
    buildError(
      "VALIDATION_ERROR",
      "로그 식별자(user) 확정 실패: Authorization Bearer 토큰 또는 DEFAULT_USER_ID가 필요합니다."
    )
  );
}

// ✅ ADD: Gemini 키는 (1) body로 오거나 (2) DB keyring에 있어야 함
if (safeMode !== "lv") {
  const hasHint = !!(gemini_key && String(gemini_key).trim());
  if (!hasHint) {
    const keysCount = geminiKeysCount;

    if (!keysCount) {
      return res.status(400).json(
        buildError(
          "VALIDATION_ERROR",
          "Gemini 키가 없습니다. 앱 설정에서 Gemini 키를 저장하거나, 요청 바디에 gemini_key를 포함하세요."
        )
      );
    }
  }
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
  userId: logUserId, // ✅ ADD
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

  const ko = normalizeKoreanQuestion(baseCore);
  const en = String(baseCore).trim();

  const makeBlock = (id, txt) => {
    const text = clipBlockText(txt, 260);
    // ✅ 전처리 실패여도 naver 쿼리는 1개 보장 (짧으면 1블록만 남아도 naver가 살아있게)
    const naverQ = fallbackNaverQueryFromText(text || ko);
    return {
      id,
      text,
      engine_queries: {
        crossref: limitChars(en, 90),
        openalex: limitChars(en, 90),
        wikidata: limitChars(ko, 50),
        gdelt: limitChars(en, 120),
        naver: naverQ.slice(0, BLOCK_NAVER_MAX_QUERIES),
      },
    };
  };

  qvfvPre = {
    answer_ko: "",
    korean_core: ko,
    english_core: en,
    blocks: [
      makeBlock(1, t1),
      makeBlock(2, t2),
    ].filter((b) => b.text),
  };
}

    // ✅ 블록별 엔진 호출 → verify에 넣을 “블록+증거” 패키지 구성
    external.crossref = [];
    external.openalex = [];
    external.wikidata = [];
    external.gdelt = [];
    external.naver = [];

const engineQueriesUsed = {
  crossref: [],
  openalex: [],
  wikidata: [],
  gdelt: [],
  naver: [],
};

const blocksForVerify = [];

// ✅ 쿼리가 비면 아예 호출하지 않고 result=[]로 처리 (calls 안 늘어남)
const runOrEmpty = async (name, fn, q) => {
  const qq = String(q || "").trim();
  if (!qq) return { result: [], ms: 0, skipped: true };
  return await safeFetchTimed(name, fn, qq, engineTimes, engineMetrics);
};

for (const b of (qvfvPre.blocks || [])) {
  const eq = b.engine_queries || {};

const qCrossref = String(eq.crossref || "").trim();
const qOpenalex = String(eq.openalex || "").trim();
const qWikidata = String(eq.wikidata || "").trim();
const qGdelt   = String(eq.gdelt   || "").trim();

  // ✅ 엔진별 쿼리 기록(빈 값 제외)
  if (qCrossref) engineQueriesUsed.crossref.push(qCrossref);
  if (qOpenalex) engineQueriesUsed.openalex.push(qOpenalex);
  if (qWikidata) engineQueriesUsed.wikidata.push(qWikidata);
  if (qGdelt) engineQueriesUsed.gdelt.push(qGdelt);

let naverQueries = Array.isArray(eq.naver) ? eq.naver : [];
naverQueries = naverQueries
  .map((q) => limitChars(buildNaverAndQuery(q), 30))
  .filter(Boolean)
  .slice(0, BLOCK_NAVER_MAX_QUERIES);

// ✅ 핵심: 혹시 여기까지 왔는데도 비면, 최소 1개는 생성해서 Naver 호출이 끊기지 않게
if (!naverQueries.length) {
  const seed = String(b?.text || "").trim() || qvfvPre?.korean_core || qvfvBaseText || query;
  naverQueries = fallbackNaverQueryFromText(seed).slice(0, BLOCK_NAVER_MAX_QUERIES);
}

  // ✅ 네이버 쿼리 기록(빈 값 제외)
  for (const nq of naverQueries) {
    const s = String(nq || "").trim();
    if (s) engineQueriesUsed.naver.push(s);
  }

  const [crPack, oaPack, wdPack, gdPack] = await Promise.all([
    runOrEmpty("crossref", fetchCrossref, qCrossref),
    runOrEmpty("openalex", fetchOpenAlex, qOpenalex),
    runOrEmpty("wikidata", fetchWikidata, qWikidata),
    runOrEmpty("gdelt", fetchGDELT, qGdelt),
  ]);

    // ─────────────────────────────
  // ✅ Naver 결과: 표시용(all)과 verify용(topK + whitelist + relevance) 분리
  // ─────────────────────────────
  let naverItemsAll = [];
  for (const nq0 of naverQueries) {
    const nq = String(nq0 || "").trim();
    if (!nq) continue;

    const { result } = await safeFetchTimed(
      "naver",
      (qq, ctx) => callNaver(qq, naverIdFinal, naverSecretFinal, ctx),
      nq,
      engineTimes,
      engineMetrics
    );
    if (Array.isArray(result) && result.length) naverItemsAll.push(...result);
  }
  naverItemsAll = dedupeByLink(naverItemsAll).slice(0, BLOCK_NAVER_MAX_ITEMS);

  // ✅ 시사성(최신/발표/연도/가격 등)일 때만 news evidence 허용
  const allowNewsEvidence = isTimeSensitiveText(`${query} ${b?.text || ""}`);

  // ✅ verify에 넣을 naver evidence는:
  //  - 화이트리스트(tier 있음)만
  //  - news는 시사성일 때만
  //  - 관련도 최소치 이상만
  //  - 상위 K개만
  const naverItemsForVerify = pickTopNaverEvidenceForVerify({
    items: naverItemsAll,
    query,
    blockText: b?.text || "",
    naverQueries,
    allowNews: allowNewsEvidence,
    topK: BLOCK_NAVER_EVIDENCE_TOPK,
    minRelevance: NAVER_RELEVANCE_MIN,
  });

  // ✅ 뉴스 엔진(gdelt)도 시사성일 때만 evidence로 사용(표시는 external에 유지)
  const gdeltForVerify = allowNewsEvidence ? topArr(gdPack.result, BLOCK_EVIDENCE_TOPK) : [];

  external.crossref.push(...(crPack.result || []));
  external.openalex.push(...(oaPack.result || []));
  external.wikidata.push(...(wdPack.result || []));
  external.gdelt.push(...(gdPack.result || []));
  external.naver.push(...(naverItemsAll || []));

  blocksForVerify.push({
    id: b.id,
    text: b.text,
    queries: {
      crossref: qCrossref,
      openalex: qOpenalex,
      wikidata: qWikidata,
      gdelt: qGdelt,
      naver: naverQueries
    },
    evidence: {
      crossref: topArr(crPack.result, BLOCK_EVIDENCE_TOPK),
      openalex: topArr(oaPack.result, BLOCK_EVIDENCE_TOPK),
      wikidata: topArr(wdPack.result, 5), // wikidata는 구조상 조금 더 허용
      gdelt: gdeltForVerify,
      naver: naverItemsForVerify,
    },
  });
}

external.naver = dedupeByLink(external.naver).slice(0, NAVER_MULTI_MAX_ITEMS);
qvfvBlocksForVerifyFull = blocksForVerify;

// ✅ 엔진별 쿼리를 partial_scores.engine_queries에 “전부” 저장
partial_scores.engine_queries = {
  crossref: uniqStrings(engineQueriesUsed.crossref, 12),
  openalex: uniqStrings(engineQueriesUsed.openalex, 12),
  wikidata: uniqStrings(engineQueriesUsed.wikidata, 12),
  gdelt: uniqStrings(engineQueriesUsed.gdelt, 12),
  naver: uniqStrings(engineQueriesUsed.naver, 12),
};

// ✅ (이 위치로 이동!) 엔진별 "결과 개수" 기록 + engines_used/excluded 계산
partial_scores.engine_results = {
  crossref: Array.isArray(external.crossref) ? external.crossref.length : 0,
  openalex: Array.isArray(external.openalex) ? external.openalex.length : 0,
  wikidata: Array.isArray(external.wikidata) ? external.wikidata.length : 0,
  gdelt: Array.isArray(external.gdelt) ? external.gdelt.length : 0,
  naver: Array.isArray(external.naver) ? external.naver.length : 0,
};

// ✅ 메트릭/타임 누적도 여기서 확정 저장(호출 끝난 뒤 값이 들어있음)
partial_scores.engine_times = engineTimes;
partial_scores.engine_metrics = engineMetrics;

// ✅ “쿼리 없으면 제외” + “calls 없으면 제외” + “results 0이면 제외”
const enginesRequested = [...engines];
const { used: enginesUsed, excluded: enginesExcluded } = computeEnginesUsed({
  enginesRequested,
  partial_scores,
  engineMetrics,
});

partial_scores.engines_requested = enginesRequested;
partial_scores.engines_used = enginesUsed;
partial_scores.engines_excluded = enginesExcluded;

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

    const rec = calcCompositeRecency({
  mode: safeMode,
  gdelt: external.gdelt,
  naver: external.naver,
  crossref: external.crossref,
  openalex: external.openalex,
});
partial_scores.recency = rec.overall;
partial_scores.recency_detail = rec.detail;

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
  safeMode, query, answerText, gemini_key, logUserId
);
    const ms_q = Date.now() - t_q;
    recordTime(geminiTimes, "github_query_builder_ms", ms_q);
    recordMetric(geminiMetrics, "github_query_builder", ms_q);

    // ✅ GitHub 검색(최대 3쿼리)
    for (const q of (ghQueries || []).slice(0, 3)) {
      const { result } = await safeFetchTimed(
        "github",
          (qq, ctx) => fetchGitHub(qq, githubTokenFinal, ctx),
        q,
        engineTimes,
        engineMetrics
      );
      if (Array.isArray(result) && result.length) external.github.push(...result);
    }

    external.github = (external.github || []).slice(0, 12);

const rec = calcCompositeRecency({
  mode: safeMode,
  github: external.github,
});
partial_scores.recency = rec.overall;
partial_scores.recency_detail = rec.detail;

        partial_scores.validity =
      (Array.isArray(external.github) && external.github.length > 0)
        ? calcValidityScore(external.github)
        : null;
    partial_scores.github_queries = ghQueries;
partial_scores.engine_queries = {
  github: uniqStrings(Array.isArray(ghQueries) ? ghQueries : [], 12),
};

// ✅ DV/CV도 engines_used 계산(쿼리/calls/results 기준)
partial_scores.engine_results = {
  github: Array.isArray(external.github) ? external.github.length : 0,
};

// QV/FV처럼 로그용으로 얘네도 남겨두면 Admin UI에서 보기 편함
partial_scores.engine_times = engineTimes;
partial_scores.engine_metrics = engineMetrics;

const enginesRequested = [...engines];
const { used: enginesUsed, excluded: enginesExcluded } = computeEnginesUsed({
  enginesRequested,
  partial_scores,
  engineMetrics,
});

partial_scores.engines_requested = enginesRequested;
partial_scores.engines_used = enginesUsed;
partial_scores.engines_excluded = enginesExcluded;

    // ✅ consistency (Gemini Pro)
    const t_cons = Date.now();
    partial_scores.consistency = await calcConsistencyFromGemini(
  safeMode,
  query,
  answerText,
  external.github,
  gemini_key,
  logUserId
);
    const ms_cons = Date.now() - t_cons;
    recordTime(geminiTimes, "consistency_ms", ms_cons);
    recordMetric(geminiMetrics, "consistency", ms_cons);

    break;
  }

  case "lv": {
    engines.push("klaw");
     external.klaw = await fetchKLawAll(klawKeyFinal, query);

    let lvSummary = null;
        if (gemini_key || geminiKeysCount > 0) {
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
        lvSummary = await fetchGeminiRotating({
  userId: logUserId,
  keyHint: gemini_key,
  model: "gemini-2.5-flash-lite",
  payload: { contents: [{ parts: [{ text: prompt }] }] },
});
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

// ✅ 이후 로직(보정계수/로그/응답)은 enginesUsed를 기준으로 사용


    // ─────────────────────────────
    // ② LV 모드는 TruthScore/가중치 계산 없이 바로 반환
    // ─────────────────────────────
   if (safeMode === "lv") {
  const elapsed = Date.now() - start;

// ✅ LV도 Gemini 총합(ms) 계산 (Flash-Lite 요약 등 포함)
partial_scores.gemini_total_ms = Object.values(geminiTimes)
  .filter((v) => typeof v === "number" && Number.isFinite(v))
  .reduce((s, v) => s + v, 0);

partial_scores.gemini_times = geminiTimes;
partial_scores.gemini_metrics = geminiMetrics;

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
    const enginesForCorrection = Array.isArray(partial_scores.engines_used)
  ? partial_scores.engines_used.filter((x) => x !== "klaw")
  : engines.filter((x) => x !== "klaw");

if (enginesForCorrection.length > 0) {
  engineStatsMap = await fetchEngineStatsMap(enginesForCorrection);
  engineFactor = computeEngineCorrectionFactor(enginesForCorrection, engineStatsMap); // 0.9~1.1
  partial_scores.engine_factor = engineFactor;
  partial_scores.engine_factor_engines = enginesForCorrection;
} else {
  engineFactor = 1.0;
  partial_scores.engine_factor = 1.0;
  partial_scores.engine_factor_engines = [];
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
    flash = await fetchGeminiRotating({
  userId: logUserId,
  keyHint: gemini_key,
  model: answerModelUsed,
  payload: { contents: [{ parts: [{ text: flashPrompt }] }] },
});
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
        flash = await fetchGeminiRotating({
  userId: logUserId,
  keyHint: gemini_key,
  model: answerModelUsed,
  payload: { contents: [{ parts: [{ text: flashPrompt }] }] },
});
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
      // ✅ (패치) 숫자 블록이면: 선택된 Naver evidence URL을 열어 "숫자 포함 발췌(evidence_text)"를 채움
      // - 특정 사이트 고정 없이 동작
      // - 숫자 블록일 때만, TOPK URL만, 총 fetch 수 제한
      if (NAVER_NUMERIC_FETCH && (safeMode === "qv" || safeMode === "fv") && Array.isArray(blocksForVerify) && blocksForVerify.length > 0) {
        let budget = NAVER_NUMERIC_FETCH_MAX;

        for (const b of blocksForVerify) {
          if (budget <= 0) break;
          if (!hasNumberLike(b?.text) && !hasNumberLike(query)) continue;

          const naverEvs = Array.isArray(b?.evidence?.naver) ? b.evidence.naver.slice(0, 3) : [];
          for (const ev of naverEvs) {
            if (budget <= 0) break;
            if (ev?.evidence_text) continue;

            const url = ev?.source_url || ev?.link;
            if (!url) continue;
            if (!isSafeExternalHttpUrl(url)) continue;

            const pageText = await withTimebox(
  ({ signal }) => fetchReadableText(url, NAVER_FETCH_TIMEOUT_MS, { signal }),
  NAVER_FETCH_TIMEOUT_MS,
  "naver_numeric_fetch"
);

const excerpt = extractExcerptContainingNumbers(pageText, b?.text || "", EVIDENCE_EXCERPT_CHARS);

            if (excerpt) {
              ev.evidence_text = excerpt;
              budget -= 1;
            }
          }
        }
      }


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
${safeVerifyInputForGemini(verifyInput, VERIFY_INPUT_CHARS)}

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
         - (중요) evidence 항목에 evidence_text가 있으면, 해당 URL에서 추출한 짧은 본문 발췌입니다. 수치/팩트 검증에 우선 사용하세요.
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
      verify = await fetchGeminiRotating({
  userId: logUserId,
  keyHint: gemini_key,
  model: m,
  payload: verifyPayload,
  opts: { label: `verify:${m}`, minChars: 20 },
});
verifyModelUsed = m;
      verifyModelUsed = m; // ✅ 실제 성공 모델 기록
      break;
    } catch (e) {
      const status = e?.response?.status;

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

const enginesUsedSet = new Set(
  Array.isArray(partial_scores.engines_used) ? partial_scores.engines_used : engines
);

const useGdelt = enginesUsedSet.has("gdelt");
const useNaver = enginesUsedSet.has("naver");

const R_t =
  (safeMode === "qv" || safeMode === "fv" || safeMode === "dv" || safeMode === "cv") &&
  typeof partial_scores.recency === "number"
    ? Math.max(0, Math.min(1, partial_scores.recency))
    : 1.0;

const N =
  (safeMode === "qv" || safeMode === "fv") &&
  useNaver &&
  typeof partial_scores.naver_tier_factor === "number"
    ? Math.max(0.9, Math.min(1.05, partial_scores.naver_tier_factor))
    : 1.0;

    // DV/CV: GitHub 유효성 Vᵣ, 없으면 0.7 중립값
        const useGithub = enginesUsedSet.has("github");

    const V_r =
      (safeMode === "dv" || safeMode === "cv") &&
      useGithub &&
      typeof partial_scores.validity === "number"
        ? Math.max(0, Math.min(1, partial_scores.validity))
        : 0.7;

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
      const rawHybrid = R_t * combined * C;
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
const enginesForWeight = Array.isArray(partial_scores.engines_used)
  ? partial_scores.engines_used.filter((x) => x !== "klaw")
  : engines.filter((x) => x !== "klaw");

await Promise.all(
  enginesForWeight.map((eName) => {
    const adjRaw =
      typeof perEngineAdjust?.[eName] === "number" &&
      Number.isFinite(perEngineAdjust[eName])
        ? perEngineAdjust[eName]
        : 1.0;

    const adj = Math.max(0.9, Math.min(1.1, adjRaw));
    const engineTruth = Math.max(0, Math.min(1, hybrid * adj));

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

// ✅ gemini 단계별 타임/메트릭도 로그로 남김 (Admin UI에서 사용)
partial_scores.gemini_times = geminiTimes;
partial_scores.gemini_metrics = geminiMetrics;

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
    engines: (Array.isArray(partial_scores.engines_used) ? partial_scores.engines_used : engines),
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
 engines: (Array.isArray(partial_scores.engines_used) ? partial_scores.engines_used : engines),
engines_requested: partial_scores.engines_requested || engines,
  partial_scores: normalizedPartial,
  flash_summary: flash,
  verify_raw: verify,
  gemini_verify_model: verifyModelUsed, // ✅ 실제로 성공한 모델
  engine_times: engineTimes,
  engine_metrics: engineMetrics,
};

// ✅ debug: effective config & whitelist meta (Render env: DEBUG_EFFECTIVE_CONFIG=1)
if (process.env.DEBUG_EFFECTIVE_CONFIG === "1") {
  const wl = loadNaverWhitelist();
  const wlHasKosis =
    !!wl &&
    Object.values(wl.tiers || {}).some(
      (t) => Array.isArray(t?.domains) && t.domains.includes("kosis.kr")
    );

    payload.effective_config = {
    NAVER_RELEVANCE_MIN,
    BLOCK_EVIDENCE_TOPK,
    BLOCK_NAVER_EVIDENCE_TOPK,

    // (패치) 숫자 블록 발췌
    NAVER_NUMERIC_FETCH,
    NAVER_FETCH_TIMEOUT_MS,
    EVIDENCE_EXCERPT_CHARS,
    NAVER_NUMERIC_FETCH_MAX,

    whitelist_version: wl?.version || null,
    whitelist_lastUpdate: wl?.lastUpdate || null,
    whitelist_has_kosis: wlHasKosis,
  };
}

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

// ✅ NAVER id/secret 인증 오류는 401로 명확히 반환
if (e?.code === "NAVER_AUTH_ERROR") {
  return res.status(401).json(
    buildError(
      "NAVER_AUTH_ERROR",
      "네이버 API 인증 실패 (ID/Secret 확인 필요)",
      e?.detail || e?.message
    )
  );
}

// ✅ httpStatus/publicMessage/detail 있으면 그대로 반환 (최상위 catch)
// - httpStatus는 number/string 모두 허용
const passStatus =
  typeof e?.httpStatus === "number"
    ? e.httpStatus
    : (typeof e?.httpStatus === "string" && /^\d+$/.test(e.httpStatus) ? Number(e.httpStatus) : null);

if (Number.isFinite(passStatus) && (e?._fatal || e?.publicMessage || e?.detail)) {
  return res.status(passStatus).json(
    buildError(
      e.code || "FATAL_ERROR",
      e.publicMessage || "요청을 처리할 수 없습니다.",
      e.detail ?? e.message
    )
  );
}

// 기본 처리: 가능한 status를 반영하되, 메시지는 과도하게 노출하지 않음
const status =
  (Number.isFinite(passStatus) && passStatus) ||
  (typeof e?.status === "number" ? e.status : undefined) ||
  (typeof e?.response?.status === "number" ? e.response.status : undefined) ||
  500;

return res.status(status).json(buildError("INTERNAL_SERVER_ERROR", "서버 내부 오류 발생", e?.message));
  }
});

// ✅ 번역 테스트 라우트 (간단형, 백호환용)
app.post("/api/translate", async (req, res) => {
  try {
    const { user_id, text, targetLang, deepl_key, gemini_key } = req.body;

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

  // ✅ 2) DeepL / Gemini 키 확보: (1) body, (2) 없으면 로그인+vault/keyring
    const authUser = await getSupabaseAuthUser(req);
const userId = await resolveLogUserId({
  user_id,
  user_email: authUser?.email || null,
  user_name: authUser?.user_metadata?.full_name || authUser?.user_metadata?.name || null,
  auth_user: authUser,
  bearer_token: getBearerToken(req),
});


    let deeplKeyFinal = (deepl_key || "").toString().trim() || null;
    let geminiKeyFinal = (gemini_key || "").toString().trim() || null;

    // DeepL 키가 body에 없으면 vault에서
    if (!deeplKeyFinal && userId) {
      const row = await loadUserSecretsRow(userId);
      const s = _ensureIntegrationsSecretsShape(_ensureGeminiSecretsShape(row.secrets));
      const v = decryptIntegrationsSecrets(s);
      deeplKeyFinal = (v.deepl_key || "").toString().trim() || null;
    }

    // Gemini 키가 body에 없으면 keyring에서
    if (!geminiKeyFinal && userId) {
      const kctx = await getGeminiKeyFromDB(userId); // { gemini_key, key_id, pt_date, next_reset_utc }
      geminiKeyFinal = (kctx.gemini_key || "").toString().trim() || null;
    }

    // ✅ 3) 최소 하나는 필요(DeepL 또는 Gemini)
    // - deeplKeyFinal이 있으면 DeepL 우선으로 돌아가고, 실패 시 Gemini fallback에만 geminiKeyFinal이 쓰임
    if (!deeplKeyFinal && !geminiKeyFinal) {
      return sendError(
        res,
        400,
        "VALIDATION_ERROR",
        "deepl_key 또는 gemini_key(또는 로그인 후 DB keyring 저장된 Gemini 키)가 필요합니다.",
        "Need deepl_key or gemini key (body or keyring)"
      );
    }

    // 4) 간단형 번역 (기존 동작 유지)
    const result = await translateText(
      text,
      targetLang ?? null,
      deeplKeyFinal ?? null,
      geminiKeyFinal ?? null
    );


    // 5) 성공 응답 (ⅩⅤ 규약: buildSuccess 사용)
    return res.json(
      buildSuccess({
        translated: result.text,
        engine: result.engine,
        targetLang: result.target || (targetLang?.toUpperCase() || "EN"),
      })
    );
  } catch (e) {
    console.error("❌ /api/translate Error:", e.message);

    // ✅ 키링 소진은 /api/verify와 동일하게 200 + 코드로 내려주기
    if (e?.code === "GEMINI_KEY_EXHAUSTED") {
      return res.status(200).json(
        buildError(
          "GEMINI_KEY_EXHAUSTED",
          "Gemini 키의 일일 할당량이 소진되었습니다. (키 로테이션/리셋 확인 필요)",
          e.detail || e.message
        )
      );
    }

    // ✅ 서버 암호화키 누락/불량 같은 치명 오류는 즉시 반환
    if (e?._fatal && e?.httpStatus) {
      return res.status(e.httpStatus).json(
        buildError(
          e.code || "FATAL_ERROR",
          e.publicMessage || "요청을 처리할 수 없습니다.",
          e.detail || e.message
        )
      );
    }

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

      const summaryText = await fetchGeminiRotating({
  userId: null,            // ✅ docs는 지금 auth/userId 흐름이 없어서: (아래 9번에서 userId 연결 추천)
  keyHint: gemini_key,
  model: "gemini-2.5-flash",
  payload: { contents: [{ parts: [{ text: prompt }] }] },
});

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
app.get("/admin/dashboard", ensureAuthOrAdminToken, async (req, res) => {
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
app.get("/admin/engine-stats", ensureAuthOrAdminToken, async (req, res) => {
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
app.post("/admin/engine-stats/override", ensureAuthOrAdminToken, async (req, res) => {
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
app.get("/admin/naver-whitelist", ensureAuthOrAdminToken, async (req, res) => {
  return res.json(
    buildSuccess({
      whitelist: whitelistData || { tiers: {} },
    })
  );
});

// Naver 도메인 tier 테스트용 (어드민)
app.get("/admin/naver-test-domain", ensureAuthOrAdminToken, (req, res) => {
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
app.get("/admin/ui", ensureAuthOrAdminToken, async (req, res) => {
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
app.get("/api/test-db", requireDiag, async (_, res) => {
  try {
    const c = await pgPool.connect();

    const r1 = await c.query("SELECT NOW() as now");
    const r2 = await c.query("select to_regclass('public.session_store') as session_store");

    c.release();

    return res.json(
      buildSuccess({
        message: "✅ DB 연결 성공",
        time: r1.rows[0].now,
        session_store: r2.rows[0].session_store,
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

app.get("/health", async (req, res) => {
  const diag = process.env.NODE_ENV !== "production" || isDiagAuthorized(req);

  let pac = { pt_date: null, next_reset_utc: null };
  if (diag) {
    try { pac = await getPacificResetInfoCached(); } catch {}
  }

  return res.status(200).json({
    status: "ok",
    version: "v18.4.0-pre",
    uptime: process.uptime().toFixed(2) + "s",
    timestamp: new Date().toISOString(),
    ...(diag ? {
      region: REGION,
      pacific_pt_date: pac.pt_date,
      pacific_next_reset_utc: pac.next_reset_utc,
    } : {}),
  });
});

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

// ✅ 세션이 "진짜로 DB에 써지는지" 테스트 (cookie + DB row 확인)
app.get("/api/test-session", requireDiag, async (req, res) => {
  try {
    if (!req.session) {
      return res.status(500).json(
        buildError("SESSION_NOT_INITIALIZED", "세션 미들웨어가 초기화되지 않았습니다.")
      );
    }

    // saveUninitialized:false 이므로 "값을 변경"해야 DB에 저장됨
    req.session.__test_counter = (req.session.__test_counter || 0) + 1;
    req.session.__test_last = new Date().toISOString();

    // 저장 완료까지 기다려야 DB 조회가 의미 있음
    await new Promise((resolve, reject) => {
      req.session.save((err) => (err ? reject(err) : resolve()));
    });

    const sid = req.sessionID;

    // DB에 row가 생겼는지 확인 (테이블/컬럼이 다르면 에러 메시지로 내려줌)
    let dbRow = null;
    let storedInDb = false;
    try {
      const r = await pgPool.query(
        "SELECT sid, expire FROM public.session_store WHERE sid=$1 LIMIT 1",
        [sid]
      );
      dbRow = r.rows?.[0] || null;
      storedInDb = !!dbRow?.sid;
    } catch (e) {
      dbRow = { db_check_error: e.message };
    }

    return res.json(
      buildSuccess({
        message: "✅ session write test ok",
        sid,
        counter: req.session.__test_counter,
        last: req.session.__test_last,
        stored_in_db: storedInDb,
        db_row: dbRow,
      })
    );
  } catch (e) {
    return res.status(500).json(
      buildError("TEST_SESSION_ERROR", "세션 테스트 실패", e.message)
    );
  }
});


// ─────────────────────────────
// ✅ (선택 권장) API 404도 JSON으로 통일
//   - /api/* 중 라우트에 매칭 안 되면 여기로 옴
// ─────────────────────────────
app.use("/api", (req, res) => {
  return res.status(404).json(
    buildError(
      "API_NOT_FOUND",
      "존재하지 않는 API입니다.",
      { method: req.method, path: req.originalUrl }
    )
  );
});

// ─────────────────────────────
// ✅ (선택 권장) 전역 에러도 JSON으로 통일 (Express Error Handler)
//   - 반드시 "모든 라우트 선언이 끝난 뒤" + "app.listen 전"에 위치해야 함
// ─────────────────────────────
app.use((err, req, res, next) => {
  const p = String(req.originalUrl || "");
const wantsJson = p.startsWith("/api") || p.startsWith("/admin");
  if (!wantsJson) {
    // admin/ejs 같은 화면 요청은 기존처럼 텍스트로 내보내고 싶으면 이렇게 둬도 됨
    // (원하면 여기도 JSON으로 바꿔도 됨)
    return res.status(err?.status || 500).send("Server error");
  }

  // body parser JSON 파싱 실패
  if (err?.type === "entity.parse.failed") {
    return res.status(400).json(
      buildError("INVALID_JSON", "JSON 파싱에 실패했습니다.", err?.message)
    );
  }

  // body size 초과
  if (err?.type === "entity.too.large") {
    return res.status(413).json(
      buildError("PAYLOAD_TOO_LARGE", "요청 바디가 너무 큽니다.", err?.message)
    );
  }

  // 기본값
  const status = err?.httpStatus || err?.status || 500;
  const code = err?.code || (status >= 500 ? "INTERNAL_SERVER_ERROR" : "REQUEST_ERROR");
  const message =
    err?.publicMessage ||
    (status >= 500
      ? "서버 내부 오류가 발생했습니다. 잠시 후 다시 시도해 주세요."
      : (err?.message || "요청 처리 중 오류가 발생했습니다."));

  const detail = DEBUG ? { message: err?.message, stack: err?.stack } : (err?.detail || null);

  return res.status(status).json(buildError(code, message, detail));
});

app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v18.4.0-pre running on port ${PORT}`);
  console.log("🔹 LV 모듈 외부화 (/src/modules/klaw_module.js)");
  console.log(
    "🔹 Translation 모듈 활성화 (DeepL + Gemini Flash-Lite Fallback)"
  );
    console.log("🔹 Naver 서버 직접 호출 (Region 제한 해제)");
  console.log("🔹 Supabase + Gemini 2.5 (Flash / Pro / Lite) 정상 동작");
});

app.use((err, req, res, next) => {
  console.error("💥 unhandled express error:", err);

  if (res.headersSent) return next(err);

  const status = err?.status || err?.statusCode || 500;

  // 운영: 내부 디테일/스택 숨김
  if (isProd) {
    return res.status(status).json(buildError("INTERNAL_SERVER_ERROR", "Server error"));
  }

  // 개발: 디테일 노출 허용
  return res.status(status).json(buildError("INTERNAL_SERVER_ERROR", err?.message || "Server error", {
    stack: err?.stack || null,
  }));
});
