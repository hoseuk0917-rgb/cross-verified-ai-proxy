// =======================================================
// Cross-Verified AI Proxy — v18.4.0-pre
// (Full Extended + LV External Module + Translation + Naver Region Detection)
// =======================================================

function __printFatal(tag, err) {
  try {
    const out =
      err && err.stack ? String(err.stack)
      : err && err.message ? String(err.message)
      : String(err);

    process.stderr.write(`${tag}\n${out}\n`);
  } catch (_e) {
    try { process.stderr.write(`${tag}\n${String(err)}\n`); } catch {}
  }
}

process.on("unhandledRejection", (reason) => {
  __printFatal("⚠️ UnhandledRejection:", reason);
});

process.on("uncaughtException", (err) => {
  __printFatal("💥 UncaughtException:", err);
  process.exitCode = 1;
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

// ─────────────────────────────
// ✅ Translation Module (DeepL v2 + safe return)
//   - DeepL key가 :fx 면 api-free, 아니면 api
//   - 실패하면 throw 하지 않고 engine:"none"으로 돌려서 상위에서 Gemini fallback 가능하게 함
// ─────────────────────────────

const DEEPL_TIMEOUT_MS = parseInt(process.env.DEEPL_TIMEOUT_MS || "25000", 10);

function _normTargetLang(t) {
  const s = String(t || "").trim().toUpperCase();
  // DeepL은 보통 EN/KO/JA/DE/FR 등, 지역코드(EN-US)도 지원
  return s || "EN";
}

function _deeplBaseForKey(key) {
  let k = String(key || "").trim();
  if (!k) return null;

  // 따옴표로 감싸진 채 저장된 경우 대비
  if ((k.startsWith('"') && k.endsWith('"')) || (k.startsWith("'") && k.endsWith("'"))) {
    k = k.slice(1, -1).trim();
  }

  // Free 키는 보통 ":fx" (대소문자 무시)
  const lower = k.toLowerCase();
  return lower.endsWith(":fx") ? "https://api-free.deepl.com" : "https://api.deepl.com";
}

// ✅ 기존 호출부 호환용 시그니처 유지: (text, targetLang, deepl_key, gemini_key)
//   - gemini_key는 여기서는 사용 안 함 (상위에서 fallback 처리)
async function translateText(text, targetLang, deepl_key, _gemini_key_unused) {
  const input = String(text ?? "");
  const key = String(deepl_key || "").trim();
  const tgt = _normTargetLang(targetLang);

  if (!key) {
    return { text: input, engine: "none", target: tgt, error: "DEEPL_KEY_MISSING" };
  }

  const base = _deeplBaseForKey(key);
  if (!base) {
    return { text: input, engine: "none", target: tgt, error: "DEEPL_BASE_RESOLVE_FAILED" };
  }

  const url = `${base}/v2/translate`;

  try {
    const params = new URLSearchParams();
    params.append("text", input);
    params.append("target_lang", tgt);

    const resp = await axios.post(url, params, {
      timeout: DEEPL_TIMEOUT_MS,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        // DeepL 공식 권장: Authorization: DeepL-Auth-Key <key>
        Authorization: `DeepL-Auth-Key ${key}`,
        // 일부 구현 호환용(있어도 무해)
        "DeepL-Auth-Key": key,
      },
      validateStatus: () => true,
    });

    const ok = resp.status >= 200 && resp.status < 300;
    const out = resp?.data?.translations?.[0]?.text;

    if (ok && out && String(out).trim()) {
      return {
        text: String(out),
        engine: "deepl",
        target: tgt,
        meta: {
          detected_source_language: resp?.data?.translations?.[0]?.detected_source_language ?? null,
          status: resp.status,
          base,
        },
      };
    }

    const msg =
      (typeof resp?.data === "string" ? resp.data :
        resp?.data?.message || resp?.data?.error || JSON.stringify(resp?.data || {}));

    return {
      text: input,
      engine: "none",
      target: tgt,
      error: `DEEPL_HTTP_${resp.status}:${String(msg).slice(0, 200)}`,
      meta: { status: resp.status, base },
    };
  } catch (e) {
    return {
      text: input,
      engine: "none",
      target: tgt,
      error: `DEEPL_EXCEPTION:${e?.message || String(e)}`,
    };
  }
}

// ─────────────────────────────
// ✅ Timeout / retry / timebox utils
// ─────────────────────────────
const HTTP_TIMEOUT_MS = parseInt(process.env.HTTP_TIMEOUT_MS || "12000", 10);
const ENGINE_TIMEBOX_MS = parseInt(process.env.ENGINE_TIMEBOX_MS || "25000", 10); // 엔진 1개 상한
const GEMINI_TIMEOUT_MS = parseInt(process.env.GEMINI_TIMEOUT_MS || "45000", 10); // Gemini는 더 길게
const GEMINI_QVFV_PRE_MODEL = process.env.GEMINI_QVFV_PRE_MODEL || "gemini-2.0-flash-lite";
const GEMINI_VERIFY_MODEL    = process.env.GEMINI_VERIFY_MODEL    || "gemini-2.0-flash";

const ENGINE_RETRY_MAX = parseInt(process.env.ENGINE_RETRY_MAX || "1", 10); // 0~1 권장
const ENGINE_RETRY_BASE_MS = parseInt(process.env.ENGINE_RETRY_BASE_MS || "350", 10);
const ENABLE_VERIFY_CACHE = String(process.env.ENABLE_VERIFY_CACHE || "0") === "1";
const VERIFY_CACHE_TTL_MS = parseInt(process.env.VERIFY_CACHE_TTL_MS || "120000", 10); // 2분
const VERIFY_CACHE_MAX = parseInt(process.env.VERIFY_CACHE_MAX || "50", 10);
const ENABLE_WIKIDATA_QVFV = String(process.env.ENABLE_WIKIDATA_QVFV || "0") === "1"; // 기본 OFF

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

const __k = String(process.env.SETTINGS_ENC_KEY_B64 || "").trim();
console.log(`🔐 SETTINGS_ENC_KEY_B64 present=${__k.length > 0} len=${__k.length}`);

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
const SETTINGS_ENC_KEY_B64 = (
  process.env.SETTINGS_ENC_KEY_B64 ||
  process.env.USER_SECRETS_ENC_KEY_B64 ||
  process.env.ENCRYPTION_KEY ||
  process.env.APP_ENC_KEY ||
  process.env.SETTINGS_ENCRYPTION_KEY ||
  process.env.YOUR_EXISTING_ENV_NAME ||   // ✅ 너가 쓰던 기존 이름(예: APP_ENC_KEY_B64 같은 것)
  ""
).trim(); // base64(32bytes)

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
const SESSION_SECRET =
  String(process.env.SESSION_SECRET || "").trim() || "dev-secret";

if (isProd && SESSION_SECRET === "dev-secret") {
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
// ✅ S-14: naver non-whitelist / inferred-official factors (single source of truth)
const NAVER_NON_WHITELIST_FACTOR = parseFloat(
  process.env.NAVER_NON_WHITELIST_FACTOR || process.env.NAVER_NONWHITELIST_WEIGHT || "0.55"
); // 비화이트리스트 기본 감점(권장 0.5~0.7)

const NAVER_INFERRED_OFFICIAL_FACTOR = parseFloat(
  process.env.NAVER_INFERRED_OFFICIAL_FACTOR || process.env.NAVER_INFERRED_OFFICIAL_WEIGHT || "0.85"
); // "공식처럼 보임" 소프트 가중치(권장 0.75~0.9)


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

// ===== Rate limit & body size config =====
const RATE_LIMIT_MAX_VERIFY = 40;        // /api/verify, /api/verify-snippet
const RATE_LIMIT_MAX_TRANSLATE = 40;     // /api/translate
const RATE_LIMIT_MAX_DOCS_ANALYZE = 20;  // /api/docs/analyze   ← 새로 추가

const BODY_JSON_LIMIT = process.env.BODY_JSON_LIMIT || "4mb";
const BODY_URLENC_LIMIT = process.env.BODY_URLENC_LIMIT || BODY_JSON_LIMIT;

app.use(express.json({ limit: BODY_JSON_LIMIT }));
app.use(express.urlencoded({ extended: true, limit: BODY_URLENC_LIMIT }));

// ===== Rate limit for main API endpoints =====
app.use(
  "/api/verify",
  makeRateLimiter("verify", RATE_LIMIT_MAX_VERIFY)
);

app.use(
  "/api/verify-snippet",
  makeRateLimiter("verify-snippet", RATE_LIMIT_MAX_VERIFY)
);

app.use(
  "/api/translate",
  makeRateLimiter("translate", RATE_LIMIT_MAX_TRANSLATE)
);

app.use(
  "/api/docs/analyze",
  makeRateLimiter("docs-analyze", RATE_LIMIT_MAX_DOCS_ANALYZE)
);

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

function hash16(s) {
  try {
    return crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 16);
  } catch {
    return "";
  }
}

// =======================================================
// ✅ S-17: short TTL in-memory cache (for repeated QV/FV tests)
// =======================================================
const __verifyCache = new Map(); // key -> { t:number, v:payload }

function makeVerifyCacheKey({ mode, query, rawQuery, user_answer, answerText, key_uuid }) {
  const obj = {
    v: 1,
    mode: String(mode || ""),
    query: String(query || ""),
    rawQuery: String(rawQuery || ""),
    user_answer: String(user_answer || ""),
    answerText: String(answerText || ""),
    key_uuid: String(key_uuid || ""),
  };
  const s = JSON.stringify(obj);
  return `vc:${hash16(s)}`;
}

function verifyCacheGet(key) {
  if (!ENABLE_VERIFY_CACHE) return null;
  if (!key) return null;

  const ent = __verifyCache.get(key);
  if (!ent) return null;

  const ttl = Math.max(0, VERIFY_CACHE_TTL_MS | 0);
  if (ttl > 0 && (Date.now() - ent.t) > ttl) {
    __verifyCache.delete(key);
    return null;
  }
  return ent.v || null;
}

function verifyCacheSet(key, payload) {
  if (!ENABLE_VERIFY_CACHE) return;
  if (!key) return;

  // 오래된 것부터 밀어내기(Map은 insertion order 유지)
  const max = Math.max(1, VERIFY_CACHE_MAX | 0);
  while (__verifyCache.size >= max) {
    const oldestKey = __verifyCache.keys().next().value;
    if (!oldestKey) break;
    __verifyCache.delete(oldestKey);
  }

  __verifyCache.set(key, { t: Date.now(), v: payload });
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
    const b = getJsonBody(req);

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

async function requireVerifyAuth(req, res, next) {
  if (!isProd) return next();

  const tok = (getBearerToken(req) || "").trim();

  // 운영에서 localtest 같은 디버그 토큰 차단
  if (tok && tok.toLowerCase() === "localtest") {
    return res.status(401).json(buildError("UNAUTHORIZED", "Invalid token"));
  }

  // 세션 로그인(패스포트) 통과
  if (req.user) return next();

  // (선택) admin 토큰(=DIAG_TOKEN or DEV_ADMIN_TOKEN) 우회 허용
  if (isAdminOverride(req)) return next();

  // Bearer가 없으면 거절
  if (!tok) {
    return res.status(401).json(buildError("UNAUTHORIZED", "Authorization required"));
  }

  // ✅ Bearer가 있으면 "Supabase JWT"로 검증해서만 통과
  const authUser = await getSupabaseAuthUser(req);
  if (authUser) return next();

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

      engines_requested: input.partial_scores.engines_requested ?? null,
      engines_used: input.partial_scores.engines_used ?? null,
      engines_excluded: input.partial_scores.engines_excluded ?? null,

      engine_exclusion_reasons: input.partial_scores.engine_exclusion_reasons ?? null,
      engine_explain: input.partial_scores.engine_explain ?? null,

      engines_used_pre: input.partial_scores.engines_used_pre ?? null,
engines_excluded_pre: input.partial_scores.engines_excluded_pre ?? null,
engine_exclusion_reasons_pre: input.partial_scores.engine_exclusion_reasons_pre ?? null,

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

/// ✅ ADD: Secret Encrypt/Decrypt (AES-256-GCM)
// - encrypt: "첫 번째로 잡힌" 키로 암호화
// - decrypt: env에 있는 "여러 키 후보"를 순서대로 시도 (키 마이그레이션/중복 대비)

function _sha256_16(buf) {
  try {
    return crypto.createHash("sha256").update(buf).digest("hex").slice(0, 16);
  } catch {
    return null;
  }
}

function _parseEncKeyRaw(raw) {
  const s = String(raw || "").trim();
  if (!s) return null;

  // 1) base64(32 bytes) 시도
  try {
    const b = Buffer.from(s, "base64");
    if (b.length === 32) return b;
  } catch {}

  // 2) hex(64 chars => 32 bytes) 시도
  if (/^[0-9a-fA-F]{64}$/.test(s)) {
    try {
      const b = Buffer.from(s, "hex");
      if (b.length === 32) return b;
    } catch {}
  }

  // 3) utf8(정확히 32 bytes) 시도
  try {
    const b = Buffer.from(s, "utf8");
    if (b.length === 32) return b;
  } catch {}

  return null;
}

function _collectEncKeyCandidates() {
  // ✅ 우선순위: "DB를 암호화할 때 쓰던 키"가 먼저 오게 해야 함
  // - Render에 SETTINGS_ENC_KEY_B64가 있는 경우가 많아서 상단 배치
  const envNames = [
    "USER_SECRETS_ENC_KEY_B64",
    "SETTINGS_ENC_KEY_B64",
    "USER_SECRETS_ENC_KEY",
    "USER_SECRETS_MASTER_KEY",
    "APP_ENC_KEY",
    "ENCRYPTION_KEY",
    "SETTINGS_ENCRYPTION_KEY",
  ];

  const all = [];

  for (const env of envNames) {
    const raw = String(process.env[env] || "").trim();
    if (!raw) continue;

    let key = null;
    let fmt = null;

    // 1) base64 → 32 bytes
    try {
      const b = Buffer.from(raw, "base64");
      if (b.length === 32) {
        key = b;
        fmt = "base64";
      }
    } catch {}

    // 2) hex(64 chars) → 32 bytes
    if (!key && /^[0-9a-fA-F]{64}$/.test(raw)) {
      key = Buffer.from(raw, "hex");
      fmt = "hex";
    }

    // 3) utf8(정확히 32 bytes)
    if (!key) {
      const b = Buffer.from(raw, "utf8");
      if (b.length === 32) {
        key = b;
        fmt = "utf8";
      }
    }

    all.push({
      env,
      parsed: !!key,
      fmt,
      raw_len: raw.length,
      key_len: key ? key.length : 0,
      sha256_16: key ? crypto.createHash("sha256").update(key).digest("hex").slice(0, 16) : null,
      key, // ✅ _getEncKey()가 cands[0].key로 쓰는 값
    });
  }

  const cands = all.filter((x) => x.parsed && x.key && x.key.length === 32);

  if (!cands.length) {
    const e = new Error("USER_SECRETS_ENC_KEY_MISSING");
    e.code = "USER_SECRETS_ENC_KEY_MISSING";
    e.httpStatus = 500;
    e._fatal = true;
    e.publicMessage =
      "서버 암호화 키(env)가 없습니다. (USER_SECRETS_ENC_KEY_B64/SETTINGS_ENC_KEY_B64/ENCRYPTION_KEY 등 확인 필요)";
    e.detail = {
      candidates: all.map(({ env, parsed, fmt, raw_len, key_len, sha256_16 }) => ({
        env,
        parsed,
        fmt,
        raw_len,
        key_len,
        sha256_16,
      })),
    };
    throw e;
  }

  // ✅ 첫 번째 후보가 곧 실제 사용 키가 됨 ( _getEncKey()가 cands[0].key )
  return cands;
}

function _getEncKey() {
  // 기존 호출부 호환 유지: "대표 키(첫 후보)"만 반환
  const cands = _collectEncKeyCandidates();
  return cands[0].key;
}

function encryptSecret(plaintext) {
  const cands = _collectEncKeyCandidates();
  const key = cands[0].key;

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

  const ivB64 = String(enc.iv || "");
  const tagB64 = String(enc.tag || "");
  const ctB64 = String(enc.ct || "");

  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const ct = Buffer.from(ctB64, "base64");

  // ✅ 최소 무결성 체크
  if (!iv.length || !tag.length || !ct.length) {
    const err = new Error("USER_SECRETS_ENC_BLOB_INVALID");
    err.code = "USER_SECRETS_ENC_BLOB_INVALID";
    err._fatal = true;
    err.httpStatus = 500;
    err.publicMessage = "저장된 키링/볼트 데이터 형식이 올바르지 않습니다. (iv/tag/ct 누락 또는 손상)";
    err.detail = { iv_len: iv.length, tag_len: tag.length, ct_len: ct.length };
    throw err;
  }

  const cands = _collectEncKeyCandidates();

  // ✅ 여러 키 후보로 복호화 시도 (키 변경/이중 세팅 대비)
  for (const cand of cands) {
    try {
      const decipher = crypto.createDecipheriv("aes-256-gcm", cand.key, iv);
      decipher.setAuthTag(tag);
      const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
      return pt.toString("utf8");
    } catch (_) {
      // 다음 후보로 계속
    }
  }

  // 전부 실패
  const err = new Error("USER_SECRETS_DECRYPT_FAILED");
  err.code = "USER_SECRETS_DECRYPT_FAILED";
  err._fatal = true;
  err.httpStatus = 500;
  err.publicMessage =
    "서버 암호화 키(env)가 DB에 저장된 키링/볼트 데이터와 일치하지 않거나, 저장된 암호문이 손상되었습니다. (SETTINGS_ENC_KEY_B64 / USER_SECRETS_ENC_KEY / ENCRYPTION_KEY 값 확인 필요)";
  err.detail = {
    cause: "Unsupported state or unable to authenticate data",
    alg: "aes-256-gcm",
    key_candidates: cands.map((x) => ({ source: x.source, sha256_16: x.sha16 })),
    iv_len: iv.length,
    tag_len: tag.length,
    ct_len: ct.length,
  };
  throw err;
}

// ─────────────────────────────
// ✅ ADD: Enc key diagnostics (for /health diag only)
// - 절대 "키 값"은 노출하지 않고 sha256 일부만 노출
// ─────────────────────────────
function getEncKeyDiagInfo() {
  const ENV_NAMES = [
    "USER_SECRETS_ENC_KEY_B64",
    "SETTINGS_ENC_KEY_B64",
    "USER_SECRETS_ENC_KEY",
    "USER_SECRETS_MASTER_KEY",
    "APP_ENC_KEY",
    "ENCRYPTION_KEY",
    "SETTINGS_ENCRYPTION_KEY",
  ];

  const sha16 = (buf) => {
    try {
      return crypto.createHash("sha256").update(buf).digest("hex").slice(0, 16);
    } catch {
      return null;
    }
  };

  const parseKey = (raw) => {
    const s = String(raw || "").trim();
    if (!s) return null;

    // 1) base64(32 bytes)
    try {
      const b = Buffer.from(s, "base64");
      if (b.length === 32) return b;
    } catch {}

    // 2) hex(64 chars => 32 bytes)
    if (/^[0-9a-fA-F]{64}$/.test(s)) {
      try {
        const b = Buffer.from(s, "hex");
        if (b.length === 32) return b;
      } catch {}
    }

    // 3) utf8(정확히 32 bytes)
    try {
      const b = Buffer.from(s, "utf8");
      if (b.length === 32) return b;
    } catch {}

    return null;
  };

  const candidates = [];
  for (const name of ENV_NAMES) {
    const raw = String(process.env[name] || "").trim();
    if (!raw) continue;

    const k = parseKey(raw);
    if (k && k.length === 32) {
      candidates.push({
        env: name,
        parsed: true,
        key_len: k.length,
        sha256_16: sha16(k),
      });
    } else {
      candidates.push({
        env: name,
        parsed: false,
        reason: "present_but_not_32bytes",
      });
    }
  }

  // ✅ 실제 서버가 쓰는 "선택된 키"(_getEncKey 기준)도 같이 표시
  let selected = null;
  try {
    const k0 = _getEncKey(); // Buffer(32) or throw
    const s0 = sha16(k0);
    const matched = candidates.find((c) => c.parsed && c.sha256_16 === s0) || null;

    selected = {
      key_len: k0?.length || 0,
      sha256_16: s0,
      matched_env: matched?.env || null,
    };
  } catch (e) {
    selected = {
      error: true,
      code: e?.code || "ENC_KEY_ERROR",
      message: e?.publicMessage || e?.message || String(e),
    };
  }

  return {
    ok: true,
    provider: process.env.USER_SECRETS_PROVIDER || "supabase",
    enc_ver_env: process.env.USER_SECRETS_ENC_VER || null,
    selected,
    candidates,
  };
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
    secrets.gemini.keyring = {
  keys: [],
  state: { active_id: null, exhausted_ids: {}, invalid_ids: {}, last_reset_pt_date: null, rate_limited_until: {} }
};
  }
  if (!Array.isArray(secrets.gemini.keyring.keys)) secrets.gemini.keyring.keys = [];
  if (!secrets.gemini.keyring.state || typeof secrets.gemini.keyring.state !== "object") {
    secrets.gemini.keyring.state = { active_id: null, exhausted_ids: {}, invalid_ids: {}, last_reset_pt_date: null, rate_limited_until: {} };
  }
  if (!secrets.gemini.keyring.state.exhausted_ids || typeof secrets.gemini.keyring.state.exhausted_ids !== "object") {
  secrets.gemini.keyring.state.exhausted_ids = {};
}
if (!secrets.gemini.keyring.state.invalid_ids || typeof secrets.gemini.keyring.state.invalid_ids !== "object") {
  secrets.gemini.keyring.state.invalid_ids = {};
}

// ✅ ADD: 429 쿨다운 상태 저장소(없으면 초기화)
if (!secrets.gemini.keyring.state.rate_limited_until || typeof secrets.gemini.keyring.state.rate_limited_until !== "object") {
  secrets.gemini.keyring.state.rate_limited_until = {};
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

function _geminiHttpStatus(e) {
  return e?.response?.status ?? e?.status ?? e?.httpStatus ?? null;
}

function _isGeminiRateLimit(e) {
  return _geminiHttpStatus(e) === 429;
}

function _isGeminiAuthKeyInvalid(e) {
  const s = _geminiHttpStatus(e);
  if (s === 401 || s === 403) return true;

  const msg = String(e?.message || e?.publicMessage || "");
  return /API key not valid|invalid api key|API_KEY_INVALID/i.test(msg);
}

// Gemini 에러 문자열에 자주 들어오는 "Please retry in 56.8s / 549ms" 파싱
function _parseGeminiRetryAfterMs(e) {
  const msg = String(e?.message || "");
  let m = msg.match(/retry in\s+([0-9.]+)\s*ms/i);
  if (m) return Math.max(0, Math.floor(parseFloat(m[1])));

  m = msg.match(/retry in\s+([0-9.]+)\s*s/i);
  if (m) return Math.max(0, Math.floor(parseFloat(m[1]) * 1000));

  const ra = e?.response?.headers?.["retry-after"] ?? e?.response?.headers?.["Retry-After"];
  if (ra != null) {
    const sec = parseFloat(String(ra));
    if (Number.isFinite(sec)) return Math.max(0, Math.floor(sec * 1000));
  }
  return null;
}

async function ensureGeminiResetIfNeeded(userId, secrets) {
  const pac = await getPacificResetInfoCached();
  const pt_date_now = pac.pt_date;

  const state = secrets?.gemini?.keyring?.state || {};
  const last = state.last_reset_pt_date;

    // PT 날짜가 바뀌면 exhausted 초기화
  // (last가 null이어도 날짜가 잡히면 바로 초기화되게)
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
  const invalid = state.invalid_ids || {};

  // ✅ 429 쿨다운 키는 일정 시간 후보에서 제외
  const rateLimitedUntil = state.rate_limited_until || {};
  const nowMs = Date.now();

  if (!keys.length) return { keyId: null, enc: null, keysCount: 0 };

  const activeId = state.active_id || keys[0]?.id || null;
  const idxRaw = keys.findIndex((k) => k.id === activeId);
  const startIdx = idxRaw >= 0 ? idxRaw : 0;

  for (let offset = 0; offset < keys.length; offset++) {
    const k = keys[(startIdx + offset) % keys.length];
    if (!k || !k.id || !k.enc) continue;
    if (exhausted[k.id]) continue;
    if (invalid[k.id]) continue;

    const until = rateLimitedUntil[k.id];
    if (Number.isFinite(until) && until > nowMs) continue;

    return { keyId: k.id, enc: k.enc, keysCount: keys.length };
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

async function markGeminiKeyRateLimitedById(userId, keyId, retryAfterMs) {
  if (!userId || !keyId) return;

  const row = await loadUserSecretsRow(userId);
  let secrets = _ensureGeminiSecretsShape(row.secrets);

  const kr = secrets.gemini.keyring;
  const state = kr.state || {};
  if (!state.rate_limited_until || typeof state.rate_limited_until !== "object") state.rate_limited_until = {};

  const ms = Number.isFinite(retryAfterMs) ? retryAfterMs : 60000;
  const until = Date.now() + Math.max(0, ms);
  state.rate_limited_until[keyId] = until;

  const keys = Array.isArray(kr.keys) ? kr.keys : [];
  state.active_id = _rotateKeyId(keys, keyId);

  kr.state = state;
  secrets.gemini.keyring = kr;

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
    // 여기까지 오면: 후보 키를 끝까지 못 구함
//  - 전부 exhausted 인지
//  - 아니면 전부 rate-limited(쿨다운) 인지 구분해서 에러코드 분기
const state2 = secrets?.gemini?.keyring?.state || {};
const exhausted2 = state2.exhausted_ids || {};
const rl2 = state2.rate_limited_until || {};
const nowMs2 = Date.now();

let nonExhausted = 0;
let nonExhaustedButRateLimited = 0;
let minUntil = null;

for (const k of keys) {
  const id = k?.id;
  if (!id) continue;
  if (exhausted2[id]) continue;
  nonExhausted++;

  const until = rl2[id];
  if (Number.isFinite(until) && until > nowMs2) {
    nonExhaustedButRateLimited++;
    if (minUntil == null || until < minUntil) minUntil = until;
  }
}

// ✅ 케이스 A: “키는 있는데 전부 쿨다운 중”
if (nonExhausted > 0 && nonExhaustedButRateLimited === nonExhausted && minUntil != null) {
  const err = new Error("GEMINI_KEYRING_RATE_LIMITED");
  err.code = "GEMINI_RATE_LIMIT";
  err.httpStatus = 200;

  const retryAfterMs = Math.max(0, Math.ceil(minUntil - nowMs2));
  err.detail = {
    keysCount,
    keysTriedCount: tried?.size ?? null,
    pt_date: pt_date_now,
    next_reset_utc: pac.next_reset_utc,
    retry_after_ms: retryAfterMs,
  };
  throw err;
}

// ✅ 케이스 B: 진짜 exhausted/없음
const err = new Error("GEMINI_KEYRING_EMPTY_OR_EXHAUSTED");
err.code = "GEMINI_KEY_EXHAUSTED";
err.httpStatus = 200;
err.detail = {
  keysCount,
  keysTriedCount: tried?.size ?? null,
  pt_date: pt_date_now,
  next_reset_utc: pac.next_reset_utc,
};
throw err;
  }

  // ✅ 핵심: “현재 후보 키 복호화 실패”는 ‘전체 소진’이 아니라 ‘해당 키만 탈락’ → 다음 키로 계속
  const tried = new Set();

  for (let i = 0; i < keysCount; i++) {
    const cand = pickGeminiKeyCandidate(secrets);
    if (!cand.keyId || !cand.enc) break;

        // 무한루프 방지: 같은 키가 다시 나오면 active_id를 "다음 키"로 넘기고 계속
        if (tried.has(cand.keyId)) {
      // ✅ 같은 keyId가 반복되면: active_id를 "다음 key"로 넘기고 계속 (무한루프 방지)
      const keysAll = Array.isArray(secrets?.gemini?.keyring?.keys) ? secrets.gemini.keyring.keys : [];
      const nextId = _rotateKeyId(keysAll, cand.keyId);
      await setGeminiActiveId(userId, secrets, nextId);
      continue;
    }

    tried.add(cand.keyId);

        let keyPlain = null;
    try {
      keyPlain = decryptSecret(cand.enc);
    } catch (err) {
      // ✅ 복호화 실패는 "키 소진"이 아니라 "서버 암호화키/데이터 불일치" 가능성이 높음 → 즉시 중단
      const e2 = new Error("GEMINI_KEY_DECRYPT_FAILED");
      e2.code = "GEMINI_KEY_DECRYPT_FAILED";
      e2.httpStatus = 500;
      e2._fatal = true;
      e2.publicMessage =
        "DB에 저장된 Gemini 키를 복호화할 수 없습니다. (서버 암호화키(env) 누락/변경 가능) 앱에서 키를 다시 저장하거나 서버 env를 확인하세요.";
      e2.detail = {
        stage: "decryptSecret",
        key_id: cand?.keyId ?? null,
        original: String(err?.message || err),
      };
      throw e2;
    }

    if (keyPlain && keyPlain.trim()) {
      await setGeminiActiveId(userId, secrets, cand.keyId);
      return {
  gemini_key: keyPlain.trim(),
  key_id: cand.keyId,
  keys_count: keysCount,          // ✅ 저장된 키 총 개수
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

function getJsonBody(req) {
  const b = req.body;
  if (!b) return {};
  if (typeof b === "object") return b;          // ?뺤긽(JSON ?뚯떛??寃쎌슦)
  if (typeof b === "string") {                  // 臾몄젣 耳?댁뒪(臾몄옄?대줈 ?ㅼ뼱??寃쎌슦)
    try { return JSON.parse(b); } catch { return {}; }
  }
  return {};
}

// ✅ 추후 어드민/로그 용: 클라이언트 IP 추출 헬퍼
function getClientIp(req) {
  // Render / 프록시 뒤에 있을 때 X-Forwarded-For 우선
  const xfwd = req.headers?.["x-forwarded-for"];
  if (typeof xfwd === "string" && xfwd.trim()) {
    // "ip1, ip2, ip3" 형태면 첫 번째가 실 클라이언트
    return xfwd.split(",")[0].trim();
  }

  // 로컬/직접 접속일 때
  return (
    req.ip ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    null
  );
}

// === Admin runtime stats & whitelist status (in-memory) ===
const ADMIN_MAX_RECENT_ERRORS = 200;

const adminStats = {
  requestsTotal: 0,
  verifyTotal: 0,
  verifyByMode: {},        // { qv: n, fv: n, ... }
  translateTotal: 0,
  docsAnalyzeTotal: 0,
  lastRequestAt: null,
  lastErrorAt: null,
};

const adminRecentErrors = [];

/**
 * verify / translate / docs_analyze 요청 카운트용 helper
 */
function markAdminRequest(kind, extra = {}) {
  adminStats.requestsTotal += 1;
  adminStats.lastRequestAt = new Date();

  if (kind === "verify") {
    adminStats.verifyTotal += 1;
    const m = (extra.mode || "unknown").toLowerCase();
    adminStats.verifyByMode[m] = (adminStats.verifyByMode[m] || 0) + 1;
  } else if (kind === "translate") {
    adminStats.translateTotal += 1;
  } else if (kind === "docs_analyze") {
    adminStats.docsAnalyzeTotal += 1;
  }
}

/**
 * 최근 에러를 메모리에 최대 ADMIN_MAX_RECENT_ERRORS 개까지 보관
 */
function pushAdminError(entry) {
  const now = new Date();
  adminStats.lastErrorAt = now;

  adminRecentErrors.push({
    time: now.toISOString(),
    ...entry,
  });

  if (adminRecentErrors.length > ADMIN_MAX_RECENT_ERRORS) {
    adminRecentErrors.splice(0, adminRecentErrors.length - ADMIN_MAX_RECENT_ERRORS);
  }
}

/**
 * (임시) 네이버 화이트리스트 상태
 *  - 지금은 env 기반; 나중에 실제 whitelist 로더와 연결 예정
 */
function getNaverWhitelistStatus() {
  return {
    version: process.env.NAVER_WHITELIST_VERSION || null,
    lastUpdate: null,
    totalHosts: null,
    hasKosis: null,
    refreshMinutes: null,
    sourceUrl: null,
    note: "TODO: 실제 whitelist 로더와 연결 필요",
  };
}

// =======================================
// Basic in-memory rate limiting
//   - per IP + bearer token
//   - 1분 슬라이딩 윈도우
// =======================================
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute

// key => { windowStart, count }
const _rateLimitBuckets = new Map();

function _getClientKey(req, scope) {
  const ip =
    (req.headers?.["x-forwarded-for"] || "")
      .toString()
      .split(",")[0]
      .trim() ||
    req.ip ||
    req.connection?.remoteAddress ||
    "unknown";

  const bearer = getBearerToken(req) || "anon";
  return `${scope}:${bearer}:${ip}`;
}

function makeRateLimiter(scope, maxPerWindow) {
  return function rateLimiter(req, res, next) {
    try {
      const now = Date.now();
      const key = _getClientKey(req, scope);
      const bucket = _rateLimitBuckets.get(key);

      // 새 윈도우 시작
      if (!bucket || now - bucket.windowStart >= RATE_LIMIT_WINDOW_MS) {
        _rateLimitBuckets.set(key, { windowStart: now, count: 1 });
        return next();
      }

      // 한 윈도우에서 허용량 초과
      if (bucket.count >= maxPerWindow) {
        return res.status(429).json(
          buildError(
            "RATE_LIMITED",
            "요청이 너무 자주 발생하고 있습니다. 잠시 후 다시 시도해 주세요.",
            {
              scope,
              window_ms: RATE_LIMIT_WINDOW_MS,
              max_per_window: maxPerWindow,
            }
          )
        );
      }

      // 현재 윈도우 안에서 카운트 증가
      bucket.count += 1;
      return next();
    } catch (err) {
      // rate limiter 자체 에러 나면 요청은 그냥 통과
      console.warn("rateLimiter error, allowing request:", err?.message || err);
      return next();
    }
  };
}

async function getSupabaseAuthUser(req) {
  // ??request ?⑥쐞 罹먯떆 (null??罹먯떆)
  if (Object.prototype.hasOwnProperty.call(req, "_supabaseAuthUser")) {
    return req._supabaseAuthUser;
  }

  const token = getBearerToken(req);
  if (!token) {
    req._supabaseAuthUser = null;
    return null;
  }

  try {
    const { data, error } = await supabase.auth.getUser(token);
    if (error) {
      req._supabaseAuthUser = null;
      return null;
    }
    req._supabaseAuthUser = data?.user || null;
    return req._supabaseAuthUser;
  } catch {
    req._supabaseAuthUser = null;
    return null;
  }
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

        const body = (() => {
      if (!req.body) return {};
      if (typeof req.body === "object") return req.body;
      if (typeof req.body === "string") {
        try { return JSON.parse(req.body); } catch { return {}; }
      }
      return {};
    })();

    const integrationsIn = body.integrations || {};
    const geminiIn = body.gemini || {};

    const action = body.action ?? geminiIn.action ?? "replace";

    // ✅ gemini_keys: (레거시) top-level gemini_keys OR (신규) gemini.keyring.keys
    const gemini_keys =
      body.gemini_keys ??
      geminiIn.keyring?.keys ??
      geminiIn.keys;

    // ✅ integrations: (레거시) top-level OR (신규) integrations.* / integrations.<provider>.*
    const naver_id =
      body.naver_id ??
      integrationsIn.naver_id ??
      integrationsIn.naver?.id ??
      integrationsIn.naver?.client_id;

    const naver_secret =
      body.naver_secret ??
      integrationsIn.naver_secret ??
      integrationsIn.naver?.secret ??
      integrationsIn.naver?.client_secret;

    const klaw_key =
      body.klaw_key ??
      integrationsIn.klaw_key ??
      integrationsIn.klaw?.key;

    const github_token =
      body.github_token ??
      integrationsIn.github_token ??
      integrationsIn.github?.token;

    const deepl_key =
      body.deepl_key ??
      integrationsIn.deepl_key ??
      integrationsIn.deepl?.key;

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

// ✅ S-15: engines_used 자동 산출
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

let tier_weight =
  (typeof tierInfo.weight === "number" && Number.isFinite(tierInfo.weight))
    ? tierInfo.weight
    : 1;

let whitelisted = !!tier;
let inferred = false;

// ✅ 비화이트리스트 기본 감점(= 1.0 방지)
if (!whitelisted) {
  tier_weight = NAVER_NON_WHITELIST_FACTOR;
}

// ✅ "공식처럼 보임"은 표시용 tier만 주고, whitelisted는 올리지 않는다(핵심)
if (!tier && hostLooksOfficial(tierInfo.host)) {
  tier = "tier2"; // 표시용 라벨
  tier_weight = NAVER_INFERRED_OFFICIAL_FACTOR; // 소프트 가중치
  inferred = true;
}

          return {
            title: cleanTitle,
            desc: cleanDesc,
            link,
            source_url,
            origin: "naver",
            naver_type: ep.type,
            tier,
            tier_weight,
            whitelisted,
            inferred,

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

// ✅ GitHub query sanitize (DV/CV 안정화: url/repo 힌트 우선)
function sanitizeGithubQuery(q, userText = "") {
  let s = String(q ?? "").replace(/\s+/g, " ").trim();
  if (!s) return s;
  s = s.replace(/["']/g, "").trim();

  const blob = `${s} ${String(userText || "")}`;

  const mUrl = blob.match(/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)(?:\.git)?/i);
  if (mUrl) return (`repo:${mUrl[1]}/${mUrl[2]}`).replace(/\.git$/i, "");

  const mRepo = blob.match(/\b([A-Za-z0-9_.-]{2,})\/([A-Za-z0-9_.-]{2,})\b/);
  if (mRepo) return (`repo:${mRepo[1]}/${mRepo[2]}`).replace(/\.git$/i, "");

  if (s.length > 240) s = s.slice(0, 240).trim();
  return s;
}

function buildGithubDebugInput({ mode, query, rawQuery, user_answer, answerText, ghUserText }) {
  const parts = [
    `mode=${String(mode || "").trim()}`,
    `query=${String(query || "").trim()}`,
    rawQuery != null ? `rawQuery=${String(rawQuery || "").trim()}` : null,
    user_answer != null ? `user_answer=${String(user_answer || "").trim()}` : null,
    answerText != null ? `answerText=${String(answerText || "").trim()}` : null,
    ghUserText != null ? `ghUserText=${String(ghUserText || "").trim()}` : null,
  ].filter(Boolean);

  const joined = parts.join(" | ");
  return {
    github_debug_input: joined,
    github_debug_len: joined.length,
  };
}

// ✅ (DV/CV 품질) 대형 curated/awesome 리스트 레포 제거 (점수 왜곡 방지)
// - TDZ 방지 위해 "function" 선언(hoist)으로 고정
function isBigCuratedListRepo(r) {
  const full = String(r?.full_name || "").toLowerCase().trim();
  const desc = String(r?.description || "").toLowerCase();
  const topics = Array.isArray(r?.topics) ? r.topics.join(" ").toLowerCase() : "";
  const stars = Number(r?.stars ?? r?.stargazers_count ?? 0);

  const blocked = new Set([
    "public-apis/public-apis",
    "awesome-selfhosted/awesome-selfhosted",
    "practical-tutorials/project-based-learning",
    "ripienaar/free-for-dev",
    "jaywcjlove/awesome-mac",
    "avelino/awesome-go",
    "vuejs/awesome-vue",
    "f/awesome-chatgpt-prompts",
    "punkpeye/awesome-mcp-servers",
    "modelcontextprotocol/servers",
    "rust-unofficial/awesome-rust",
    "vsouza/awesome-ios",
    "serhii-londar/open-source-mac-os-apps",
    "alebcay/awesome-shell",
    "jondot/awesome-react-native",
    "matteocrippa/awesome-swift",
  ]);
  if (blocked.has(full)) return true;

  const blob = `${full} ${desc} ${topics}`;
  if (
    stars >= 20000 &&
    (blob.includes("awesome") ||
      blob.includes("curated") ||
      blob.includes("list of") ||
      blob.includes("resources") ||
      blob.includes("directory") ||
      blob.includes("public api") ||
      blob.includes("public apis"))
  ) return true;

  return false;
}

async function fetchGitHub(q, token, ctx = {}) {
  const signal = ctx?.signal;

  if (!token) throw new Error("GITHUB_TOKEN_REQUIRED");

  const headers = {
    "User-Agent": "CrossVerifiedAI",
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
  };

  const userText = String(ctx?.userText || ctx?.user_text || "").trim();

  // page/per_page: ctx 우선, 없으면 ENV 기본
  const page = Math.max(1, Number(ctx?.page || 1));
  const perPage = Math.min(
    100,
    Math.max(1, Number(ctx?.per_page || ctx?.perPage || process.env.GITHUB_SEARCH_PER_PAGE || 50))
  );

// DV/CV ... sanitize (caller에서 이미 sanitize 했으면 skip 가능)
const rawQ = String(q ?? "").trim();
const q2 = ctx?.skipSanitize ? rawQ : sanitizeGithubQuery(rawQ, userText);
if (!q2) return [];

  const url = "https://api.github.com/search/repositories";

  const run = async (pageNo) => {
    const resp = await axios.get(url, {
      headers,
      params: { q: q2, per_page: perPage, page: pageNo },
      timeout: HTTP_TIMEOUT_MS,
      signal,
    });
    return Array.isArray(resp?.data?.items) ? resp.data.items : [];
  };

  let items = [];
  try {
    items = await run(page);

    // ✅ 1) 1페이지가 curated/awesome으로만 꽉 찼으면 2페이지 1회 보강(정확히 1번)
    if (page === 1 && items.length > 0) {
      const onlyCurated = items.every((r) => {
        try {
          return typeof isBigCuratedListRepo === "function" && isBigCuratedListRepo(r);
        } catch {
          return false;
        }
      });

      if (onlyCurated) {
        const items2 = await run(2);
        if (items2.length) items = [...items, ...items2];
      }
    }

    // ✅ 2) 아예 0개면(일시/검색특이) 2페이지 1회 보강
    if (page === 1 && items.length === 0) {
      items = await run(2);
    }
  } catch (e) {
    const s = e?.response?.status;

    // ✅ 토큰 불량/만료/권한없음 → 치명 오류로 중단
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

  return (items || []).map((it) => ({
    name: it?.full_name || it?.name,
    full_name: it?.full_name,
    url: it?.html_url,
    description: it?.description,
    stars: it?.stargazers_count,
    forks: it?.forks_count,
    updated: it?.updated_at,
    language: it?.language,
    topics: it?.topics,
    size: it?.size,
  }));
}

// ✅ GitHub 결과 relevance 필터(awesome/curated/list 레포 제거 포함)
function isRelevantGithubRepo(r) {
  if (!r || typeof r !== "object") return false;

  const full = String(r?.full_name || "").toLowerCase().trim();
  const name = String(r?.name || "").toLowerCase().trim();
  if (!full && !name) return false;

  // ✅ (DV/CV 품질) 대형 curated/awesome 리스트 레포 제거
  try {
    if (typeof isBigCuratedListRepo === "function" && isBigCuratedListRepo(r)) return false;
  } catch {}

  const desc = String(r?.description || "").toLowerCase();
  const topics = Array.isArray(r?.topics) ? r.topics.join(" ").toLowerCase() : "";
  const blob = `${full} ${name} ${desc} ${topics}`;

  // 추가로 흔한 “목록 레포” 패턴(블록리스트 외) 억제
  if (
    blob.includes("awesome") ||
    blob.includes("curated") ||
    blob.includes("list of") ||
    blob.includes("collection") ||
    blob.includes("resources") ||
    blob.includes("directory")
  ) {
    const stars = Number(r?.stars ?? r?.stargazers_count ?? 0);
    // 별이 높으면 거의 확정적으로 목록 레포 → 제거
    if (stars >= 5000) return false;
  }

  // “README만/빈 레포” 성격 최소 컷(너무 공격적이면 여기만 완화하면 됨)
  const size = Number(r?.size ?? 0);
  const language = String(r?.language || "").trim();
  if (!language && size > 0 && size < 20) return false;

  return true;
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
  const status =
    e?.response?.status ?? e?.httpStatus ?? e?.status ?? e?.statusCode ?? null;

  const apiMsg =
    e?.response?.data?.error?.message ||
    e?.response?.data?.message ||
    e?.publicMessage ||
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
    err.httpStatus = 401;
    err.publicMessage = "Gemini API 키가 필요합니다.";
    err.detail = { stage: "raw", model, label };
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
        err.code = "GEMINI_EMPTY_TEXT";
        err._gemini_empty = true;
        err.httpStatus = 502;
        err.detail = { stage: "raw", model, label, finishReason, blockReason };
        throw err; // ✅ 빈 텍스트는 retry하지 않음
      }

      return text;
    } catch (e) {
      const status = e?.response?.status ?? e?.httpStatus ?? e?.status ?? e?.statusCode ?? null;
      const code = e?.code || e?.name;
      const msg = geminiErrMessage(e);

      // ✅ INVALID_GEMINI_KEY (보통 400 + "API key not valid")
      if (
        status === 400 &&
        /API key not valid|API_KEY_INVALID|invalid api key/i.test(String(msg || ""))
      ) {
        const err2 = new Error("INVALID_GEMINI_KEY");
        err2.code = "INVALID_GEMINI_KEY";
        err2.httpStatus = 401;
        err2.publicMessage = "Gemini API 키가 유효하지 않습니다. 키를 다시 확인해 주세요.";
        err2.detail = { stage: "raw", model, label, status, message: msg };
        throw err2;
      }

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
            msg
          );
        }
        await sleep(baseMs * Math.pow(2, attempt));
        continue;
      }

      throw e;
    }
  }
}

async function fetchGeminiRotating({ userId, keyHint, model, payload, opts = {} }) {
  const label0 = opts.label || `gemini:${model}`;
  const hint = String(keyHint || "").trim();

  const getStatus = (e) =>
    e?.response?.status ?? e?.status ?? e?.statusCode ?? e?.httpStatus ?? null;

  const _mergedErrMsg = (e) => {
    const msg0 = String(e?.message || "");
    const msg1 = String(e?.detail?.message || "");
    const msg2 = String(e?.response?.data?.error?.message || "");
    return `${msg0} ${msg1} ${msg2}`.trim();
  };

  const _isInvalidKey = (e) => {
    const merged = _mergedErrMsg(e);
    return (
      e?.code === "INVALID_GEMINI_KEY" ||
      /api key not valid/i.test(merged)
    );
  };

  const _parseRetryAfterMs = (e) => {
    const msg = _mergedErrMsg(e);

    // (1) message: "Please retry in ..."
    let raMs = null;
    const mMs = msg.match(/retry in\s+([0-9.]+)\s*ms/i);
    const mS = msg.match(/retry in\s+([0-9.]+)\s*s/i);
    if (mMs) raMs = Math.max(0, Math.ceil(parseFloat(mMs[1])));
    else if (mS) raMs = Math.max(0, Math.ceil(parseFloat(mS[1]) * 1000));

    // (2) header: Retry-After
    if (raMs == null) {
      const ra = e?.response?.headers?.["retry-after"] ?? e?.response?.headers?.["Retry-After"];
      if (ra != null) {
        const sec = parseFloat(String(ra).trim());
        if (Number.isFinite(sec)) raMs = Math.max(0, Math.ceil(sec * 1000));
      }
    }

    if (raMs == null) raMs = 60000; // fallback 60s
    return raMs;
  };

  // 0) hint(body에서 온 keyHint) 1회 시도 -> 401/403/429면 keyring으로 fallback
  if (hint) {
    try {
      return await fetchGeminiRaw({
        model,
        gemini_key: hint,
        payload,
        opts: { ...opts, label: `${label0}#hint` },
      });
    } catch (e) {
      const st = getStatus(e);
      console.error("Gemini call failed:", `${label0}#hint`, `status=${st}`, geminiErrMessage(e));
      if (st !== 401 && st !== 403 && st !== 429) throw e;
      // fallthrough -> keyring
    }
  }

  // 1) keyring rotating
  const row0 = await loadUserSecretsRow(userId);
  let secrets0 = _ensureGeminiSecretsShape(row0.secrets);

  const pac = await ensureGeminiResetIfNeeded(userId, secrets0);
  const pt_date_now = pac.pt_date;

  const tried = new Set();
  let lastErr = null;
  let lastKctx = null;

  const keysCount0 = Array.isArray(secrets0?.gemini?.keyring?.keys) ? secrets0.gemini.keyring.keys.length : 0;
  const maxTries = Math.max(1, keysCount0 + 1);

  for (let t = 0; t < maxTries; t++) {
    let kctx;
    try {
      kctx = await getGeminiKeyFromDB(userId);
    } catch (e) {
      lastErr = e;
      break;
    }

    lastKctx = kctx;

    const key = String(kctx?.gemini_key || "").trim();
    const keyId = kctx?.key_id || null;

    if (!key || !keyId) break;

    // 같은 key_id만 계속 나오면 무한루프 방지
    if (tried.has(keyId)) break;
    tried.add(keyId);

    try {
      return await fetchGeminiRaw({
        model,
        gemini_key: key,
        payload,
        opts: { ...opts, label: `${label0}#${keyId}` },
      });
    } catch (e) {
      lastErr = e;
      const st = getStatus(e);

      // 핵심: 401/403은 “소진”이 아니라 “키/제한 문제”일 가능성이 큼 → 다음 키로 넘김
      console.error("Gemini call failed:", `${label0}#${keyId}`, `status=${st}`, geminiErrMessage(e));

      if (st === 429) {
        const raMs = _parseRetryAfterMs(e);
        await markGeminiKeyRateLimitedById(userId, keyId, raMs);
        continue;
      }

      // ✅ 400 invalid key / 401 / 403 => "오늘만 exhausted" 처리해서 회전
      if (st === 401 || st === 403 || (st === 400 && _isInvalidKey(e)) || _isInvalidKey(e)) {
        const row = await loadUserSecretsRow(userId);
        let secrets = _ensureGeminiSecretsShape(row.secrets);
        await markGeminiKeyExhausted(userId, secrets, keyId, lastKctx?.pt_date ?? pt_date_now ?? null);
        continue;
      }

      throw e;
    }
  }

  // 2) 여기까지 오면: hint 실패 + keyring도 전부 실패
  const err = new Error("Gemini keys are not usable. (keyring)");

  const _keysStoredCount =
    Number.isFinite(lastKctx?.keys_count) ? lastKctx.keys_count :
    Number.isFinite(lastKctx?.keysCount) ? lastKctx.keysCount :
    null;

  const _lastMsg = lastErr ? String(lastErr?.message || lastErr) : null;
  const _lastStatus =
    Number.isFinite(lastErr?.response?.status) ? lastErr.response.status :
    Number.isFinite(lastErr?.status) ? lastErr.status :
    Number.isFinite(lastErr?.httpStatus) ? lastErr.httpStatus :
    null;

  const _is429 =
    _lastStatus === 429 ||
    (_lastMsg && /status\s*=?\s*429|quota exceeded|rate limit|generate_content_free_tier_requests/i.test(_lastMsg));

  let _retryAfterMs = null;
  if (_lastMsg) {
    const mMs = _lastMsg.match(/retry in\s+([0-9.]+)\s*ms/i);
    const mS  = _lastMsg.match(/retry in\s+([0-9.]+)\s*s/i);
    if (mMs) _retryAfterMs = Math.max(0, Math.ceil(parseFloat(mMs[1])));
    else if (mS) _retryAfterMs = Math.max(0, Math.ceil(parseFloat(mS[1]) * 1000));
  }
  if (_retryAfterMs == null) {
    const ra = lastErr?.response?.headers?.["retry-after"] ?? lastErr?.response?.headers?.["Retry-After"];
    if (ra != null) {
      const sec = parseFloat(String(ra).trim());
      if (Number.isFinite(sec)) _retryAfterMs = Math.max(0, Math.ceil(sec * 1000));
    }
  }

  err.code = _is429 ? "GEMINI_RATE_LIMIT" : "GEMINI_KEY_EXHAUSTED";
  err.detail = {
    keysCount: (_keysStoredCount ?? tried.size),
    keysTriedCount: tried.size,
    pt_date: pt_date_now,
    next_reset_utc: pac.next_reset_utc,
    last_error: _lastMsg,
    last_status: _lastStatus,
    retry_after_ms: _retryAfterMs,
  };

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

// ✅ fetchGeminiSmart: direct gemini_key가 있어도 "rotating(=hint 1회 + DB fallback)" 경로를 타게 함
// 수정 버전: qvfv_preprocess 는 자동으로 lite 모델 사용
async function fetchGeminiSmart({ userId, gemini_key, keyHint, model, payload, opts = {} }) {
  // 0) 모델 기본값 + qvfv_preprocess 라벨이면 lite 강제
  let modelFinal = String(model || "").trim();

  // 기본값 없으면 서버 디폴트(FLASH) 사용
  if (!modelFinal) {
    modelFinal = GEMINI_VERIFY_MODEL || "gemini-2.0-flash";
  }

  const labelRaw = opts.label || "";
  const labelLower = String(labelRaw).toLowerCase();

  // qv/fv 전처리 라벨이면 무조건 lite 사용
  if (labelLower.includes("qvfv_preprocess")) {
    modelFinal = GEMINI_QVFV_PRE_MODEL || "gemini-2.0-flash-lite";
  }

  const label0 = labelRaw || `gemini:${modelFinal}`;
  const directKey = String(gemini_key ?? "").trim();
  const hintKey = String(keyHint ?? "").trim();

  const getStatus = (e) =>
    e?.response?.status ?? e?.status ?? e?.statusCode ?? null;

  // 1) directKey(클라이언트에서 gemini_key)가 있으면 1회만 시도
  if (directKey) {
    try {
      return await fetchGeminiRaw({
        model: modelFinal,
        gemini_key: directKey,
        payload,
        opts: { ...opts, label: `${label0}#direct` },
      });
    } catch (e) {
      const st = getStatus(e);
      console.error(
        "Gemini call failed:",
        `${label0}#direct`,
        `status=${st}`,
        geminiErrMessage(e)
      );
      // 401/403/429만 fallback (그 외는 그대로 throw)
      if (st !== 401 && st !== 403 && st !== 429) throw e;
      // fallthrough → rotating
    }
  }

  // 2) 나머지는 keyHint(있으면 1순위) + keyring fallback 으로 rotating
  return await fetchGeminiRotating({
    userId,
    keyHint: hintKey || null,
    model: modelFinal,
    payload,
    opts: { ...opts, label: label0 },
  });
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

  const text = await fetchGeminiSmart({
  userId,                 // ???꾨옒?먯꽌 ?⑥닔 ?쒓렇?덉쿂瑜?userId 諛쏄쾶 諛붽? 嫄곕씪 ?ш린???꾩떆
  gemini_key,
  keyHint: gemini_key,
  // ✅ pro 금지 → flash 계열만 사용
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
    let baseText =
      user_answer && user_answer.trim().length > 0
        ? `질문:\n${query}\n\n검증 대상 내용(요약 또는 코드):\n${user_answer}`
        : `질문:\n${query}`;

        const prompt = `
너는 DV/CV 모드에서 "GitHub 근거 수집"을 위한 1회성 분류+쿼리 생성기다.

[1] 먼저 입력이 "코드/개발" 질의인지 판정하라.
- YES(코드/개발): 에러/버그/스택트레이스/로그, server.js 등 파일/코드, 라이브러리/프레임워크, 설정, 배포/DevOps, 보안, 성능, 테스트, API/DB 설계, 리팩터링 등
- NO(비코드): 통계/정책/사회/경제/역사/일반 사실관계, 단순 정보질문, 번역/요약, 의견, 잡담 등

[2] 출력은 반드시 JSON 객체 1개만(설명/마크다운/추가 텍스트 금지)

- NO면 아래 형식 "딱 이것만" 출력:
{"queries":["__NON_CODE__::<간단사유(한국어)>::<confidence 0-1>"]}

- YES면 GitHub repository search(q=...)에서 결과가 잘 나오는 영문 키워드 기반 쿼리 1~3개 출력:
{"queries":["query1","query2","query3"]}

[3] YES일 때 쿼리 규칙
- 따옴표(") 사용 금지 (검색 0건 유발하니 절대 쓰지 말 것)
- 너무 긴 문장 금지. 짧은 핵심 키워드 위주.
- 가능하면 in:name,description,readme 를 붙여 검색 적중률을 올릴 것
- 필요하면 stars:>50 같은 제한은 1개 쿼리에만 가볍게
- 사용자가 준 기술 키워드(예: express-rate-limit, trust proxy 등)는 그대로 포함

[예시]
입력: "2024년 한국 합계출산율은?"
출력: {"queries":["__NON_CODE__::통계/인구 질문(코드 아님)::0.95"]}

입력: "server.js에서 express rate limit이 과하게 걸릴 때 진단/개선"
출력: {"queries":["express-rate-limit trust proxy in:name,description,readme","express rate limit middleware x-forwarded-for in:readme stars:>50"]}

입력:
${baseText}
`.trim();

    const text = await fetchGeminiSmart({
      userId,
      gemini_key,
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
  .map((s) =>
    String(s || "")
      .replace(/["']/g, "")           // ✅ 따옴표 제거(0 results 방지)
      .replace(/\s+/g, " ")
      .trim()
  )
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

// ✅ S-14: naver non-whitelist / inferred-official weights
// - single source of truth는 상단의 FACTOR(환경변수 포함)이고,
// - 아래 WEIGHT는 “호환(alias)” 용도로만 유지한다.
const NAVER_NONWHITELIST_WEIGHT = NAVER_NON_WHITELIST_FACTOR;
const NAVER_INFERRED_OFFICIAL_WEIGHT = NAVER_INFERRED_OFFICIAL_FACTOR;
const NAVER_STRICT_YEAR_MATCH = (process.env.NAVER_STRICT_YEAR_MATCH ?? "true").toLowerCase() !== "false";
const NAVER_NUM_MATCH_BOOST = parseFloat(process.env.NAVER_NUM_MATCH_BOOST || "1.25"); // 숫자 매칭 있으면 보너스

// ✅ 숫자/단위 감지 (숫자 발췌 패치용)
function hasNumberLike(text) {
  const s = String(text || "");
  return (
    /\d/.test(s) ||
    /%|퍼센트|만\s*명|명|대|원|달러|억원|조원|km|m\/s|GHz|MHz/.test(s)
  );
}

function hasStrongNumberLike(text) {
  const t = String(text || "");
  if (!t) return false;

  // 연도는 강한 숫자 주장으로 취급
  if (/\b(19\d{2}|20\d{2}|2100)\b/.test(t)) return true;

  // 1,234 / 12,345.67 형태
  if (/\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b/.test(t)) return true;

  // 3자리 이상 숫자(통계량/금액에서 흔함)
  if (/\b\d{3,}(?:\.\d+)?\b/.test(t)) return true;

  // 퍼센트
  if (/\b\d+(?:\.\d+)?\s*%/.test(t)) return true;

  // 한국어 단위(1.2억, 300만 등)
  if (/\b\d+(?:\.\d+)?\s*(?:조|억|만|천|백)\b/.test(t)) return true;

  return false;
}

function hostFromUrl(u = "") {
  try { return new URL(String(u || "")).hostname.toLowerCase(); } catch { return ""; }
}

function isTrustedNumericEvidenceItem(x) {
  const u =
    String(
      x?.url ||
      x?.source_url ||
      x?.sourceUrl ||
      x?.link ||
      x?.href ||
      ""
    ).trim();

  const h =
    String(x?.host || "").trim().toLowerCase() ||
    hostFromUrl(u);

  if (!h) return false;
  return NUMERIC_PRUNE_TRUSTED_HOSTS.some(t => h === t || h.endsWith("." + t));
}

function normalizeNumToken(t) {
  return String(t || "").trim().replace(/,/g, "");
}

function extractYearTokens(text) {
  const s = String(text || "");
  const years = new Set();
  const m = s.match(/\b(19\d{2}|20\d{2})\b/g);
  if (m) for (const y of m) years.add(y);
  return [...years];
}

// 연도(4자리)는 제외하고 “수치 주장”에 가까운 숫자(소수/2자리 이상)만 뽑음
function extractQuantNumberTokens(text) {
  const s = String(text || "");
  const raw = s.match(/\d[\d,]*(?:\.\d+)?/g) || [];
  const out = new Set();

  for (const tok of raw) {
    const t = normalizeNumToken(tok);
    if (!t) continue;

    // 4자리 연도는 제외
    if (/^(19\d{2}|20\d{2})$/.test(t)) continue;

    // 너무 짧은 숫자(1자리)는 제외 (노이즈 방지)
    if (/^\d$/.test(t)) continue;

    out.add(t);
  }
  return [...out];
}

function countTokenHits(tokens, hayText) {
  if (!Array.isArray(tokens) || tokens.length === 0) return 0;
  const hay = normalizeNumToken(hayText);
  let hits = 0;
  for (const tok of tokens) {
    const t = normalizeNumToken(tok);
    if (!t) continue;
    if (hay.includes(t)) hits += 1;
  }
  return hits;
}

const NAVER_FETCH_TIMEOUT_MS = parseInt(process.env.NAVER_FETCH_TIMEOUT_MS || "5000", 10);
const EVIDENCE_EXCERPT_CHARS = parseInt(process.env.EVIDENCE_EXCERPT_CHARS || "700", 10);
const NAVER_NUMERIC_FETCH_MAX = parseInt(process.env.NAVER_NUMERIC_FETCH_MAX || "8", 10);
const STRICT_NUMERIC_PRUNE =
  String(process.env.STRICT_NUMERIC_PRUNE ?? "false").toLowerCase() === "true";

  // ✅ Naver: widen pool, keep topK tight
const NAVER_QUERY_MAX = Math.max(1, Math.min(5, parseInt(process.env.NAVER_QUERY_MAX || "3", 10)));
const NAVER_PER_QUERY_DISPLAY = Math.max(3, Math.min(50, parseInt(process.env.NAVER_PER_QUERY_DISPLAY || "10", 10)));
const NAVER_POOL_MAX = Math.max(5, Math.min(100, parseInt(process.env.NAVER_POOL_MAX || "20", 10)));

// 숫자/통계류는 본문에 숫자 발췌가 비어도 title/url에만 숫자가 있을 수 있어서 예외로 킵
const NUMERIC_PRUNE_TRUSTED_HOSTS = (process.env.NUMERIC_PRUNE_TRUSTED_HOSTS ||
  "stat.go.kr,kosis.kr,data.go.kr,mois.go.kr,worldbank.org,oecd.org,imf.org,who.int,un.org")
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

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

  const needle = `${String(blockText || "")} ${String(query || "")}`;
  const yearTokens = Array.from(needle.matchAll(/\b(19\d{2}|20\d{2})\b/g)).map(m => m[1]);
  const numTokens = Array.from(needle.matchAll(/(\d+(?:\.\d+)?)/g)).map(m => m[1]).filter(x => x && x.length <= 10);

  const scored = [];
  for (const it of list) {
    if (!allowNews && it?.naver_type === "news") continue; // ✅ 시사성 질문에서만 news 허용

    const text = `${it?.title || ""} ${it?.desc || ""}`;
    const rel = keywordHitRatio(text, kw);
    if (rel < minRel) continue; // ✅ 무관한 결과 evidence 제외

    const isWhitelisted = (it?.whitelisted === true) || !!it?.tier;
    const isInferred = (it?.inferred === true);

    const hasAnyNum = hasNumberLike(text);
    const hasYear = yearTokens.length ? yearTokens.some(y => text.includes(y)) : false;
    const hasExactNum = numTokens.length ? numTokens.some(n => text.includes(n)) : false;

    // ✅ inferred는 관련도 충분할 때만 통과
    const allowInferred = isInferred && rel >= Math.max(minRel + 0.10, 0.25);

    // ✅ 숫자/연도형 질의에서만 비화이트리스트 예외 허용(수치/연도 매칭 + 높은 관련도)
    const allowNonWhitelist =
      !isWhitelisted && !isInferred &&
      (needNum || yearTokens.length > 0) &&
      (hasExactNum || hasYear || (hasAnyNum && rel >= 0.35)) &&
      rel >= Math.max(minRel + 0.15, 0.35);

    if (!isWhitelisted && !allowInferred && !allowNonWhitelist) continue;

    let baseW =
      (typeof it?.tier_weight === "number" && Number.isFinite(it.tier_weight) ? it.tier_weight : 1) *
      (typeof it?.type_weight === "number" && Number.isFinite(it.type_weight) ? it.type_weight : 1);

// ✅ (중복 감점 방지)
// - 비화이트리스트/인퍼드 감점은 item.tier_weight(또는 생성 단계)에서 이미 반영되는 구조이므로
//   여기서 추가로 곱하지 않음

    // ✅ 숫자/연도 매칭 가산
    let bonus = 1.0;
    if (needNum) bonus *= (hasAnyNum ? 1.15 : 0.8);
    if (NAVER_STRICT_YEAR_MATCH && yearTokens.length) bonus *= (hasYear ? 1.10 : 0.85);
    if (numTokens.length && hasExactNum) bonus *= NAVER_NUM_MATCH_BOOST;

    const score = baseW * (0.6 + 0.4 * rel) * bonus;
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

  const text = await fetchGeminiSmart({
    userId,
    gemini_key,
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

// =======================================================
// Snippet Verification Shim (/api/verify-snippet)
//   - Convert snippet payload -> FV verify payload
function snippetToVerifyBody(req, res, next) {
  const b = getJsonBody(req);

  const snippetRaw = String(
    b?.snippet ?? b?.snippet_text ?? b?.text ?? ""
  ).trim();

  const questionRaw = String(
    b?.question ?? b?.prompt ?? ""
  ).trim();

  if (!snippetRaw) {
    return res.status(400).json(buildError("VALIDATION_ERROR", "snippet is required"));
  }

  // hard clip
  const clippedCore = snippetRaw.slice(0, VERIFY_MAX_CORE_TEXT_CHARS);

  // IMPORTANT:
  // - query/rawQuery는 "snippet"으로 고정해야 qvfv_preprocess(쿼리빌더/블록)가 snippet 기반으로 돌아감
  const clippedQuery = String(clippedCore)
    .slice(0, (typeof VERIFY_MAX_QUERY_CHARS === "number" && VERIFY_MAX_QUERY_CHARS > 0) ? VERIFY_MAX_QUERY_CHARS : 5000)
    .trim();

  // drop raw snippet fields to avoid collisions
  const {
    snippet: __drop_snippet,
    snippet_text: __drop_snippet_text,
    text: __drop_text,
    question: __drop_question,
    prompt: __drop_prompt,
    ...rest
  } = b;

  const clippedUserAnswer = String(rest.user_answer ?? clippedCore)
    .slice(0, VERIFY_MAX_USER_ANSWER_CHARS);

  // snippet meta (keep original question only as meta; DO NOT seed queries with it)
  const questionText = String(b?.question ?? b?.question_text ?? b?.q ?? "").trim();

const snippetMeta = {
  is_snippet: true,
  input_snippet: snippetRaw,
  snippet_core: clippedCore,
  question: questionText || null,
  snippet_id: b?.snippet_id ?? b?.snippetId ?? null,
  snippet_hash: b?.snippet_hash ?? b?.snippetHash ?? null,
};

req.body = {
  ...rest,

  // ✅ snippet 전용: query/rawQuery는 무조건 snippet_core로 고정
  // (질문(question)은 snippet_meta.question으로만 보존)
  rawQuery: String(rest.rawQuery ?? clippedCore).trim(),
  query: String(clippedCore).trim(),

  // ✅ default model for snippet verify
  gemini_model: rest.gemini_model ?? "flash",

  // ✅ verifyCoreHandler로 snippet 메타 전달
  snippet_meta: snippetMeta,
};

  return next();
}

function extractJsonObjectFromText(raw) {
  try {
    let s = String(raw || "").trim();
    if (!s) return null;

    // 1) 코드펜스 제거(있으면)
    const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (fence && fence[1]) s = String(fence[1]).trim();

    // 2) 첫 '{'부터 균형잡힌 '}'까지 스캔 (문자열 내부 괄호는 무시)
    const first = s.indexOf("{");
    if (first < 0) return null;

    let depth = 0;
    let inStr = false;
    let esc = false;

    for (let i = first; i < s.length; i++) {
      const ch = s[i];

      if (inStr) {
        if (esc) { esc = false; continue; }
        if (ch === "\\") { esc = true; continue; }
        if (ch === "\"") { inStr = false; continue; }
        continue;
      }

      if (ch === "\"") { inStr = true; continue; }
      if (ch === "{") { depth++; continue; }
      if (ch === "}") {
        depth--;
        if (depth === 0) {
          const jsonText = s.slice(first, i + 1);
          return JSON.parse(jsonText);
        }
      }
    }

    // 3) fallback: 끝 '}'까지 잘라서 한 번 더
    const last = s.lastIndexOf("}");
    if (last > first) {
      const jsonText = s.slice(first, last + 1);
      return JSON.parse(jsonText);
    }

    return null;
  } catch {
    return null;
  }
}

// ─────────────────────────────
// ✅ Verify Core (QV / FV / DV / CV / LV)
//   - DV/CV: GitHub 기반 TruthScore 직접 계산 (Gemini→GitHub)
//   - LV: TruthScore 없이 K-Law 결과만 제공 (Ⅸ 명세 반영)
// ─────────────────────────────
const verifyCoreHandler = async (req, res) => {
    // ✅ answerText 공용 선선언 (ReferenceError 방지)
  const __b0 = (req && req.body && typeof req.body === "object") ? req.body : {};
  const __answerText0 = String((__b0.answerText ?? __b0.user_answer ?? __b0.query ?? "")).trim();
  let answerText = __answerText0;

  // ✅ TDZ 방지: verify 핸들러 스코프에서 먼저 선언
  let ghUserText = String(req.body?.query || "").trim();

  // --- GitHub debug input (does NOT affect github_queries) ---
  const __ghDebug = buildGithubDebugInput({
    mode: req.body?.mode,
    query: req.body?.query,
    rawQuery: req.body?.rawQuery,
    user_answer: req.body?.user_answer,
    answerText: answerText,
    ghUserText,
  });
  
  let __irrelevant_urls = [];
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

    // ??FV?먯꽌 "?ъ떎 臾몄옣"??query? 遺꾨━?댁꽌 蹂대궡怨??띠쓣 ???ъ슜
    core_text,

    user_id,
    user_email,
    user_name,

    // 🔍 /api/verify-snippet → snippetToVerifyBody에서 실어주는 메타
    snippet_meta,
    } = req.body;

  const safeMode = (mode || "").trim().toLowerCase();

  // Admin 통계용: verify 요청 카운트
  markAdminRequest("verify", { mode: safeMode || "unknown" });

  // ??normalize rawQuery/key_uuid without redeclare ??깂
  const rawQuery = String(req.body?.rawQuery ?? "").trim();
  const key_uuid = String(req.body?.key_uuid ?? req.body?.keyUuid ?? "").trim();

  // ??S-17: cache hit (QV/FV heavy path) ??MUST be before heavy work/switch
  let __cacheKey = null;
  if (safeMode === "qv" || safeMode === "fv") {
    __cacheKey = makeVerifyCacheKey({
      mode: safeMode,
      query,
      rawQuery,
      core_text,
      user_answer,
      answerText: __answerText0,
      key_uuid,
    });

    const __cachedPayload = __cacheKey ? verifyCacheGet(__cacheKey) : null;
    if (__cachedPayload) {
      const elapsedMs = Date.now() - start;

      const out = {
        ...__cachedPayload,
        elapsed: elapsedMs,
        cached: true,
      };

      if (out.partial_scores && typeof out.partial_scores === "object") {
        out.partial_scores = { ...out.partial_scores, cache_hit: true };
      } else {
        out.partial_scores = { cache_hit: true };
      }

      // 🔍 스니펫 요청이면 응답에 메타 필드 추가
      if (snippet_meta && typeof snippet_meta === "object") {
        const { is_snippet, input_snippet, snippet_core } = snippet_meta;

        if (is_snippet) {
          out.is_snippet = true;
        }

        if (typeof input_snippet === "string" && input_snippet.trim()) {
          out.input_snippet = input_snippet;
        }

        if (typeof snippet_core === "string" && snippet_core.trim()) {
          out.snippet_core = snippet_core;
        }
      }

      return res.json(buildSuccess(out));
    }
  }

// ✅ (B안 보강) Gemini sentinel이 가끔 뚫려도 "명백한 비코드(통계/정책/일반사실)"는 DV/CV에서 차단
const looksObviouslyNonCode = (s) => {
  const t = String(s || "").trim();
  if (!t) return true;

  // 코드/개발 힌트(이게 하나라도 있으면 non-code로 단정하지 않음)
  const codeHint =
    /(server\.js|stack|error|exception|trace|http|api|express|node|npm|yarn|pnpm|docker|kubernetes|k8s|redis|postgres|sql|jwt|oauth|flutter|dart|react|typescript|javascript|git(hub)?|commit|pull request|pr|issue|rate[- ]?limit|nginx|render|supabase|curl|powershell|python|파이썬)/i;

  // 비코드(통계/정책/일반사실) 힌트 — "명백한" 케이스만(고정밀)
  const nonCode =
    /(합계출산율|출산율|인구|gdp|물가|실업률|환율|주가|대통령|선거|법률|정책|날씨|여행|맛집|번역|요약|연봉|집값|부동산|금리|코스피|코스닥|비트코인)/i;

  // 개발 문맥이면 non-code 아님
  if (t.includes("```")) return false;
  if (/\.(js|mjs|cjs|ts|tsx|jsx|dart|py|go|java|kt|cs|cpp|c|rs|swift|sql|yml|yaml|json|env)\b/i.test(t)) return false;

  return nonCode.test(t) && !codeHint.test(t);
};

// ✅ (DV/CV 보강) GitHub 결과 relevance 필터(헛다리 repo로 검증 진행되는 것 방지)
const tokenizeGhQuery = (s) => {
  const t = String(s || "").toLowerCase();
  const tokens = (t.match(/[a-z0-9][a-z0-9._-]{1,}|[가-힣]{2,}/g) || [])
    .map(x => x.trim())
    .filter(Boolean);

  // GitHub 검색 qualifier/불용어 제거
  const stop = new Set([
    "in", "name", "description", "readme", "stars", "forks", "language",
    "sort", "order", "repo", "repos", "repository", "repositories",
    "example", "examples", "dataset", "data", "검증", "예시", "레포", "repo로"
  ]);

  const out = [];
  for (const tok of tokens) {
    if (stop.has(tok)) continue;
    if (/^\d+$/.test(tok)) continue;
    if (tok.length <= 1) continue;
    out.push(tok);
  }
  // unique
  return Array.from(new Set(out)).slice(0, 24);
};

const scoreGithubItem = (item, tokens) => {
  const name =
    String(item?.full_name || item?.name || item?.repo || item?.repository || "").toLowerCase();
  const desc =
    String(item?.description || item?.summary || item?.snippet || item?.text || "").toLowerCase();
  const url =
    String(item?.html_url || item?.url || "").toLowerCase();
  const blob = `${name} ${desc} ${url}`.trim();

  const isStrong = (tok) => tok.includes("-") || tok.includes(".") || tok.length >= 8;

  let total = 0;
  let strong = 0;

  for (const tok of tokens) {
    if (!tok) continue;
    if (!blob.includes(tok)) continue;

    total += 1;
    if (isStrong(tok)) strong += 1;

    // name에 직접 박혀있으면 가중
    if (name && name.includes(tok)) total += 1;
  }

  const stars = Number(item?.stargazers_count ?? item?.stars ?? 0) || 0;
  return { total, strong, stars };
};

const filterGithubEvidence = (items, rawQuery) => {
  const list = Array.isArray(items) ? items : [];
  const tokens = tokenizeGhQuery(rawQuery);

  if (!tokens.length || !list.length) {
    return { items: list, info: { in: list.length, out: list.length, reason: "no_tokens_or_items" } };
  }

  // dedupe by url/full_name
  const seen = new Set();
  const uniq = [];
  for (const it of list) {
    const key = String(it?.html_url || it?.url || it?.full_name || it?.name || "").toLowerCase();
    if (!key) continue;
    if (seen.has(key)) continue;
    seen.add(key);
    uniq.push(it);
  }

  const scored = uniq.map(it => {
    const s = scoreGithubItem(it, tokens);
    return { it, ...s };
  });

  scored.sort((a, b) => {
    if (b.strong !== a.strong) return b.strong - a.strong;
    if (b.total !== a.total) return b.total - a.total;
    if (b.stars !== a.stars) return b.stars - a.stars;
    return 0;
  });

  // ✅ 기준: (strong>=1 && total>=2) OR total>=4
  const kept = scored.filter(x => (x.strong >= 1 && x.total >= 2) || x.total >= 4);

  // fallback: 전부 탈락이면, “가장 높은 점수 1개”만(단, total>=2) 유지
  let final = kept;
  if (final.length === 0 && scored.length > 0) {
    const best = scored[0];
    final = (best.total >= 2) ? [best] : [];
  }

  return {
    items: final.map(x => x.it),
    info: {
      in: list.length,
      uniq: uniq.length,
      out: final.length,
      top: scored[0] ? { total: scored[0].total, strong: scored[0].strong, stars: scored[0].stars } : null,
      rule: "(strong>=1 && total>=2) OR total>=4; fallback best if total>=2",
    },
  };
};

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

  // 🧠 QV/FV에서 Gemini 모델 선택 (기본: flash, 옵션: pro)
  // - 클라이언트에서 gemini_model: "flash" | "pro" | undefined 로 전달 가능
  // - 아무 값도 안 오면 기본은 flash 로 간다.
  const geminiModelRaw = (gemini_model || "").toString().trim().toLowerCase();
  let verifyModel = null;        // 최종 verify 모델
  let verifyModelUsed = null;    // 실제로 사용된 verify 모델(로그/응답용)

  // ✅ verify 단계는 flash/flash-lite만 허용 (pro 금지)
if (safeMode === "qv" || safeMode === "fv" || safeMode === "dv" || safeMode === "cv") {
  const g = String(geminiModelRaw || "");
  if (g === "flash-lite" || g === "lite" || /flash-lite/i.test(g)) {
    verifyModel = "gemini-2.5-flash-lite";
  } else {
    verifyModel = "gemini-2.5-flash";
  }
}

  // 🌱 기본값은 "선택된 verify 모델"로 설정 (fallback 등에서 사용)
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

// ✅ snake_case alias (어딘가에 engine_times / engine_metrics 참조가 남아있어도 런타임 에러 방지)
const engine_times = engineTimes;
const engine_metrics = engineMetrics;

  const geminiTimes = {};
  const geminiMetrics = {};

  // ✅ QV/FV 2-call 구조용: 전처리 결과(답변/블록/증거)를 요청 스코프에 보관
  let qvfvPre = null;
  const NAVER_QUERY_MAX = Math.max(1, Math.min(5, parseInt(process.env.NAVER_QUERY_MAX || "3", 10)));

  // =======================================================
// ✅ Naver query expansion helpers (widen pool via diversity)
// - place here (right above qvfvBlocksForVerifyFull) so it's easy to find
// =======================================================

function __uniqStrings(arr) {
  const out = [];
  const seen = new Set();
  for (const v of arr || []) {
    const s = String(v || "").trim();
    if (!s) continue;
    const k = s.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}

function __expandNaverQueries(baseQueries, seedInfo = {}) {
  // baseQueries: 기본 Naver 쿼리 배열
  const base = Array.isArray(baseQueries)
    ? baseQueries.map(q => String(q || "").trim()).filter(Boolean)
    : [];

  // seedInfo: { korean_core, english_core } 같은 구조
  const ko = String(seedInfo.korean_core || "").trim();
  const en = String(seedInfo.english_core || "").trim();

  const extraSeeds = [];
  if (ko) extraSeeds.push(ko);
  if (en) extraSeeds.push(en);

  const expanded = [...base];

  for (const s of extraSeeds) {
    if (!s) continue;
    expanded.push(s);

    // 괄호, 중복 공백 제거한 버전도 한 번 더 추가
    const stripped = s.replace(/[()]/g, " ").replace(/\s+/g, " ").trim();
    if (stripped && stripped !== s) {
      expanded.push(stripped);
    }
  }

  // uniqStrings는 이미 서버에 있는 헬퍼 그대로 사용
  return uniqStrings(expanded, 12);
}

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
    if (ENABLE_WIKIDATA_QVFV) {
  engines.push("crossref", "openalex", "wikidata", "gdelt", "naver");
} else {
  engines.push("crossref", "openalex", "gdelt", "naver");
}

        // QV/FV 전처리는 항상 lite 계열 모델 사용
    //   - 기본값: gemini-2.0-flash-lite
    //   - 필요하면 환경변수 GEMINI_QVFV_PRE_MODEL 로 override 가능
    const preprocessModel =
      (process.env.GEMINI_QVFV_PRE_MODEL && process.env.GEMINI_QVFV_PRE_MODEL.trim())
        || "gemini-2.0-flash-lite";

    const qvfvBaseText = (safeMode === "fv" && userCoreText) ? userCoreText : query;

    // ✅ QV/FV 전처리 원샷 (답변+블록+블록별 쿼리)
    // ??QV/FV ?꾩쿂由??먯꺑 (?듬?+釉붾줉+釉붾줉蹂?荑쇰━)
try {
  const t_pre = Date.now();
  let pre = await preprocessQVFVOneShot({
    mode: safeMode,
    query,
    core_text: qvfvBaseText,
    gemini_key,
    modelName: preprocessModel,
    userId: logUserId, // ??ADD
  });

  const ms_pre = Date.now() - t_pre;
  recordTime(geminiTimes, "qvfv_preprocess_ms", ms_pre);
  recordMetric(geminiMetrics, "qvfv_preprocess", ms_pre);

  //    블록 텍스트는 무조건 snippet_core(또는 core_text)로 고정한다.
  const __isSnippet =
    !!(snippet_meta && typeof snippet_meta === "object" && snippet_meta.is_snippet);

  if (__isSnippet) {
    const __core = String(
      snippet_meta?.snippet_core ?? core_text ?? qvfvBaseText ?? query ?? ""
    ).trim();

    if (__core) {
      const __ko = String(pre?.korean_core || "").trim() || normalizeKoreanQuestion(__core);
      const __en = String(pre?.english_core || "").trim() || String(__core).trim();

      const __makeBlock = (id, txt) => {
        const text = clipBlockText(txt, 260);
        const naverQ = fallbackNaverQueryFromText(text || __ko);
        return {
          id,
          text,
          engine_queries: {
            crossref: limitChars(__en, 90),
            openalex: limitChars(__en, 90),
            wikidata: limitChars(__ko, 50),
            gdelt: limitChars(__en, 120),
            naver: naverQ.slice(0, BLOCK_NAVER_MAX_QUERIES),
          },
        };
      };

      pre = {
        ...pre,
        answer_ko: "", // snippet-FV에서는 answer 필요 없음(확장 서술 방지)
        korean_core: __ko,
        english_core: __en,
        blocks: [__makeBlock(1, __core)].filter((b) => b && b.text),
      };
    }
  }

  qvfvPre = pre;
  qvfvPreDone = true;

  partial_scores.qvfv_pre = {
    korean_core: pre.korean_core,
    english_core: pre.english_core,
    blocks_count: pre.blocks.length,
    model_used: preprocessModel,
  };
  partial_scores.qv_answer = safeMode === "qv" ? pre.answer_ko : null;
} catch (e) {
      if (
  e?.code === "INVALID_GEMINI_KEY" ||
  e?.code === "GEMINI_KEY_EXHAUSTED" ||
  e?.code === "GEMINI_KEY_MISSING" ||
  e?.code === "GEMINI_RATE_LIMIT"
) throw e;

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

  // ----- Naver evidence 선택 준비 -----
  const allowNewsEvidence = isTimeSensitiveText(`${query} ${b?.text || ""}`);

  // ✅ qvfvPre에서 korean_core / english_core를 안전하게 꺼냄
  const qvfvKoreanCore = String(qvfvPre?.korean_core ?? "").trim();
  const qvfvEnglishCore = String(qvfvPre?.english_core ?? "").trim();

  // ✅ Naver용 확장 쿼리: 여기서 한 번만 계산
  const naverQueriesExpanded = __expandNaverQueries(naverQueries, {
    korean_core: qvfvKoreanCore,
    english_core: qvfvEnglishCore,
  });

  // ✅ 확장된 쿼리를 기준으로 evidence 선택
  let naverItemsForVerify = pickTopNaverEvidenceForVerify({
    items: naverItemsAll,
    query,
    blockText: b?.text || "",
    naverQueries: naverQueriesExpanded,
    allowNews: allowNewsEvidence,
    topK: BLOCK_NAVER_EVIDENCE_TOPK,
    minRelevance: NAVER_RELEVANCE_MIN,
  });

  // ----- fallback: strict 필터로 0개 나오면 그래도 뭔가 채워주기 -----
  if (
    (!Array.isArray(naverItemsForVerify) || naverItemsForVerify.length === 0) &&
    Array.isArray(naverItemsAll) &&
    naverItemsAll.length > 0
  ) {
    // 1) 먼저 news 제외 풀
    const __poolNoNews = allowNewsEvidence
      ? naverItemsAll
      : naverItemsAll.filter((r) => r?.naver_type !== "news");

    // 2) tier/whitelisted/inferred 우선
    const __poolPrefer = (__poolNoNews.length ? __poolNoNews : naverItemsAll).filter((r) =>
      !!(r?.tier || r?.whitelisted || r?._whitelist_inferred || r?.inferred)
    );

    // 3) 최종 풀 (prefer > noNews > all)
    const __poolFinal =
      __poolPrefer.length > 0
        ? __poolPrefer
        : __poolNoNews.length > 0
        ? __poolNoNews
        : naverItemsAll;

    naverItemsForVerify = topArr(__poolFinal, BLOCK_NAVER_EVIDENCE_TOPK);
  }

  // ----- gdelt / external / blocksForVerify -----
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
      // ✅ 여기서도 bare korean_core 안 쓰고 확장 쿼리만 사용
      naver: naverQueriesExpanded,
    },
    evidence: {
      crossref: topArr(crPack.result, BLOCK_EVIDENCE_TOPK),
      openalex: topArr(oaPack.result, BLOCK_EVIDENCE_TOPK),
      wikidata: topArr(wdPack.result, 5),
      gdelt: gdeltForVerify,
      naver: topArr(naverItemsForVerify, BLOCK_NAVER_EVIDENCE_TOPK),
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

// ✅ PRE-FINALIZE(호출단계) used/excluded 계산: 쿼리/calls/results 기준
const { used: enginesUsedPre, excluded: enginesExcludedPre } = computeEnginesUsed({
  enginesRequested,
  partial_scores,
  engineMetrics,
});

partial_scores.engines_requested = enginesRequested;

// ⚠️ engines_used / engines_excluded 는 FINALIZE(프루닝 이후)에서만 확정한다.
// 여기서는 디버그용 pre 정보를 별도 필드로만 저장.
partial_scores.engines_used_pre = enginesUsedPre;
partial_scores.engines_excluded_pre = enginesExcludedPre;
partial_scores.engine_exclusion_reasons_pre = Object.fromEntries(
  Object.entries(enginesExcludedPre || {}).map(([k, v]) => [k, v?.reason || "excluded"])
);

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

    // naver tier × type factor (✅ 실제 blocks evidence에 붙은 naver 우선)
// blocksForVerify가 스코프에 없을 수도 있으니 안전하게 처리
const naverUsed = (typeof blocksForVerify !== "undefined" && Array.isArray(blocksForVerify))
  ? blocksForVerify.flatMap((b) => (Array.isArray(b?.evidence?.naver) ? b.evidence.naver : []))
  : [];

const naverPool = (naverUsed.length > 0)
  ? naverUsed
  : (Array.isArray(external.naver) ? external.naver : []);

if (naverPool.length > 0) {
  const weights = naverPool
    .map((item) => {
      const tw =
        (typeof item?.tier_weight === "number" && Number.isFinite(item.tier_weight))
          ? item.tier_weight
          : (item?.whitelisted === true ? 1 : NAVER_NON_WHITELIST_FACTOR);

      const vw =
        (typeof item?.type_weight === "number" && Number.isFinite(item.type_weight))
          ? item.type_weight
          : 1;

      return tw * vw;
    })
    .filter((w) => Number.isFinite(w) && w > 0);

  partial_scores.naver_used_count = naverUsed.length;
  partial_scores.naver_pool_count = naverPool.length;

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

    // ✅ GitHub 결과 누적: 중복 방지 + 상한(cap)
    const GH_CAP = Math.max(1, Number(process.env.GITHUB_MAX_REPOS || 30));
    const ghSeen = new Set(
      (Array.isArray(external.github) ? external.github : [])
        .map(r => String(r?.full_name || r?.html_url || r?.url || r?.name || "").toLowerCase().trim())
        .filter(Boolean)
    );

    function pushGithubRepos(repos) {
      if (!Array.isArray(repos) || repos.length === 0) return;
      if (!Array.isArray(external.github)) external.github = [];

      for (const r of repos) {
        if (!r) continue;
        if (external.github.length >= GH_CAP) break;

        const k = String(r?.full_name || r?.html_url || r?.url || r?.name || "").toLowerCase().trim();
        if (!k) continue;
        if (ghSeen.has(k)) continue;

        ghSeen.add(k);
        external.github.push(r);
      }
    }

    const answerText =
  (safeMode === "cv" && user_answer && user_answer.trim().length > 0)
    ? user_answer
    : query;

// ✅ GitHub 관련 로직에서 항상 쓰는 텍스트(= TDZ 방지)
ghUserText = String(query || "").trim();

const __cachedPayload = __cacheKey ? verifyCacheGet(__cacheKey) : null;
if (__cachedPayload) {
  const elapsedMs = Date.now() - start;

  const out = {
    ...__cachedPayload,
    elapsed: elapsedMs,
    cached: true,
  };

  if (out.partial_scores && typeof out.partial_scores === "object") {
    out.partial_scores = { ...out.partial_scores, cache_hit: true };
  } else {
    out.partial_scores = { cache_hit: true };
  }

  return res.json(buildSuccess(out));
}

// ✅ (B안 보강) Gemini가 sentinel을 놓쳐도, "명백한 비코드"는 DV/CV를 강제 종료
if ((safeMode === "dv" || safeMode === "cv") && looksObviouslyNonCode(rawQuery || query)) {
  const elapsedMs = Date.now() - start;

  const suggestedMode =
    userCoreText && userCoreText.trim().length > 0 ? "fv" : "qv";

  const classifier = {
    type: "obvious_non_code",
    method: "server/looksObviouslyNonCode",
    confidence: 0.99,
    reason: "obvious non-code stats/policy/general query",
  };

  const msg =
    `DV/CV 모드는 GitHub(코드/레포/이슈/커밋) 근거 기반 검증 전용입니다.\n` +
    `현재 질의는 통계/정책/일반 사실 질문으로 보여 DV/CV를 종료합니다.\n\n` +
    `- 권장: 동일 질의를 ${suggestedMode.toUpperCase()}로 보내 주세요.\n` +
    `- DV/CV를 유지하려면: 코드/로그/레포 링크/에러 메시지 등 개발 근거를 포함해 주세요.\n`;

  return res.status(200).json({
    success: true,
    data: {
      code: "MODE_MISMATCH",
      suggested_mode: suggestedMode,
      classifier,

      mode: safeMode,
      truthscore: "0.00%",
      truthscore_pct: 0,
      truthscore_01: 0,
      elapsed: elapsedMs,

      engines: [],
      engines_requested: ["github"],

      partial_scores: {
  ...__ghDebug,
  mode_mismatch: true,
  expected: "code/dev query grounded on GitHub",
  received: "obvious non-code stats/policy/general query",
  suggested_mode: suggestedMode,
  classifier,
},

      flash_summary: msg,
      verify_raw:
        "```json\n" +
        JSON.stringify(
          {
            code: "MODE_MISMATCH",
            mode_mismatch: true,
            mode: safeMode,
            suggested_mode: suggestedMode,
            classifier,
            reason: "obvious non-code query blocked before GitHub search",
          },
          null,
          2
        ) +
        "\n```",

      // 프론트/로그가 기대하면 유지(안 써도 되지만 안전)
      engine_times: {},
      engine_metrics: {},
      gemini_times: {},
      gemini_metrics: {},
      github_repos: [],
    },
    timestamp: new Date().toISOString(),
  });
}

    // ✅ GitHub 쿼리 생성 (Gemini) + (B안) 1-call 분류: 비코드면 sentinel로 종료
const t_q = Date.now();
const ghQueriesRaw = await buildGithubQueriesFromGemini(
  safeMode, query, answerText, gemini_key, logUserId
);
ghUserText = String(query || "").trim();
const ms_q = Date.now() - t_q;
recordTime(geminiTimes, "github_query_builder_ms", ms_q);
recordMetric(geminiMetrics, "github_query_builder", ms_q);

// NOTE: buildGithubQueriesFromGemini는 항상 "배열"을 리턴한다고 가정
let ghQueries = Array.isArray(ghQueriesRaw)
  ? ghQueriesRaw
      .map(x =>
        String(x || "")
          .replace(/["']/g, "")   // ✅ 따옴표 제거(검색 0건 방지)
          .replace(/\s+/g, " ")
          .trim()
      )
      .filter(Boolean)
  : [];

// ✅ (B안) sentinel 규칙: ["__NON_CODE__::<reason>::<confidence>"] 면 DV/CV 종료
let github_classifier = { is_code_query: true, reason: "", confidence: null };

const forceGithubEvidenceQuery =
  /(?:github|깃허브|repo|repository|레포|리포|issue|pull request|pr|commit|branch|npm|package|sdk|library)/i.test(
    `${query} ${ghUserText || ""}`
  ) ||
  /(?:github\.com\/)?[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+/i.test(`${query} ${answerText || ""}`);

if (
  ghQueries.length === 1 &&
  typeof ghQueries[0] === "string" &&
  ghQueries[0].startsWith("__NON_CODE__::")
) {
  // ✅ repo 힌트/개발근거 키워드가 있으면 sentinel을 “검색용 쿼리”로 강제 교체하고 DV 계속
  if (forceGithubEvidenceQuery) {
    const src = String(`${query} ${answerText || ""} ${ghUserText || ""}`);
    const m = src.match(/(?:github\.com\/)?([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/i);

    if (m) {
      const owner = m[1];
      const repo = String(m[2]).replace(/\.git$/i, "");
      ghQueries = [
        `user:${owner} ${repo} in:name,description,readme`,
        `${owner}/${repo} in:name,description`,
      ];
    } else {
      ghQueries = [
        `${query} in:name,description,readme`,
        `${query} stars:>20 in:name,description,readme`,
      ];
    }

    // github_classifier는 “강제 통과”로 기록만 남기고 아래 흐름 계속
    github_classifier.is_code_query = true;
    github_classifier.reason = "forced_github_mode: repo hint / github keywords";
    github_classifier.confidence = github_classifier.confidence ?? 0.6;

  } else {
    // ⬇️ (여기 아래는 기존 코드 그대로) non-code면 DV/CV 종료 return ...
  github_classifier.is_code_query = false;

  const prefix = "__NON_CODE__::";
  const rest = ghQueries[0].slice(prefix.length);

  // reason에 "::"가 들어가도 안전하게 파싱 (마지막 "::" 뒤를 confidence로 시도)
  let reason = (rest || "").trim();
  let confidence = null;

  const lastSep = rest.lastIndexOf("::");
  if (lastSep >= 0) {
    const maybeReason = rest.slice(0, lastSep).trim();
    const maybeConfStr = rest.slice(lastSep + 2).trim();
    const conf = Number(maybeConfStr);
    if (Number.isFinite(conf)) {
      reason = maybeReason || reason;
      confidence = conf;
    }
  }

  github_classifier.reason = reason;
  github_classifier.confidence = confidence;

    const elapsedMs = Date.now() - start;

  const suggestedMode =
    (safeMode === "cv" && typeof user_answer === "string" && user_answer.trim().length > 0)
      ? "fv"
      : "qv";

  const classifier = {
    type: "gemini_non_code",
    method: "buildGithubQueriesFromGemini/sentinel",
    confidence: github_classifier.confidence,
    reason: github_classifier.reason || "gemini_classified_non_code",
  };

  const msg =
    `DV/CV 모드는 GitHub(코드/레포/이슈/커밋) 근거 기반 검증 전용입니다.\n` +
    `Gemini 분류 결과: 비코드 질의로 판단되어 DV/CV를 종료합니다.\n` +
    (github_classifier.reason ? `사유: ${github_classifier.reason}\n` : "") +
    (github_classifier.confidence !== null ? `confidence: ${github_classifier.confidence}\n` : "") +
    `\n권장:\n` +
    `- 일반 사실/통계/정책 검증이면 ${suggestedMode.toUpperCase()}로 보내세요.\n` +
    `- DV/CV를 유지하려면 server.js/로그/에러/코드블록/레포 링크 등 "코드 근거"를 포함하세요.\n`;

  return res.status(200).json({
    success: true,
    data: {
      // ✅ (A안) 표준화
      code: "MODE_MISMATCH",
      suggested_mode: suggestedMode,
      classifier,

      mode: safeMode,
      truthscore: "0.00%",
      truthscore_pct: 0,
      truthscore_01: 0,
      elapsed: elapsedMs,

      engines: [],
      engines_requested: ["github"],

      partial_scores: {
  ...__ghDebug,
  mode_mismatch: true,
  expected: "code/dev query grounded on GitHub",
  received: "gemini classified non-code query",

  github_classifier,
  github_queries: ghQueries,
  engine_queries: { github: [] },
  engine_results: { github: 0 },
},

      // DV/CV 응답 포맷 유지(프론트/로그 안정)
      flash_summary: msg,
      verify_raw:
        "```json\n" +
        JSON.stringify(
          {
            mode_mismatch: true,
            code: "MODE_MISMATCH",
            mode: safeMode,
            suggested_mode: suggestedMode,
            classifier,
            github_classifier,
            note: "Non-code query rejected by Gemini classifier sentinel; no GitHub search executed.",
          },
          null,
          2
        ) +
        "\n```",

      gemini_verify_model: "gemini-2.5-flash", // 분류/쿼리빌더 호출 모델(참고용)
      engine_times: {},
      engine_metrics: {},
      gemini_times: {},
      gemini_metrics: {},

      github_repos: [],
    },
    timestamp: new Date().toISOString(),
  });
}

// ✅ (DV/CV 품질) GitHub 검색 쿼리에서 'awesome/curated list'류를 기본 제외
// - 사용자가 리스트를 원하면(awesome/list 등) 그대로 둠
const wantsCuratedListsFromText = (t) =>
  /\b(awesome|curated|curation|list|directory|collection|resources|public[- ]?apis)\b/i.test(String(t || ""));

ghUserText = String(answerText || query || "").trim();
const allowCuratedLists = wantsCuratedListsFromText(`${rawQuery || ""} ${answerText || ""} ${query || ""} ${ghUserText || ""}`);

// ✅ (DV/CV 품질) GitHub repo relevance 필터 + 1회 fallback
const githubRepoBlob = (r) => {
  const topics = Array.isArray(r?.topics) ? r.topics.join(" ") : "";
  return `${r?.full_name || ""}\n${r?.name || ""}\n${r?.description || ""}\n${topics}`.toLowerCase();
};

// 질의에 "강한 앵커"가 있으면 그게 repo 메타에 반드시 있어야 통과
const needExpressRateLimit = /express-rate-limit/i.test(rawQuery);
const needRedis = /\bredis\b/i.test(rawQuery);

// 1차 relevance 판정
const isRelevantGithubRepo = (r) => {
  const blob = githubRepoBlob(r);

  if (needExpressRateLimit) {
    // express-rate-limit 관련이면 "express-rate-limit" 또는 공식 store 이름( rate-limit-redis )이 최소 1개는 있어야 함
    if (!blob.includes("express-rate-limit") && !blob.includes("rate-limit-redis")) return false;
  }
  if (needRedis) {
    // redis가 질의에 있으면 repo 메타에도 redis가 있어야 함 (Hono/Koa 같은 엉뚱한 레포 컷)
    if (!blob.includes("redis")) return false;
  }
  return true;
};

// ✅ DV/CV: GitHub 검색 실행 (Gemini가 만든 ghQueries 기반)
if (
  (safeMode === "dv" || safeMode === "cv") &&
  Array.isArray(ghQueries) &&
  ghQueries.length > 0
) {
  const githubSeen = new Set(); // ghQueries 전체에 대해 중복 제거
const githubCapTotal = Math.max(1, Number(process.env.GITHUB_DV_CV_MAX_REPOS || 18));
const githubCapPerQuery = Math.max(1, Number(process.env.GITHUB_DV_CV_MAX_PER_QUERY || 8));

// ✅ curated 의도는 요청당 1번만 계산
const wantCurated =
  wantsCuratedListsFromText(rawQuery) || wantsCuratedListsFromText(ghUserText);

// curated 허용 조건: 전역 allowCuratedLists 이거나, 질문/텍스트가 curated를 원할 때
const allowCurated = Boolean(allowCuratedLists || wantCurated);

// ✅ gh repo 중복 제거(여러 query/page에서 같은 repo 나오는 것 방지)
const ghSeen = new Set();

for (const q of ghQueries) {
  const q1 = sanitizeGithubQuery(q, ghUserText);
  if (!q1) continue;

  // engine_queries.github (있을 때만 push + 중복 방지)
  try {
    if (
      typeof engineQueries === "object" &&
      engineQueries &&
      Array.isArray(engineQueries.github)
    ) {
      const exists = engineQueries.github.some(
        (x) => String(x || "").toLowerCase().trim() === String(q1 || "").toLowerCase().trim()
      );
      if (!exists) engineQueries.github.push(q1);
    }
  } catch {}

  // 1) page 1
  const pack1 = await safeFetchTimed(
  "github",
  (qq, ctx) => fetchGitHub(qq, githubTokenFinal, { ...ctx, page: 1, skipSanitize: true }),
  q1,
  engineTimes,
  engineMetrics
);

let r1 = Array.isArray(pack1?.result) ? pack1.result : [];
r1 = r1.filter(isRelevantGithubRepo);

if (!allowCurated) r1 = r1.filter(r => !isBigCuratedListRepo(r));

// 2) page 2 (page1이 "필터 후 0"이면 한 번 더)
if (!r1.length) {
  const pack2 = await safeFetchTimed(
  "github",
  (qq, ctx) => fetchGitHub(qq, githubTokenFinal, { ...ctx, page: 2, skipSanitize: true }),
  q1,
  engineTimes,
  engineMetrics
);

  let r2 = Array.isArray(pack2?.result) ? pack2.result : [];
  r2 = r2.filter(isRelevantGithubRepo);
  if (!allowCurated) r2 = r2.filter(r => !isBigCuratedListRepo(r));

  if (r2.length) r1 = r2;
}

if (r1.length) {
  // per-query cap
  if (r1.length > githubCapPerQuery) r1 = r1.slice(0, githubCapPerQuery);

  // dedupe across all ghQueries/pages
  const uniq = [];
  for (const it of r1) {
    const k = String(it?.full_name || it?.html_url || it?.url || it?.name || "").toLowerCase().trim();
    if (!k) continue;
    if (githubSeen.has(k)) continue;
    githubSeen.add(k);
    uniq.push(it);
    if (external.github.length + uniq.length >= githubCapTotal) break;
  }

  if (uniq.length) pushGithubRepos(uniq);
}

// total cap reached? stop further ghQueries loop
if (external.github.length >= githubCapTotal) break;
    }
  }
}

// 🌟 필터링 전 raw 보관(디버깅/메시지용)
const github_raw_before_filter = Array.isArray(external.github) ? [...external.github] : [];

// 1차 필터
external.github = (external.github || [])
  .filter(isRelevantGithubRepo)
  .filter(r => !isBigCuratedListRepo(r));

// ✅ fallback 트리거(Express rate-limit 류 질의일 때만)
const needExpressRateLimit = (() => {
  const base = `${query || ""} ${answerText || ""}`.toLowerCase();

  // ghQueries가 scope에 없을 수도 있으니 방어
  const qs =
    (typeof ghQueries !== "undefined" && Array.isArray(ghQueries) ? ghQueries : [])
      .map(x => String(x || "").toLowerCase());

  const blob = [base, ...qs].join(" ");

  return (
    blob.includes("express-rate-limit") ||
    blob.includes("rate-limit-redis") ||
    blob.includes("rate limit redis") ||
    blob.includes("keygenerator") ||
    blob.includes("trust proxy")
  );
})();
  
// 0건이면(특히 express-rate-limit 케이스) GitHub에 1회 fallback 쿼리 추가로 더 찾아봄
if (
  (safeMode === "dv" || safeMode === "cv") &&
  external.github.length === 0 &&
  needExpressRateLimit
) {
  const extraQueries = [
    // repositories search에서 유효한 qualifier 조합
    `org:express-rate-limit rate-limit-redis`,
    `"rate-limit-redis" "express-rate-limit" in:name,description,readme`,
  ];

  for (const q of extraQueries.slice(0, 2)) {
    // engine_queries에도 남기기(있을 때만)
    try {
      if (typeof engineQueries === "object" && engineQueries && Array.isArray(engineQueries.github)) {
        engineQueries.github.push(q);
      }
    } catch {}

    const { result } = await safeFetchTimed(
      "github",
      (qq, ctx) => fetchGitHub(qq, githubTokenFinal, { ...ctx, userText: ghUserText }),
        sanitizeGithubQuery(q, ghUserText),
      engineTimes,
      engineMetrics
    );
    if (Array.isArray(result) && result.length) pushGithubRepos(result);
  }

  // fallback 후 재필터
  external.github = (external.github || []).filter(isRelevantGithubRepo);
}

// ✅ GitHub 결과 정리: 중복 제거 + stars 우선 + 최신 업데이트 우선 (품질 개선)
external.github = (external.github || [])
  .filter(Boolean)
  .map(r => ({
    ...r,
    stars: Number(r?.stars ?? r?.stargazers_count ?? 0),
    updated: String(r?.updated ?? r?.updated_at ?? ""),
  }))
  .filter(r => !isBigCuratedListRepo(r)) // ✅ 추가: curated list 제거

  // 중복 제거(이름 기준) — 네 로그처럼 중복(repo가 2번) 나오는 것 방지
  .filter((r, idx, arr) => {
    const key = String(r?.name || "").toLowerCase();
    if (!key) return false;
    return idx === arr.findIndex(x => String(x?.name || "").toLowerCase() === key);
  })
  // stars 내림차순 → updated 최신순
  .sort((a, b) => {
    const ds = (b.stars - a.stars);
    if (ds !== 0) return ds;
    const ta = Date.parse(a.updated || "") || 0;
    const tb = Date.parse(b.updated || "") || 0;
    return tb - ta;
  })
  .slice(0, 12);

  // ✅ GitHub results dedupe (multi-query/page overlap) + cap
if (Array.isArray(external.github) && external.github.length > 1) {
  const seen = new Set();
  const uniq = [];

  for (const r of external.github) {
    const key = String(r?.full_name || r?.html_url || r?.url || "").toLowerCase().trim();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    uniq.push(r);
  }

  const cap = Math.max(
    1,
    parseInt(process.env.GITHUB_MAX_RESULTS_KEEP || "40", 10) || 40
  );
  external.github = uniq.slice(0, cap);
}

const GH_MIN_STARS = 3;

const ghUrlHit = /https?:\/\/github\.com\/[^\s/]+\/[^\s/]+/i.test(rawQuery);
const ghOwnerRepoMatch = String(rawQuery || "").match(/\b[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\b/);
// api/verify 같은 일반 경로 오탐 방지: owner/repo 토큰에 - _ . 중 하나라도 있을 때만 repo로 인정
const ghOwnerRepoHit = !!(ghOwnerRepoMatch && /[-_.]/.test(ghOwnerRepoMatch[0]));
const ghHardRepoHint = ghUrlHit || ghOwnerRepoHit;

const ghMaxStars = Math.max(
  0,
  ...(Array.isArray(external.github) ? external.github : []).map(r =>
    Number(r?.stars ?? r?.stargazers_count ?? 0)
  )
);

if ((safeMode === "dv" || safeMode === "cv") && !ghHardRepoHint && ghMaxStars < GH_MIN_STARS) {
  external.github = [];
}

// ✅ DV/CV는 GitHub 근거가 0이면 여기서 종료(헛소리 방지) + (스키마 통일: code/suggested_mode/classifier)
if (
  (safeMode === "dv" || safeMode === "cv") &&
  (!Array.isArray(external.github) || external.github.length === 0)
) {
  const suggestedMode = safeMode; // 모드는 맞는데 근거가 없음 → 모드 유지 + 입력을 더 구체화 유도

  const classifier = {
    type: "github_no_results",
    method: "github/search",
    confidence: null,
    reason: "no_results",
  };

    // ✅ 실제로 기록된 github queries 우선 (sanitize된 q1이 engineQueries.github에 들어감)
  const usedGhQueries =
    (typeof engineQueries === "object" &&
      engineQueries &&
      Array.isArray(engineQueries.github) &&
      engineQueries.github.length > 0)
      ? engineQueries.github
      : (Array.isArray(ghQueries) ? ghQueries : []);

  const githubCount = Array.isArray(external?.github) ? external.github.length : 0;

  const msg =
    `DV/CV 모드는 GitHub(코드/레포/이슈/커밋) 근거 기반 검증 전용입니다.\n` +
    `하지만 이번 요청은 GitHub 검색 결과가 0건이라 근거를 확보하지 못했습니다.\n\n` +
    `- 생성/사용된 GitHub queries:\n  - ${(Array.isArray(usedGhQueries) ? usedGhQueries.join("\n  - ") : "")}\n\n` +
    `권장:\n` +
    `- 레포 URL/패키지명/에러 로그/코드 블록을 포함해서 다시 요청\n` +
    `- 일반 사실/통계 검증이면 QV/FV로 보내기\n`;

  return res.status(200).json({
    success: true,
    data: {
      code: "NO_EVIDENCE",
      suggested_mode: suggestedMode,
      classifier,

      mode: safeMode,
      truthscore: "0.00%",
      truthscore_pct: 0,
      truthscore_01: 0,
      elapsed: Date.now() - start,

      engines: [],
      engines_requested: ["github"],

      partial_scores: {
       ...__ghDebug,
        no_evidence: true,
        expected: "GitHub evidence (repo/code/issue/commit)",
        received: "github search returned 0 results",
        suggested_mode: suggestedMode,
        classifier,

        github_queries: Array.isArray(usedGhQueries) ? usedGhQueries : [],
        engine_queries: {
          github: Array.isArray(usedGhQueries) ? usedGhQueries.slice(0, 12) : [],
        },
        engine_results: { github: githubCount },
      },

      flash_summary: msg,
      verify_raw:
        "```json\n" +
        JSON.stringify(
          {
            code: "NO_EVIDENCE",
            mode: safeMode,
            suggested_mode: suggestedMode,
            classifier,
            github_queries: Array.isArray(usedGhQueries) ? usedGhQueries : [],
            note: "No GitHub evidence found; DV/CV aborted before Gemini verify to avoid hallucination.",
          },
          null,
          2
        ) +
        "\n```",

      /// 프론트/로그 안정용(있어도 되고 없어도 되지만, 통일 위해 유지)
      engine_times: engineTimes,
      engine_metrics: engineMetrics,
      gemini_times: geminiTimes,
      gemini_metrics: geminiMetrics,
      github_repos: [],
    },
    timestamp: new Date().toISOString(),
  });
}

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
    // ✅ 실제로 사용된 github queries 우선 (sanitize된 q1이 engineQueries.github에 들어감)
const usedGhQueriesMain =
  (typeof engineQueries === "object" &&
    engineQueries &&
    Array.isArray(engineQueries.github) &&
    engineQueries.github.length > 0)
    ? engineQueries.github
    : (Array.isArray(ghQueries) ? ghQueries : []);

partial_scores.github_queries = usedGhQueriesMain;
partial_scores.engine_queries = {
  github: uniqStrings(usedGhQueriesMain, 12),
};

// ✅ DV/CV도 engines_used 계산(쿼리/calls/results 기준)
partial_scores.engine_results = {
  github: Array.isArray(external.github) ? external.github.length : 0,
};

// QV/FV처럼 로그용으로 얘네도 남겨두면 Admin UI에서 보기 편함
partial_scores.engine_times = engineTimes;
partial_scores.engine_metrics = engineMetrics;

const enginesRequested = [...engines];

const { used: enginesUsedPre, excluded: enginesExcludedPre } = computeEnginesUsed({
  enginesRequested,
  partial_scores,
  engineMetrics,
});

partial_scores.engines_requested = enginesRequested;

// FINALIZE에서 engines_used 확정(여긴 pre만)
partial_scores.engines_used_pre = enginesUsedPre;
partial_scores.engines_excluded_pre = enginesExcludedPre;
partial_scores.engine_exclusion_reasons_pre = Object.fromEntries(
  Object.entries(enginesExcludedPre || {}).map(([k, v]) => [k, v?.reason || "excluded"])
);

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
너는 대한민국 법령 및 판례를 요약해주는 엔진이다.
[사용자 질의]
${query}

[아래는 K-Law API에서 가져온 JSON 응답이다.]
이 JSON 안에 포함된 관련 법령·판례를 확인하고 질의에 답하는 데 중요한 내용만 요약해라.

- 한국어로 3~7개의 bullet
- 법령/조문 또는 사건명 + 핵심(의무/금지/절차)
- 서론/결론 금지

[K-Law JSON]
${JSON.stringify(external.klaw).slice(0, 6000)}
      `.trim();

      try {
        const t_lv = Date.now();
        lvSummary = await fetchGeminiSmart({
  userId: logUserId,
  keyHint: gemini_key,
  model: "gemini-2.5-flash-lite",
  payload: { contents: [{ parts: [{ text: prompt }] }] },
});
        const ms_lv = Date.now() - t_lv;
        recordTime(geminiTimes, "lv_flash_lite_summary_ms", ms_lv);
        recordMetric(geminiMetrics, "lv_flash_lite_summary", ms_lv);
      } catch (e) {
        if (
  e?.code === "INVALID_GEMINI_KEY" ||
  e?.code === "GEMINI_KEY_EXHAUSTED" ||
  e?.code === "GEMINI_KEY_MISSING" ||
  e?.code === "GEMINI_RATE_LIMIT"
) throw e;

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

// ③ 엔진 보정계수는 engines_used(E_eff) FINALIZE 이후 계산하도록 아래로 이동
engineFactor = 1.0;
partial_scores.engine_factor = 1.0;
partial_scores.engine_factor_engines = [];

    // ─────────────────────────────
    // ④ Gemini 요청 단계 (Flash → Pro)
    //   - QV/FV: 전처리에서 이미 답변/블록 생성 → 여기서는 검증(verify)만 수행
    //   - DV/CV: external을 포함한 요약(flash) + 검증(verify)
    // ─────────────────────────────
let flash = "";
let verify = "";
let verifyMeta = null;

// ✅ verify 단계에서 쓸 Gemini 모델 (flash / flash-lite만 허용)
if (verifyModel && /flash-lite/i.test(String(verifyModel))) {
  // 예: "flash-lite", "gemini-2.5-flash-lite"
  verifyModelUsed = "gemini-2.5-flash-lite";
} else {
  // null / "flash" / "pro" / 기타 → 전부 flash로 통일
  verifyModelUsed = "gemini-2.5-flash";
}

// ✅ flash(요약/답변) 단계에서 쓸 모델 (flash / flash-lite만 허용)
let answerModelUsed = "gemini-2.5-flash"; // 기본값

if (safeMode === "qv" || safeMode === "fv") {
  // QV/FV에서도 이제 flash / flash-lite만 허용
  const gRaw = String(geminiModelRaw || "").toLowerCase();

  if (gRaw === "flash-lite" || gRaw === "lite") {
    answerModelUsed = "gemini-2.5-flash-lite";
  } else {
    // "" / "flash" / "pro" / 기타 → 모두 flash 고정
    answerModelUsed = "gemini-2.5-flash";
  }
}

    try {
      // 4-1) Flash 단계
      if (safeMode === "qv") {
  flash = (partial_scores.qv_answer || "").toString();

  // 전처리 실패 시: 여기서라도 답변 생성
  if (!flash.trim()) {
    const flashPrompt = `[QV] ${query}\n한국어로 6~10문장으로 답변만 작성하세요.`;
    const t_flash = Date.now();
    flash = await fetchGeminiSmart({
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
        flash = await fetchGeminiSmart({
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
            // ✅ (패치) 숫자/연도 블록이면: 블록별로 "가장 맞는" Naver URL을 골라 evidence_text를 채움
            if (NAVER_NUMERIC_FETCH && (safeMode === "qv" || safeMode === "fv") && Array.isArray(blocksForVerify) && blocksForVerify.length > 0) {
  let budget = NAVER_NUMERIC_FETCH_MAX;

  // 이미 본 URL 중복 fetch 방지(성능/부하)
  const __nfSeen = new Set();

    // (일반화) 화이트리스트 tier1 전체를 "핵심 공공/국제 도메인"으로 보고
  // 숫자 검증 시 우선순위를 조금 더 올려 줌.
  //
  // - 도메인은 naver_whitelist.json 의 tiers.tier1.domains 에서만 관리
  // - 코드는 "tier1에 속해 있냐?"만 본다.
  const wlForNumeric = loadNaverWhitelist();
  const __numericPriorityDomains = Array.isArray(wlForNumeric?.tiers?.tier1?.domains)
    ? wlForNumeric.tiers.tier1.domains
    : [];

  const __isCoreStatHost = (host = "") =>
    __numericPriorityDomains.some((d) => host.endsWith(d));

  const __getHostFromUrl = (u = "") => {
    try {
      const _u = new URL(u);
      return String(_u.hostname || "").toLowerCase();
    } catch {
      return "";
    }
  };

  for (const b of blocksForVerify) {
    if (budget <= 0) break;
    if (!hasNumberLike(b?.text) && !hasNumberLike(query)) continue;

    const evsAll = Array.isArray(b?.evidence?.naver) ? b.evidence.naver : [];
    if (evsAll.length === 0) continue;

    const needle = `${String(b?.text || "")} ${String(query || "")}`.trim();
    const years = Array.from(needle.matchAll(/\b(19\d{2}|20\d{2})\b/g)).map(m => m[1]);
    const nums  = Array.from(needle.matchAll(/(\d+(?:\.\d+)?)/g)).map(m => m[1]).filter(x => x && x.length <= 10);
    const kw = extractKeywords(needle, 12);

    // URL별 fetch 후보 3개 정도만: 연도/숫자 매칭 + 관련도 + 화이트리스트/도메인 가중치
    const scored = [];
    for (const ev of evsAll) {
      const urlCand = String(ev?.source_url || ev?.link || "").trim();
      if (!urlCand) continue;
      if (!isSafeExternalHttpUrl(urlCand)) continue;

      const text = `${String(ev?.title || "")} ${String(ev?.desc || "")}`;
      const rel = keywordHitRatio(text, kw);

      const isWhitelisted = (ev?.whitelisted === true) || !!ev?.tier;
      const isInferred = (ev?.inferred === true);

      const hasYear = years.length ? years.some(y => text.includes(y)) : false;
      const hasExactNum = nums.length ? nums.some(n => text.includes(n)) : false;
      const hasAnyNum = hasNumberLike(text);

      const allowInferred = isInferred && rel >= 0.25;
      const allowNonWhitelist =
        !isWhitelisted && !isInferred &&
        (hasYear || hasExactNum || (hasAnyNum && rel >= 0.35));

      if (!isWhitelisted && !allowInferred && !allowNonWhitelist) continue;

      let baseW = 1.0;
      if (typeof ev?.tier_weight === "number" && Number.isFinite(ev.tier_weight)) baseW *= ev.tier_weight;
      if (typeof ev?.type_weight === "number" && Number.isFinite(ev.type_weight)) baseW *= ev.type_weight;

      // (추가) 도메인 기준 가중치 – 통계청/KOSIS 계열은 강하게 우대
      const hostRaw = String(ev?.host || ev?.source_host || "").toLowerCase();
      const hostFromUrl = __getHostFromUrl(urlCand);
      const host = hostRaw || hostFromUrl;

      let hostBonus = 1.0;
      if (host && __isCoreStatHost(host)) {
        hostBonus *= 1.35;        // 통계청/KOSIS/국가통계/국제통계 사이트 강한 우대
      } else if (host && host.endsWith("un.org")) {
        hostBonus *= 1.15;        // UN 계열(인구 DB 등)
      } else if (host && host.includes("blog.naver.com")) {
        // 블로그는 기본적으로 숫자가 잘 맞아도 살짝 디스카운트
        hostBonus *= 0.9;
      }

      let bonus = 1.0;
      if (years.length || nums.length) {
        if (hasYear) bonus *= 1.10;
        if (hasExactNum) bonus *= NAVER_NUM_MATCH_BOOST;
        if (!hasYear && !hasExactNum) bonus *= 0.85;
      }
      if (hasAnyNum) bonus *= 1.10;

      const score = baseW * hostBonus * (0.55 + 0.45 * rel) * bonus;
      scored.push({ ev, score, host });
    }

    if (scored.length === 0) continue;

    scored.sort((a, b) => b.score - a.score);

    // (추가) 핵심 통계 도메인에서 최소 1개는 보호 슬롯으로 확보
    let corePreferred = null;
    for (const item of scored) {
      if (item.host && __isCoreStatHost(item.host)) {
        corePreferred = item;
        break;
      }
    }

    const candidates = [];
    const candSeen = new Set();

    if (corePreferred && corePreferred.ev) {
      const ev = corePreferred.ev;
      const u = String(ev?.source_url || ev?.link || "").trim();
      candidates.push(ev);
      if (u) candSeen.add(u);
    }

    for (const item of scored) {
      if (candidates.length >= 3) break;
      const ev = item.ev;
      if (!ev) continue;
      if (corePreferred && ev === corePreferred.ev) continue;

      const u = String(ev?.source_url || ev?.link || "").trim();
      if (u && candSeen.has(u)) continue;

      candidates.push(ev);
      if (u) candSeen.add(u);
    }

    for (const ev of candidates) {
      if (budget <= 0) break;
      if (ev?.evidence_text) continue;

      const url = String(ev?.source_url || ev?.link || "").trim();
      if (!url) continue;

      if (__nfSeen.has(url)) continue;
      __nfSeen.add(url);

      let pageText = null;
      try {
        pageText = await withTimebox(
          ({ signal }) => fetchReadableText(url, NAVER_FETCH_TIMEOUT_MS, { signal }),
          NAVER_FETCH_TIMEOUT_MS,
          "naver_numeric_fetch"
        );
      } catch {
        continue;
      }
      if (!pageText) continue;

      const excerpt = extractExcerptContainingNumbers(pageText, needle, EVIDENCE_EXCERPT_CHARS);
      if (!excerpt) continue;

      if (NAVER_STRICT_YEAR_MATCH && years.length) {
        if (!years.some(y => excerpt.includes(y))) continue;
      }

      ev.evidence_text = excerpt;
      budget -= 1;
    }
  }
}

// ✅ S-12: evidence-aware block pruning (no-evidence blocks removed BEFORE Gemini verify)
// - blocksForVerify는 "검증 입력"이므로 여기서 잘라내면 (1) 환각 블록 방지 (2) verify 시간 단축
if ((safeMode === "qv" || safeMode === "fv") && Array.isArray(blocksForVerify) && blocksForVerify.length > 0) {
  const dropped = [];
  const kept = [];
  const numeric_soft_warnings = [];

  for (const b of blocksForVerify) {
    const ev = b?.evidence || {};

    // 엔진 evidence가 1개라도 있으면 통과
    const hasAnyEvidence = Object.values(ev).some((v) => Array.isArray(v) && v.length > 0);
    if (!hasAnyEvidence) {
      dropped.push({
        id: b?.id,
        text: String(b?.text || "").slice(0, 220),
        reason: "no_engine_evidence",
      });
      continue;
    }

    // 숫자/연도 주장 블록이면: excerpt/title/desc 어디든 숫자 흔적이 있는 evidence가 최소 1개는 있어야 통과
    // (숫자근거 없이 숫자블록이 붙으면 QV2에서 '근거 있는데도 무근거' / '중간구간 환각' 둘 다 악화)
        const claimText = `${b?.text || ""} ${query || ""}`;
    const isNumericClaim = hasStrongNumberLike(claimText);

    if (isNumericClaim) {
      const evItems = Object.values(ev).filter(Array.isArray).flat();

      const evTextBlob = evItems
        .map((x) => `${x?.evidence_text || ""} ${x?.title || ""} ${x?.desc || ""} ${x?.url || ""} ${x?.host || ""}`)
        .join(" ");

      const hasTrusted = evItems.some(isTrustedNumericEvidenceItem);

      // ✅ 기본: 숫자 못 찾더라도 "소프트 킵" (Gemini가 최종 판단)
      // ✅ 필요하면 STRICT_NUMERIC_PRUNE=true로 예전처럼 하드 드랍 가능
      if (!hasNumberLike(evTextBlob) && !hasTrusted) {
        if (STRICT_NUMERIC_PRUNE) {
          dropped.push({
            id: b?.id,
            text: String(b?.text || "").slice(0, 220),
            reason: "numeric_claim_no_numeric_evidence",
          });
          continue;
        } else {
          numeric_soft_warnings.push({
            id: b?.id,
            text: String(b?.text || "").slice(0, 220),
            reason: "numeric_claim_no_numeric_evidence",
            action: "soft_keep",
          });
        }
      }
    }

    kept.push(b);
  }

  // blocksForVerify가 const여도 안전하게(배열 in-place 교체)
  blocksForVerify.splice(0, blocksForVerify.length, ...kept);

    partial_scores.evidence_prune = {
    before: kept.length + dropped.length,
    after: kept.length,
    dropped,
    numeric_soft_warnings,
  };
}

// (log) numeric_evidence_match 직전: 숫자 claim 블록/엔진 개괄 로그
if ((safeMode === "qv" || safeMode === "fv") && Array.isArray(blocksForVerify) && blocksForVerify.length > 0) {
  try {
    const numericCandidates = [];

    for (const b of blocksForVerify) {
      const txt = `${b?.text || ""} ${query || ""}`;
      if (!hasStrongNumberLike(txt)) continue;

      const ev = b?.evidence || {};
      const enginesWithEvidence = Object.keys(ev).filter(
        (k) => Array.isArray(ev[k]) && ev[k].length > 0
      );

      numericCandidates.push({
        id: b?.id,
        text: String(b?.text || "").slice(0, 200),
        engines: enginesWithEvidence,
      });
    }

    partial_scores.numeric_evidence_match_pre = {
      blocks_total: blocksForVerify.length,
      numeric_candidates: numericCandidates,
    };
  } catch (_e) {
    // logging 실패는 무시
  }
}

// ✅ S-13/S-12: numeric/year strict evidence match + (optional) drop no-evidence claim blocks (QV/FV)
// (insert here: AFTER evidence_prune block, BEFORE FINALIZE block)
if ((safeMode === "qv" || safeMode === "fv") && Array.isArray(blocksForVerify) && blocksForVerify.length > 0) {
  // ✅ 기본은 SOFT(블록/근거 안 버림). STRICT=true일 때만 하드 필터/드랍

  const cleanEvidenceText = (raw = "") => {
    let s = String(raw || "");
    s = s.replace(/<script[\s\S]*?<\/script>/gi, " ");
    s = s.replace(/<style[\s\S]*?<\/style>/gi, " ");
    s = s.replace(/<[^>]+>/g, " ");
    s = s.replace(/&nbsp;|&amp;|&quot;|&#39;|&lt;|&gt;/g, " ");
    s = s.replace(/\s+/g, " ").trim();
    s = s.replace(/\b(복사|공유|인쇄|댓글|신고|추천|구독)\b/g, " ").replace(/\s+/g, " ").trim();
    return s;
  };

  const extractNumericTokens = (text = "") => {
  const t = String(text || "");

  // years: 4자리 연도만
  const years = Array.from(new Set((t.match(/\b(19\d{2}|20\d{2}|2100)\b/g) || [])));

  // nums: 콤마/소수 포함 숫자 토큰 추출 후 정규화(콤마 제거)
  const rawNums = t.match(/\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b|\b\d+(?:\.\d+)?\b/g) || [];
  const nums = Array.from(
    new Set(
      rawNums
        .map((x) => normalizeNumToken(x))          // "5,156" -> "5156"
        .filter((n) => {
          if (!n) return false;

          // 연도(YYYY)는 nums에서 제외 (years에서만 체크)
          if (/^(19\d{2}|20\d{2}|2100)$/.test(n)) return false;

          // 너무 약한 숫자(한 자리)는 제외
          if (/^\d$/.test(n)) return false;

          // 최소 3자리 이상 or 소수는 유지
          return n.includes(".") || n.length >= 3;
        })
    )
  );

  return { years, nums };
};

  const isLikelyClaimText = (text = "") => {
    const t = String(text || "").trim();
    if (t.length < 12) return false;
    if (/\b(이다|입니다|한다|했다|예정|계획|완료|도입|시행)\b/.test(t)) return true;
    if (/(19\d{2}|20\d{2})/.test(t)) return true;
    if (/\b\d+(?:\.\d+)?\b/.test(t)) return true;
    return false;
  };

    const numericPassForEvidence = (claimTokens, evidenceText) => {
    const evRaw = String(evidenceText || "");
    const evCompact = evRaw.replace(/[,\s]/g, ""); // "5,156" -> "5156" (+ 공백도 제거)

    const years = Array.isArray(claimTokens?.years) ? claimTokens.years : [];
    const nums  = Array.isArray(claimTokens?.nums)  ? claimTokens.nums  : [];

    const needYear = years.length > 0;
    const needNum  = nums.length > 0;

    const yearsHit = needYear
      ? years.some(y => evRaw.includes(String(y)) || evCompact.includes(String(y)))
      : false;

    const numsHit = needNum
      ? nums.some(n => {
          const s = String(n);
          const sCompact = s.replace(/[,\s]/g, "");
          return evRaw.includes(s) || evCompact.includes(sCompact);
        })
      : false;

    // ✅ STRICT=true면 강하게(year && num), STRICT=false면 약하게(year || num)
    if (needYear && needNum) return STRICT_NUMERIC_PRUNE ? (yearsHit && numsHit) : (yearsHit || numsHit);
    if (needYear) return yearsHit;
    if (needNum) return numsHit;
    return true;
  };

  const countTotalBlockEvidence = (block) => {
    const ev = block?.evidence;
    if (!ev || typeof ev !== "object") return 0;
    let n = 0;
    for (const k of Object.keys(ev)) {
      const arr = ev?.[k];
      if (Array.isArray(arr)) n += arr.length;
    }
    return n;
  };

  const beforeBlocks = blocksForVerify.length;

  const droppedBlocks = [];   // STRICT일 때 실제 드랍
  const candidates = [];      // SOFT일 때 드랍 “후보” 로그
  const touched = [];
  const mismatchFallback = []; // 숫자 필터 결과 0이라 fallback으로 원본 유지한 기록

  let itemsBefore = 0;
  let itemsAfter = 0;

  const keptBlocks = [];

  for (const b of blocksForVerify) {
    const claimText = String(b?.text || "");
    const tokens = extractNumericTokens(`${claimText} ${query || ""}`);

    if (b?.evidence && typeof b.evidence === "object") {
      for (const eng of Object.keys(b.evidence)) {
        const arr = b.evidence?.[eng];
        if (!Array.isArray(arr) || arr.length === 0) continue;

        itemsBefore += arr.length;

        const cleaned = arr.map((it) => {
          const merged =
            it?.evidence_text ||
            it?.excerpt ||
            it?.snippet ||
            it?.description ||
            it?.title ||
            "";
          return { ...it, evidence_text: cleanEvidenceText(merged) };
        });

        let keptArr = cleaned;

        // ✅ 숫자/연도 토큰이 있는 “주장”만 매칭 적용
        if (tokens.years.length > 0 || tokens.nums.length > 0) {
          const filtered = cleaned.filter(
  (it) => isTrustedNumericEvidenceItem(it) || numericPassForEvidence(tokens, it?.evidence_text)
);

          if (filtered.length > 0) {
            keptArr = filtered; // 통과가 있으면 필터 적용
          } else {
            if (STRICT_NUMERIC_PRUNE) {
              keptArr = filtered; // STRICT면 0개여도 그대로 (→ 이후 block drop 가능)
            } else {
              keptArr = cleaned;  // ✅ SOFT면 0개로 만들지 말고 fallback 유지
              mismatchFallback.push({
                text: claimText.slice(0, 180),
                engine: eng,
                years: tokens.years,
                nums: tokens.nums,
                before: cleaned.length,
                after: cleaned.length,
                note: "numeric_filter_zero_keep_original(cleaned) because STRICT_NUMERIC_PRUNE=false",
              });
            }
          }

          // touched 로그: STRICT일 때는 실제 after(0 포함), SOFT일 때는 fallback이면 before==after라서 mismatchFallback로 남김
          if (keptArr.length !== arr.length) {
            touched.push({
              text: claimText.slice(0, 180),
              engine: eng,
              before: arr.length,
              after: keptArr.length,
              years: tokens.years,
              nums: tokens.nums,
            });
          }
        }

        b.evidence[eng] = keptArr;
        itemsAfter += keptArr.length;
      }
    }

    const totalEv = countTotalBlockEvidence(b);

    // ✅ “근거 0” 블록 드랍은 STRICT일 때만
    if (totalEv <= 0 && isLikelyClaimText(claimText)) {
      const rec = { text: claimText.slice(0, 220), reason: "no_evidence_block" };
      if (STRICT_NUMERIC_PRUNE) {
        droppedBlocks.push(rec);
        continue;
      } else {
        candidates.push(rec); // SOFT: 후보로만 기록하고 킵
      }
    }

    keptBlocks.push(b);
  }

  // ✅ STRICT일 때만 실제 pruning 적용(그래도 전부 비면 원본 유지)
  if (STRICT_NUMERIC_PRUNE) {
    if (keptBlocks.length > 0) {
      blocksForVerify.splice(0, blocksForVerify.length, ...keptBlocks);
      partial_scores.block_prune = {
        strict_prune: true,
        before: beforeBlocks,
        after: keptBlocks.length,
        dropped: droppedBlocks,
      };
    } else {
      partial_scores.block_prune = {
        strict_prune: true,
        before: beforeBlocks,
        after: beforeBlocks,
        dropped: droppedBlocks,
        note: "all_blocks_dropped_but_kept_original_to_avoid_empty_answer",
      };
    }
  } else {
    // SOFT: 블록은 안 줄임
    partial_scores.block_prune = {
      strict_prune: false,
      before: beforeBlocks,
      after: beforeBlocks,
      dropped_candidates: candidates,
      note: "soft_mode: did not drop blocks; recorded candidates only",
    };
  }

  // [DEBUG] NAVER raw evidence + block-level evidence just before numeric_evidence_match
if (DEBUG) {
  try {
    console.log("=== NAVER RAW EVIDENCE (external.naver) ===");
    for (const ev of (external?.naver || [])) {
      console.log({
        host: ev?.source_host || ev?.host || null,
        type: ev?.naver_type || null,
        title: ev?.title || null,
        link: ev?.link || ev?.source_url || ev?.url || null,
      });
    }

    console.log("=== NAVER BLOCK EVIDENCE (blocksForVerify.evidence.naver) ===");
    const __blocksForLog = Array.isArray(blocksForVerify) ? blocksForVerify : [];
    for (const b of __blocksForLog) {
      const evs = Array.isArray(b?.evidence?.naver) ? b.evidence.naver : [];
      console.log({
        block_id: b?.id ?? null,
        block_text_preview: String(b?.text || "").slice(0, 80),
        evidence_count: evs.length,
        links: evs.map(ev => ev?.link || ev?.source_url || ev?.url).filter(Boolean),
      });
    }
  } catch (logErr) {
    console.warn("numeric_evidence_match debug log failed:", logErr?.message || logErr);
  }
}

  partial_scores.numeric_evidence_match = {
    strict_prune: STRICT_NUMERIC_PRUNE,
    items_before: itemsBefore,
    items_after: itemsAfter,
    touched: touched.slice(0, 30),
    mismatch_fallback: mismatchFallback.slice(0, 30),
  };
}

// ✅ FINALIZE: engines_requested / engines_used(E_eff) / engine_explain / engine_exclusion_reasons
{
  // requested 확정
  if (!Array.isArray(partial_scores.engines_requested) || partial_scores.engines_requested.length === 0) {
    partial_scores.engines_requested = Array.isArray(engines) ? engines.slice() : [];
  }

  const __requested = partial_scores.engines_requested.slice();
  const __used = [];
  const __reasons = {};
  const __explain = {};

  const __countBlockEvidence = (engineKey) => {
    if (!Array.isArray(blocksForVerify)) return 0;
    let n = 0;
    for (const b of blocksForVerify) {
      const arr = b?.evidence?.[engineKey];
      if (Array.isArray(arr)) n += arr.length;
    }
    return n;
  };

  for (const name of __requested) {
    if (!name) continue;

    const extArr = external?.[name];
    const extCount = Array.isArray(extArr) ? extArr.length : 0;

    const blockCount =
      (safeMode === "qv" || safeMode === "fv") ? __countBlockEvidence(name) : 0;

    const ms =
      (typeof engineTimes?.[name] === "number" && Number.isFinite(engineTimes[name]))
        ? engineTimes[name]
        : null;

    let used = false;

    // ✅ used 판정(모드별)
    if (name === "klaw") {
      // lv는 위에서 return 하니까 사실상 여기까지 오면 제외 취급
      used = (safeMode === "lv") && extCount > 0;
      if (!used) __reasons[name] = "excluded_policy";
    } else if (safeMode === "qv" || safeMode === "fv") {
  // QV/FV: prune 이후 blocks evidence 기준이 “정답”
  used = blockCount > 0;

  if (!used) {
    const preReason =
      (partial_scores?.engine_exclusion_reasons_pre &&
        typeof partial_scores.engine_exclusion_reasons_pre[name] === "string")
        ? partial_scores.engine_exclusion_reasons_pre[name]
        : null;

    // pre에서 no_query/no_calls/no_results가 잡혔으면 그걸 우선 반영
    __reasons[name] = preReason || "no_block_evidence";
  }
} else {
  // DV/CV(+기타): external 결과 기준
  used = extCount > 0;

  if (!used) {
    const preReason =
      (partial_scores?.engine_exclusion_reasons_pre &&
        typeof partial_scores.engine_exclusion_reasons_pre[name] === "string")
        ? partial_scores.engine_exclusion_reasons_pre[name]
        : null;

    __reasons[name] = preReason || "no_results";
  }
}

    if (used) __used.push(name);

    __explain[name] = {
      used,
      ext_count: extCount,
      block_evidence_count: blockCount,
      ms,
    };
  }

  // ✅ 핵심: fallback으로 채우지 말 것(증거 0이면 engines_used = [])
  partial_scores.engines_used = __used;
  partial_scores.effective_engines = __used.slice();
  partial_scores.effective_engines_count = __used.length;

  // (옵션) excluded도 같이 남기고 싶으면
  partial_scores.engines_excluded = __requested.filter((x) => x && !__used.includes(x));

  partial_scores.engine_explain = __explain;

  // 기존 exclusion reason이 있으면 merge
  const __prev =
    (partial_scores.engine_exclusion_reasons && typeof partial_scores.engine_exclusion_reasons === "object")
      ? partial_scores.engine_exclusion_reasons
      : {};

  partial_scores.engine_exclusion_reasons = {
    ...__prev,
    ...__reasons,
    ...(__used.length ? {} : { _all: "all_pruned_or_no_evidence" }),
  };
}

// ─────────────────────────────
// ③ 엔진 보정계수 조회 (서버 통계 기반) — FINALIZE 이후(E_eff 기준)
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

      const __blocksText =
  (safeMode === "qv" || safeMode === "fv") &&
  Array.isArray(blocksForVerify) &&
  blocksForVerify.length > 0
    ? blocksForVerify.map((b) => String(b?.text || "").trim()).filter(Boolean).join("\n")
    : "";

const coreText =
  safeMode === "qv"
    ? (flash && flash.trim().length > 0
        ? flash
        : (__blocksText || qvfvPre?.korean_core || query))
    : safeMode === "fv"
    ? (userCoreText || __blocksText || query)
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
You are the evaluation module of "Cross-Verified AI".

RETURN ONLY VALID JSON.
- No markdown, no triple backticks, no code fences, no extra text.
- Must start with "{" and end with "}".
- Strict JSON: double quotes for keys/strings, no trailing commas.

[INPUT JSON]
${safeVerifyInputForGemini(verifyInput, VERIFY_INPUT_CHARS)}

[TASK]
1) Blocks
- If input.blocks is a non-empty array: evaluate each block in order.
- If input.blocks is empty: split input.core_text into 2~8 short blocks (keep meaning) and evaluate.

For each block output:
- id: number (keep given id if present, otherwise 1..N)
- text: block text
- block_truthscore: number in [0,1]
- irrelevant_urls: array of URLs (strings). If evidence URLs are irrelevant to the block meaning, put them here.
- evidence: { support: string[], conflict: string[] } (engine names only, e.g. "naver","crossref","openalex","wikidata","gdelt","github","klaw")
- comment: 1~2 Korean sentences explaining why.
  - If you can, cite at least one evidence item briefly like: [host] title (url)

Rules:
- If evidence looks irrelevant/ambiguous for this block: include those URLs in irrelevant_urls AND set block_truthscore <= 0.55 and explain in comment.
- If there is no usable evidence: set block_truthscore around 0.55 and explain "근거 부족".

2) Overall
- overall_truthscore_raw: number in [0,1], aggregate based on block_truthscore (you may lightly consider input.partial_scores like recency/validity).
- summary: 1~3 Korean sentences.

3) Engine adjust
- engine_adjust: object of per-engine factor in [0.90, 1.10]
- Prefer engines in input.partial_scores.engines_used (if present). Otherwise use input.engines_requested or known engines.
- If an engine has no usable evidence for this request, keep it at 1.00.

[OUTPUT JSON SCHEMA]
{
  "blocks": [
    {
      "id": 1,
      "text": "…",
      "block_truthscore": 0.85,
      "irrelevant_urls": [],
      "evidence": { "support": ["naver"], "conflict": [] },
      "comment": "…"
    }
  ],
  "overall": {
    "overall_truthscore_raw": 0.82,
    "summary": "…"
  },
  "engine_adjust": {
    "crossref": 1.00,
    "openalex": 1.00,
    "wikidata": 1.00,
    "gdelt": 1.00,
    "naver": 1.00,
    "github": 1.00,
    "klaw": 1.00
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
      verify = await fetchGeminiSmart({
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
      if (
  e?.code === "INVALID_GEMINI_KEY" ||
  e?.code === "GEMINI_KEY_EXHAUSTED" ||
  e?.code === "GEMINI_KEY_MISSING" ||
  e?.code === "GEMINI_RATE_LIMIT"
) throw e;

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
if (!verify || !String(verify).trim()) {
  verifyMeta = null;
  __irrelevant_urls = [];
  if (DEBUG) console.warn("⚠️ verify failed on all models:", lastVerifyErr?.message || "unknown");
} else {
  // ✅ JSON만 뽑아내기(코드펜스/잡문 있어도 최대한 복구)
  try {
    let s = String(verify || "").trim();

    // 1) ```json ... ``` 코드펜스 제거
    const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (fence && fence[1]) s = String(fence[1]).trim();

    // 2) 첫 { ~ 마지막 } 까지 우선 추출(기존 방식 유지 + fence 제거로 안정화)
    const first = s.indexOf("{");
    const last = s.lastIndexOf("}");
    const jsonText = (first >= 0 && last > first) ? s.slice(first, last + 1) : s;

    verifyMeta = JSON.parse(jsonText);

// ✅ (optional) normalize if helper exists
if (typeof normalizeVerifyMeta === "function") {
  try {
    verifyMeta = normalizeVerifyMeta(verifyMeta, verifyEvidenceLookup);
  } catch (_) {}
}

// ✅ irrelevant_urls는 "딱 1번만" 수집
try {
  const _blocks = Array.isArray(verifyMeta?.blocks) ? verifyMeta.blocks : [];
  const _urls = _blocks
    .flatMap(b => (Array.isArray(b?.irrelevant_urls) ? b.irrelevant_urls : []))
    .map(u => String(u || "").trim())
    .filter(Boolean);

  __irrelevant_urls = Array.from(new Set(_urls));
} catch (_) {
  __irrelevant_urls = [];
}

// ✅ NEW: conflict_meta 요약 (support/conflict 구조만 집계, TruthScore에는 아직 미반영)
try {
  if (verifyMeta && Array.isArray(verifyMeta.blocks)) {
    const blocks = verifyMeta.blocks;

    const byEngine = {};
    let total_blocks = 0;
    let support_blocks = 0;
    let conflict_blocks = 0;

    for (const b of blocks) {
      if (!b) continue;
      total_blocks += 1;

      const ev = b.evidence || {};
      const supportList = Array.isArray(ev.support) ? ev.support.filter(Boolean) : [];
      const conflictList = Array.isArray(ev.conflict) ? ev.conflict.filter(Boolean) : [];

      const hasSupport = supportList.length > 0;
      const hasConflict = conflictList.length > 0;

      if (hasSupport) support_blocks += 1;
      if (hasConflict) conflict_blocks += 1;

      const engines = new Set([...supportList, ...conflictList]);
      for (const name of engines) {
        if (!name) continue;
        if (!byEngine[name]) {
          byEngine[name] = { support: 0, conflict: 0, blocks: 0 };
        }
        byEngine[name].blocks += 1;
      }

      for (const name of supportList) {
        if (!name) continue;
        if (!byEngine[name]) {
          byEngine[name] = { support: 0, conflict: 0, blocks: 0 };
        }
        byEngine[name].support += 1;
      }

      for (const name of conflictList) {
        if (!name) continue;
        if (!byEngine[name]) {
          byEngine[name] = { support: 0, conflict: 0, blocks: 0 };
        }
        byEngine[name].conflict += 1;
      }
    }

    const denom = support_blocks + conflict_blocks;
    const conflict_index =
      denom > 0 ? Math.max(0, Math.min(1, conflict_blocks / denom)) : null;

    if (partial_scores && typeof partial_scores === "object") {
      partial_scores.conflict_meta = {
        total_blocks,
        support_blocks,
        conflict_blocks,
        conflict_index,
        by_engine: byEngine,
      };
    }
  }
} catch (e) {
  if (DEBUG) console.warn("⚠️ conflict_meta summarize error:", e.message || e);
}
} catch {
  verifyMeta = null;
  __irrelevant_urls = [];
  if (DEBUG) console.warn("⚠️ verifyMeta JSON parse fail");
}
}
    } catch (e) {
      if (
  e?.code === "INVALID_GEMINI_KEY" ||
  e?.code === "GEMINI_KEY_EXHAUSTED" ||
  e?.code === "GEMINI_KEY_MISSING" ||
  e?.code === "GEMINI_RATE_LIMIT"
) throw e;

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

// ✅ E_eff(Effective engines): 실제로 evidence가 남아있는 엔진 개수 기반 coverage factor
const effEngines = Array.from(enginesUsedSet).filter((e) => e && e !== "klaw");
const E_eff = effEngines.length;

// ✅ coverage factor (QV/FV에만 의미있게 적용, DV/CV는 1.0 유지)
const E_cov = (() => {
  if (!(safeMode === "qv" || safeMode === "fv")) return 1.0;

  let f = 1.0;
  if (E_eff >= 3) f = 1.0;
  else if (E_eff === 2) f = 0.96;
  else if (E_eff === 1) f = 0.90;
  else f = 0.85;

  // ✅ 예외: 엔진이 1개여도 “강한 공식/통계/정부급” 근거면 감점 완화
  const hasStrongOfficial = (() => {
    if (!enginesUsedSet.has("naver")) return false;
    const nv = Array.isArray(external?.naver) ? external.naver : [];
    return nv.some((x) => {
      const host = String(x?.source_host || x?.host || "").toLowerCase();
      const tw =
        typeof x?.tier_weight === "number" && Number.isFinite(x.tier_weight)
          ? x.tier_weight
          : null;
      const tier = String(x?.tier || "").toLowerCase();
      const wl = (x?.whitelisted === true) || !!x?.tier;
      const inferred = x?.inferred === true;

      if (tw != null && tw >= 0.95) return true;
      if (tier === "tier1") return true;
      if (host.includes("kosis.kr")) return true;
      if (host.endsWith(".go.kr")) return true;
      if (wl && !inferred && (typeof hostLooksOfficial === "function") && hostLooksOfficial(host)) return true;

      return false;
    });
  })();

  if (E_eff <= 1 && hasStrongOfficial) f = Math.max(f, 0.97);
  return f;
})();

// (로그용) partial_scores에 남겨두면 디버깅 편함
partial_scores.effective_engines = effEngines;
partial_scores.effective_engines_count = E_eff;
partial_scores.coverage_factor = E_cov;

const useGdelt = enginesUsedSet.has("gdelt");
const useNaver = enginesUsedSet.has("naver");
const useGithub = enginesUsedSet.has("github");

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
  const combined = 0.7 * G + 0.3 * V_r;
  const rawHybrid = R_t * combined * C; // DV/CV는 E_cov 적용 안 함(위에서 1.0)
  hybrid = Math.max(0, Math.min(1, rawHybrid));
} else {
  // QV/FV:
  const rawHybrid = R_t * N * G * C * E_cov;
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

// snippet_meta(for snippet-FV/QV) attach snippet/question info if provided
let snippetMeta = null;
if (safeMode === "fv" || safeMode === "qv") {
  // 1) preferred: snippetToVerifyBody가 넣어준 snippet_meta
  if (snippet_meta && typeof snippet_meta === "object") {
    const s = snippet_meta;

    const hasAny =
      !!s.is_snippet ||
      (typeof s.input_snippet === "string" && s.input_snippet.trim()) ||
      (typeof s.snippet_core === "string" && s.snippet_core.trim()) ||
      (typeof s.question === "string" && s.question.trim()) ||
      (s.snippet_id != null) ||
      (s.snippet_hash != null);

    if (hasAny) {
      snippetMeta = {
        is_snippet: !!s.is_snippet,
        input_snippet: (typeof s.input_snippet === "string" && s.input_snippet.trim()) ? s.input_snippet : null,
        snippet_core: (typeof s.snippet_core === "string" && s.snippet_core.trim()) ? s.snippet_core : null,
        question: (typeof s.question === "string" && s.question.trim()) ? s.question : null,
        snippet_id: s.snippet_id ?? null,
        snippet_hash: s.snippet_hash ?? null,
      };
      partial_scores.snippet_meta = snippetMeta;
    }
  }

  // 2) fallback: legacy fields (req.body.snippet/question)
  if (!snippetMeta) {
    const __b = (req && req.body && typeof req.body === "object") ? req.body : {};
    const __snippet = typeof __b.snippet === "string" ? __b.snippet : null;
    const __question = typeof __b.question === "string" ? __b.question : null;
    const __snippetId = __b.snippet_id ?? null;
    const __snippetHash = __b.snippet_hash ?? null;

    if (__snippet || __question || __snippetId || __snippetHash) {
      snippetMeta = {
        snippet: __snippet,
        question: __question,
        snippet_id: __snippetId,
        snippet_hash: __snippetHash,
      };
      partial_scores.snippet_meta = snippetMeta;
    }
  }
}

const sourcesText = safeSourcesForDB(
  {
    meta: { mode: safeMode, snippet_meta: snippetMeta || null },
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

    truth_score: Number(truthscore),     // ??double precision
    summary: summaryText,

    cross_score: Number(G),              // ??raw(0~1)
    adjusted_score: Number(hybrid),      // ??adjusted(0~1)

    status: safeMode,                    // ??mode 而щ읆 ?놁쑝???ш린 ???
    engines: (Array.isArray(partial_scores.engines_used) ? partial_scores.engines_used : engines),
    keywords: keywordsForLog,            // ??array(text[])
    elapsed: String(elapsed),            // ??text

    model_main: answerModelUsed,         // ??QV/FV ?좉? 諛섏쁺 (?먮뒗 湲곕낯 flash)
    model_eval: verifyModelUsed,         // ???ㅼ젣 ?깃났??verify 紐⑤뜽
    sources: sourcesText,

    gemini_model: verifyModelUsed,       // ???ㅼ젣 ?깃났??verify 紐⑤뜽
    error: null,
    created_at: new Date(),
  },
]);

  // ?????????????????????????????
  // ??野껉퀗??獄쏆꼹??(??깅?域뱀뮇鍮??類κ묶嚥???묐릅)
  //   - truthscore(0~1)를 바로 퍼센트로 쓰지 않고
  //   - conflict_meta / effective_engines / coverage_factor 기반으로
  //     한번 더 "안전하게" 스무딩해서 truthscore_01을 만든다.
  // ?????????????????????????????

  // 1) raw truthscore → 0~1 스케일 기본값
  let truthscore_01_raw = Number(truthscore.toFixed(4));
  let truthscore_01 = truthscore_01_raw;

  try {
    const effEngines = Array.isArray(partial_scores?.effective_engines)
      ? partial_scores.effective_engines
      : [];
    const effCount =
      typeof partial_scores?.effective_engines_count === "number"
        ? partial_scores.effective_engines_count
        : effEngines.length;

    const coverage =
      typeof partial_scores?.coverage_factor === "number"
        ? partial_scores.coverage_factor
        : 1;

    const conflictIdx =
      typeof partial_scores?.conflict_meta?.conflict_index === "number"
        ? partial_scores.conflict_meta.conflict_index
        : 0;

    const hasStrongConflict = conflictIdx >= 0.8;          // (예) 대부분 conflict일 때
    const lowCoverage = coverage < 0.5 || effCount <= 1;   // 엔진이 너무 적거나 coverage가 낮을 때

    let t = truthscore_01;

    // 1-A) 강한 상충(conflict) + 낮은 점수(≤0.5)면 false 쪽으로 조금 더 눌러줌
    //      - 예: 0.15 → 0.12 정도로 내려가서 "거짓 + 상충"이 더 분명해짐
    if (hasStrongConflict && t <= 0.5) {
      t *= 0.8;
    }

    // 1-B) coverage가 낮고 엔진도 1~2개뿐이면 "불확실 → 0.5 근처"로 가볍게 스무딩
    //      - 너무 낮은 점수/높은 점수를 0.5 쪽으로 살짝 당겨서
    //        "엔진 부족한 상황에서의 과신"을 줄이기 위함
    if (lowCoverage) {
      t = 0.5 * t + 0.25;   //  t ← 0.5·t + 0.25   (0 → 0.25, 1 → 0.75 쪽으로)
    }

    // 1-C) 최종 클램프
    if (t < 0) t = 0;
    if (t > 1) t = 1;

    truthscore_01 = Number(t.toFixed(4));
  } catch (_e) {
    // 스무딩 중 에러가 나면 raw 그대로 사용
    truthscore_01 = truthscore_01_raw;
  }

  // 2) 퍼센트 변환은 항상 최종 truthscore_01 기준으로
  const truthscore_pct = Math.round(truthscore_01 * 10000) / 100; // 2 decimals
  const truthscore_text = `${truthscore_pct.toFixed(2)}%`;

  // ??normalizedPartial???怨뺤쨮 ??곸몵????곕뼊 ??덉뵬??띿쓺 ????
  const normalizedPartial = partial_scores;

  const payload = {
    mode: safeMode,
    truthscore: truthscore_text,
    truthscore_pct,
    truthscore_01,
    elapsed,

  // ??S-15: engines_used ?먮룞 ?곗텧(紐낆떆 ?몄텧)
  engines: (Array.isArray(partial_scores.engines_used) ? partial_scores.engines_used : engines),
  engines_requested: (partial_scores.engines_requested || engines),
  engines_used: (Array.isArray(partial_scores.engines_used)
    ? partial_scores.engines_used
    : (Array.isArray(partial_scores.engines_used_pre) ? partial_scores.engines_used_pre : [])),

  engines_excluded: (Array.isArray(partial_scores.engines_excluded)
    ? partial_scores.engines_excluded
    : (Array.isArray(partial_scores.engines_requested)
        ? partial_scores.engines_requested.filter(x => x && !(Array.isArray(partial_scores.engines_used) ? partial_scores.engines_used : []).includes(x))
        : (partial_scores.engines_excluded_pre && typeof partial_scores.engines_excluded_pre === "object"
            ? Object.keys(partial_scores.engines_excluded_pre)
            : []))),

  partial_scores: normalizedPartial,

  flash_summary: flash,
  verify_raw: verify,
  gemini_verify_model: verifyModelUsed, // ???ㅼ젣濡??깃났??紐⑤뜽
  engine_times: engineTimes,
  engine_metrics: engineMetrics,
};

// snippet_meta를 최종 payload top-level에도 노출
if (snippetMeta) {
  payload.snippet_meta = snippetMeta;
}

// ✅ diagnostics: 점수가 이렇게 나온 이유를 한 번에 보기 위한 요약 정보
//   - effective_engines / coverage_factor / conflict_meta
//   - numeric_evidence_match_pre / numeric_evidence_match
try {
  const ps = partial_scores || {};

  const effEngines = Array.isArray(ps.effective_engines)
    ? ps.effective_engines
    : [];
  const effCount =
    typeof ps.effective_engines_count === "number"
      ? ps.effective_engines_count
      : effEngines.length;

  const coverage =
    typeof ps.coverage_factor === "number" ? ps.coverage_factor : null;

  const conflictMeta =
    ps.conflict_meta && typeof ps.conflict_meta === "object"
      ? ps.conflict_meta
      : null;

  const numericPre =
    ps.numeric_evidence_match_pre &&
    typeof ps.numeric_evidence_match_pre === "object"
      ? ps.numeric_evidence_match_pre
      : null;

  const numericFinal =
    ps.numeric_evidence_match &&
    typeof ps.numeric_evidence_match === "object"
      ? ps.numeric_evidence_match
      : null;

  payload.diagnostics = {
    effective_engines: effEngines,
    effective_engines_count: effCount,
    coverage_factor: coverage,
    conflict_meta: conflictMeta,
    numeric_evidence_match_pre: numericPre,
    numeric_evidence_match: numericFinal,
  };
} catch {
  // diagnostics 구성 중 에러는 무시 (응답 자체에는 영향 주지 않음)
}

// ✅ verdict_label & verdict_detail: truthscore_01 + conflict_meta 기반 요약 라벨
try {
  // 0~1 구간 점수
  const t01 =
    typeof payload.truthscore_01 === "number"
      ? payload.truthscore_01
      : typeof truthscore === "number"
        ? Number(truthscore.toFixed(4))
        : null;

  const diag = payload.diagnostics || {};
  const effEngines = Array.isArray(diag.effective_engines)
    ? diag.effective_engines
    : [];
  const effCount =
    typeof diag.effective_engines_count === "number"
      ? diag.effective_engines_count
      : effEngines.length;

  // conflict_index는 diagnostics.conflict_meta 또는 partial_scores.conflict_meta에서 가져옴
  let cMeta = null;
  if (diag.conflict_meta && typeof diag.conflict_meta === "object") {
    cMeta = diag.conflict_meta;
  } else if (
    partial_scores &&
    typeof partial_scores.conflict_meta === "object"
  ) {
    cMeta = partial_scores.conflict_meta;
  }

  const cIndex =
    cMeta && typeof cMeta.conflict_index === "number"
      ? cMeta.conflict_index
      : null;

  let vLabel = null;

  if (t01 != null) {
    // 매우 높은 점수 + 충돌 없음/약함 → likely_true
    if (t01 >= 0.75 && (cIndex == null || cIndex <= 0.2)) {
      vLabel = "likely_true";
    }
    // 매우 낮은 점수 + 충돌 강함 → likely_false_conflict
    else if (t01 <= 0.25 && cIndex != null && cIndex >= 0.5) {
      vLabel = "likely_false_conflict";
    }
    // 매우 낮은 점수 + 명시적 conflict는 없지만 사실상 거짓에 가까움
    else if (t01 <= 0.25) {
      vLabel = "likely_false";
    }
    // 중간 이하 점수지만 conflict_index가 거의 1에 가까움 → conflict 쪽으로 해석
    else if (t01 < 0.5 && cIndex != null && cIndex >= 0.9) {
      vLabel = "likely_false_conflict";
    }
    // 점수는 중간 이상인데 conflict도 큰 편 → 혼재/논쟁적
    else if (t01 >= 0.5 && cIndex != null && cIndex >= 0.6) {
      vLabel = "controversial_or_mixed";
    }
    // 그 외 애매한 구간 → borderline_uncertain
    else {
      vLabel = "borderline_uncertain";
    }
  }

  if (vLabel) {
    payload.verdict_label = vLabel;
    payload.verdict_detail = {
      mode: safeMode,
      truthscore_01: t01,
      conflict_index: cIndex,
      effective_engines: effEngines,
      effective_engines_count: effCount,
    };

    let vMessage = null;
    if (vLabel === "likely_true") {
      vMessage = "대체로 사실일 가능성이 높습니다.";
    } else if (vLabel === "likely_false_conflict") {
      vMessage =
        "사실이 아닐 가능성이 높고, 검색된 근거들과 상충합니다.";
    } else if (vLabel === "likely_false") {
      vMessage = "사실이 아닐 가능성이 높습니다.";
    } else if (vLabel === "borderline_uncertain") {
      vMessage =
        "근거가 충분하지 않아 불확실하거나 추가 검증이 필요합니다.";
    } else if (vLabel === "controversial_or_mixed") {
      vMessage =
        "서로 다른 방향의 근거가 섞여 있어 해석에 주의가 필요합니다.";
    }

    if (vMessage) {
      payload.verdict_message_ko = vMessage;
    }
  }
} catch {
  // verdict 계산 실패해도 전체 응답은 그대로 유지
}

// ✅ (필수) QV/FV/DV/CV에서 Gemini가 0ms 스킵인데 success:true로 나가는 것 방지
const NEED_GEMINI =
  safeMode === "qv" || safeMode === "fv" || safeMode === "dv" || safeMode === "cv";

if (NEED_GEMINI) {
  const gemMs = Number(payload?.partial_scores?.gemini_total_ms || 0);
  const flLen = String(flash || "").trim().length;
  const vrLen = String(verify || "").trim().length;

  // gemini_total_ms=0 AND flash/verify 둘 다 비면 "스킵"으로 판단하고 실패 처리
  if (!(gemMs > 0 || flLen > 0 || vrLen > 0)) {
    return res.status(500).json({
      success: false,
      code: "GEMINI_SKIPPED",
      message:
        "Gemini stage was skipped unexpectedly (gemini_total_ms=0, flash/verify empty). Check gemini key resolution and skip/early-return logic.",
      timestamp: new Date().toISOString(),
    });
  }
}

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

// ✅ S-17: cache set (only QV/FV)
if (safeMode === "qv" || safeMode === "fv") {
  payload.cached = false;
  if (__cacheKey && (safeMode === "qv" || safeMode === "fv")) {
  verifyCacheSet(__cacheKey, payload);
}
}

// 🔹 QV/FV 모드에서는 Naver 결과도 같이 내려줌
//    - external.naver "풀"이 아니라, blocksForVerify에 실제로 들어간 naver evidence만 내려서 UI 노이즈를 줄임
//    + verify 단계에서 나온 irrelevant_urls가 있으면 응답에서만 prune (추가 호출 없음)
if (safeMode === "qv" || safeMode === "fv") {
  // blocksForVerify에 실제로 들어간 naver evidence만 모음
  const __naverEvidenceUsed =
    (typeof blocksForVerify !== "undefined" && Array.isArray(blocksForVerify))
      ? blocksForVerify.flatMap(b => (Array.isArray(b?.evidence?.naver) ? b.evidence.naver : []))
      : [];

  // 혹시 dedupeByLink가 없다면(드물지만) 대비해서 로컬 dedupe
  const __deduped = (typeof dedupeByLink === "function")
    ? dedupeByLink(__naverEvidenceUsed)
    : (() => {
        const seen = new Set();
        const out = [];
        for (const r of (__naverEvidenceUsed || [])) {
          const u = String(r?.link || r?.source_url || r?.url || "").trim();
          const k = u || JSON.stringify([r?.title || "", r?.source_host || "", r?.naver_type || ""]);
          if (seen.has(k)) continue;
          seen.add(k);
          out.push(r);
        }
        return out;
      })();

  const __irSet = new Set(
    (Array.isArray(__irrelevant_urls) ? __irrelevant_urls : [])
      .map(u => String(u || "").trim())
      .filter(Boolean)
  );

  payload.naver_results = (__irSet.size > 0)
    ? __deduped.filter(r => {
        const u = String(r?.link || r?.source_url || r?.url || "").trim();
        return u ? !__irSet.has(u) : true;
      })
    : __deduped;

  if (__irSet.size > 0) {
    payload.partial_scores = { ...(payload.partial_scores || {}), irrelevant_urls: Array.from(__irSet) };
  }
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

// ✅ Gemini 키 invalid는 401로 명확히 반환
if (e?.code === "INVALID_GEMINI_KEY") {
  return res.status(401).json(
    buildError(
      "INVALID_GEMINI_KEY",
      "Gemini API 키가 유효하지 않습니다. 설정에서 키를 다시 저장해 주세요.",
      e?.detail || e?.message
    )
  );
}

// Admin 대시보드용 에러 기록
  pushAdminError({
    type: "verify",
    code: e?.code || null,
    message: e?.message || String(e),
  });

if (e?.code === "GEMINI_RATE_LIMIT") {
  return res.status(200).json({
    success: false,
    code: "GEMINI_RATE_LIMIT",
    message: "Gemini 요청이 일시적으로 과도합니다(429). 잠시 후 재시도해 주세요.",
    timestamp: new Date().toISOString(),
    detail: e.detail || null,
  });
}

// ✅ Gemini 키링 모두 소진(쿼터/인증 등)도 코드 유지해서 그대로 반환
if (e?.code === "GEMINI_KEY_EXHAUSTED") {
  const st = (typeof e?.httpStatus === "number" ? e.httpStatus : 200);
  return res.status(st).json(
    buildError(
      "GEMINI_KEY_EXHAUSTED",
      "Gemini 키를 사용할 수 없습니다. (쿼터/인증/키링 상태 확인)",
      e?.detail || e?.message
    )
  );
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

// ✅ Gemini 키 문제는 401로 명확히 반환 (GEMINI_SKIPPED로 뭉개지지 않게)
if (e?.code === "INVALID_GEMINI_KEY") {
  return res.status(401).json(
    buildError(
      "INVALID_GEMINI_KEY",
      "Gemini API 키가 유효하지 않습니다. (키 확인 필요)",
      e?.detail || e?.message
    )
  );
}

if (e?.code === "GEMINI_KEY_MISSING") {
  return res.status(401).json(
    buildError(
      "GEMINI_KEY_MISSING",
      "Gemini API 키가 없습니다. (앱 설정 저장/로그인 vault 또는 요청 body에 gemini_key 필요)",
      e?.detail || e?.message
    )
  );
}

// ✅ Gemini invalid key는 401로 명확히 반환 (안전망)
{
  const rawMsg =
    e?.response?.data?.error?.message ||
    e?.response?.data?.message ||
    e?.message ||
    "";
  const isInvalidGeminiKey =
    e?.code === "INVALID_GEMINI_KEY" ||
    /API key not valid|API_KEY_INVALID|invalid api key/i.test(String(rawMsg));

  if (isInvalidGeminiKey) {
    return res.status(401).json(
      buildError(
        "INVALID_GEMINI_KEY",
        "Gemini API 키가 유효하지 않습니다. 키를 다시 저장/교체하세요.",
        e?.detail ?? rawMsg
      )
    );
  }
}

// ✅ Gemini key invalid => 401
if (e?.code === "INVALID_GEMINI_KEY") {
  return res.status(401).json(
    buildError(
      "INVALID_GEMINI_KEY",
      "Gemini API 키가 유효하지 않습니다. (키를 확인/교체하세요)",
      e?.detail ?? e?.message
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
};

app.post(
  "/api/verify",
  blockDevRoutesInProd,
  verifyRateLimit,
  guardProdKeyUuid,
  requireVerifyAuth,
  rejectLvOnVerify,
  enforceVerifyPayloadLimits,
  verifyCoreHandler
);

// ✅ Snippet verification endpoint (web/PC/extension)
app.post(
  "/api/verify-snippet",
  blockDevRoutesInProd,
  verifyRateLimit,
  guardProdKeyUuid,
  requireVerifyAuth,
  snippetToVerifyBody,
  rejectLvOnVerify,
  enforceVerifyPayloadLimits,
  verifyCoreHandler
);

// ✅ QV/FV/DV/CV 공통 검증 엔드포인트
//   - 기존 /api/verify 호출(앱의 QV/FV/DV/CV 모드)이 여기로 들어옴
app.post("/api/verify", verifyCoreHandler);

// ✅ Snippet 전용 검증 엔드포인트
//   - /api/verify-snippet → snippetToVerifyBody가 snippet 전용 payload로 변환
//   - 변환된 body를 verifyCoreHandler로 넘김
app.post(
  "/api/verify-snippet",
  snippetToVerifyBody,
  verifyCoreHandler
);

// ✅ /api/verify에서는 lv 금지 (LV는 /api/lv 전용)
function rejectLvOnVerify(req, res, next) {
  const m = String(req.body?.mode || "").trim().toLowerCase();
  if (m === "lv") {
    return res
      .status(400)
      .json(buildError("LV_ENDPOINT_REQUIRED", "LV 모드는 /api/lv 엔드포인트를 사용하세요."));
  }
  return next();
}

// ✅ LV endpoint (keeps existing LV logic inside verifyCoreHandler)
function forceLvMode(req, _res, next) {
  const b = (req.body && typeof req.body === "object") ? req.body : {};

  // query가 없으면 question/prompt도 받아주기
  const q0 =
    (typeof b.query === "string" && b.query.trim()) ||
    (typeof b.question === "string" && b.question.trim()) ||
    (typeof b.prompt === "string" && b.prompt.trim()) ||
    "";

  const cleaned = {};
  const put = (k, v) => {
    if (v === undefined || v === null) return;
    if (typeof v === "string" && v.trim() === "") return;
    cleaned[k] = v;
  };

  // ✅ LV는 이 필드만 통과(나머지는 drop)
  put("query", String(q0).slice(0, VERIFY_MAX_QUERY_CHARS || 5000));
  put("rawQuery", b.rawQuery);

  put("user_id", b.user_id);
  put("user_email", b.user_email);
  put("user_name", b.user_name);
  put("key_uuid", b.key_uuid);

  put("klaw_key", b.klaw_key);
  put("gemini_key", b.gemini_key);
  put("gemini_model", b.gemini_model);
  put("debug", b.debug);

  cleaned.mode = "lv";
  req.body = cleaned;
  return next();
}

app.post("/api/lv",
  verifyRateLimit,
  forceLvMode,
  enforceVerifyPayloadLimits,
  requireVerifyAuth,
  guardProdKeyUuid,
  verifyCoreHandler
);

// ✅ 번역 테스트 라우트 (간단형, 백호환용)
app.post("/api/translate", async (req, res) => {
  try {
    const { user_id, text, targetLang, deepl_key, gemini_key } = req.body;
    // ✅ docs/analyze도 verify처럼 "로그/키링용 userId"를 만든다
const auth_user = await getSupabaseAuthUser(req);
const bearer_token = getBearerToken(req);

const logUserId = await resolveLogUserId({
  user_id: user_id ?? null,
  user_email: null,
  user_name: null,
  auth_user,
  bearer_token,
});

const userId = logUserId; // ✅ /api/translate: keyring/vault lookup용

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

    let deeplKeyFinal = (deepl_key || "").toString().trim() || null;
let geminiKeyFinal = (gemini_key || "").toString().trim() || null;

// ✅ userId가 있을 때만 DB에서 vault/keyring 상태를 확인
let geminiKeysCount = 0;

if (userId) {
  const row = await loadUserSecretsRow(userId);
  const s = _ensureIntegrationsSecretsShape(_ensureGeminiSecretsShape(row.secrets));

  // DeepL 키가 body에 없으면 vault에서
  if (!deeplKeyFinal) {
    const v = decryptIntegrationsSecrets(s);
    deeplKeyFinal = (v.deepl_key || "").toString().trim() || null;
  }

  // ✅ keyring에 실제 Gemini 키가 “존재”할 때만 keyring 사용 가능
  geminiKeysCount = (s?.gemini?.keyring?.keys || []).length;
}

// ✅ Gemini 사용 가능 조건을 “userId 존재”가 아니라 “(body gemini_key) 또는 (keyring keysCount>0)”로 엄격화
const canUseGemini = !!geminiKeyFinal || geminiKeysCount > 0;

// ✅ 최소 하나 필요(DeepL or Gemini)
if (!deeplKeyFinal && !canUseGemini) {
  return sendError(
    res,
    400,
    "VALIDATION_ERROR",
    "deepl_key 또는 gemini_key(또는 DB keyring에 Gemini 키 저장)가 필요합니다.",
    { userId: userId || null, geminiKeysCount }
  );
}

// 4) 간단 번역: DeepL 우선, 실패/none이면 Gemini로 fallback (keyring 가능)
let result = null;

const tgt = targetLang ? String(targetLang).toUpperCase() : null;

const geminiTranslate = async () => {
  const prompt = `
You are a professional translator.
Translate the following text into ${tgt || "EN"}.
Return ONLY the translated text (no quotes, no markdown).

TEXT:
${text}
  `.trim();

  const out = await fetchGeminiSmart({
    userId: userId,                  // ✅ keyring 사용 가능
    keyHint: geminiKeyFinal ?? null,  // ✅ body 키가 있으면 hint 1회, 없으면 keyring
    model: "gemini-2.5-flash",
    payload: { contents: [{ parts: [{ text: prompt }] }] },
    opts: { label: "translate:simple" },
  });

  return { text: (out || "").trim(), engine: "gemini", target: tgt };
};

if (deeplKeyFinal) {
  // DeepL 우선
  let deeplErr = null;

  try {
    result = await translateText(
      text,
      tgt || null,
      deeplKeyFinal ?? null,
      geminiKeyFinal ?? null
    );
  } catch (e) {
    deeplErr = e;
    // DeepL이 throw면 일단 "none + 원문"으로 두고, 아래에서 Gemini fallback(가능할 때만)
    result = { text: String(text ?? "").trim(), engine: "none", target: tgt };
  }

  // ✅ DeepL 호출 직후(DeepL 결과를 받은 다음)에:
try {
  console.log("ℹ️ /api/translate DeepL-after:", {
    engine: String(result?.engine || ""),
    status: result?.meta?.status ?? null,
    base: result?.meta?.base ?? null,
    error: result?.error ?? null,
    deeplErr: deeplErr ? (deeplErr.message || String(deeplErr)) : null,
  });
} catch {}

  const _in = String(safeText ?? text ?? "").trim();

  // result가 string이거나, {text}/{translated}/{translation} 형태여도 안전하게 읽기
  const _out0 =
    typeof result === "string"
      ? String(result).trim()
      : String(result?.text ?? result?.translated ?? result?.translation ?? "").trim();

  const _eng0 =
    typeof result === "object" && result
      ? String(result?.engine ?? "").toLowerCase()
      : "";

  const _looksNone0 = (_eng0 === "none" || !_out0 || _out0 === _in);

  // ✅ DeepL이 none/원문이면: "Gemini 사용 가능(canUseGemini)할 때만" fallback
  if (_looksNone0 && canUseGemini) {
    result = await geminiTranslate();
  }

  // 최종 결과 재평가
  const _out1 =
    typeof result === "string"
      ? String(result).trim()
      : String(result?.text ?? result?.translated ?? result?.translation ?? "").trim();

  const _eng1 =
    typeof result === "object" && result
      ? String(result?.engine ?? "").toLowerCase()
      : "";

  const _looksNone1 = (_eng1 === "none" || !_out1 || _out1 === _in);

  // ✅ 최종도 none/원문이면 성공으로 보내지 말고 에러 처리
  if (_looksNone1) {
    const e = new Error("TRANSLATION_NO_ENGINE_EXECUTED");
    e.code = "TRANSLATION_NO_ENGINE_EXECUTED";
    e.detail = {
      deepl_failed: !!deeplErr,
      deepl_err: deeplErr ? (deeplErr.message || String(deeplErr)) : null,
      has_deepl: !!deeplKeyFinal,
      can_use_gemini: !!canUseGemini,
    };
    throw e;
  }

  // ✅ 응답에서 result.text를 쓰니까: 결과를 반드시 {text, engine, target}로 정규화
  if (typeof result === "string") {
    result = { text: _out1, engine: "deepl", target: tgt };
  } else if (!result || typeof result !== "object") {
    result = { text: _out1, engine: "deepl", target: tgt };
  } else {
    if (result.text == null) result.text = _out1;
    if (!result.engine) result.engine = "deepl";
    if (!result.target) result.target = tgt;
  }

} else {
  // DeepL 없으면 Gemini
  result = await geminiTranslate();
}
  
        // 5) 최종 응답 (표준 포맷: buildSuccess 사용)
    return res.json(
      buildSuccess({
        translated: result.text,
        engine: result.engine,
        targetLang: result.target || (targetLang?.toUpperCase() || "EN"),
      })
    );
  } catch (e) {
    console.error("❌ /api/translate Error:", e.message);
    console.error("❌ /api/translate stack:", e?.stack || e);

    // ✅ 번역 에러도 verification_logs 에 남겨두기 (mode = 'translate')
    try {
      const b = getJsonBody(req);
      const textRaw =
        b?.text ??
        b?.snippet ??
        b?.content ??
        null;

      await supabase.from("verification_logs").insert([
        {
          mode: "translate",
          query: textRaw ? String(textRaw).slice(0, 500) : null, // 번역 원문 일부만
          answer: null,
          truthscore: null,
          engines: null,
          keywords: null,
          elapsed: null,
          model_main: null,
          model_eval: null,
          sources: null,
          gemini_model: null,
          error: e.message,
          created_at: new Date(),
        },
      ]);
    } catch (logErr) {
      console.error("❌ verification_logs insert (translate) failed:", logErr.message);
    }

    // ✅ 번역 쪽도 /api/verify(/api/verify-snippet)와 동일하게 200 + 코드로 내려주기
    if (e?.code === "GEMINI_KEY_EXHAUSTED") {
      return res.status(200).json(
        buildError(
          "GEMINI_KEY_EXHAUSTED",
          "Gemini 번역 일일 할당량 소진으로 응답을 생성할 수 없습니다. (콘솔 설정/쿼터 확인 필요)",
          e.detail || e.message
        )
      );
    }

    // 🔥 치명적인 키 복호화/환경 문제 등은 그대로 httpStatus + publicMessage로 전달
    if (e?._fatal && e?.httpStatus) {
      return res.status(e.httpStatus).json(
        buildError(
          e.code || "FATAL_ERROR",
          e.publicMessage || "번역 엔진 처리 중 치명적인 오류가 발생했습니다.",
          e.detail || e.message
        )
      );
    }

    return sendError(
      res,
      500,
      "TRANSLATION_ENGINE_ERROR",
      "번역 엔진 오류로 번역을 수행할 수 없습니다.",
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
    // Admin 통계용: docs_analyze 요청 카운트
    markAdminRequest("docs_analyze");

    const {
      user_id,
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

// ================================
// Admin dashboard APIs (beta)
// ================================
app.get("/api/admin/status", (req, res) => {
  return res.json(
    buildSuccess({
      server_time: new Date().toISOString(),
      stats: adminStats,
      whitelist: getNaverWhitelistStatus(),
    })
  );
});

app.get("/api/admin/errors/recent", (req, res) => {
  return res.json(
    buildSuccess({
      total: adminRecentErrors.length,
      // 최신 것이 앞에 오도록 reverse
      items: adminRecentErrors.slice().reverse(),
    })
  );
});

        // ✅ docs/analyze: Supabase Bearer로 userId(키링용) 해석
    const auth_user = await getSupabaseAuthUser(req);
    const bearer_token = getBearerToken(req);

    const logUserId = await resolveLogUserId({
  user_id: user_id ?? null,
  user_email: null,
  user_name: null,
  auth_user,
  bearer_token,
});

const userId = logUserId; // ✅ docs/analyze: keyring/vault 용 userId (1회 resolve 결과)

    // ✅ body gemini_key는 "힌트(1회)" 용도. 없으면 DB keyring 사용
let geminiKeyFinal = (gemini_key || "").toString().trim() || null;
let deeplKeyFinal = (deepl_key || "").toString().trim() || null;

let geminiKeysCount = 0;

if (logUserId) {
  const row = await loadUserSecretsRow(logUserId);
  const s = _ensureIntegrationsSecretsShape(_ensureGeminiSecretsShape(row.secrets));

  if (!deeplKeyFinal) {
    const v = decryptIntegrationsSecrets(s);
    deeplKeyFinal = (v.deepl_key || "").toString().trim() || null;
  }

  geminiKeysCount = (s?.gemini?.keyring?.keys || []).length;
}

    const canUseGemini = !!geminiKeyFinal || geminiKeysCount > 0;
    console.log("ℹ️ /api/docs/analyze key-state:", {
    userId: userId || null,
    has_deepl: !!deeplKeyFinal,
    deepl_len: deeplKeyFinal ? String(deeplKeyFinal).length : 0,
    geminiKeysCount,
    has_gemini_body: !!geminiKeyFinal,
    canUseGemini,
    });

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
    if (wantsSummary && !canUseGemini) {
      return sendError(
        res,
        400,
        "DOC_SUMMARY_REQUIRES_GEMINI",
        "요약(summary)을 수행하려면 gemini_key가 필요합니다."
      );
    }

    // 번역 요청인데 DeepL/Gemini 둘 다 없음
    if (wantsTranslate && !deeplKeyFinal && !canUseGemini) {
      return sendError(
        res,
        400,
        "DOC_TRANSLATE_REQUIRES_ENGINE",
        "번역(translate)을 수행하려면 deepl_key 또는 gemini_key 중 하나가 필요합니다."
      );
    }

    let summaryResult = null;
    let translateResult = null;

    // ✅ (핵심) translateResult에 최종 번역 결과를 반드시 저장 (응답에서 사용)
translateResult = {
  text: String(tr?.text ?? tr?.translated ?? tr?.translation ?? "").trim(),
  engine: String(tr?.engine ?? "none"),
  targetLang:
    (String(tr?.targetLang ?? tr?.target ?? __docTgtLang).trim().toUpperCase() || __docTgtLang),
};

    // ─────────────────────────────
    // 1) 요약 (Gemini 2.5 Flash)
    // ─────────────────────────────
        if (wantsSummary && canUseGemini) {
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

         const summaryText = await fetchGeminiSmart({
        userId: logUserId,
        keyHint: geminiKeyFinal ?? null,
        model: "gemini-2.5-flash",
        payload: { contents: [{ parts: [{ text: prompt }] }] },
      });
      summaryResult = (summaryText || "").trim();
    }

// 2) 번역 (DeepL 우선 → none/원문이면 Gemini fallback)
let tr = null;

// docs/analyze용 타겟 언어(normalize)
const __docTgtLang = (() => {
  const raw =
    (req.body?.target_lang ?? req.body?.targetLang ?? "EN");
  return String(raw).trim().toUpperCase() || "EN";
})();

// Gemini 번역 헬퍼
const __geminiTranslateDoc = async (srcText) => {
  const prompt = `
You are a professional translator.
Translate the following text into ${__docTgtLang}.
Return ONLY the translated text (no quotes, no markdown).

TEXT:
${srcText}
  `.trim();

  const out = await fetchGeminiSmart({
    userId,
    keyHint: geminiKeyFinal ?? null,  // body에 있으면 힌트, 없으면 keyring
    model: "gemini-2.5-flash",
    payload: { contents: [{ parts: [{ text: prompt }] }] },
    opts: { label: "docs:translate" },
  });

  return {
    text: (out || "").trim(),
    engine: "gemini",
    targetLang: __docTgtLang,
  };
};

if (wantsTranslate) {
  const _in = String(safeText ?? text ?? "").trim();

  // 1) DeepL 먼저 시도
  if (deeplKeyFinal) {
    try {
      tr = await translateText(
  safeText,
  __docTgtLang,
  deeplKeyFinal ?? null,
  geminiKeyFinal ?? null
  
);
    } catch (e) {
      // DeepL이 예외 던지면 "none + 원문"으로 두고 아래에서 평가
      tr = {
        text: _in,
        engine: "none",
        targetLang: __docTgtLang,
        error: `DEEPL_EXCEPTION:${e?.message || String(e)}`,
      };
    }
    // ✅ (핵심) translateResult에 최종 번역 결과를 반드시 저장 (응답에서 사용)
translateResult = {
  text: String(tr?.text ?? tr?.translated ?? tr?.translation ?? "").trim(),
  engine: String(tr?.engine ?? "none"),
  targetLang: (String(tr?.targetLang ?? tr?.target ?? __docTgtLang).trim().toUpperCase() || __docTgtLang),
};
  }

  // 2) DeepL 결과 평가
  const _out0 =
    typeof tr === "string"
      ? String(tr).trim()
      : String(tr?.text ?? tr?.translated ?? tr?.translation ?? "").trim();

  const _eng0 =
    typeof tr === "object" && tr
      ? String(tr?.engine ?? "").toLowerCase()
      : "";

  const _looksNone0 = (_eng0 === "none" || !_out0 || _out0 === _in);

  // 3) none/원문 + Gemini 사용 가능하면 fallback
  if (_looksNone0 && canUseGemini) {
    tr = await __geminiTranslateDoc(safeText);
  }

  // 4) 최종 평가
  const _out1 =
    typeof tr === "string"
      ? String(tr).trim()
      : String(tr?.text ?? tr?.translated ?? tr?.translation ?? "").trim();

  const _eng1 =
    typeof tr === "object" && tr
      ? String(tr?.engine ?? "").toLowerCase()
      : "";

  const _looksNone1 = (_eng1 === "none" || !_out1 || _out1 === _in);

  if (_looksNone1) {
    const e = new Error("TRANSLATION_NO_ENGINE_EXECUTED");
    e.code = "TRANSLATION_NO_ENGINE_EXECUTED";
    e.detail = {
      has_deepl: !!deeplKeyFinal,
      can_use_gemini: !!canUseGemini,
      target: __docTgtLang,
    };
    throw e;
  }

  // 5) tr 정규화 (응답에서 tr.text / tr.engine / tr.targetLang 쓰기 편하게)
  if (typeof tr === "string") {
    tr = {
      text: _out1,
      engine: deeplKeyFinal ? "deepl" : "gemini",
      targetLang: __docTgtLang,
    };
  } else if (!tr || typeof tr !== "object") {
    tr = {
      text: _out1,
      engine: deeplKeyFinal ? "deepl" : "gemini",
      targetLang: __docTgtLang,
    };
  } else {
    if (tr.text == null) tr.text = _out1;
    if (!tr.engine) tr.engine = deeplKeyFinal ? "deepl" : "gemini";
    if (!tr.targetLang) tr.targetLang = __docTgtLang;
  }
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
  let enc_diag = null;

  if (diag) {
    try { pac = await getPacificResetInfoCached(); } catch {}
    try { enc_diag = getEncKeyDiagInfo(); } catch (e) {
      enc_diag = {
        ok: false,
        code: e?.code || "ENC_DIAG_ERROR",
        message: e?.publicMessage || e?.message || String(e),
      };
    }
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
      enc_diag, // ✅ 여기!
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
  const p = String(req?.originalUrl || req?.url || "");
  const wantsJson = p.startsWith("/api") || p.startsWith("/admin");

  // admin/ejs 같은 화면 요청은 텍스트로
  if (!wantsJson) {
    // ✅ 서버 콘솔에는 항상 남김(원인 추적용)
    console.error("💥 Express error (non-json):", err?.stack || err, {
      method: req?.method,
      path: p,
    });
    return res.status(err?.status || 500).send("Server error");
  }

  // body parser JSON 파싱 실패
  if (err?.type === "entity.parse.failed") {
    console.warn("⚠️ INVALID_JSON:", err?.message, {
      method: req?.method,
      path: p,
    });
    return res.status(400).json(
      buildError("INVALID_JSON", "JSON 파싱에 실패했습니다.", err?.message)
    );
  }

  // body size 초과
  if (err?.type === "entity.too.large") {
    console.warn("⚠️ PAYLOAD_TOO_LARGE:", err?.message, {
      method: req?.method,
      path: p,
    });
    return res.status(413).json(
      buildError("PAYLOAD_TOO_LARGE", "요청 바디가 너무 큽니다.", err?.message)
    );
  }

  const status = err?.httpStatus || err?.status || 500;
  const code =
    err?.code || (status >= 500 ? "INTERNAL_SERVER_ERROR" : "REQUEST_ERROR");

  // ✅ 500대(또는 DEBUG)면 스택을 무조건 콘솔에 출력
  if (status >= 500 || DEBUG) {
    console.error("💥 INTERNAL_SERVER_ERROR:", err?.stack || err, {
      method: req?.method,
      path: p,
    });
  } else {
    console.warn("⚠️ REQUEST_ERROR:", err?.message || String(err), {
      method: req?.method,
      path: p,
    });
  }

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