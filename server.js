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
  /(authorization|cookie|set-cookie|x-admin-token|x-api-key|api[-_]?key|secret|token|password|session|gemini|openai|naver|supabase|groq|service[_-]?key|client_secret|refresh_token|access_token)/i;

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

   const src = (source || "DATABASE_URL");

  if (!/^postgres(ql)?:\/\//i.test(u)) {
    throw new Error(src + " must start with postgres:// or postgresql://");
  }
  if (/^postgres(ql)?:\/\/https?:\/\//i.test(u)) {
    throw new Error(src + " is malformed (contains https:// after protocol)");
  }
  if (u.includes("onrender.com")) {
    throw new Error(src + " must be a Postgres URL (Supabase), not a Render app URL");
  }

  // ✅ Render Postgres 인스턴스 차단 (dpg-xxx...render.com 등)
  try {
    const host = new URL(u).hostname || "";
    if (host.includes("render.com") || host.includes("postgres.render.com")) {
      throw new Error(src + " points to Render Postgres. Use SUPABASE_DATABASE_URL instead.");
    }
  } catch {}

  return { url: u, source };
}

const { url: DB_URL, source: DB_URL_SOURCE } = pickDatabaseUrl();

// ✅ 부팅 로그(비밀값 노출 없이: host만)
try {
  const host = new URL(DB_URL).hostname || "unknown";
  const via = (DB_URL_SOURCE || "DATABASE_URL");
  if (!isProd) {
    console.log("✅ DB URL selected via " + via + " (host=" + host + ")");
  } else {
    console.log("✅ DB URL selected via " + via);
  }
} catch {
  console.log("✅ DB URL selected via " + (DB_URL_SOURCE || "DATABASE_URL"));
}

// ✅ 여기서 먼저 풀/스토어 준비
const useSsl =
  process.env.PGSSL === "false"
    ? false
    : { rejectUnauthorized: false }; // Supabase/Pooler면 로컬도 SSL 필요한 경우 많음

// ─────────────────────────────
// ✅ PG Pool (db_termination 복구용 Proxy Pool)
//  - db_termination/연결종료 류 에러 발생 시: 풀을 새로 만들고 1회 재시도
//  - connect-pg-simple(session store)에도 같은 proxy를 전달 → 세션도 자동 복구 기대
// ─────────────────────────────

function _isPgTerminationError(err) {
  const code = String(err?.code || "");
  const msg = String(err?.message || "");
  if (code === "XX000" && /db_termination/i.test(msg)) return true;
  if (/terminating connection|server closed the connection|connection terminated|db_termination/i.test(msg)) return true;
  return false;
}

function _createPgPool() {
  const _isFinitePosInt = (x) => Number.isFinite(Number(x)) && Number(x) > 0;

  // ✅ PROD 기본값을 더 여유롭게 (env가 있으면 env가 우선)
  const _idleMs =
    _isFinitePosInt(process.env.PGPOOL_IDLE_MS)
      ? parseInt(process.env.PGPOOL_IDLE_MS, 10)
      : (isProd ? 30000 : 10000);

  const _connMs =
    _isFinitePosInt(process.env.PGPOOL_CONN_MS)
      ? parseInt(process.env.PGPOOL_CONN_MS, 10)
      : (isProd ? 20000 : 10000);

  const pool = new pg.Pool({
    connectionString: DB_URL,
    ssl: useSsl,
    max: parseInt(process.env.PGPOOL_MAX || "5", 10),
    idleTimeoutMillis: _idleMs,
    connectionTimeoutMillis: _connMs,
    keepAlive: true,
  });

  // ✅ 중요: Pool 'error' 이벤트 핸들러 없으면 프로세스가 죽을 수 있음
  pool.on("error", (err) => {
    console.error("⚠️ PG POOL ERROR (idle client):", err.code || "", err.message);

    // db_termination류면 풀을 리셋(비동기 fire-and-forget)
    if (_isPgTerminationError(err)) {
      console.warn("⚠️ PG POOL: db_termination detected → resetting pool");
      void _resetPgPool(err);
    }
  });

  return pool;
}

let _pgPool = _createPgPool();
let _pgPoolResetting = false;

// ✅ 외부(예: connect-pg-simple)가 pool.on(...)을 호출할 수 있으니,
//    리스너를 기억해두고 pool 교체 시에도 재부착
const _pgPoolListeners = [];

function _attachRememberedListeners(pool) {
  if (!pool) return;
  for (const [ev, fn] of _pgPoolListeners) {
    try {
      pool.on(ev, fn);
    } catch (_) {}
  }
}

_attachRememberedListeners(_pgPool);

async function _resetPgPool(reasonErr) {
  if (_pgPoolResetting) return;
  _pgPoolResetting = true;
  try {
    const old = _pgPool;
    _pgPool = _createPgPool();

    // 새 풀로 교체되면, 기억된 리스너 재부착
    _attachRememberedListeners(_pgPool);

    try {
      if (old) await old.end().catch(() => {});
    } catch (_) {}
  } finally {
    _pgPoolResetting = false;
  }
}

// ✅ 코드 전체에서 pgPool.query / pgPool.connect / pgPool.on / pgPool.end 를 그대로 쓰되,
//    내부에서 복구/재시도/리스너 유지
const pgPool = {
  async query(text, params) {
    try {
      return await _pgPool.query(text, params);
    } catch (e) {
      if (_isPgTerminationError(e)) {
        console.warn("⚠️ PG POOL: query failed by db_termination → reset + retry once");
        await _resetPgPool(e);
        return await _pgPool.query(text, params);
      }
      throw e;
    }
  },

  async connect() {
    try {
      return await _pgPool.connect();
    } catch (e) {
      if (_isPgTerminationError(e)) {
        console.warn("⚠️ PG POOL: connect failed by db_termination → reset + retry once");
        await _resetPgPool(e);
        return await _pgPool.connect();
      }
      throw e;
    }
  },

  on(ev, fn) {
    if (!ev || typeof fn !== "function") return this;
    _pgPoolListeners.push([ev, fn]);
    try {
      _pgPool.on(ev, fn);
    } catch (_) {}
    return this;
  },

  end(cb) {
    if (cb) {
      try {
        return _pgPool.end(cb);
      } catch (e) {
        return cb(e);
      }
    }

    return (async () => {
      try {
        return await _pgPool.end();
      } catch (_) {
        return undefined;
      }
    })();
  },
};

// ✅ Session store schema/table (configurable)
// - PROD에서도 코드가 죽지 않게 기본값 제공
// - Supabase에서 스키마/테이블명을 바꿨다면 env로 오버라이드 가능
const SESSION_STORE_SCHEMA =
  String(process.env.SESSION_STORE_SCHEMA || "public").trim() || "public";

const SESSION_STORE_TABLE =
  String(process.env.SESSION_STORE_TABLE || "session_store").trim() || "session_store";

// ✅ connect-pg-simple session store 생성 (session() mount 전에 반드시 정의되어야 함)
const PgStore = connectPgSimple(session);
const sessionStore = new PgStore({
  pool: pgPool,
  schemaName: SESSION_STORE_SCHEMA,
  tableName: SESSION_STORE_TABLE,
  createTableIfMissing: !isProd, // ✅ DEV에서는 자동생성 허용, PROD는 고정
  pruneSessionInterval: 60 * 10,
});

// ✅ PROD 부팅 가드: session_store 테이블 존재 확인
// - "테이블이 진짜 없음"이면 종료
// - 그 외(일시 타임아웃/네트워크 흔들림)는 경고만 찍고 부팅 계속(Render cold start 보호)
const SESSION_STORE_BOOTSTRAP_TRIES = parseInt(
  process.env.SESSION_STORE_BOOTSTRAP_TRIES || (isProd ? "8" : "2"),
  10
);

const SESSION_STORE_BOOTSTRAP_DELAY_MS = parseInt(
  process.env.SESSION_STORE_BOOTSTRAP_DELAY_MS || (isProd ? "600" : "200"),
  10
);

function _sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function _ensureSessionStoreTableOnce() {
  const q = `
    select 1 as ok
    from information_schema.tables
    where table_schema = $1 and table_name = $2
    limit 1
  `;
  const r = await pgPool.query(q, [SESSION_STORE_SCHEMA, SESSION_STORE_TABLE]);
  const ok = Array.isArray(r?.rows) && r.rows.length > 0;
  if (!ok) {
    const err = new Error(
      `Missing ${SESSION_STORE_SCHEMA}.${SESSION_STORE_TABLE}. Create it in Supabase before running in production.`
    );
    err.code = "SESSION_STORE_MISSING";
    throw err;
  }
}

async function _bootstrapSessionStoreTable() {
  let lastErr = null;

  for (let i = 1; i <= SESSION_STORE_BOOTSTRAP_TRIES; i++) {
    try {
      await _ensureSessionStoreTableOnce();
      return true;
    } catch (e) {
      lastErr = e;

      // 테이블이 진짜 없으면 재시도 의미 없음 → 즉시 throw
      if (String(e?.code || "") === "SESSION_STORE_MISSING") throw e;

      const code = String(e?.code || "");
      const msg = String(e?.message || e);

      console.error(
        `❌ session store bootstrap failed (${i}/${SESSION_STORE_BOOTSTRAP_TRIES}):`,
        code,
        msg
      );

      if (i < SESSION_STORE_BOOTSTRAP_TRIES) {
        await _sleep(SESSION_STORE_BOOTSTRAP_DELAY_MS);
        continue;
      }
    }
  }

  // 여기까지 오면 "테이블은 있을 가능성이 높지만" 연결/타임아웃 류로 실패
  // → PROD라도 Render cold start 보호 위해 부팅은 계속
  console.warn(
    "⚠️ session store bootstrap gave up; continuing without hard-fail (cold start / transient DB issue)."
  );
  return false;
}

void (async () => {
  try {
    await _bootstrapSessionStoreTable();
    if (!isProd) {
      console.log(
        `✅ session store table ok: ${SESSION_STORE_SCHEMA}.${SESSION_STORE_TABLE}`
      );
    }
  } catch (e) {
    console.error("❌ session store table check failed:", e?.code || "", e?.message || e);

    // "테이블이 없음"은 PROD에서 정상 운영 불가 → 종료 유지
    if (isProd && String(e?.code || "") === "SESSION_STORE_MISSING") {
      process.exit(1);
    }

    // 그 외(타임아웃/일시 장애)는 종료하지 않음
  }
})();

function _isPgTransientBootstrapError(err) {
  const code = String(err?.code || "");
  const msg = String(err?.message || "");

  // 네가 본 케이스(“timeout4” 류 포함) + 일반 네트워크/타임아웃
  if (/timeout4/i.test(msg)) return true;
  if (/connection terminated due to connection timeout/i.test(msg)) return true;
  if (/connection terminated|server closed the connection|terminating connection/i.test(msg)) return true;
  if (/connect timed out|ETIMEDOUT|ECONNRESET|EPIPE|ENETUNREACH|EHOSTUNREACH/i.test(msg)) return true;

  // PG 에러코드 중 “일시 장애”에 가까운 것들(너무 보수적으로만)
  if (code === "57P03") return true; // cannot_connect_now
  if (code === "53300") return true; // too_many_connections

  return false;
}

function _isPgFatalBootstrapError(err) {
  const code = String(err?.code || "");
  // ✅ 확정적 설정/권한 오류는 PROD에서 바로 죽이는 게 맞음
  if (code === "SESSION_STORE_MISSING") return true;
  if (code === "28P01") return true; // invalid_password
  if (code === "28000") return true; // invalid_authorization_specification
  if (code === "3D000") return true; // invalid_catalog_name (db does not exist)
  if (code === "3F000") return true; // invalid_schema_name
  return false;
}

async function _sleepMs(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ✅ session_store 존재 확인(없으면 SESSION_STORE_MISSING 던짐)
async function _ensureSessionStoreTable() {
  const q = `
    select 1 as ok
    from information_schema.tables
    where table_schema = $1 and table_name = $2
    limit 1
  `;
  const r = await pgPool.query(q, [SESSION_STORE_SCHEMA, SESSION_STORE_TABLE]);
  const ok = Array.isArray(r?.rows) && r.rows.length > 0;
  if (!ok) {
    const err = new Error(
      `Missing ${SESSION_STORE_SCHEMA}.${SESSION_STORE_TABLE}. Create it in Supabase before running in production.`
    );
    err.code = "SESSION_STORE_MISSING";
    throw err;
  }
}

void (async () => {
  const maxTry = parseInt(process.env.SESSION_STORE_BOOTSTRAP_TRIES || "6", 10);
  const baseDelay = parseInt(process.env.SESSION_STORE_BOOTSTRAP_DELAY_MS || "500", 10);

  for (let i = 1; i <= Math.max(1, maxTry); i++) {
    try {
      await _ensureSessionStoreTable();
      if (!isProd) {
        console.log(`✅ session store table ok: ${SESSION_STORE_SCHEMA}.${SESSION_STORE_TABLE}`);
      } else {
        console.log(`✅ session store table ok: ${SESSION_STORE_SCHEMA}.${SESSION_STORE_TABLE}`);
      }
      return;
    } catch (e) {
      const code = e?.code || "";
      const msg = e?.message || e;

      console.error("❌ session store table check failed:", code, msg);

      if (isProd && _isPgFatalBootstrapError(e)) {
        process.exit(1);
      }

      // PROD에서는 “일시 장애”면 재시도 후에도 죽이지 않고 서비스 계속(부팅루프 방지)
      const transient = _isPgTransientBootstrapError(e);
      if (!transient) {
        if (isProd) {
          // 비일시적이지만 fatal로 분류되지 않은 케이스는 안전하게 계속(필요시 로그 보고 env로 조정)
          console.error("⚠️ session store bootstrap: non-transient but non-fatal → continue without exit");
          return;
        }
        return;
      }

      if (i < maxTry) {
        const delay = Math.min(8000, baseDelay * Math.pow(2, i - 1));
        console.warn(`⚠️ session store bootstrap retry ${i}/${maxTry} after ${delay}ms`);
        await _sleepMs(delay);
        continue;
      }

      if (isProd) {
        console.error("⚠️ session store bootstrap exhausted retries → continue without exit (avoid boot loop)");
      }
      return;
    }
  }
})();

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

  const ttl = (() => {
  const n = Number(VERIFY_CACHE_TTL_MS);
  return Number.isFinite(n) && n > 0 ? n : 0;
})();
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

  // Node timer upper bound: 2^31-1 (≈ 24.85 days)
  const MAX_TIMER_MS = 0x7fffffff;

  // cleanup은 "정확한 스케줄"이 아니라 메모리 정리용이므로,
  // windowMs가 아무리 커도 6시간마다만 돌게(= overflow 방지 + 충분)
  const cleanupMsRaw = Math.max(60_000, Math.min(Number(windowMs) || 0, 6 * 60 * 60 * 1000));
  const cleanupMs = Math.min(cleanupMsRaw, MAX_TIMER_MS);

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

  const cutStr = (v, n) => {
    const s = (v == null) ? "" : String(v);
    return s.length > n ? s.slice(0, n) : s;
  };

  const cutArr = (v, n) => (Array.isArray(v) ? v.slice(0, n) : []);

  const pickUrl = (x) => {
    if (!x || typeof x !== "object") return null;
    return String(
      x.source_url ||
      x.url ||
      x.link ||
      x.href ||
      x.naver_url ||
      x.permalink ||
      ""
    ).trim() || null;
  };

  const hostFromUrl = (u) => {
    try { return u ? (new URL(u)).hostname : null; } catch { return null; }
  };

  const tierScore = (t) => {
    // 낮을수록 우선 (1이 최고)
    const n = Number(t);
    if (Number.isFinite(n)) return n;
    return 99;
  };

  // 0) 원본 그대로 시도
  const s0 = tryStr(input);
  if (s0) return s0;

  // ─────────────────────────────
  // 1) blocks + external을 "안전 축약" (JSON 깨짐 없이)
  // ─────────────────────────────

  // (A) blocks: 기존 방식 유지하되 조금 더 방어적으로 축약
  const slimBlocks = Array.isArray(input?.blocks)
    ? input.blocks.map((b) => {
        const ev = b?.evidence || {};

        const topk = Math.min(
          3,
          (Number.isFinite(BLOCK_EVIDENCE_TOPK) ? BLOCK_EVIDENCE_TOPK : 3)
        );

        const nTopk = Math.min(
          3,
          (Number.isFinite(BLOCK_NAVER_EVIDENCE_TOPK) ? BLOCK_NAVER_EVIDENCE_TOPK : 3)
        );

        const slimNaver = cutArr(ev.naver, nTopk).map((x) => ({
          title: x?.title || null,
          link: x?.link || null,
          naver_type: x?.naver_type || null,
          tier: x?.tier || null,
        }));

        // queries가 너무 커지는 케이스 방지(값만 짧게)
        const q0 = b?.queries && typeof b.queries === "object" ? b.queries : null;
        const slimQueries = q0
          ? Object.fromEntries(
              Object.entries(q0).slice(0, 8).map(([k, v]) => {
                if (Array.isArray(v)) return [k, v.slice(0, 4).map((s) => cutStr(s, 120))];
                return [k, cutStr(v, 160)];
              })
            )
          : null;

        return {
          id: b?.id ?? null,
          text: cutStr(String(b?.text || ""), 320),
          queries: slimQueries,
          evidence: {
            crossref: cutArr(ev.crossref, topk).map((s) => cutStr(s, 220)),
            openalex: cutArr(ev.openalex, topk).map((s) => cutStr(s, 220)),
            wikidata: cutArr(ev.wikidata, 5).map((s) => cutStr(s, 220)),
            gdelt: cutArr(ev.gdelt, topk).map((s) => cutStr(s, 220)),
            naver: slimNaver,
          },
        };
      })
    : [];

  // (B) external: "근거 풀"을 최소 형태로 남김
  const buildSlimExternal = (ext) => {
    if (!ext || typeof ext !== "object") return { truncated: true, reason: "no_external" };

    // 가능한 한 “사용한 엔진” 위주로만 남김
    const used0 = input?.partial_scores?.engines_used;
    const used = Array.isArray(used0) ? used0.map(String) : null;

    const engineKeys = Object.keys(ext).filter((k) => Array.isArray(ext[k]));
    const ordered = (() => {
      const base = used && used.length ? used.filter((k) => engineKeys.includes(k)) : [];
      const rest = engineKeys.filter((k) => !base.includes(k));
      return [...base, ...rest];
    })();

    const PER_ENGINE_CAP = 3;
    const TOTAL_CAP = 10;

    // evidence_text는 verifyInput에서 너무 비싸니까 “tier 1/2만 아주 짧게” 허용
    const baseExcerpt = (typeof EVIDENCE_EXCERPT_CHARS === "number" && Number.isFinite(EVIDENCE_EXCERPT_CHARS))
      ? EVIDENCE_EXCERPT_CHARS
      : 700;
    const EXCERPT_CAP = Math.max(120, Math.min(260, Math.floor(baseExcerpt * 0.35))); // ~245 chars

    // evidence_text 전체 예산(너무 커지면 바로 제거)
    let textBudget = Math.max(300, Math.min(2400, Math.floor(limit * 0.18)));

    const slimItem = (engine, x) => {
      if (x == null) return null;

      // 문자열 evidence(예: crossref/openalex가 string)도 처리
      if (typeof x === "string") {
        return cutStr(x, 260);
      }

      if (typeof x !== "object") return null;

      const url = pickUrl(x);
      const host = x.host || x.hostname || hostFromUrl(url);
      const title = x.title || x.name || x.headline || x.display_name || null;

      const tier = (x.tier != null) ? x.tier : null;

      // tier 기반 excerpt 포함(오직 naver tier 1/2)
      let evidence_text = null;
      if (
        engine === "naver" &&
        typeof x.evidence_text === "string" &&
        x.evidence_text.trim().length > 0
      ) {
        const ts = tierScore(tier);
        const allow = (ts === 1 || ts === 2);
        if (allow && textBudget > 0) {
          const t = cutStr(x.evidence_text.trim(), Math.min(EXCERPT_CAP, textBudget));
          if (t) {
            evidence_text = t;
            textBudget -= t.length;
          }
        }
      }

      // naver_type 같은 최소 메타만 유지
      const out = {
        host: host || null,
        title: title ? cutStr(title, 180) : null,
        url: url || null,
      };

      if (engine === "naver") {
        out.tier = tier;
        out.naver_type = x.naver_type || null;
      }

      if (evidence_text) out.evidence_text = evidence_text;

      // null 제거로 크기 절감
      for (const k of Object.keys(out)) {
        if (out[k] == null || out[k] === "") delete out[k];
      }
      return Object.keys(out).length ? out : null;
    };

    const out = {};
    let total = 0;

    for (const k of ordered) {
      if (total >= TOTAL_CAP) break;

      let arr = ext[k];
      if (!Array.isArray(arr) || !arr.length) continue;

      // naver는 tier 낮은 것 우선
      if (k === "naver") {
        arr = [...arr].sort((a, b) => tierScore(a?.tier) - tierScore(b?.tier));
      }

      const kept = [];
      for (const x of arr) {
        if (kept.length >= PER_ENGINE_CAP) break;
        if (total >= TOTAL_CAP) break;

        const si = slimItem(k, x);
        if (si == null) continue;

        kept.push(si);
        total += 1;
      }

      if (kept.length) out[k] = kept;
    }

    // 정말 아무것도 못 남기면 truncated 처리
    if (!Object.keys(out).length) {
      return { truncated: true, reason: "external_empty_after_slim" };
    }

    out._meta = {
      slim: true,
      truncated: true,
      caps: { per_engine: PER_ENGINE_CAP, total: TOTAL_CAP, excerpt_cap: EXCERPT_CAP },
    };

    return out;
  };

  const slimExternal = buildSlimExternal(input?.external);

  const slim1 = {
    mode: input?.mode,
    query: input?.query,
    core_text: input?.core_text ? cutStr(String(input.core_text), 2000) : "",
    blocks: slimBlocks,
    // ✅ 핵심: external을 완전 삭제하지 말고, "top-tier 중심 축약본"을 넣는다
    external: slimExternal,
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

  const s1 = tryStr(slim1);
  if (s1) return s1;

  // 2) 더 작게(queries 제거 + external 완전 truncate)
  const slimmer = {
    mode: slim1.mode,
    query: slim1.query,
    core_text: slim1.core_text,
    blocks: slimBlocks.slice(0, 3).map((b) => ({ id: b.id, text: b.text, evidence: b.evidence })),
    partial_scores: {
      recency: slim1.partial_scores?.recency ?? null,
      engines_used: slim1.partial_scores?.engines_used ?? null,
      engines_requested: slim1.partial_scores?.engines_requested ?? null,
      engine_results: slim1.partial_scores?.engine_results ?? null,
    },
    external: { truncated: true, reason: "too_large" },
  };

  const s2 = tryStr(slimmer);
  if (s2) return s2;

  // 3) 진짜 최종: 최소 JSON
  return JSON.stringify({
    mode: input?.mode || null,
    query: input?.query || null,
    core_text: input?.core_text ? cutStr(String(input.core_text), 1500) : "",
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
  if (!secrets.integrations || typeof secrets.integrations !== "object") {
    secrets.integrations = {};
  }
  const it = secrets.integrations;

  if (!it.naver || typeof it.naver !== "object") it.naver = { id_enc: null, secret_enc: null };
  if (!it.klaw || typeof it.klaw !== "object") it.klaw = { key_enc: null };
  if (!it.github || typeof it.github !== "object") it.github = { token_enc: null };
  if (!it.deepl || typeof it.deepl !== "object") it.deepl = { key_enc: null };

  // ✅ ADD: Groq
  if (!it.groq || typeof it.groq !== "object") it.groq = { api_key_enc: null };

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
  // ✅ ADD: Groq (accept groq_key / groq_api_key 둘 다)
  _setEncOrClear(it.groq, "api_key_enc", patch.groq_key ?? patch.groq_api_key);

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

    // ✅ ADD: Groq
    groq_api_key: _getDec(it.groq, "api_key_enc"),
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

  // PT 날짜가 바뀌면 "일일 소진(exhausted)"만 초기화
  // + 429 쿨다운은 짧은 TTL이므로 날짜 변경 시 같이 초기화(스테일 방지)
  if (pt_date_now && last && last !== pt_date_now) {
    state.exhausted_ids = {};
    state.rate_limited_until = {};
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

async function markGeminiKeyInvalid(userId, secrets, keyId, pt_date_now, meta = {}) {
  if (!keyId) return;

  const state = secrets?.gemini?.keyring?.state || {};
  if (!state.invalid_ids || typeof state.invalid_ids !== "object") state.invalid_ids = {};

  // invalid_ids 값은 "truthy"면 후보에서 제외되므로, 메타는 자유롭게 넣어도 됨
  state.invalid_ids[keyId] = {
    pt_date: pt_date_now || "unknown",
    reason: meta?.reason ?? null,
    status: meta?.status ?? null,
  };

  // invalid로 박았으면 exhausted에서 제거(혼선 방지)
  try { delete state.exhausted_ids?.[keyId]; } catch (_) {}

  const keys = Array.isArray(secrets?.gemini?.keyring?.keys) ? secrets.gemini.keyring.keys : [];
  state.active_id = _rotateKeyId(keys, keyId);

  secrets.gemini.keyring.state = state;
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

  // ✅ tried는 "키 0개" 케이스에서도 detail 생성 중 참조될 수 있으므로 먼저 선언
  const tried = new Set();

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
        keysTriedCount: tried.size,
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
      keysTriedCount: tried.size,
      pt_date: pt_date_now,
      next_reset_utc: pac.next_reset_utc,
    };
    throw err;
  }

    // ✅ 핵심: “현재 후보 키 복호화 실패”는 ‘전체 소진’이 아니라 ‘해당 키만 탈락’ → 다음 키로 계속
  for (let i = 0; i < keysCount; i++) {
    const cand = pickGeminiKeyCandidate(secrets);
    if (!cand.keyId || !cand.enc) break;

    // 무한루프 방지: 같은 키가 다시 나오면 active_id를 "다음 키"로 넘기고 계속
    if (tried.has(cand.keyId)) {
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
      // ✅ 복호화 실패는 "키 소진"이 아니라 "서버 암호화키(env) 누락/변경" 가능성이 높음 → 즉시 중단
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
        keys_count: keysCount,
        pt_date: pt_date_now,
        next_reset_utc: pac.next_reset_utc,
      };
    }

    // 빈키 → 해당 키만 exhausted 처리 후 다음 키로 진행
    await markGeminiKeyExhausted(userId, secrets, cand.keyId, pt_date_now);
  }

  // ✅ 여기까지 왔으면:
  //   A) 전부 exhausted/invalid 이거나
  //   B) "쓸 수 있는 키는 있는데" 전부 429 쿨다운 중(rate_limited_until) 이거나
  // → B는 GEMINI_RATE_LIMIT으로 정확히 분기해야 함(현재 오분류 원인)
  {
    const state2 = secrets?.gemini?.keyring?.state || {};
    const exhausted2 = state2.exhausted_ids || {};
    const invalid2 = state2.invalid_ids || {};
    const rl2 = state2.rate_limited_until || {};
    const nowMs2 = Date.now();

    let nonExhaustedNonInvalid = 0;
    let nonExhaustedNonInvalidButRateLimited = 0;
    let minUntil = null;

    for (const k of keys) {
      const id = k?.id;
      if (!id) continue;
      if (invalid2[id]) continue;       // invalid는 사용자 조치 필요 → 후보 제외
      if (exhausted2[id]) continue;     // 일일 소진 → 후보 제외

      nonExhaustedNonInvalid++;

      const until = rl2[id];
      if (Number.isFinite(until) && until > nowMs2) {
        nonExhaustedNonInvalidButRateLimited++;
        if (minUntil == null || until < minUntil) minUntil = until;
      }
    }

    // ✅ 케이스 B: “쓸 수 있는 키는 있는데 전부 쿨다운 중”
    if (
      nonExhaustedNonInvalid > 0 &&
      nonExhaustedNonInvalidButRateLimited === nonExhaustedNonInvalid &&
      minUntil != null
    ) {
      const err = new Error("GEMINI_KEYRING_RATE_LIMITED");
      err.code = "GEMINI_RATE_LIMIT";
      err.httpStatus = 200;

      const retryAfterMs = Math.max(0, Math.ceil(minUntil - nowMs2));
      err.detail = {
        keysCount,
        keysTriedCount: tried.size,
        pt_date: pt_date_now,
        next_reset_utc: pac.next_reset_utc,
        retry_after_ms: retryAfterMs,
      };
      throw err;
    }
  }

  // ✅ 케이스 A: 진짜 exhausted/없음
  const err = new Error("GEMINI_KEYRING_EMPTY_OR_EXHAUSTED");
  err.code = "GEMINI_KEY_EXHAUSTED";
  err.httpStatus = 200;
  err.detail = { keysCount, keysTriedCount: tried.size, pt_date: pt_date_now, next_reset_utc: pac.next_reset_utc };
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
  // admin/status에서 쓰는 "요약"은 실제 메타로 연결
  const meta = getNaverWhitelistMeta();
  return {
    loaded: !!meta?.loaded,
    version: meta?.version ?? null,
    lastUpdate: meta?.lastUpdate ?? null,
    daysPassed: meta?.daysPassed ?? null,
    totalHosts: meta?.totalHosts ?? null,
    hasKosis: meta?.hasKosis ?? null,

    // 운영/디버그 참고용
    env_version: meta?.env_version ?? (process.env.NAVER_WHITELIST_VERSION || null),
    sourceUrl: NAVER_WHITELIST_SOURCE_URL || null,
    refreshMinutes: NAVER_WHITELIST_UPDATE_INTERVAL_HOURS ? (NAVER_WHITELIST_UPDATE_INTERVAL_HOURS * 60) : null,
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

// ✅ mail fail(invalid_grant) 대응: 메일만 쿨다운, whitelist 업데이트 등 본업은 계속
const ADMIN_NOTICE_MAIL_COOLDOWN_MS = Math.max(
  60_000,
  (parseInt(process.env.ADMIN_NOTICE_MAIL_COOLDOWN_MS || "0", 10) || 0) * 1000
) || (12 * 60 * 60 * 1000); // 기본 12h

let __adminMailDisabledUntilMs = 0;
let __adminMailLastFail = null;

// ✅ Gmail env 최소 구성 확인(없으면 sendAdminNotice가 조용히 skip)
function __isAdminMailConfigured() {
  const id = String(process.env.GMAIL_CLIENT_ID || "").trim();
  const secret = String(process.env.GMAIL_CLIENT_SECRET || "").trim();
  const refresh = String(process.env.GMAIL_REFRESH_TOKEN || "").trim();
  // redirect uri / ADMIN_EMAIL 은 sendAdminNotice에서 별도 체크(또는 optional)
  if (!id || !secret || !refresh) return false;
  return true;
}

async function sendAdminNotice(subject, html, toOverride = null) {
  try {
    if (!__isAdminMailConfigured()) {
      if (DEBUG) console.warn("⚠️ Admin mail skipped: Gmail env not configured");
      return { ok: false, skipped: true, reason: "MAIL_NOT_CONFIGURED" };
    }

    const to = String(toOverride || process.env.ADMIN_EMAIL || "").trim();
    if (!to) {
      if (DEBUG) console.warn("⚠️ Admin mail skipped: NO_TO");
      return { ok: false, skipped: true, reason: "NO_TO" };
    }

    const now = Date.now();
    if (__adminMailDisabledUntilMs && now < __adminMailDisabledUntilMs) {
      if (DEBUG) {
        console.warn(
          "⚠️ Admin mail skipped: cooldown active until",
          new Date(__adminMailDisabledUntilMs).toISOString(),
          __adminMailLastFail ? `lastFail=${__adminMailLastFail}` : ""
        );
      }
      return { ok: false, skipped: true, reason: "MAIL_COOLDOWN" };
    }

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
        accessToken,
      },
    });

    await transporter.sendMail({
      from: `"Cross-Verified Notifier" <${process.env.GMAIL_USER}>`,
      to,
      subject,
      html,
    });

    // 성공 시 실패 메타 초기화
    __adminMailLastFail = null;
    __adminMailDisabledUntilMs = 0;
    return { ok: true };
  } catch (err) {
    const msg = String(err?.message || "MAIL_FAIL");
    console.error("❌ Mail fail:", msg);

    // invalid_grant 류면 일정 시간 메일 시도 중단 (화이트리스트 갱신 자체는 계속)
    if (__looksLikeInvalidGrant(err)) {
      __adminMailLastFail = "invalid_grant";
      __adminMailDisabledUntilMs = Date.now() + ADMIN_NOTICE_MAIL_COOLDOWN_MS;
      console.error(
        "❌ Mail disabled (cooldown) due to invalid_grant-like error. " +
          "Action: re-issue Gmail refresh token (GMAIL_REFRESH_TOKEN) in Render env. " +
          "Disabled until: " +
          new Date(__adminMailDisabledUntilMs).toISOString()
      );
      return { ok: false, disabled: true, reason: "INVALID_GRANT_COOLDOWN" };
    }

    __adminMailLastFail = msg.slice(0, 120);
    return { ok: false, reason: "MAIL_FAIL", message: msg };
  }
}

function __looksLikeInvalidGrant(err) {
  const m1 = String(err?.message || "").toLowerCase();
  const m2 = String(err?.response?.data?.error || "").toLowerCase();
  const m3 = JSON.stringify(err?.response?.data || {}).toLowerCase();

  // google oauth2 / nodemailer에서 흔히 보이는 케이스들
  if (m1.includes("invalid_grant") || m2.includes("invalid_grant") || m3.includes("invalid_grant")) return true;
  if (m1.includes("unauthorized_client") || m2.includes("unauthorized_client") || m3.includes("unauthorized_client")) return true;
  if (m1.includes("invalid_client") || m2.includes("invalid_client") || m3.includes("invalid_client")) return true;
  if (m1.includes("token") && m1.includes("revoked")) return true;

  return false;
}

// ✅ removed duplicate sendAdminNotice(subject, html)
// canonical sendAdminNotice(subject, html, toOverride = null) is defined above

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
  // dev/local에서는 그대로 허용
  if (process.env.NODE_ENV !== "production") return next();

  // ✅ PROD: 진단/트리거 엔드포인트는 "DIAG 전용 토큰" 또는 "ADMIN 토큰"만 허용
  // - DEV_ADMIN_TOKEN은 PROD에서 절대 허용하지 않음
  try {
    const adminHdr = String(req.headers["x-admin-token"] || "").trim();

    const diagTok = String(
      process.env.DIAG_ADMIN_TOKEN || process.env.DIAG_TOKEN || ""
    ).trim();

    const adminTok = String(process.env.ADMIN_TOKEN || "").trim();

    if (
      adminHdr &&
      ((diagTok && adminHdr === diagTok) || (adminTok && adminHdr === adminTok))
    ) {
      return next();
    }
  } catch (_) {}

  // ✅ PROD에서는 존재 자체를 숨김
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

        const body0 = (() => {
  if (!req.body) return {};
  if (typeof req.body === "object") return req.body;
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return {};
})();

// ✅ allow "settings" wrapper too (ex: { settings:{ integrations:{...}} })
const body = (body0 && typeof body0.settings === "object" && body0.settings) ? body0.settings : body0;

// ✅ allow integrations to be at root OR under settings
const integrationsIn =
  (body && typeof body.integrations === "object" && body.integrations) ? body.integrations :
  (body0 && typeof body0.integrations === "object" && body0.integrations) ? body0.integrations :
  {};

// ✅ gemini section can be at root OR under settings
const geminiIn =
  (body && typeof body.gemini === "object" && body.gemini) ? body.gemini :
  (body0 && typeof body0.gemini === "object" && body0.gemini) ? body0.gemini :
  {};

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

// ✅ Groq (router)
const groq_key =
  body.groq_key ??
  body.groq_api_key ??
  integrationsIn.groq_key ??
  integrationsIn.groq_api_key ??
  integrationsIn.groq?.key ??
  integrationsIn.groq?.api_key ??
  integrationsIn.groq?.token;

const hasOtherPayload =
  naver_id !== undefined ||
  naver_secret !== undefined ||
  klaw_key !== undefined ||
  github_token !== undefined ||
  deepl_key !== undefined ||
  groq_key !== undefined;

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
  groq_key, // ✅ ADD: store groq key to secrets.integrations.groq.api_key_enc
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
has_groq: !!it.groq?.api_key_enc, // ✅ ADD
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

        const invalidIds = state.invalid_ids || {};
    const rl = state.rate_limited_until || {};
    const nowMs = Date.now();

    const rate_limited_active_ids = Object.entries(rl)
      .filter(([, until]) => Number.isFinite(until) && until > nowMs)
      .map(([id]) => id);

    return res.json(buildSuccess({
      pt_date: pac.pt_date,
      next_reset_utc: pac.next_reset_utc,
      key_count: keys.length,
      active_id: state.active_id || null,

      exhausted_count: Object.keys(exhaustedIds).length,
      exhausted_ids: exhaustedIds,

      invalid_count: Object.keys(invalidIds).length,
      invalid_ids: invalidIds,

      rate_limited_count: rate_limited_active_ids.length,
      rate_limited_active_ids,
      rate_limited_until: rl,
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
// ✅ whitelist auto-update config
const NAVER_WHITELIST_SOURCE_URL = String(process.env.NAVER_WHITELIST_SOURCE_URL || "").trim(); // 원격 JSON URL
const NAVER_WHITELIST_AUTO_UPDATE = process.env.NAVER_WHITELIST_AUTO_UPDATE === "1";
const NAVER_WHITELIST_UPDATE_INTERVAL_HOURS = Math.max(
  1,
  parseInt(process.env.NAVER_WHITELIST_UPDATE_INTERVAL_HOURS || "24", 10) || 24
);

// ✅ mail notify (optional)
const WL_NOTIFY_EMAIL_TO = String(process.env.WL_NOTIFY_EMAIL_TO || "").trim();
const WL_NOTIFY_EMAIL_FROM = String(process.env.WL_NOTIFY_EMAIL_FROM || "").trim();
const SMTP_HOST = String(process.env.SMTP_HOST || "").trim();
const SMTP_PORT = parseInt(process.env.SMTP_PORT || "587", 10) || 587;
const SMTP_USER = String(process.env.SMTP_USER || "").trim();
const SMTP_PASS = String(process.env.SMTP_PASS || "").trim();
const SMTP_SECURE = process.env.SMTP_SECURE === "1"; // 465면 보통 1

// ✅ derived/compat
const NAVER_WHITELIST_UPDATE_INTERVAL_MIN = NAVER_WHITELIST_UPDATE_INTERVAL_HOURS * 60;
const NAVER_WHITELIST_REMOTE_URL = NAVER_WHITELIST_SOURCE_URL; // compat (admin status 등에서 사용)

// ✅ last update meta (diag/admin)
globalThis.__NAVER_WL_UPDATE_LAST = globalThis.__NAVER_WL_UPDATE_LAST || null;

// ✅ fetch remote json with timeout
async function __fetchJsonWithTimeout(url, timeoutMs = 20_000) {
  if (!url) throw new Error("WL_REMOTE_URL_EMPTY");
  if (typeof fetch !== "function") throw new Error("FETCH_NOT_AVAILABLE");

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);

  try {
    const r = await fetch(url, {
      method: "GET",
      headers: { "Accept": "application/json" },
      signal: ctrl.signal,
    });
    if (!r.ok) {
      throw new Error(`WL_REMOTE_HTTP_${r.status}`);
    }
    const json = await r.json();
    return json;
  } finally {
    clearTimeout(t);
  }
}

function __normalizeWhitelistJson(json) {
  if (!json || typeof json !== "object") throw new Error("WL_JSON_INVALID");
  if (!json.tiers || typeof json.tiers !== "object") throw new Error("WL_JSON_MISSING_TIERS");

  // normalize domains: trim/lower/strip www, dedupe
  const tiers = json.tiers;
  for (const [tier, info] of Object.entries(tiers)) {
    const arr = Array.isArray(info?.domains) ? info.domains : [];
    const set = new Set();
    for (const d of arr) {
      const dom = _stripWww(String(d || "").trim().toLowerCase());
      if (dom) set.add(dom);
    }
    tiers[tier] = { ...(info || {}), domains: Array.from(set) };
  }

  // display-only domains normalize (loadNaverWhitelist와 동일한 방향)
  try {
    const list = [];
    if (Array.isArray(json.display_only_domains)) list.push(...json.display_only_domains);
    if (json.display_only && Array.isArray(json.display_only.domains)) list.push(...json.display_only.domains);
    if (json.displayOnly && Array.isArray(json.displayOnly.domains)) list.push(...json.displayOnly.domains);

    const set = new Set();
    for (const d of list) {
      const dom = _stripWww(String(d || "").trim().toLowerCase());
      if (dom) set.add(dom);
    }
    json.display_only_domains = Array.from(set);
    json._display_only_set = new Set(json.display_only_domains);
  } catch (_) {}

  // lastUpdate 기본값 보정(없으면 "now")
  if (!json.lastUpdate) json.lastUpdate = new Date().toISOString();

  return json;
}

function __summarizeTierCounts(wl) {
  const tiers = {};
  let totalHosts = 0;
  const tObj = (wl?.tiers && typeof wl.tiers === "object") ? wl.tiers : {};
  for (const [k, v] of Object.entries(tObj)) {
    const n = Array.isArray(v?.domains) ? v.domains.length : 0;
    tiers[k] = n;
    totalHosts += n;
  }
  return { tiers, totalHosts };
}

function __diffWhitelist(oldWl, newWl) {
  const out = {
    changed: false,
    added: 0,
    removed: 0,
    perTier: {},
    old: __summarizeTierCounts(oldWl),
    next: __summarizeTierCounts(newWl),
  };

  const tiers = new Set([
    ...Object.keys(oldWl?.tiers || {}),
    ...Object.keys(newWl?.tiers || {}),
  ]);

  for (const t of tiers) {
    const a0 = new Set((oldWl?.tiers?.[t]?.domains || []).map((x) => _stripWww(String(x || "").toLowerCase())));
    const a1 = new Set((newWl?.tiers?.[t]?.domains || []).map((x) => _stripWww(String(x || "").toLowerCase())));

    let add = 0, rem = 0;
    for (const x of a1) if (x && !a0.has(x)) add++;
    for (const x of a0) if (x && !a1.has(x)) rem++;

    if (add || rem) out.changed = true;
    out.added += add;
    out.removed += rem;
    out.perTier[t] = { added: add, removed: rem };
  }

  return out;
}

function __isWhitelistMailConfigured() {
  // 1) Gmail OAuth2 mailer (sendAdminNotice) 경로: ADMIN_EMAIL or WL_NOTIFY_EMAIL_TO 필요
  const hasTo = !!(WL_NOTIFY_EMAIL_TO || process.env.ADMIN_EMAIL);
  const hasGmailMailer = !!(process.env.GMAIL_USER && process.env.GMAIL_CLIENT_ID && process.env.GMAIL_CLIENT_SECRET && process.env.GMAIL_REFRESH_TOKEN);
  if (hasTo && hasGmailMailer) return true;

  // 2) SMTP 직접 경로
  const hasSmtp = !!(SMTP_HOST && SMTP_USER && SMTP_PASS && (WL_NOTIFY_EMAIL_TO || process.env.ADMIN_EMAIL));
  return hasSmtp;
}

async function __sendWhitelistNoticeEmail(subject, html) {
  try {
    const to = WL_NOTIFY_EMAIL_TO || process.env.ADMIN_EMAIL;
    if (!to) return { ok: false, skipped: true, reason: "NO_TO" };

    const hasGmailCreds = !!(
      process.env.GMAIL_USER &&
      process.env.GMAIL_CLIENT_ID &&
      process.env.GMAIL_CLIENT_SECRET &&
      process.env.GMAIL_REFRESH_TOKEN
    );
    const hasSmtp = !!(SMTP_HOST && SMTP_USER && SMTP_PASS);

    // 1) prefer Gmail OAuth2 mailer if available
    if (hasGmailCreds) {
      const r = await sendAdminNotice(subject, html, to);

      // Gmail 성공이면 종료
      if (r?.ok) return r;

      // Gmail이 쿨다운/invalid_grant/실패면 SMTP가 있으면 즉시 폴백
      const needFallback =
        hasSmtp &&
        (
          r?.disabled === true ||
          r?.reason === "INVALID_GRANT_COOLDOWN" ||
          r?.reason === "MAIL_COOLDOWN" ||
          r?.reason === "MAIL_FAIL" ||
          r?.reason === "MAIL_NOT_CONFIGURED" ||
          r?.reason === "NO_TO"
        );

      if (!needFallback) return r;
      // else: continue to SMTP below
    }

    // 2) fallback: SMTP direct
    if (!hasSmtp) {
      return { ok: false, skipped: true, reason: "MAIL_NOT_CONFIGURED" };
    }

    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });

    const from = WL_NOTIFY_EMAIL_FROM || SMTP_USER;
    await transporter.sendMail({
      from,
      to,
      subject,
      html,
    });

    return { ok: true, via: "smtp_fallback" };
  } catch (e) {
    console.error("❌ WL mail fail:", e?.message || e);
    return { ok: false, reason: "WL_MAIL_FAIL", message: String(e?.message || e) };
  }
}

/**
 * ✅ whitelist auto-update (remote json → disk + in-memory override)
 * - 메일 실패해도 업데이트 자체는 성공/유지
 * - force=1이면 강제 fetch
 */
async function updateNaverWhitelistIfNeeded({ force = false, reason = "auto" } = {}) {
  const startedAt = new Date().toISOString();
  const now = Date.now();

  const result = {
    success: true,
    updated: false,
    changed: false,
    reason,
    startedAt,
    finishedAt: null,
    remote_url_set: !!NAVER_WHITELIST_SOURCE_URL,
    interval_hours: NAVER_WHITELIST_UPDATE_INTERVAL_HOURS,
    diff: null,
    message: null,
  };

  try {
    if (!NAVER_WHITELIST_SOURCE_URL) {
  result.success = false;
  result.message = "NAVER_WHITELIST_SOURCE_URL not set";
  result.finishedAt = new Date().toISOString();

  globalThis.__NAVER_WL_UPDATE_LAST = { ...result, ts: Date.now() };
  return result;
}

    // current whitelist
    let oldWl = null;
    try { oldWl = loadNaverWhitelist(); } catch (_) {}

    // decide whether to update (based on lastUpdate or file mtime)
    let should = !!force;

    if (!should) {
      // prefer wl.lastUpdate if parseable, else file mtime
      let baseMs = null;
      try {
        const lu = oldWl?.lastUpdate ? new Date(String(oldWl.lastUpdate).trim()).getTime() : NaN;
        if (Number.isFinite(lu)) baseMs = lu;
      } catch (_) {}

      if (!baseMs) {
        try {
          const st = fs.statSync(whitelistPath);
          baseMs = st?.mtimeMs || null;
        } catch (_) {}
      }

      if (!baseMs) {
        should = true; // no baseline → update
      } else {
        const elapsedH = (now - baseMs) / (1000 * 60 * 60);
        should = elapsedH >= NAVER_WHITELIST_UPDATE_INTERVAL_HOURS;
      }
    }

    if (!should) {
      result.message = "skip: not due";
      result.finishedAt = new Date().toISOString();
      globalThis.__NAVER_WL_UPDATE_LAST = { ...result, ts: Date.now() };
      return result;
    }

    // fetch remote
    const remote = await __fetchJsonWithTimeout(NAVER_WHITELIST_SOURCE_URL, 20_000);
    const newWl0 = __normalizeWhitelistJson(remote);

    // diff
    const diff = __diffWhitelist(oldWl, newWl0);
    result.diff = diff;
    result.changed = !!diff.changed;

    // write to disk (best-effort)
    try {
      fs.mkdirSync(path.dirname(whitelistPath), { recursive: true });
      fs.writeFileSync(whitelistPath, JSON.stringify(newWl0, null, 2), "utf-8");
    } catch (e) {
      // disk write가 실패해도 런타임 override로는 적용 가능
      console.error("❌ WL write file fail:", e?.message || e);
      result.message = `write_fail:${String(e?.message || e)}`;
    }

    // in-memory override (즉시 반영)
    globalThis.__NAVER_WL_OVERRIDE = newWl0;
    _NAVER_WL_CACHE = { mtimeMs: 0, json: null };

    result.updated = true;
    result.finishedAt = new Date().toISOString();

    // notify (changed only)
    if (result.changed && __isWhitelistMailConfigured()) {
      const subj = `✅ Naver whitelist updated (${newWl0?.version || "no-version"})`;
      const html =
        `<h3>Naver whitelist updated</h3>` +
        `<ul>` +
        `<li>Reason: ${String(reason)}</li>` +
        `<li>Version: ${String(newWl0?.version || "")}</li>` +
        `<li>LastUpdate: ${String(newWl0?.lastUpdate || "")}</li>` +
        `<li>Added: ${diff.added}, Removed: ${diff.removed}</li>` +
        `<li>TotalHosts: ${diff.next.totalHosts}</li>` +
        `</ul>` +
        `<pre style="white-space:pre-wrap">${JSON.stringify(diff.perTier, null, 2)}</pre>`;

      // ✅ 메일 실패해도 업데이트는 유지
      await __sendWhitelistNoticeEmail(subj, html);
    }

    globalThis.__NAVER_WL_UPDATE_LAST = { ...result, ts: Date.now() };
    return result;
  } catch (e) {
    result.success = false;
    result.message = String(e?.message || e);

    result.finishedAt = new Date().toISOString();
    globalThis.__NAVER_WL_UPDATE_LAST = { ...result, ts: Date.now() };
    console.error("❌ updateNaverWhitelistIfNeeded fail:", result.message);

    return result;
  }
}

globalThis.updateNaverWhitelistIfNeeded = updateNaverWhitelistIfNeeded;

// ✅ auto schedule (interval)
// - Node timer limit: max 2^31-1 ms (~24.8 days)
// - 그래서 "주기적 체크"만 돌리고, 실제 업데이트 주기는 updateNaverWhitelistIfNeeded 내부의
//   NAVER_WHITELIST_UPDATE_INTERVAL_HOURS 로 결정한다.
if (NAVER_WHITELIST_AUTO_UPDATE && NAVER_WHITELIST_SOURCE_URL) {
  try {
    const _MAX_TIMER_MS = 0x7fffffff; // 2147483647
    const CHECK_HOURS = Math.max(
      1,
      parseInt(process.env.NAVER_WHITELIST_SCHEDULE_CHECK_HOURS || "6", 10) || 6
    );
    const ms = Math.min(_MAX_TIMER_MS, Math.max(60_000, CHECK_HOURS * 60 * 60 * 1000));

    const t = setInterval(() => {
      updateNaverWhitelistIfNeeded({ force: false, reason: "interval" })
        .catch((e) => console.error("❌ WL interval update error:", e?.message || e));
    }, ms);

    if (t && typeof t.unref === "function") t.unref();

    setTimeout(() => {
      updateNaverWhitelistIfNeeded({ force: false, reason: "boot" })
        .catch((e) => console.error("❌ WL boot update error:", e?.message || e));
    }, 3000);
  } catch (e) {
    console.error("❌ WL schedule setup fail:", e?.message || e);
  }
}

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

// =======================================================
// ✅ E_eff (effective engines) helpers
// - Evidence pruning 이후의 blocksForVerify 기준으로 "유효 evidence가 1개 이상 남은 엔진"만 계산
// =======================================================
function __isEvidenceCountable(ev) {
  if (!ev) return false;

  if (ev._pruned || ev._excluded || ev._exclude || ev._irrelevant_pruned) return false;

  const u = ev.url ?? ev.link ?? ev.href ?? null;
  if (!u) return true;
  return true;
}

function __calcEngineEvidenceCounts(blocksForVerify) {
  const counts = Object.create(null);
  if (!Array.isArray(blocksForVerify)) return counts;

  for (const b of blocksForVerify) {
    const evidence = b?.evidence;
    if (!evidence || typeof evidence !== "object") continue;

    for (const [engine, items] of Object.entries(evidence)) {
      if (!Array.isArray(items)) continue;

      let c = 0;
      for (const ev of items) {
        if (__isEvidenceCountable(ev)) c += 1;
      }
      counts[engine] = (counts[engine] || 0) + c;
    }
  }
  return counts;
}

function __getEffectiveEngines(enginesRequested, counts) {
  const req = Array.isArray(enginesRequested) ? enginesRequested : [];
  const out = [];
  for (const e of req) {
    if ((counts?.[e] || 0) > 0) out.push(e);
  }
  return out;
}

function loadNaverWhitelist() {
  // ✅ whitelist override(원격 갱신 적용 시) 우선 사용
  if (globalThis.__NAVER_WL_OVERRIDE) return globalThis.__NAVER_WL_OVERRIDE;

  try {
    const st = fs.statSync(whitelistPath);
    if (_NAVER_WL_CACHE.json && _NAVER_WL_CACHE.mtimeMs === st.mtimeMs) return _NAVER_WL_CACHE.json;

    const raw = fs.readFileSync(whitelistPath, "utf-8");
    const json = JSON.parse(raw);

    if (!json?.tiers || typeof json.tiers !== "object") {
      throw new Error("naver_whitelist.json missing 'tiers'");
    }

    // ✅ NEW: display-only domains (show-only, not scoring evidence)
    // supports:
    //   - json.display_only_domains: ["namu.wiki", ...]
    //   - json.display_only.domains: [...]
    //   - json.displayOnly.domains: [...]
    try {
      const list = [];
      if (Array.isArray(json.display_only_domains)) list.push(...json.display_only_domains);
      if (json.display_only && Array.isArray(json.display_only.domains)) list.push(...json.display_only.domains);
      if (json.displayOnly && Array.isArray(json.displayOnly.domains)) list.push(...json.displayOnly.domains);

      const set = new Set();
      for (const d of list) {
        const dom = _stripWww(String(d || "").trim().toLowerCase());
        if (dom) set.add(dom);
      }

      json.display_only_domains = Array.from(set);
      // in-memory fast lookup
      json._display_only_set = new Set(json.display_only_domains);
    } catch (_) {}

    _NAVER_WL_CACHE = { mtimeMs: st.mtimeMs, json };
    return json;
  } catch (e) {
    if (DEBUG) console.warn("⚠️ whitelist load failed:", e.message);
    return null;
  }
}

// ✅ Naver whitelist meta (admin/diag)
function getNaverWhitelistMeta() {
  let wl = null;
  try { wl = loadNaverWhitelist(); } catch (_) {}

  let fileMtimeIso = null;
  let fileMtimeMs = null;
  try {
    const st = fs.statSync(whitelistPath);
    fileMtimeMs = st.mtimeMs;
    fileMtimeIso = new Date(st.mtimeMs).toISOString();
  } catch (_) {}

  const tiers = {};
  let totalHosts = 0;

  if (wl && typeof wl === "object") {
    const tObj = (wl.tiers && typeof wl.tiers === "object") ? wl.tiers : {};
    for (const [k, v] of Object.entries(tObj)) {
      const n = Array.isArray(v?.domains) ? v.domains.length : 0;
      tiers[k] = n;
      totalHosts += n;
    }
  }

  const hasKosis =
    !!wl &&
    Object.values(wl?.tiers || {}).some(
      (t) => Array.isArray(t?.domains) && t.domains.includes("kosis.kr")
    );

  // daysPassed 계산(가능할 때만)
  let daysPassed = null;
  try {
    const lu = wl?.lastUpdate ? String(wl.lastUpdate).trim() : "";
    if (lu) {
      const d = new Date(lu);
      if (!Number.isNaN(d.getTime())) {
        daysPassed = Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
        if (daysPassed < 0) daysPassed = 0;
      }
    }
  } catch (_) {}

  return {
    loaded: !!wl,
    version: wl?.version || null,
    lastUpdate: wl?.lastUpdate || null,
    daysPassed,
    totalHosts: Number.isFinite(totalHosts) ? totalHosts : null,
    tiers,
    hasKosis,
    file_mtime_ms: fileMtimeMs,
    file_mtime_iso: fileMtimeIso,
    env_version: process.env.NAVER_WHITELIST_VERSION || null,
  };
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

  if (!wl || !host) {
    return { tier: null, weight: 1, host, match_domain: null, bias_penalties: [] };
  }

  // ✅ NEW: display-only domains (show-only)
  try {
    const set =
      (wl._display_only_set instanceof Set)
        ? wl._display_only_set
        : new Set(Array.isArray(wl.display_only_domains) ? wl.display_only_domains : []);

    for (const d of set) {
      if (_hostMatchesDomain(host, d)) {
        return {
          tier: null,
          weight: 0.1,
          base_weight: 0.1,
          host,
          match_domain: d,
          bias_penalties: [],
          display_only: true,
        };
      }
    }
  } catch (_) {}

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

          const source_url = i.originallink || i.link; // ✅news는 originallink가 진짜 출처
const tierInfo = resolveNaverTier(source_url);
const typeWeight = NAVER_TYPE_WEIGHTS[ep.type] ?? 1;

const display_only = !!tierInfo.display_only;

// ✅(옵션) 화이트리스트가 없더라도 "공식 성격" 도메인이면...
let tier = tierInfo.tier;

let tier_weight =
  (typeof tierInfo.weight === "number" && Number.isFinite(tierInfo.weight))
    ? tierInfo.weight
    : 1;

let whitelisted = !!tier;
let inferred = false;

// ✅ display-only는 "표시만" (증거/스코어링은 아래 루프에서 제외 처리 예정)
if (display_only) {
  tier = null;
  whitelisted = false;
  inferred = false;
  tier_weight = NAVER_NON_WHITELIST_FACTOR;
} else {
  // ✅ 비화이트리스트 기본 감점(= 1.0 방지)
  if (!whitelisted) {
    tier_weight = NAVER_NON_WHITELIST_FACTOR;
  }

  // ✅ "공식처럼 보임"은 tier만 주고, whitelisted는 true로 두지 않음(유지)
  if (!tier && hostLooksOfficial(tierInfo.host)) {
    tier = "tier2"; // 표시용 티어
    tier_weight = NAVER_INFERRED_OFFICIAL_FACTOR;
    inferred = true;
  }
}

return {
  title: cleanTitle,
  desc: cleanDesc,
  link,
  source_url,
  origin: "naver",
  naver_type: ep.type,

  // ✅ whitelist/tier meta
  tier,
  tier_weight,
  type_weight: typeWeight,
  whitelisted,
  inferred,
  display_only,

  // ✅ news만 pubDate가 있음
  pubDate: ep.type === "news" ? (i.pubDate || null) : null,

  // ✅ domain 판정은 source_url(=originallink) 기준
  source_host: tierInfo.host || null,
  match_domain: tierInfo.match_domain || null,

  ...(inferred ? { _whitelist_inferred: true } : {}),
  ...(display_only ? { _whitelist_display_only: true } : {}),
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

  const qq0 = String(q || "").replace(/\s+/g, " ").trim();
  if (!qq0) return [];

  // ✅ 너무 짧은 쿼리는 노이즈/느림 대비 효용이 낮아서 기본 스킵 (env로 제어)
  const __minChars = (() => {
    const v = Number(process.env.GDELT_QUERY_MIN_CHARS ?? 18);
    const n = (Number.isFinite(v) && v >= 0) ? Math.floor(v) : 18;
    return n;
  })();
  if (__minChars > 0 && qq0.length < __minChars) return [];

  // ✅ env overrides (기본을 더 공격적으로)
  const __timeout = (() => {
    const v = Number(process.env.GDELT_TIMEOUT_MS ?? 4500);
    const t = (Number.isFinite(v) && v > 0) ? Math.floor(v) : 4500;
    // HTTP_TIMEOUT_MS보다 길게 잡지 않음(안전)
    return (typeof HTTP_TIMEOUT_MS === "number" && Number.isFinite(HTTP_TIMEOUT_MS))
      ? Math.min(t, Math.floor(HTTP_TIMEOUT_MS))
      : t;
  })();

  const __maxrecords = (() => {
    const v = Number(process.env.GDELT_MAXRECORDS ?? 1);
    let n = (Number.isFinite(v) && v > 0) ? Math.floor(v) : 1;
    if (n > 3) n = 3; // 과도 호출 방지
    return n;
  })();

  // ✅ query length cap (GDELT API 안정)
  const q120 = (qq0.length > 120) ? qq0.slice(0, 120).trim() : qq0;

  const { data } = await axios.get(
    `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q120)}&format=json&maxrecords=${__maxrecords}`,
    { timeout: __timeout, signal }
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

  const _isOverloaded = (e) => {
    const st = getStatus(e);
    const msg = _mergedErrMsg(e);
    return st === 503 || /model is overloaded|overloaded/i.test(msg);
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

    if (raMs == null) raMs = 15000; // fallback 15s (Gemini overload는 너무 길게 잡지 않음)
    return raMs;
  };

  const _throwOverloaded200 = (e, modelUsed) => {
    const st = getStatus(e);
    const raMs = _parseRetryAfterMs(e);

    const err = new Error("GEMINI_OVERLOADED");
    err.code = "GEMINI_OVERLOADED";
    err.httpStatus = 200;
    err.publicMessage =
      "Gemini 모델이 과부하(503) 상태라 검증을 수행할 수 없습니다. 잠시 후 다시 시도해 주세요.";
    err.detail = {
      status: st,
      model: modelUsed || model,
      retry_after_ms: raMs,
      last_error: _mergedErrMsg(e),
    };
    throw err;
  };

  const _maybeLiteModel = (m) => {
    const s = String(m || "").trim();
    if (!s) return "gemini-2.5-flash-lite";
    if (/flash-lite/i.test(s)) return s;
    if (/flash/i.test(s)) return "gemini-2.5-flash-lite";
    // flash 계열이 아니면 모델은 유지(다만 overload면 어차피 동일하게 터질 확률 큼)
    return s;
  };

  const _overloadRetries = Math.max(0, parseInt(process.env.GEMINI_OVERLOAD_RETRIES || "1", 10));
  const _overloadBaseSleepMs = Math.max(300, parseInt(process.env.GEMINI_OVERLOAD_SLEEP_MS || "900", 10));

  async function _tryOverloadRecover({ modelTry, gemini_key, labelSuffix }) {
    // 1) 같은 모델로 짧게 재시도
    for (let a = 0; a < _overloadRetries; a++) {
      await sleep(_overloadBaseSleepMs * (a + 1));
      try {
        return await fetchGeminiRaw({
          model: modelTry,
          gemini_key,
          payload,
          opts: { ...opts, label: `${label0}${labelSuffix}#retry${a + 1}` },
        });
      } catch (e2) {
        if (!_isOverloaded(e2)) throw e2; // overload가 아니면 그대로 위로
      }
    }

    // 2) flash → flash-lite 1회 폴백
    const lite = _maybeLiteModel(modelTry);
    if (lite && lite !== modelTry) {
      try {
        return await fetchGeminiRaw({
          model: lite,
          gemini_key,
          payload,
          opts: { ...opts, label: `${label0}${labelSuffix}#lite` },
        });
      } catch (e3) {
        if (_isOverloaded(e3)) _throwOverloaded200(e3, lite);
        throw e3;
      }
    }

    // 3) 그래도 overload면 200 코드로 종료
    _throwOverloaded200(new Error("GEMINI_OVERLOADED"), modelTry);
  }

  // 0) hint(body에서 온 keyHint) 1회 시도 -> 401/403/429면 keyring으로 fallback
  //    overload(503)면: 짧게 재시도 + flash-lite 폴백 후에도 실패하면 200코드 종료
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

      if (_isOverloaded(e)) {
        return await _tryOverloadRecover({ modelTry: model, gemini_key: hint, labelSuffix: "#hint" });
      }

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

      console.error("Gemini call failed:", `${label0}#${keyId}`, `status=${st}`, geminiErrMessage(e));

      // ✅ overload면: 키 소진/회전하지 말고 짧게 재시도 + lite 폴백
      if (_isOverloaded(e)) {
        try {
          return await _tryOverloadRecover({ modelTry: model, gemini_key: key, labelSuffix: `#${keyId}` });
        } catch (eOv) {
          // _tryOverloadRecover가 200 에러를 throw할 수 있음 → 그대로 전파
          throw eOv;
        }
      }

      if (st === 429) {
        const raMs = _parseRetryAfterMs(e);
        await markGeminiKeyRateLimitedById(userId, keyId, raMs);
        continue;
      }

            // ✅ 400 invalid key / 401 / 403 => exhausted(쿼터 소진) 금지. invalid_ids로 마킹 후 회전
      if (st === 401 || st === 403 || (st === 400 && _isInvalidKey(e)) || _isInvalidKey(e)) {
        const row = await loadUserSecretsRow(userId);
        let secrets = _ensureGeminiSecretsShape(row.secrets);
        await markGeminiKeyInvalid(
          userId,
          secrets,
          keyId,
          lastKctx?.pt_date ?? pt_date_now ?? null,
          { reason: "AUTH_OR_INVALID_KEY", status: st }
        );
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

  // ✅ 최종 에러가 overload면: 200코드 에러로 통일
  if (lastErr && _isOverloaded(lastErr)) {
    _throwOverloaded200(lastErr, model);
  }

  const _is429 =
  _lastStatus === 429 ||
  (_lastMsg && /status\s*=?\s*429|quota exceeded|rate limit|generate_content_free_tier_requests/i.test(_lastMsg));

const _isRateLimit =
  _is429 ||
  (lastErr && (lastErr.code === "GEMINI_RATE_LIMIT" || lastErr.message === "GEMINI_KEYRING_RATE_LIMITED"));

let _retryAfterMs = null;
if (lastErr) {
  try {
    _retryAfterMs =
      Number.isFinite(lastErr?.detail?.retry_after_ms) ? lastErr.detail.retry_after_ms : _parseRetryAfterMs(lastErr);
  } catch {}
}

err.code = _isRateLimit ? "GEMINI_RATE_LIMIT" : "GEMINI_KEY_EXHAUSTED";

    // (옵션) keyring 상태를 detail에 포함(디버깅/운영 가시성)
  let _kr_state = null;
  try {
    const rowS = await loadUserSecretsRow(userId);
    const secretsS = _ensureGeminiSecretsShape(rowS.secrets);
    _kr_state = secretsS?.gemini?.keyring?.state || null;
  } catch (_) {}

  const _exhausted_ids = _kr_state?.exhausted_ids || {};
  const _invalid_ids = _kr_state?.invalid_ids || {};
  const _rl_until = _kr_state?.rate_limited_until || {};
  const _nowMs = Date.now();

  const _rate_limited_active_ids = Object.entries(_rl_until)
    .filter(([, until]) => Number.isFinite(until) && until > _nowMs)
    .map(([id]) => id);

  err.detail = {
    keysCount: (_keysStoredCount ?? tried.size),
    keysTriedCount: tried.size,
    pt_date: pt_date_now,
    next_reset_utc: pac.next_reset_utc,
    last_error: _lastMsg,
    last_status: _lastStatus,
    retry_after_ms: _retryAfterMs,

    exhausted_count: Object.keys(_exhausted_ids).length,
    exhausted_ids: _exhausted_ids,

    invalid_count: Object.keys(_invalid_ids).length,
    invalid_ids: _invalid_ids,

    rate_limited_count: _rate_limited_active_ids.length,
    rate_limited_active_ids: _rate_limited_active_ids,
    rate_limited_until: _rl_until,
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
  //    - 401/403/429 뿐 아니라 5xx(특히 503 overload)도 rotating으로 fallthrough 허용
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

      const is5xx = typeof st === "number" && st >= 500;

      // 401/403/429/5xx만 fallback (그 외는 그대로 throw)
      if (st !== 401 && st !== 403 && st !== 429 && !is5xx) throw e;

      // fallthrough → rotating
      // (rotating의 hint overload-recover를 태우기 위해, keyHint가 비어있으면 directKey를 hint로 사용)
    }
  }

  // 2) 나머지는 keyHint(있으면 1순위) + keyring fallback 으로 rotating
  const hintForRotating = hintKey || directKey || null;

  return await fetchGeminiRotating({
    userId,
    keyHint: hintForRotating,
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
const NAVER_YEAR_MISS_PENALTY = Math.min(
  1.0,
  Math.max(0.0, parseFloat(process.env.NAVER_YEAR_MISS_PENALTY || "0.90"))
); // 0~1 (낮을수록 강한 패널티) / default 완화: 0.90
const NUMERIC_SOFT_WARNING_PENALTY = Math.min(
  1.0,
  Math.max(0.0, parseFloat(process.env.NUMERIC_SOFT_WARNING_PENALTY || "0.97"))
);
const NAVER_NUM_MATCH_BOOST = parseFloat(process.env.NAVER_NUM_MATCH_BOOST || "1.25"); // 숫자 매칭 보너스

function normalizeNumToken(s) {
  const raw = String(s || "").trim();
  if (!raw) return "";
  // keep digits and dot only (commas/spaces removed)
  const cleaned = raw.replace(/[,\s]/g, "").replace(/[^\d.]/g, "");
  if (!cleaned) return "";
  // collapse multiple dots into one sequence (e.g., "1.2.3" -> "1.23")
  const parts = cleaned.split(".");
  if (parts.length <= 1) return cleaned;
  return parts[0] + "." + parts.slice(1).join("");
}

// "수량성 숫자" 토큰만 (연도/1자리 제외, 콤마 포함 숫자 지원)
function extractQuantNumberTokens(text) {
  const s = String(text || "");
  if (!s) return [];
  const yearsSet = new Set(extractYearTokens(s).map((y) => String(y)));

  const rawTokens = [];
  const re = /\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b|\b\d+(?:\.\d+)?\b/g;

    for (const m of s.matchAll(re)) {
    const tok = m[0];
    const norm = normalizeNumToken(tok);
    if (!norm) continue;

    // 제외: 연도(예: 2025)
    if (yearsSet.has(norm)) continue;

    // 제외: 1자리 숫자(노이즈 많음)
    if (/^\d$/.test(norm)) continue;

    // 너무 긴 숫자 토큰 제외(오탐 방지)
    if (norm.length > 12) continue;

    // 기본 토큰
    rawTokens.push(tok);

    // ✅ 한국어 단위(만/억/조) 확장 토큰 추가
    // 예) "5,156만" -> tok="5,156", unit="만" => "51560000" 도 같이 넣음
    try {
      const idxAfter = (typeof m.index === "number" ? m.index : -1) + tok.length;
      const unit = idxAfter >= 0 ? s.slice(idxAfter, idxAfter + 1) : "";
      const baseNum = Number(norm);

      let mul = 0;
      if (unit === "만") mul = 1e4;
      else if (unit === "억") mul = 1e8;
      else if (unit === "조") mul = 1e12;

      if (mul > 0 && Number.isFinite(baseNum) && baseNum > 0) {
        const scaled = String(Math.round(baseNum * mul));
        // scaled도 토큰으로 추가(후단 dedupe/normalize에서 정리됨)
        rawTokens.push(scaled);
      }
    } catch (_e) {}
  }

  // normalize 기준 dedup
  const seen = new Set();
  const uniq = [];
  for (const t of rawTokens) {
    const n = normalizeNumToken(t);
    if (!n || seen.has(n)) continue;
    seen.add(n);
    uniq.push(t);
  }
  return uniq;
}

// ✅ 숫자/단위 감지 (숫자 발췌 패치용)
function hasNumberLike(text) {
  const s = String(text || "");
  if (!s) return false;

  // any Arabic digit
  if (/\d/.test(s)) return true;

  // common numeric markers / units (Korean + English)
  // - Korean: 퍼센트, 조/억/만/천/백, 명/건/대/원/달러/유로 등
  // - English: %, km, m/s, mph/kph, Hz-family, kg/g/mg, L/ml, °C/°F
  if (/(%|퍼센트|조|억|만|천|백|명|건|대|원|달러|유로|km\b|m\/s\b|mph\b|kph\b|ghz\b|mhz\b|khz\b|hz\b|kg\b|mg\b|g\b|l\b|ml\b|°c\b|°f\b)/i.test(s)) {
    return true;
  }

  return false;
}

function hasStrongNumberLike(text) {
  const t = String(text || "");
  if (!t) return false;

  // explicit year
  if (/\b(19\d{2}|20\d{2}|2100)\b/.test(t)) return true;

  // 1,234 / 12,345.67
  if (/\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b/.test(t)) return true;

  // 3+ digits or decimal
  if (/\b\d{3,}(?:\.\d+)?\b/.test(t)) return true;

  // percent
  if (/\b\d+(?:\.\d+)?\s*%/.test(t) || /\b\d+(?:\.\d+)?\s*퍼센트\b/.test(t)) return true;

  // Korean magnitude units with an explicit number (e.g., 1.2억, 300만)
  if (/\d+(?:\.\d+)?\s*(?:조|억|만|천|백)/.test(t)) return true;

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

function extractYearTokens(text) {
  const s = String(text || "");
  const years = new Set();
  const m = s.match(/\b(19\d{2}|20\d{2}|2100)\b/g);
  if (m) for (const y of m) years.add(y);
  return [...years];
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
  topK,
  minRelevance,
}) {
  const list = Array.isArray(items) ? items : [];
  const K = Number.isFinite(topK) && topK > 0 ? topK : 3;
  const minRel = Number.isFinite(minRelevance) ? minRelevance : 0.15;

  const needle = String(blockText || "").trim();
const yearTokens = extractYearTokens(needle);
const numTokens = extractQuantNumberTokens(needle); // years/1-digit 제외한 "수량성 숫자" 토큰
const numTokensCompact = numTokens.map(normalizeNumToken);

  const kw = extractKeywords([query, blockText, ...(naverQueries || [])].join(" "), 14);
  const needNum = hasNumberLike(blockText) || hasNumberLike(query);

  // tier1(core) 도메인 1개는 최소 포함되도록(가능하면)
  const wl = loadNaverWhitelist();
  const tier1Domains = Array.isArray(wl?.tiers?.tier1?.domains) ? wl.tiers.tier1.domains : [];

  const __getHostFromUrl = (u = "") => {
    try {
      return String(new URL(u).hostname || "").toLowerCase();
    } catch {
      return "";
    }
  };

  const __isCoreHost = (host = "") =>
    tier1Domains.some((d) => host.endsWith(String(d || "").toLowerCase()));

  const __hitCount = (haystack, keywords) => {
    const text = String(haystack || "").toLowerCase();
    const ks = Array.isArray(keywords) ? keywords : [];
    let hit = 0;
    for (const k of ks) {
      const kk = String(k || "").toLowerCase();
      if (!kk) continue;
      if (text.includes(kk)) hit++;
    }
    return hit;
  };

  const __minHits = (kwLen) => {
    if (!kwLen) return 1;
    if (kwLen <= 2) return 1;       // 키워드가 1~2개면 1개 히트 허용
    if (kwLen <= 4) return 2;       // 3~4개면 최소 2개 히트
    return Math.max(2, Math.ceil(kwLen * 0.25));
  };

  const scored = [];
  for (const it of list) {
    const urlCand = String(it?.source_url || it?.link || "").trim();
    if (!urlCand) continue;
    if (!isSafeExternalHttpUrl(urlCand)) continue;

    const text = `${it?.title || ""} ${it?.desc || ""}`.trim();

    // display-only는 evidence로 쓰지 않음
    const isDisplayOnly = (it?.display_only === true) || (it?._whitelist_display_only === true);
    if (isDisplayOnly) continue;

    // whitelist-only: 비화이트리스트는 제외
    const isWhitelisted = (it?.whitelisted === true) || !!it?.tier;
    if (!isWhitelisted) continue;

    // ✅ "한국" 1개만 맞아도 통과" 문제 해결: 최소 키워드 히트 수 요구
    const hits = __hitCount(text, kw);
    const needHits = __minHits(kw.length);
    if (hits < needHits) continue;

    const rel = kw.length ? hits / kw.length : 0;
    if (rel < minRel) continue;

    const isNews = it?.naver_type === "news";
    const hasAnyNum = hasNumberLike(text);
const textCompact = String(text || "").replace(/[,\s]/g, "");
const urlCompact = String(urlCand || "").replace(/[,\s]/g, "");

const hasYear = yearTokens.length
  ? yearTokens.some((y) => {
      const yy = String(y);
      return (
        text.includes(yy) ||
        textCompact.includes(yy) ||
        urlCand.includes(yy) ||
        urlCompact.includes(yy)
      );
    })
  : false;

const hasExactNum = numTokensCompact.length
  ? numTokensCompact.some((n) => {
      const nn = String(n || "");
      return nn && (textCompact.includes(nn) || urlCompact.includes(nn));
    })
  : false;

    // ✅ 숫자형 질문이면: "숫자/연도 단서 없는 뉴스"는 잡음으로 보고 제외
    if (isNews && needNum && !hasAnyNum && !hasYear && !hasExactNum) continue;

    let baseW =
      (typeof it?.tier_weight === "number" && Number.isFinite(it.tier_weight) ? it.tier_weight : 1) *
      (typeof it?.type_weight === "number" && Number.isFinite(it.type_weight) ? it.type_weight : 1);

    let bonus = 1.0;
    if (needNum) bonus *= hasAnyNum ? 1.15 : 0.85;
  // ✅ year soft flag (no hard drop) + tag for logging
// - NOTE: 여기(선정/스코어링)에서 __pen으로 감점하지 않는다 (중복 감점 방지)
// - 최종 TruthScore 감점은 Swap-in A/B(soft_penalty_factor → 1회 곱)에서만 수행
if (NAVER_STRICT_YEAR_MATCH && yearTokens.length) {
  if (hasYear) {
    bonus *= 1.10;
  } else {
    const __pen = Math.min(1.0, Math.max(0.0, Number(NAVER_YEAR_MISS_PENALTY) || 0.90));

    // "메타(제목/스니펫)" 기준 soft-year-miss 태깅
    // (이미 excerpt 단계에서 찍혔으면 덮어쓰지 않음)
    if (!it?._soft_year_miss) {
      it._soft_year_miss = true;
      it._soft_year_miss_years = yearTokens.slice(0, 6);
      it._soft_year_miss_penalty = __pen;
      it._soft_year_miss_where = "naver_item_meta";
    } else {
      // 기존 플래그는 유지하되 penalty가 없으면 채움
      if (
        !(typeof it._soft_year_miss_penalty === "number" && Number.isFinite(it._soft_year_miss_penalty))
      ) {
        it._soft_year_miss_penalty = __pen;
      }
      if (!it._soft_year_miss_where) it._soft_year_miss_where = "naver_item_meta";
    }
  }
}

    if (numTokens.length && hasExactNum) bonus *= NAVER_NUM_MATCH_BOOST;

    const hostRaw = String(it?.host || it?.source_host || "").toLowerCase();
    const host = hostRaw || __getHostFromUrl(urlCand);
    const isCore = !!(host && __isCoreHost(host));
    const hostBonus = isCore ? 1.12 : 1.0;

    const score = baseW * hostBonus * (0.6 + 0.4 * rel) * bonus;
    scored.push({ it, score, url: urlCand, isCore });
  }

  scored.sort((a, b) => b.score - a.score);

  // ✅ tier1(core) 도메인이 있으면 최소 1개는 포함시키기(가능할 때)
  const out = [];
  const seen = new Set();

  const corePick = scored.find((x) => x.isCore && x.it);
  if (corePick?.it) {
    out.push(corePick.it);
    if (corePick.url) seen.add(corePick.url);
  }

  for (const x of scored) {
    if (out.length >= K) break;
    const u = x.url || String(x?.it?.source_url || x?.it?.link || "");
    if (u && seen.has(u)) continue;
    out.push(x.it);
    if (u) seen.add(u);
  }

  return out.slice(0, K);
}

async function preprocessQVFVOneShot({
  mode,
  query,
  core_text,
  question,     // ✅ADD
  gemini_key,
  modelName,
  userId,
}) {
  // mode: "qv" | "fv"
  // QV: 답변 생성 + 답변 기준 블록/쿼리 생성
  // FV: core_text(사실문장) 기준 블록/쿼리 생성 (답변 생성 X)

const baseCore = (core_text || query || "").toString().trim();
const userIntentQ = String(question || "").trim();

 const prompt = `
너는 Cross-Verified AI의 "전처리 엔진"이다.
목표: (QV) 답변 생성 + 의미블록 분해 + 블록별 외부검증 엔진 쿼리 생성을 한 번에 수행한다.

[입력]
- mode: ${mode}                // "qv" | "fv"
- user_query: ${query}
- user_question_intent(있으면 최우선): ${userIntentQ ? userIntentQ : "(없음)"}
- core_text(FV에서만 사용): ${mode === "fv" ? baseCore : "(QV에서는 무시)"}

[절대 규칙 — 위반하면 실패]
1) 출력은 JSON 1개만. (설명/접두어/접미어/코드블록/마크다운/줄바꿈 코멘트 모두 금지)
2) JSON은 반드시 double quote(")만 사용하고, trailing comma 금지.
3) blocks는 반드시 1~${QVFV_MAX_BLOCKS}개.
4) block.text는 "검증 대상 텍스트"에서 문장을 그대로 복사해서 사용(의역/요약/새 주장 추가 금지).
5) naver 쿼리에는 '+'를 절대 포함하지 말 것.
6) user_question_intent가 있으면 다의어/중의성(예: 수도/은행/배터리/애플 등) 해소에 반드시 사용하고,
   반대 의미로 튀는 naver 쿼리는 만들지 말 것. (필요 시 수식어/괄호로 의미 고정)

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

    function __cleanAcademicQuery(s) {
  const raw = String(s || "")
    .replace(/[^\p{L}\p{N}\s]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();

  // 너무 짧으면 원문 유지
  if (raw.length < 8) return raw;

  // 간단 stopwords 제거(영문)
  const stop = new Set(["is","are","was","were","the","a","an","of","to","in","on","and","or","for","with","as","by","from"]);
  const toks = raw.split(" ").filter(w => {
    const lw = w.toLowerCase();
    if (stop.has(lw)) return false;
    return lw.length >= 2;
  });

  const out = toks.join(" ").trim();
  return out.length >= 8 ? out : raw;
}

    // ✅ engine query 기본값/길이제한 강제
    const crossrefQ = limitChars(__cleanAcademicQuery(eq.crossref || english_core), 90);
    const openalexQ = limitChars(__cleanAcademicQuery(eq.openalex || english_core), 90);
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

  const snippetRaw = String(b?.snippet ?? b?.snippet_text ?? b?.text ?? "").trim();
  const questionRaw = String(b?.question ?? b?.prompt ?? "").trim();

  const snippetId = b?.snippet_id ?? b?.snippetId ?? null;
  const snippetHash = b?.snippet_hash ?? b?.snippetHash ?? null;

  if (!snippetRaw) {
    return res.status(400).json(buildError("VALIDATION_ERROR", "snippet is required"));
  }

  // hard clip to match enforceVerifyPayloadLimits
  const clippedCore = snippetRaw.slice(0, VERIFY_MAX_CORE_TEXT_CHARS);

  // ✅ query/rawQuery는 snippet로 고정 (preprocess가 snippet 기반으로 돌도록)
  const clippedQuery = String(clippedCore).slice(0, VERIFY_MAX_QUERY_CHARS || 5000).trim();

  // drop raw snippet fields to avoid collisions
  const {
    snippet: __drop_snippet,
    snippet_text: __drop_snippet_text,
    text: __drop_text,
    question: __drop_question,
    prompt: __drop_prompt,
    snippet_id: __drop_snippet_id,
    snippetId: __drop_snippetId,
    snippet_hash: __drop_snippet_hash,
    snippetHash: __drop_snippetHash,
    ...rest
  } = b;

  const clippedUserAnswer = String(rest.user_answer ?? clippedCore)
    .slice(0, VERIFY_MAX_USER_ANSWER_CHARS);

  const snippetMeta = {
    is_snippet: true,
    input_snippet: snippetRaw,
    snippet_core: clippedCore,
    question: questionRaw || null,
    snippet_id: snippetId,
    snippet_hash: snippetHash,
  };

  req.body = {
    ...rest,

    // force FV
    mode: "fv",

    // FV core_text = snippet
    core_text: clippedCore,

    // keep/clip user_answer
    user_answer: clippedUserAnswer,

    // preserve original intent (but preprocess는 snippet 기반)
    rawQuery: clippedQuery,
    query: clippedQuery,

    // default model for snippet verify
    gemini_model: rest.gemini_model ?? "flash",

    // pass snippet meta
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

// =======================================================
// ✅ verify_raw URL scrubbers (prevent hallucinated URLs)
// =======================================================
function normalizeUrlKey(u) {
  const s0 = String(u || "").trim();
  if (!s0) return "";
  try {
    const x = new URL(s0);
    x.hash = ""; // fragment 제거
    let s = x.toString();

    // path가 "/"가 아닌데 끝이 "/"면 제거 (trailing slash 차이 흡수)
    try {
      if (s.endsWith("/") && x.pathname && x.pathname !== "/") s = s.slice(0, -1);
    } catch (_) {}

    return s;
  } catch (_) {
    // URL 파싱 실패면, 최소한 trailing slash만 흡수
    return s0.endsWith("/") ? s0.slice(0, -1) : s0;
  }
}

function collectExternalEvidenceUrls(external, opts) {
  const set = new Set();
  const ex = external && typeof external === "object" ? external : {};
  const o = (opts && typeof opts === "object") ? opts : {};
  const strictNaverWhitelist = !!o.strictNaverWhitelist;

  for (const k of Object.keys(ex)) {
    const key = String(k || "").trim().toLowerCase();
    const arr = Array.isArray(ex[k]) ? ex[k] : [];

    for (const it of arr) {
      // ✅ snippet에서는 "naver"만 whitelist URL만 allowlist에 넣는다
      if (strictNaverWhitelist && key === "naver") {
  const isWl =
    (it?.whitelisted === true) ||
    !!it?.tier ||
    (it?.display_only === true) ||
    (it?._whitelist_display_only === true);
  if (!isWl) continue;
}

      const u =
        it?.url ??
        it?.link ??
        it?.source_url ??
        it?.sourceUrl ??
        it?.pdf_url ??
        it?.html_url ??
        it?.homepage ??
        null;

      const raw = String(u || "").trim();
      if (!raw || !/^https?:\/\//i.test(raw)) continue;

      set.add(raw);
      const nkey = (typeof normalizeUrlKey === "function") ? normalizeUrlKey(raw) : null;
      if (nkey) set.add(nkey);
    }
  }
  return set;
}

function scrubUnknownUrlsInText(text, allowedUrls) {
  const t = String(text || "");
  if (!t) return t;
  if (!(allowedUrls instanceof Set) || allowedUrls.size === 0) return t;

  return t
    .replace(/https?:\/\/[^\s)"]+/gi, (u) => {
      const raw = String(u || "").trim();
      const key = normalizeUrlKey(raw);
      return (allowedUrls.has(raw) || (key && allowedUrls.has(key))) ? raw : "";
    })
    .replace(/\(\s*\)/g, "")
    .trim();
}

function scrubVerifyMetaUnknownUrls(verifyMeta, allowedUrls) {
  if (!verifyMeta || typeof verifyMeta !== "object") return;
  if (!(allowedUrls instanceof Set) || allowedUrls.size === 0) return;

  const blocks = Array.isArray(verifyMeta.blocks) ? verifyMeta.blocks : [];
  for (const b of blocks) {
    if (!b || typeof b !== "object") continue;

    // irrelevant_urls: allow-list only
    if (Array.isArray(b.irrelevant_urls)) {
      b.irrelevant_urls = b.irrelevant_urls
        .map(u => String(u || "").trim())
        .filter(u => {
  const key = normalizeUrlKey(u);
  return u && (allowedUrls.has(u) || (key && allowedUrls.has(key)));
});
    }

    // comment: strip unknown URLs
    if (typeof b.comment === "string") {
      b.comment = scrubUnknownUrlsInText(b.comment, allowedUrls);
    }
  }

  // overall.summary: strip unknown URLs
  if (verifyMeta.overall && typeof verifyMeta.overall === "object") {
    if (typeof verifyMeta.overall.summary === "string") {
      verifyMeta.overall.summary = scrubUnknownUrlsInText(verifyMeta.overall.summary, allowedUrls);
    }
  }
}

function normalizeEnginesRequested(engines_requested, engine_metrics) {
  const set = new Set(Array.isArray(engines_requested) ? engines_requested : []);
  const em = (engine_metrics && typeof engine_metrics === "object") ? engine_metrics : {};
  for (const [name, m] of Object.entries(em)) {
    const calls = Number(m?.calls ?? 0);
    if (calls > 0) set.add(String(name));
  }
  return Array.from(set);
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
  let verifyRawJson = ""; // ✅ NEW: payload.verify_raw로 내려줄 "정제된 JSON 문자열"
  let verifyRawJsonSanitized = ""; // ✅ NEW(S-19): evidence 정합화된 verify JSON
  let logUserId = null;   // ???붿껌留덈떎 ?낅┰
  let authUser = null;    // ???붿껌留덈떎 ?낅┰

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

  let safeMode = String(req.body?.mode ?? mode ?? "").trim().toLowerCase();
  const rawMode = safeMode; // ✅ 요청된 원래 mode를 보존(뒤에서 fallback plan에서 사용)

// ✅ /api/verify-snippet은 "FV 고정" + 라우터 개입 금지 (endpoint 기준)
// ✅ snippet_meta.is_snippet은 "입력 타입 메타"일 뿐, mode 강제에 쓰지 않는다.
const __isVerifySnippetPath = String(req.path || "") === "/api/verify-snippet";
const __isSnippetPayload = !!(snippet_meta && snippet_meta.is_snippet === true);

if (__isVerifySnippetPath) {
  safeMode = "fv";
}

// ✅ Groq Router(plan) - mode 자동분류 + 멀티 실행 계획
// - safeMode가 비었거나 auto/overlay 류일 때만 개입
// - qv+lv는 허용, qv+fv는 버림(필요없다고 했으니)
let __routerPlan = null;
let __runLvExtra = false;
let __routerCacheKey = null; // ✅ S-17: router plan cache key (separate from __cacheKey)
// ✅ helper: build router_plan for response (always reflect final safeMode)
function __buildRouterPlanPublicFinal({ safeMode, rawMode, routerPlan, runLvExtra }) {
  try {
    const __sf0 = String(safeMode || "qv").toLowerCase();
    const __sf =
      __sf0 === "auto" || __sf0 === "null" || __sf0 === "undefined" ? "qv" : __sf0;

    const __plan =
      Array.isArray(routerPlan?.plan) && routerPlan.plan.length > 0
        ? routerPlan.plan
        : [{ mode: __sf, priority: 1, reason: "router_missing_or_failed" }];

    const __runs =
      Array.isArray(routerPlan?.runs) && routerPlan.runs.length > 0
        ? routerPlan.runs.map((x) => String(x).toLowerCase()).filter(Boolean)
        : __plan.map((x) => String(x?.mode ?? x).toLowerCase()).filter(Boolean);

        return {
      enabled: !!GROQ_ROUTER_ENABLE,

      // ✅ "plan 객체 존재"가 아니라, 실제 라우터 실행/캐시히트 여부로 used 판단
      used: (typeof __routerUsed !== "undefined") ? !!__routerUsed : !!routerPlan,
      cached: (typeof __routerCached !== "undefined") ? !!__routerCached : null,

      // ✅ 요청된 raw mode도 같이 남김 (디버깅)
      raw_mode: String(rawMode ?? "").toLowerCase(),

      // ✅ always final safeMode (stale 방지)
      safe_mode_final: String(__sf).toLowerCase(),

      primary: String(
        routerPlan?.primary ??
          routerPlan?.mode ??
          routerPlan?.safe_mode_final ??
          __sf
      ).toLowerCase(),

      runs: (__runs.length > 0 ? __runs : [__sf]).slice(0, 5),

      plan: __plan.slice(0, 5).map((x) => ({
        mode: String(x?.mode ?? "").toLowerCase(),
        priority: Number.isFinite(Number(x?.priority)) ? Number(x.priority) : undefined,
      })),

      confidence:
        (routerPlan && typeof routerPlan.confidence === "number") ? routerPlan.confidence : null,

      reason: routerPlan?.reason ?? (__plan?.[0]?.reason ?? "router_missing_or_failed"),
      run_lv_extra: !!runLvExtra,

      // ✅ /api/verify-snippet 또는 snippet_meta.is_snippet 기반으로 판단
      is_snippet: (typeof __isSnippetEndpoint !== "undefined") ? !!__isSnippetEndpoint : null,

      cache_hit: (typeof __routerCached !== "undefined") ? !!__routerCached : null,

      model:
        routerPlan?.model ??
        (typeof GROQ_ROUTER_MODEL !== "undefined" ? GROQ_ROUTER_MODEL : null),

      lv_extra: !!(routerPlan?.lv_extra || runLvExtra),

      status: !GROQ_ROUTER_ENABLE
        ? "disabled"
        : (routerPlan ? (__plan.length > 0 ? "ok" : "ok_no_plan") : "missing_plan"),

      // ✅ router cache key(해시) 노출: 캐시 추적용 (민감정보 없음: 이미 sha16 기반)
      cache_key:
        (routerPlan && (routerPlan._cache_key || routerPlan.cache_key))
          ? String(routerPlan._cache_key || routerPlan.cache_key)
          : null,
    };
  } catch (_) {
    return null;
  }
}

let __routerCached = false;

// NOTE: __cacheKey는 이 핸들러의 "다른 캐시(응답/verify 캐시 등)"에서 계속 쓰이므로 유지
let __cacheKey = null;

// 환경변수로 라우터 전체 on/off 가능
const GROQ_ROUTER_ENABLE = String(process.env.GROQ_ROUTER_ENABLE || "1") !== "0";

// ✅ Groq Router in-memory cache (process-wide via globalThis)
// - Same input => skip Groq call
// - TTL + MAX size (LRU-ish via Map insertion order)
const GROQ_ROUTER_CACHE_ENABLE = String(process.env.GROQ_ROUTER_CACHE_ENABLE || "1") !== "0";
const GROQ_ROUTER_CACHE_TTL_MS = parseInt(process.env.GROQ_ROUTER_CACHE_TTL_MS || "300000", 10); // 5min
const GROQ_ROUTER_CACHE_MAX = parseInt(process.env.GROQ_ROUTER_CACHE_MAX || "500", 10);

const __ROUTER_CACHE =
  globalThis.__CVA_GROQ_ROUTER_CACHE ||
  (globalThis.__CVA_GROQ_ROUTER_CACHE = new Map());

function __routerCacheGet(k) {
  try {
    if (!GROQ_ROUTER_CACHE_ENABLE) return null;
    if (!k) return null;
    const hit = __ROUTER_CACHE.get(k);
    if (!hit) return null;
    const now = Date.now();
    if (hit.exp && hit.exp <= now) {
      __ROUTER_CACHE.delete(k);
      return null;
    }
    // refresh recency (LRU-ish)
    __ROUTER_CACHE.delete(k);
    __ROUTER_CACHE.set(k, hit);
    const v = hit.v ?? null;
if (!v || typeof v !== "object") return v;
// ✅ return a clone so later mutations won't poison the cache object
try {
  return (typeof structuredClone === "function")
    ? structuredClone(v)
    : JSON.parse(JSON.stringify(v));
} catch (_) {
  return { ...v };
}
  } catch (_) {
    return null;
  }
}

function __routerCacheSet(k, v) {
  try {
    if (!k) return;
    const now = Date.now();
    const exp = now + Math.max(1000, Number(GROQ_ROUTER_CACHE_TTL_MS) || 300000);
    __ROUTER_CACHE.set(k, { v, exp, t: now });

    // evict oldest
    const maxN = Math.max(50, Number(GROQ_ROUTER_CACHE_MAX) || 500);
    while (__ROUTER_CACHE.size > maxN) {
      const firstKey = __ROUTER_CACHE.keys().next().value;
      if (!firstKey) break;
      __ROUTER_CACHE.delete(firstKey);
    }
  } catch (_) {}
}

// ✅ helper: request -> user groq key
async function __getUserGroqKey(req) {
  // 로그인 토큰에서 userId 확보 (기존 헬퍼 재사용)
  let userId = null;
  try {
    const au = await getSupabaseAuthUser(req);
    userId = au?.id || null;
  } catch (_) {}

  // 네가 이미 추가한 함수 사용 (user_secrets 우선, env fallback optional)
  return await __getGroqApiKeyForUser({ supabase, userId });
}

// ✅ S-17: Groq Router execution (sets safeMode + __runLvExtra + __routerPlan, with in-memory plan cache)
let __routerUsed = false; // ✅ 실제 라우터 실행/캐시히트 여부
try {
  const _rawMode = String(safeMode || "").trim().toLowerCase();
  const __cacheMode =
  (_rawMode === "overlay" || _rawMode === "route") ? "auto" : _rawMode;

  const __isSn =
    (typeof __isSnippetEndpoint !== "undefined") ? !!__isSnippetEndpoint : false;

  const _shouldRoute =
    GROQ_ROUTER_ENABLE &&
    !__isSn &&
    (!safeMode || _rawMode === "auto" || _rawMode === "overlay" || _rawMode === "route");

  if (_shouldRoute) {
    // auth user (best-effort) — avoid ReferenceError when authUser is not in scope
    let __au = (typeof authUser !== "undefined" ? authUser : null) || null;
    if (!__au) {
      try { __au = await getSupabaseAuthUser(req); } catch (_) { __au = null; }
    }

    const __rq0 = String(req.body?.query ?? "").trim();
    const __rPath0 = String(req.path || "");

    // user hash (do not leak raw id)
    const __rUidRaw = String(__au?.id || (typeof logUserId !== "undefined" ? logUserId : null) || "anon");
    const __rUHash =
      (typeof hash16 === "function")
        ? hash16(__rUidRaw)
        : (typeof sha16 === "function")
          ? sha16(__rUidRaw)
          : __rUidRaw.slice(0, 16);

         const __rQHash =
      (typeof sha16 === "function")
        ? sha16(__rq0)
        : __rq0.slice(0, 64);
    
        const __rSn0 = String(req.body?.snippet ?? req.body?.core_text ?? req.body?.snippet_meta?.snippet_core ?? "").slice(0, 1800);
        const __rHasSn = __rSn0.trim().length >= 20 ? "1" : "0";
        const __rSnHash = (typeof sha16 === "function") ? sha16(__rSn0) : __rSn0.slice(0, 64);

        // ✅ router cache key (separate from other __cacheKey uses)
    // - include snippet presence/hash to avoid "fv cached" leaking into non-snippet requests
    __routerCacheKey =
  (typeof sha16 === "function")
    ? sha16(
        `router:v3|u=${__rUHash}|p=${__rPath0}|m=${__cacheMode}|hs=${__rHasSn}|s=${__rSnHash}|q=${__rQHash}`.slice(0, 4000)
      )
    : `router:v3|u=${__rUHash}|p=${__rPath0}|m=${__cacheMode}|hs=${__rHasSn}|s=${__rSnHash}|q=${__rQHash}`.slice(0, 4000);

    // cache hit?
    const __cachedPlan = __routerCacheGet(__routerCacheKey);
    if (__cachedPlan) {
  __routerPlan = __cachedPlan;
    try { if (__routerPlan && typeof __routerPlan === "object") __routerPlan._cache_key = __routerCacheKey; } catch (_) {}
  __routerCached = true;
  __routerUsed = true; // ✅ cache hit도 "used"
  try { if (__routerPlan && typeof __routerPlan === "object") __routerPlan.cached = true; } catch (_) {}
} else {
      // ✅ load user Groq key (Supabase vault) — 없으면 라우터 스킵하고 qv로 진행
      let __routerCacheable = false; // ✅ only cache when user has groq key and router actually ran
      const __groqKey = await __getUserGroqKey(req);

if (!__groqKey) {
  // 라우터는 "키 없는 사용자"에겐 실행하지 않음 (기본 qv)
  safeMode = "qv";
  __runLvExtra = false;

  __routerPlan = {
    raw_mode: _rawMode,
    safe_mode_final: "qv",
    primary: "qv",
    plan: [{ mode: "qv", priority: 1, reason: "router_skipped_no_user_groq_key" }],
    runs: ["qv"],
    cached: false,
    lv_extra: false,
  };

  __routerCacheable = false; // ✅ DO NOT cache this result
} else {
  __routerUsed = true; // ✅ 실제 라우터 호출 경로
  __routerCacheable = true;

  __routerPlan = await groqRoutePlan({
    authUser: __au,
    groq_api_key: __groqKey, // ✅ extra field: groqRoutePlan이 안 쓰면 무시됨
    query: __rq0,
    snippet: String(req.body?.snippet ?? req.body?.core_text ?? "").slice(0, 1800),
    question: String(req.body?.question ?? "").slice(0, 800),
    hintMode: (_rawMode === "auto" || _rawMode === "overlay" || _rawMode === "route") ? null : _rawMode,
  });
  try { if (__routerPlan && typeof __routerPlan === "object") __routerPlan._cache_key = __routerCacheKey; } catch (_) {}
}
      __routerCached = false;
try {
  if (__routerCacheable && __routerCacheKey && __routerPlan) {
    __routerCacheSet(__routerCacheKey, __routerPlan);
  }
} catch (_) {}
    }

       // plan 해석: primary 모드 + 추가 실행
const primaryRaw =
  String(
    __routerPlan?.primary ??
      __routerPlan?.mode ??
      (__routerPlan?.plan?.[0]?.mode ?? "qv")
  )
    .toLowerCase()
    .trim();

const runsRaw = Array.isArray(__routerPlan?.runs)
  ? __routerPlan.runs.map((x) => String(x).toLowerCase().trim()).filter(Boolean)
  : Array.isArray(__routerPlan?.plan)
    ? __routerPlan.plan
        .map((x) => String(x?.mode ?? x).toLowerCase().trim())
        .filter(Boolean)
    : [];

// ✅ FV top-level 게이트: "검증할 스니펫/클레임"이 있을 때만 fv 허용
const __snClaim0 = String(
  req.body?.snippet ??
  req.body?.core_text ??
  req.body?.snippet_meta?.snippet_core ??
  ""
).trim();
const __hasSnippetClaim = __snClaim0.length >= 20;

// ✅ top-level safeMode는 qv/fv만 허용 (lv는 extra로만)
let topPrimary = "qv";
if (primaryRaw === "fv" && __hasSnippetClaim) topPrimary = "fv";

// top-level mode 확정
safeMode = topPrimary;

// ─────────────────────────────
// ✅ LV extra 게이트(서버에서 보수적으로 차단)
// - auto에서 기본 lv로 튀는 리스크 방지
// - "법/조항/판례/처벌/소송/계약" 등 법률 신호 있을 때만 허용
function __looksLegalLike(s) {
  const t = String(s || "").trim();
  if (!t) return false;

  const reKo =
    /(민법|형법|형사|민사|행정법|상법|근로기준법|개인정보보호법|저작권법|상표법|특허법|부동산|임대차|상가임대차|소송|고소|고발|기소|항소|상고|판결|판례|대법원|헌재|헌법재판소|처벌|벌금|징역|과태료|손해배상|위자료|계약|해지|해제|위약금|조항|제\s*\d+\s*조|시행령|시행규칙|법률|법령)/i;

  const reEn =
    /\b(statute|case law|precedent|supreme court|criminal|civil|lawsuit|litigation|penalty|fine|imprisonment|contract|breach|termination)\b/i;

  return reKo.test(t) || reEn.test(t);
}

const __q0 = String(req.body?.query ?? query ?? "").trim();
const __qu0 = String(req.body?.question ?? "").trim();
const __sn0 = String(req.body?.snippet ?? req.body?.core_text ?? req.body?.snippet_meta?.snippet_core ?? "").trim();

// 법률 신호는 query/question/snippet 중 하나라도 잡히면 OK
const __legalSignal = __looksLegalLike(__q0) || __looksLegalLike(__qu0) || __looksLegalLike(__sn0);

// 라우터 confidence가 있으면 최소 기준 요구(없으면 “신호 기반”으로만)
const __conf0 =
  (typeof __routerPlan?.confidence === "number" && Number.isFinite(__routerPlan.confidence))
    ? __routerPlan.confidence
    : null;

const __lvAllowed = __legalSignal && (__conf0 === null || __conf0 >= 0.55);

// lv extra 조건: primary가 lv였거나, runs에 lv가 포함되어 있으면 ON
// 단, __lvAllowed를 통과해야만 ON
const wantLvExtraRaw = primaryRaw === "lv" || runsRaw.includes("lv");
const wantLvExtra = wantLvExtraRaw && __lvAllowed;
__runLvExtra = !!wantLvExtra;

// ✅ router plan도 "top-level lv"로 보이지 않도록 정규화 (diagnostics 안정화)
// - primary/safe_mode_final: qv or fv
// - plan/runs: [topPrimary] (+ lv extra면 lv를 뒤에 추가)
// - qv+fv 조합은 만들지 않음
try {
  if (__routerPlan && typeof __routerPlan === "object") {
    // fv를 원했는데 스니펫이 없어서 서버가 qv로 내린 경우 흔적 남김
    if (primaryRaw === "fv" && !__hasSnippetClaim) {
      __routerPlan.reason = (__routerPlan.reason || "") ? __routerPlan.reason : "server_downgrade_fv_no_snippet";
    }

    // lv를 원했는데 서버가 차단한 경우 흔적 남김
    if (wantLvExtraRaw && !__lvAllowed) {
      __routerPlan.reason = (__routerPlan.reason || "") ? __routerPlan.reason : "server_block_lv_not_legal";
    }

    __routerPlan.safe_mode_final = topPrimary;
    __routerPlan.primary = topPrimary;

    const _plan0 = [
      { mode: topPrimary, priority: 1, reason: "router_primary_top" },
    ];

    if (wantLvExtra) {
      _plan0.push({ mode: "lv", priority: 2, reason: "router_lv_extra_gated" });
      __routerPlan.lv_extra = true;
    } else {
      __routerPlan.lv_extra = false;
    }

    __routerPlan.plan = _plan0;
    __routerPlan.runs = _plan0.map((x) => x.mode);
  }
} catch (_) {}
  }
} catch (e) {
  // 라우터 실패해도 기존 흐름 유지 (qv/fv 강제/기본 로직으로 진행)
  __routerPlan = null;
  __runLvExtra = false;
  __routerCached = false;
} finally {
  __routerCacheKey = null;
}

  // ✅ S-17d: normalize + fallback router_plan (never keep "auto" in plan/runs/primary)
try {
  const __sf0 = String(safeMode || "qv").toLowerCase();
const __sf =
  (__sf0 === "auto" ||
   __sf0 === "overlay" ||
   __sf0 === "route" ||
   __sf0 === "null" ||
   __sf0 === "undefined")
    ? "qv"
    : __sf0;

  // 0) ✅ fallback: never leave __routerPlan null
  if (!__routerPlan) {
    __routerPlan = {
      raw_mode: String(rawMode || "auto").toLowerCase(),
      safe_mode_final: __sf,
      primary: __sf,
      plan: [{ mode: __sf, priority: 1, reason: "router_missing_or_failed" }],
      runs: [__sf],
      model: (typeof GROQ_ROUTER_MODEL !== "undefined" ? GROQ_ROUTER_MODEL : null),
      cached: false,
      lv_extra: false,
      error: "router_plan_was_null",
    };
  }

  // 1) primary / safe_mode_final normalize
  const _p0 = String(__routerPlan.primary ?? "").toLowerCase();
  if (_p0 === "auto" || !_p0) __routerPlan.primary = __sf;

  if (!__routerPlan.safe_mode_final) __routerPlan.safe_mode_final = __sf;
  if (String(__routerPlan.safe_mode_final).toLowerCase() === "auto") __routerPlan.safe_mode_final = __sf;

  // 2) plan normalize (auto/empty -> __sf), especially for missing/failed reasons
  if (!Array.isArray(__routerPlan.plan) || __routerPlan.plan.length === 0) {
    __routerPlan.plan = [{ mode: __sf, priority: 1, reason: "router_plan_empty" }];
  } else {
    const _r0 = __routerPlan.plan[0] || {};
    const _m0 = String(_r0?.mode ?? "").toLowerCase();
    const _reason0 = String(_r0?.reason ?? "").toLowerCase();

    if (
      (_m0 === "auto" || !_m0) &&
      (_reason0.includes("missing") || _reason0.includes("failed") || _reason0.includes("null"))
    ) {
      __routerPlan.plan = [{ ..._r0, mode: __sf }];
    } else if (_m0 === "auto" || !_m0) {
      // even if reason is absent, never keep auto/empty
      __routerPlan.plan = [{ ..._r0, mode: __sf }];
    }
  }

  // 3) runs normalize: always non-empty, no "auto"
  if (Array.isArray(__routerPlan.runs)) {
    const _runs = __routerPlan.runs.map(x => String(x).toLowerCase());
    const _runs2 = _runs.map(x => (x === "auto" ? __sf : x)).filter(Boolean);
    __routerPlan.runs = _runs2.length > 0 ? _runs2 : [__sf];
  } else if (Array.isArray(__routerPlan.plan)) {
    const _runs2 = __routerPlan.plan
      .map(x => String(x?.mode ?? x).toLowerCase())
      .map(x => (x === "auto" ? __sf : x))
      .filter(Boolean);
    __routerPlan.runs = _runs2.length > 0 ? _runs2 : [__sf];
  } else {
    __routerPlan.runs = [__sf];
  }
} catch (_) {}

// ✅ safety: 라우터 미사용/실패/빈값이면 기본 qv (auto/overlay/route 포함)
const __sm0 = String(safeMode || "").toLowerCase();
if (
  !__sm0 ||
  __sm0 === "auto" ||
  __sm0 === "overlay" ||
  __sm0 === "route" ||
  __sm0 === "null" ||
  __sm0 === "undefined"
) {
  safeMode = "qv";
}

// ✅ router diagnostics
// - router_plan은 “응답에 붙일 때” __buildRouterPlanPublicFinal(...)로만 생성/부착한다.
// - 여기서는 사전 계산/캐시를 만들지 않는다. (safeMode가 뒤에서 바뀔 수 있어 불일치 위험)

// ─────────────────────────────
// ✅ Groq Router (mode judge) — OpenAI-compatible endpoint
// - key: user_secrets(integrations.groq.api_key_enc) 우선, 없으면 env GROQ_API_KEY fallback(선택)
// - returns: { plan: [{mode:"qv"|"fv"|"lv", priority:int, reason:string}], confidence:0..1 }
// ─────────────────────────────
const GROQ_API_BASE = process.env.GROQ_API_BASE || "https://api.groq.com/openai/v1";
const GROQ_ROUTER_MODEL = process.env.GROQ_ROUTER_MODEL || "llama-3.3-70b-versatile";
const GROQ_ROUTER_TIMEOUT_MS = parseInt(process.env.GROQ_ROUTER_TIMEOUT_MS || "12000", 10);
const ENABLE_GROQ_ROUTER = GROQ_ROUTER_ENABLE; // alias: keep single source of truth

// (선택) env fallback 허용 여부
const GROQ_ALLOW_ENV_FALLBACK = String(process.env.GROQ_ALLOW_ENV_FALLBACK || "0") === "1";

function _safeJsonParse(s) {
  try { return JSON.parse(s); } catch { return null; }
}

function _normalizeRouterPlan(obj) {
  // 강제 형태 보정 + 안전장치(절대 lv가 primary가 되지 않게 / qv+fv 동시 방지)
  const out = {
    plan: [],
    runs: [],
    primary: "qv",
    confidence: null,
    reason: null,
    raw: obj ?? null,
  };

  const conf =
    (typeof obj?.confidence === "number" && Number.isFinite(obj.confidence))
      ? Math.max(0, Math.min(1, obj.confidence))
      : null;

  const topReason = String(obj?.reason ?? "").slice(0, 120) || null;

  // 입력 후보: plan 우선, 없으면 runs 배열도 허용
  const src = Array.isArray(obj?.plan) ? obj.plan : (Array.isArray(obj?.runs) ? obj.runs : []);
  const modes = new Set(["qv", "fv", "lv"]);
  const norm = [];

  for (const it of src) {
    const m = String(it?.mode ?? it?.m ?? it ?? "").trim().toLowerCase();
    if (!modes.has(m)) continue;

    const pr0 = (typeof it?.priority === "number" && Number.isFinite(it.priority)) ? it.priority : 1;
    const r0 = String(it?.reason ?? it?.why ?? "").slice(0, 180);

    norm.push({ mode: m, priority: pr0, reason: r0 });
  }

  // priority 정렬
  norm.sort((a, b) => (a.priority || 1) - (b.priority || 1));

  // 중복 제거(첫 등장 유지)
  const seen = new Set();
  let plan = norm.filter(x => (seen.has(x.mode) ? false : (seen.add(x.mode), true)));

  // plan 비면 안전 fallback
  if (!plan.length) {
    plan = [{ mode: "qv", priority: 1, reason: "fallback" }];
  }

  // ✅ qv+fv 동시 방지: 둘 다 있으면 priority가 더 낮은 것만 유지(동률이면 qv 우선)
  const hasQv = plan.some(x => x.mode === "qv");
  const hasFv = plan.some(x => x.mode === "fv");
  if (hasQv && hasFv) {
    const qv = plan.find(x => x.mode === "qv");
    const fv = plan.find(x => x.mode === "fv");
    const keep = (fv.priority < qv.priority) ? "fv" : "qv";
    plan = plan.filter(x => x.mode === keep || x.mode === "lv");
  }

  // ✅ lv가 1순위로 오면 절대 허용하지 않음: lv는 뒤로 내리고, primary는 qv/fv로 강제
  if (plan[0]?.mode === "lv") {
    const maxP = Math.max(...plan.map(x => Number(x.priority || 1)));
    plan = plan
      .filter(x => x.mode !== "lv")
      .concat([{ mode: "lv", priority: maxP + 1, reason: "demote_lv_primary" }]);
  }

  // runs/primary 구성
  out.plan = plan;
  out.runs = plan.map(x => x.mode);

  // primary는 qv/fv만
  const p0 = String(plan[0]?.mode || "qv").toLowerCase();
  out.primary = (p0 === "fv") ? "fv" : "qv";

  out.confidence = conf;
  out.reason = topReason;

  return out;
}

async function _getGroqApiKeyForUser(authUser) {
  // authUser 없으면 null
  if (!authUser?.id) return null;

  // ✅ 1) 단일 소스: user_secrets(integrations.groq.api_key_enc) 우선
  try {
    if (typeof __getGroqApiKeyForUser === "function") {
      const k1 = await __getGroqApiKeyForUser({ supabase, userId: authUser.id });
      const kk1 = String(k1 || "").trim();
      if (kk1) return kk1;
    }
  } catch (_) {}

  // ✅ 2) 레거시(있으면만): loadUserSecretsRow + decryptIntegrationsSecrets 방식도 fallback으로 유지
  try {
    if (typeof loadUserSecretsRow === "function" && typeof decryptIntegrationsSecrets === "function") {
      const row = await loadUserSecretsRow(authUser.id);
      const secrets = row?.secrets || {};
      const dec = decryptIntegrationsSecrets(secrets);
      const k2 = String(dec?.groq_key || dec?.groq_api_key || "").trim();
      if (k2) return k2;
    }
  } catch (_) {}

  // ✅ 3) (선택) env fallback
  try {
    if (typeof GROQ_ALLOW_ENV_FALLBACK !== "undefined" && GROQ_ALLOW_ENV_FALLBACK) {
      const envK = String(process.env.GROQ_API_KEY || process.env.GROQ_KEY || "").trim();
      if (envK) return envK;
    }
  } catch (_) {}

  return null;
}

async function groqRoutePlan({ authUser, groq_api_key, query, snippet, question, hintMode }) {
  if (!ENABLE_GROQ_ROUTER) {
    return { plan: [{ mode: (hintMode || "qv"), priority: 1, reason: "router_disabled" }], confidence: null, raw: null };
  }

    const apiKey = (groq_api_key && String(groq_api_key).trim().length >= 10)
    ? String(groq_api_key).trim()
    : await _getGroqApiKeyForUser(authUser);

  if (!apiKey) {
    return {
      plan: [{ mode: (hintMode || (String(snippet || "").trim() ? "fv" : "qv")), priority: 1, reason: "no_groq_key" }],
      confidence: null,
      raw: null,
      router_ms: 0,
      model: GROQ_ROUTER_MODEL,
    };
  }

    const q = String(query || "").trim();
  const sn = String(snippet || "").trim();
  const qu = String(question || "").trim();

  // ✅ FV는 “검증할 claim/snippet”이 있을 때만 의미가 있음 (너무 짧으면 질문일 확률 ↑)
  const __hasSnippetClaim = sn.length >= 20;

  // 라우터 입력 구성(너무 길면 잘라서 비용/지연 감소)
  const input = {
    query: q.slice(0, 1200),
    snippet: (__hasSnippetClaim ? sn : "").slice(0, 1800),
    question: qu.slice(0, 800),
    hint_mode: String(hintMode || "").trim().toLowerCase() || null,
    has_snippet_claim: __hasSnippetClaim,
    snippet_len: sn.length,
    policy: {
      allow_multi: true,
      prefer: "qv_or_fv",
      note: "Return JSON only.",
    },
  };

  const sys = [
  "You are a strict mode router for a fact-checking / verification system.",
  "Return ONLY valid JSON. No prose. No markdown. No code fences.",
  "",
  "Allowed modes: qv, fv, lv.",
  "Definitions:",
  "- qv: general fact questions / knowledge queries.",
  "- fv: verifying a provided factual sentence/snippet/AI answer (claim-check).",
  "- lv: explicit Korean legal/statute/case interpretation (조/항/호, 법령/시행령/시행규칙, 판례/대법원/헌재, specific law names, or asks for 조문/법적근거).",
  "",
  "STRICT RULES:",
  "- Default is qv.",
  "- Use fv ONLY when user supplies a snippet/claim to verify (not just a question).",
  "- Use lv ONLY when explicit legal/statute/case interpretation is requested.",
  "- NEVER output lv as the first (primary) plan item.",
  "  If legal is needed, output: [{mode:'qv',priority:1,...},{mode:'lv',priority:2,...}]",
  "- Do NOT output qv+fv together.",
  "- If unsure, output ONLY [{mode:'qv',priority:1,reason:'default_uncertain'}] and set confidence <= 0.60.",
  "- Keep reason short (<= 8 words).",
  "",
  "JSON schema:",
  '{"plan":[{"mode":"qv|fv|lv","priority":1,"reason":"short"}],"confidence":0.0,"reason":"short"}',
].join("\n");

  const user = JSON.stringify(input);
  const payload = {
    model: GROQ_ROUTER_MODEL,
    temperature: 0.0,
    messages: [
      { role: "system", content: sys },
      { role: "user", content: user },
    ],
    // Groq가 지원하면 JSON 강제(미지원이어도 무시될 수 있음)
    response_format: { type: "json_object" },
  };

  const t0 = Date.now();
  try {
    const resp = await axios.post(
      `${GROQ_API_BASE}/chat/completions`,
      payload,
      {
        timeout: GROQ_ROUTER_TIMEOUT_MS,
        headers: {
  Authorization: `Bearer ${apiKey}`,
  "Content-Type": "application/json",
  Accept: "application/json",
},
      }
    );

    const txt =
      resp?.data?.choices?.[0]?.message?.content ??
      resp?.data?.choices?.[0]?.text ??
      "";

    const parsed = _safeJsonParse(String(txt).trim()) || _safeJsonParse(String(txt).replace(/```json|```/g, "").trim()) || null;
    const norm = _normalizeRouterPlan(parsed || {});
    norm.router_ms = Date.now() - t0;
    norm.model = GROQ_ROUTER_MODEL;
        // ✅ 서버측 sanitize: 모델이 규칙을 어겨도 최종 plan을 보수적으로 고정
    try {
      const __hasSnippetClaim = String(sn || "").trim().length >= 20;

      let plan = Array.isArray(norm?.plan) ? norm.plan : [];
      plan = plan
        .map((x) => ({
          mode: String(x?.mode || "").toLowerCase().trim(),
          priority: Number.isFinite(Number(x?.priority)) ? Number(x.priority) : 1,
          reason: String(x?.reason || "").slice(0, 120),
        }))
        .filter((x) => x.mode === "qv" || x.mode === "fv" || x.mode === "lv");

      // 1) snippet claim 없으면 fv 제거
      if (!__hasSnippetClaim) plan = plan.filter((x) => x.mode !== "fv");

      // 2) qv+fv 동시 나오면 fv만 남김(단, claim 있을 때)
      const hasQv = plan.some((x) => x.mode === "qv");
      const hasFv = plan.some((x) => x.mode === "fv");
      if (hasQv && hasFv) {
        plan = plan.filter((x) => x.mode !== "qv");
      }

      // 3) lv가 첫 아이템이면 qv를 앞에 강제 삽입 (lv primary 금지)
      if (plan.length > 0 && plan[0].mode === "lv") {
        plan = [
          { mode: "qv", priority: 1, reason: "server_insert_qv" },
          ...plan.map((x, i) => ({ ...x, priority: i + 2 })),
        ];
      }

      // 4) plan 비면 qv fallback
      if (!plan.length) {
        plan = [{ mode: "qv", priority: 1, reason: "server_fallback" }];
      }

      norm.plan = plan;
      norm.primary = plan[0]?.mode || "qv";
      norm.runs = plan.map((x) => x.mode);
      if (!norm.reason) norm.reason = plan[0]?.reason || null;
      norm.has_snippet_claim = __hasSnippetClaim;
    } catch (_) {}
    return norm;
  } catch (e) {
    return {
      plan: [{ mode: (hintMode || (sn ? "fv" : "qv")), priority: 1, reason: `router_error:${String(e?.code || e?.message || "unknown").slice(0,60)}` }],
      confidence: null,
      raw: null,
      router_ms: Date.now() - t0,
      model: GROQ_ROUTER_MODEL,
    };
  }
}

// ✅ get Groq api key (user_secrets 우선, env fallback optional)
async function __getGroqApiKeyForUser({ supabase, userId }) {
  // 1) user_secrets.secrets.integrations.groq.api_key_enc 우선
  try {
    if (supabase && userId) {
      const { data, error } = await supabase
        .from("user_secrets")
        .select("secrets")
        .eq("user_id", userId)
        .maybeSingle();

      if (!error && data?.secrets?.integrations?.groq?.api_key_enc) {
        const enc = data.secrets.integrations.groq.api_key_enc;

        // 프로젝트 내 기존 복호화 함수 우선 사용(있으면 그걸로)
        let key = null;
        if (typeof decryptSecret === "function") key = await decryptSecret(enc);
        else if (typeof decryptUserSecret === "function") key = await decryptUserSecret(enc);
        else if (typeof decryptField === "function") key = await decryptField(enc);
        else if (typeof decryptAES === "function") key = await decryptAES(enc);

        if (key && String(key).trim()) return String(key).trim();
      }
    }
  } catch (_) {
    // fall through
  }

  // 2) env fallback (옵션)
  if (GROQ_ALLOW_ENV_FALLBACK) {
    const envKey = String(process.env.GROQ_API_KEY || "").trim();
    if (envKey) return envKey;
  }
  return null;
}

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
  const userCoreText = String(core_text || req.body?.snippet_meta?.snippet_core || "").trim();

  // 기본 검증
  if (!query) {
    return res
      .status(400)
      .json(buildError("VALIDATION_ERROR", "query가 누락되었습니다."));
  }

// ✅ allow auto/overlay/route: 아직 raw 값이면 (라우터 결과가 있으면 그걸 우선) 최종 top-level로 정규화
if (safeMode === "auto" || safeMode === "overlay" || safeMode === "route") {
  const __sf = String(__routerPlan?.safe_mode_final || "qv").toLowerCase();
  safeMode = (__sf === "fv") ? "fv" : "qv";
}

// ✅ /api/verify에서 lv 직접 호출 금지 (LV는 /api/lv 전용)
// - 라우터가 qv + lv_extra 형태로 추가실행하는 건 OK
try {
  const __path0 = String(req.path || "");
  if (__path0 === "/api/verify" && String(safeMode || "").toLowerCase() === "lv") {
    return res
      .status(400)
      .json(buildError("INVALID_MODE", "LV는 /api/lv 전용입니다. (/api/verify에서는 qv/fv/dv/cv만 허용)"));
  }
} catch (_) {}

// ✅ FV는 “검증할 스니펫/클레임”이 있을 때만 허용 (없으면 QV로 강제)
// - /api/verify-snippet은 이미 위에서 FV 고정이라 여기서 건드리지 않음
try {
  if (!__isVerifySnippetPath && String(safeMode || "").toLowerCase() === "fv") {
    const __snClaim = String(
      req.body?.snippet ??
      req.body?.core_text ??
      req.body?.snippet_meta?.snippet_core ??
      ""
    ).trim();

    const __hasSnippetClaim = __snClaim.length >= 20;
    if (!__hasSnippetClaim) {
      safeMode = "qv";
      // (선택) router plan이 있으면 진단용으로 같이 정리
      try {
        if (__routerPlan && typeof __routerPlan === "object") {
          __routerPlan.primary = "qv";
          __routerPlan.safe_mode_final = "qv";
          __routerPlan.plan = [{ mode: "qv", priority: 1, reason: "server_downgrade_fv_no_snippet" }];
          __routerPlan.runs = ["qv"];
          __routerPlan.lv_extra = !!(__routerPlan.lv_extra || __runLvExtra);
          __routerPlan.reason = __routerPlan.reason || "server_downgrade_fv_no_snippet";
        }
      } catch (_) {}
    }
  }
} catch (_) {}

const allowedModes = ["qv", "fv", "dv", "cv", "lv"];
if (!allowedModes.includes(safeMode)) {
  return res
    .status(400)
    .json(buildError("INVALID_MODE", `지원하지 않는 모드입니다: ${safeMode || mode || "(empty)"}`));
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
  // ✅ attach router diagnostics to partial_scores (avoid TDZ issues)
try {
  if (partial_scores && typeof partial_scores === "object") {
    partial_scores.router_plan = __buildRouterPlanPublicFinal({
      safeMode,
      rawMode,
      routerPlan: __routerPlan,
      runLvExtra: __runLvExtra,
    });
  }
} catch (_) {}

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
  const userQuestion = String(req?.body?.question || "").trim();

let pre = await preprocessQVFVOneShot({
  mode: safeMode,
  query,
  core_text: qvfvBaseText,
  question: userQuestion, // ✅ADD
  gemini_key,
  modelName: preprocessModel,
  userId: logUserId, // ✅ADD
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

// ✅ (NEW) block cap: snippet이면 더 공격적으로 제한해서 전체 runtime 줄이기
const __isSnippetVerify =
  !!(snippet_meta && typeof snippet_meta === "object" && snippet_meta.is_snippet);

const __maxBlocksNormal = (() => {
  const v = Number(process.env.QVFV_MAX_BLOCKS ?? process.env.QVFV_BLOCKS_MAX ?? 2);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : 2;
})();
const __maxBlocksSnippet = (() => {
  const v = Number(process.env.QVFV_SNIPPET_MAX_BLOCKS ?? 1);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : 1;
})();
const __maxBlocks = __isSnippetVerify ? __maxBlocksSnippet : __maxBlocksNormal;

try {
  if (qvfvPre && Array.isArray(qvfvPre.blocks)) {
    const beforeN = qvfvPre.blocks.length;
    if (beforeN > __maxBlocks) {
      qvfvPre.blocks = qvfvPre.blocks.slice(0, __maxBlocks);
    }
    if (partial_scores && typeof partial_scores === "object") {
      partial_scores.qvfv_blocks_capped = {
        before: beforeN,
        after: Array.isArray(qvfvPre.blocks) ? qvfvPre.blocks.length : 0,
        max: __maxBlocks,
        is_snippet: __isSnippetVerify,
      };
    }
  }
} catch (e) {
  try {
    if (partial_scores && typeof partial_scores === "object") {
      partial_scores.qvfv_blocks_capped = { error: true, message: e?.message || String(e) };
    }
  } catch {}
}

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

// ✅ Naver total call budget (요청 전체: 블록 합산)
// - ⚠️ __caps 초기화 전에 접근하면 TDZ 에러가 나므로, 여기서는 선언만 해두고
//   실제 초기화/로깅은 const __caps 선언 직후에 수행한다.
let __naverBudget = null;

// ✅ call caps + early-stop (QV/FV)
const __capNum = (v, d) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};

const __caps = {
  total: __capNum(process.env.ENGINE_CALL_CAP_TOTAL, 999),
  academic: __capNum(process.env.ENGINE_CALL_CAP_ACADEMIC, 999), // crossref+openalex 합
  gdelt: __capNum(process.env.ENGINE_CALL_CAP_GDELT, 999),
  naver: __capNum(process.env.ENGINE_CALL_CAP_NAVER, 999), // ✅ 요청 전체 naver query 호출 상한

  // ✅ Naver per-block cap (블록당 naver query cap)
  naver_per_block: __capNum(process.env.NAVER_QUERIES_PER_BLOCK_CAP, 2),
  naver_per_block_snippet: __capNum(process.env.NAVER_QUERIES_PER_BLOCK_CAP_SNIPPET, 1),

  // ✅ blocks cap (verify prompt size / runtime cap)
  blocks: __capNum(process.env.QVFV_BLOCKS_CAP, 4),
  blocks_snippet: __capNum(process.env.QVFV_BLOCKS_CAP_SNIPPET, 2),

  early_min_eeff: __capNum(process.env.EARLY_STOP_MIN_EEFF, 2),
  early_min_evidence: __capNum(process.env.EARLY_STOP_MIN_EVIDENCE, 6),
  early_require_strong:
    String(process.env.EARLY_STOP_REQUIRE_STRONG_OFFICIAL ?? "true").toLowerCase() !== "false",
};

// ✅ Naver total call budget (요청 전체: 블록 합산)
// - __caps.naver 는 "naver query 호출 수" 총 상한
__naverBudget =
  (Number.isFinite(__caps?.naver) ? Math.max(0, Math.trunc(__caps.naver)) : 999999);

try {
  if (partial_scores && typeof partial_scores === "object") {
    partial_scores.naver_budget_total_cap =
      Number.isFinite(__caps?.naver) ? Math.max(0, Math.trunc(__caps.naver)) : null;
    partial_scores.naver_budget_remaining = __naverBudget;
  }
} catch {}

const __capState = {
  calls_total: 0,
  calls_academic: 0,
  calls_gdelt: 0,
  calls_naver: 0,
  early_stop: false,
  early_stop_reason: null,
};

const __capConsume = (name) => {
  if (__capState.calls_total >= __caps.total) return false;

  if (name === "crossref" || name === "openalex") {
    if (__capState.calls_academic >= __caps.academic) return false;
    __capState.calls_total += 1;
    __capState.calls_academic += 1;
    return true;
  }

  if (name === "gdelt") {
    if (__capState.calls_gdelt >= __caps.gdelt) return false;
    __capState.calls_total += 1;
    __capState.calls_gdelt += 1;
    return true;
  }

  if (name === "naver") {
    if (__capState.calls_naver >= __caps.naver) return false;
    __capState.calls_total += 1;
    __capState.calls_naver += 1;
    return true;
  }

  __capState.calls_total += 1;
  return true;
};

const __hasStrongOfficialEvidence = (arr) => {
  try {
    if (!Array.isArray(arr) || arr.length === 0) return false;

    const isOfficialHost = (host) => {
      const h = String(host || "").toLowerCase();
      if (!h) return false;
      if (h.includes("kosis.kr")) return true;
      if (h.endsWith(".go.kr")) return true;
      if (typeof hostLooksOfficial === "function" && hostLooksOfficial(h)) return true;
      return false;
    };

    for (const x of arr) {
      if (typeof __isEvidenceLikeItem === "function" && !__isEvidenceLikeItem(x)) continue;

      const host = String(x?.source_host || x?.host || x?.domain || "").toLowerCase();
      const tw =
        (typeof x?.tier_weight === "number" && Number.isFinite(x.tier_weight))
          ? x.tier_weight
          : null;

      const tier = String(x?.tier || "").toLowerCase();
      const wl = (x?.whitelisted === true) || !!x?.tier;
      const inferred = x?.inferred === true;

      if (tw != null && tw >= 0.95) return true;
      if (tier === "tier1") return true;
      if (wl && !inferred && isOfficialHost(host)) return true;
      if (isOfficialHost(host)) return true;
    }
    return false;
  } catch (_) {
    return false;
  }
};

// ✅ early-stop helper (mid-block checkpoints)
const __sliceN = (a, n = 24) => (Array.isArray(a) ? a.slice(0, Math.max(0, Math.trunc(n))) : []);

const __tryEarlyStop = (where, packs = {}) => {
  try {
    if (__capState.early_stop) return true;

    const chk = __shouldEarlyStopApprox({
      cr: __sliceN(packs?.cr, 24),
      oa: __sliceN(packs?.oa, 24),
      wd: __sliceN(packs?.wd, 24),
      gd: __sliceN(packs?.gd, 24),
      nv: __sliceN(packs?.nv, 24),
    });

    if (chk && chk.ok) {
      __capState.early_stop = true;
      __capState.early_stop_reason = { where, ...chk };
      return true;
    }
    return false;
  } catch (_e) {
    return false;
  }
};

const runOrEmpty = async (name, fn, q) => {
  const qq = String(q || "").trim();
  if (!qq) return { result: [], ms: 0, skipped: true };
  return await safeFetchTimed(name, fn, qq, engineTimes, engineMetrics);
};

// ✅ 쿼리가 비면 호출하지 않고 result=[]로 처리 + cap 초과도 호출 안 함
// ✅ ACADEMIC(Crossref/OpenAlex) + GDELT: block마다 돌리지 말고 "요청당 1회"만(기본 on)
// - env: ACADEMIC_SINGLE_QUERY=false 로 끄면 기존처럼 block별 호출
// - env: GDELT_SINGLE_QUERY=false 로 끄면 기존처럼 block별 호출
const __academicSingle = String(process.env.ACADEMIC_SINGLE_QUERY ?? "true").toLowerCase() !== "false";
const __gdeltSingle = String(process.env.GDELT_SINGLE_QUERY ?? "true").toLowerCase() !== "false";

// "대표 엔진 쿼리"를 블록 0개여도 안정적으로 만든다
const __firstEq =
  (Array.isArray(qvfvPre?.blocks) && qvfvPre.blocks[0] && typeof qvfvPre.blocks[0] === "object")
    ? (qvfvPre.blocks[0].engine_queries || {})
    : {};

const academicBaseEn = String(qvfvPre?.english_core || qvfvBaseText || query || "").trim();

const crossrefGlobalQ = __academicSingle
  ? String(__firstEq.crossref || academicBaseEn || "").trim()
  : "";

const openalexGlobalQ = __academicSingle
  ? String(__firstEq.openalex || academicBaseEn || "").trim()
  : "";

const gdeltGlobalQ = __gdeltSingle
  ? String(__firstEq.gdelt || academicBaseEn || "").trim()
  : "";

// ✅ snippet request 여부를 먼저 확정 (GDELT 등 비용 큰 엔진 제어에 사용)
// - 기존 코드에 __isSnippetVerify가 있으면 그 값을 우선 사용(중복 플래그 방지)
const __isSnippetReq =
  (typeof __isSnippetVerify === "boolean")
    ? __isSnippetVerify
    : !!(snippet_meta && typeof snippet_meta === "object" && snippet_meta.is_snippet);

// ✅ 기본 정책: snippet 검증에서는 GDELT 호출을 끈다 (환경변수로만 허용)
const __gdeltDisableSnippet =
  String(process.env.GDELT_DISABLE_SNIPPET ?? "true").toLowerCase() !== "false";

let crossrefGlobalPack = { result: [], ms: 0, skipped: true };
let openalexGlobalPack = { result: [], ms: 0, skipped: true };
let gdeltGlobalPack = { result: [], ms: 0, skipped: true };

if (__academicSingle) {
  const qc = limitChars(crossrefGlobalQ, 90);
  const qo = limitChars(openalexGlobalQ, 90);

  if (String(qc || "").trim()) {
    try {
      if (__capConsume("crossref")) {
        crossrefGlobalPack = await safeFetchTimed("crossref", fetchCrossref, qc, engineTimes, engineMetrics);
        try { engineQueriesUsed.crossref.push(qc); } catch {}
      } else {
        crossrefGlobalPack = { result: [], ms: 0, skipped: true, reason: "cap" };
      }
    } catch (e) {
      crossrefGlobalPack = { result: [], ms: 0, skipped: true, reason: "error", error: String(e?.message || e) };
    }
  }

  if (String(qo || "").trim()) {
    try {
      if (__capConsume("openalex")) {
        openalexGlobalPack = await safeFetchTimed("openalex", fetchOpenAlex, qo, engineTimes, engineMetrics);
        try { engineQueriesUsed.openalex.push(qo); } catch {}
      } else {
        openalexGlobalPack = { result: [], ms: 0, skipped: true, reason: "cap" };
      }
    } catch (e) {
      openalexGlobalPack = { result: [], ms: 0, skipped: true, reason: "error", error: String(e?.message || e) };
    }
  }
}

let __gdeltGlobalFetched = false;

// ✅ strong official 충분하면 GDELT까지 갈 이유가 적음 (기본 ON, env로 OFF 가능)
const __gdeltDisableOnStrongOfficial =
  String(process.env.GDELT_DISABLE_ON_STRONG_OFFICIAL ?? "true").toLowerCase() !== "false";

const __ensureGdeltGlobal = async (why = "single", ctx = {}) => {
  if (!__gdeltSingle) return gdeltGlobalPack;
  if (__gdeltGlobalFetched) return gdeltGlobalPack;
  __gdeltGlobalFetched = true;

  // ✅ snippet 기본: GDELT 호출 스킵
  if (__isSnippetReq && __gdeltDisableSnippet) {
    gdeltGlobalPack = { result: [], ms: 0, skipped: true, reason: "snippet_disabled" };
    return gdeltGlobalPack;
  }

  // ✅ strong official evidence가 이미 있으면 스킵(선택)
  if (__gdeltDisableOnStrongOfficial) {
    try {
      const _candidates = [
        external?.naver,
        external?.wikidata,
        external?.crossref,
        external?.openalex,

        // ✅ "현재 블록에서 막 얻은 pack"도 같이 본다 (external에 merge되기 전이라도 감지)
        ctx?.nv,
        ctx?.wd,
        ctx?.cr,
        ctx?.oa,

        // ✅ academicSingle이면 globalPack.result도 참고(혹시 external merge 전이면)
        crossrefGlobalPack?.result,
        openalexGlobalPack?.result,
      ];

      let hasStrong = false;
      for (const arr of _candidates) {
        if (__hasStrongOfficialEvidence(arr)) { hasStrong = true; break; }
      }

      if (hasStrong) {
        gdeltGlobalPack = { result: [], ms: 0, skipped: true, reason: "strong_official_skip", why };
        return gdeltGlobalPack;
      }
    } catch {}
  }

  const qq = limitChars(gdeltGlobalQ, 120);
  if (!String(qq || "").trim()) {
    gdeltGlobalPack = { result: [], ms: 0, skipped: true, reason: "empty" };
    return gdeltGlobalPack;
  }

  try {
    if (__capConsume("gdelt")) {
      gdeltGlobalPack = await safeFetchTimed("gdelt", fetchGDELT, qq, engineTimes, engineMetrics);
      try { engineQueriesUsed.gdelt.push(qq); } catch {}
    } else {
      gdeltGlobalPack = { result: [], ms: 0, skipped: true, reason: "cap" };
    }
  } catch (e) {
    gdeltGlobalPack = { result: [], ms: 0, skipped: true, reason: "error", error: String(e?.message || e) };
  }

  return gdeltGlobalPack;
};

// ✅ single 모드여도 여기서 선호출하지 않음 (블록 진행 + early-stop 이후 필요할 때만 1회 호출)
if (__gdeltSingle) {
  // (옵션) 강제로 선호출하고 싶으면 env로만 켜기
  const __prefetch = String(process.env.GDELT_PREFETCH_SINGLE ?? "false").toLowerCase() === "true";
  if (__prefetch) {
    try { await __ensureGdeltGlobal("prefetch"); } catch {}
  }
}

const __maxBlocksInput = __isSnippetReq ? __caps.blocks_snippet : __caps.blocks;

const __blocksInput = Array.isArray(qvfvPre.blocks)
  ? qvfvPre.blocks.slice(0, Math.max(1, Math.trunc(__maxBlocksInput)))
  : [];

try {
  partial_scores.qvfv_block_cap = {
    is_snippet: __isSnippetReq,
    cap: Math.max(1, Math.trunc(__maxBlocksInput)),
    original: Array.isArray(qvfvPre.blocks) ? qvfvPre.blocks.length : 0,
    used: __blocksInput.length,
    truncated: Array.isArray(qvfvPre.blocks) ? (qvfvPre.blocks.length > __blocksInput.length) : false,
  };
} catch {}

for (const b of __blocksInput) {
  if (__capState.early_stop) break;

  const eq = b.engine_queries || {};

  const qCrossref = __academicSingle ? String(crossrefGlobalQ || "").trim() : String(eq.crossref || "").trim();
  const qOpenalex = __academicSingle ? String(openalexGlobalQ || "").trim() : String(eq.openalex || "").trim();
  const qWikidata = String(eq.wikidata || "").trim();
  const qGdelt = __gdeltSingle ? String(gdeltGlobalQ || "").trim() : String(eq.gdelt || "").trim();

  // ✅ 엔진별 쿼리 기록은 "실제 호출(cap 통과)" 시점에만 push 한다.
// (여기서는 push 하지 않음)

  // ✅ 핵심: crPack/oaPack/wdPack/gdPack "항상 정의" (ReferenceError 방지)
  // - academicSingle / gdeltSingle 이면 globalPack을 재사용
  // - 아니면 per-block로 호출하되, cap/empty/snip-disable 모두 안전 처리
  let crPack = { result: [], ms: 0, skipped: true };
  let oaPack = { result: [], ms: 0, skipped: true };
  let wdPack = { result: [], ms: 0, skipped: true };
  let gdPack = { result: [], ms: 0, skipped: true };

  // crossref/openalex
  if (__academicSingle) {
    crPack = crossrefGlobalPack || crPack;
    oaPack = openalexGlobalPack || oaPack;
  } else {
    if (String(qCrossref || "").trim()) {
  try {
    if (__capConsume("crossref")) {
      crPack = await safeFetchTimed("crossref", fetchCrossref, qCrossref, engineTimes, engineMetrics);
      try { engineQueriesUsed.crossref.push(qCrossref); } catch {}
    } else {
      crPack = { result: [], ms: 0, skipped: true, reason: "cap" };
    }
  } catch (e) {
    crPack = { result: [], ms: 0, skipped: true, reason: "error", error: String(e?.message || e) };
  }
}

    if (String(qOpenalex || "").trim()) {
  try {
    if (__capConsume("openalex")) {
      oaPack = await safeFetchTimed("openalex", fetchOpenAlex, qOpenalex, engineTimes, engineMetrics);
      try { engineQueriesUsed.openalex.push(qOpenalex); } catch {}
    } else {
      oaPack = { result: [], ms: 0, skipped: true, reason: "cap" };
    }
  } catch (e) {
    oaPack = { result: [], ms: 0, skipped: true, reason: "error", error: String(e?.message || e) };
  }
}
  }

    // wikidata (per-block) - ✅ early-stop checkpoint(academic 이후)
  try {
    __tryEarlyStop("mid_block_after_academic", {
      cr: [
        ...__sliceN((external && Array.isArray(external.crossref)) ? external.crossref : [], 12),
        ...__sliceN((crPack && Array.isArray(crPack.result)) ? crPack.result : [], 12),
      ],
      oa: [
        ...__sliceN((external && Array.isArray(external.openalex)) ? external.openalex : [], 12),
        ...__sliceN((oaPack && Array.isArray(oaPack.result)) ? oaPack.result : [], 12),
      ],
      wd: __sliceN((external && Array.isArray(external.wikidata)) ? external.wikidata : [], 24),
      gd: __sliceN((external && Array.isArray(external.gdelt)) ? external.gdelt : [], 24),
      nv: __sliceN((external && Array.isArray(external.naver)) ? external.naver : [], 24),
    });
  } catch {}

  if (__capState.early_stop) {
    wdPack = { result: [], ms: 0, skipped: true, reason: "early_stop" };
  } else if (String(qWikidata || "").trim()) {
    try {
      if (__capConsume("wikidata")) {
        wdPack = await safeFetchTimed("wikidata", fetchWikidata, qWikidata, engineTimes, engineMetrics);
        try { engineQueriesUsed.wikidata.push(qWikidata); } catch {}
      } else {
        wdPack = { result: [], ms: 0, skipped: true, reason: "cap" };
      }
    } catch (e) {
      wdPack = { result: [], ms: 0, skipped: true, reason: "error", error: String(e?.message || e) };
    }
  }

  // ✅ checkpoint: wikidata 이후(= gdelt/naver 스킵 판단)
  try {
    __tryEarlyStop("mid_block_after_wikidata", {
      cr: [
        ...__sliceN((external && Array.isArray(external.crossref)) ? external.crossref : [], 12),
        ...__sliceN((crPack && Array.isArray(crPack.result)) ? crPack.result : [], 12),
      ],
      oa: [
        ...__sliceN((external && Array.isArray(external.openalex)) ? external.openalex : [], 12),
        ...__sliceN((oaPack && Array.isArray(oaPack.result)) ? oaPack.result : [], 12),
      ],
      wd: [
        ...__sliceN((external && Array.isArray(external.wikidata)) ? external.wikidata : [], 12),
        ...__sliceN((wdPack && Array.isArray(wdPack.result)) ? wdPack.result : [], 12),
      ],
      gd: __sliceN((external && Array.isArray(external.gdelt)) ? external.gdelt : [], 24),
      nv: __sliceN((external && Array.isArray(external.naver)) ? external.naver : [], 24),
    });
  } catch {}

    // gdelt - ✅ early-stop이면 스킵
  if (__capState.early_stop) {
    gdPack = { result: [], ms: 0, skipped: true, reason: "early_stop" };
  } else if (__gdeltSingle) {
  gdPack = (await __ensureGdeltGlobal("single", {
  cr: (crPack && Array.isArray(crPack.result)) ? crPack.result : [],
  oa: (oaPack && Array.isArray(oaPack.result)) ? oaPack.result : [],
  wd: (wdPack && Array.isArray(wdPack.result)) ? wdPack.result : [],
  nv: (external && Array.isArray(external.naver)) ? external.naver : [],
})) || gdPack;
} else {
    // ✅ snippet 기본: GDELT 호출 스킵 (global과 동일 정책)
    if (__isSnippetReq && __gdeltDisableSnippet) {
      gdPack = { result: [], ms: 0, skipped: true, reason: "snippet_disabled" };
    } else if (String(qGdelt || "").trim()) {
      try {
        if (__capConsume("gdelt")) {
          gdPack = await safeFetchTimed("gdelt", fetchGDELT, qGdelt, engineTimes, engineMetrics);
          try { engineQueriesUsed.gdelt.push(qGdelt); } catch {}
        } else {
          gdPack = { result: [], ms: 0, skipped: true, reason: "cap" };
        }
      } catch (e) {
        gdPack = { result: [], ms: 0, skipped: true, reason: "error", error: String(e?.message || e) };
      }
    }
  }

  // ✅ checkpoint: gdelt 이후(= naver 스킵 판단)
  try {
    __tryEarlyStop("mid_block_after_gdelt", {
      cr: [
        ...__sliceN((external && Array.isArray(external.crossref)) ? external.crossref : [], 12),
        ...__sliceN((crPack && Array.isArray(crPack.result)) ? crPack.result : [], 12),
      ],
      oa: [
        ...__sliceN((external && Array.isArray(external.openalex)) ? external.openalex : [], 12),
        ...__sliceN((oaPack && Array.isArray(oaPack.result)) ? oaPack.result : [], 12),
      ],
      wd: [
        ...__sliceN((external && Array.isArray(external.wikidata)) ? external.wikidata : [], 12),
        ...__sliceN((wdPack && Array.isArray(wdPack.result)) ? wdPack.result : [], 12),
      ],
      gd: [
        ...__sliceN((external && Array.isArray(external.gdelt)) ? external.gdelt : [], 12),
        ...__sliceN((gdPack && Array.isArray(gdPack.result)) ? gdPack.result : [], 12),
      ],
      nv: __sliceN((external && Array.isArray(external.naver)) ? external.naver : [], 24),
    });
  } catch {}

  let naverQueriesBase = Array.isArray(eq.naver) ? eq.naver : [];
  naverQueriesBase = naverQueriesBase
    .map((q) => limitChars(buildNaverAndQuery(q), 30))
    .filter(Boolean)
    .slice(0, BLOCK_NAVER_MAX_QUERIES);

  // ✅ 혹시 여기까지 왔는데도 비면, 최소 1개는 생성해서 Naver 호출이 끊기지 않게
  if (!naverQueriesBase.length) {
    const seed = String(b?.text || "").trim() || qvfvPre?.korean_core || qvfvBaseText || query;
    naverQueriesBase = fallbackNaverQueryFromText(seed).slice(0, BLOCK_NAVER_MAX_QUERIES);
  }

  // ✅ qvfvPre에서 korean_core / english_core를 안전하게 꺼냄
  const qvfvKoreanCore = String(qvfvPre?.korean_core ?? "").trim();
  const qvfvEnglishCore = String(qvfvPre?.english_core ?? "").trim();

  // ✅ Naver용 확장 쿼리: 여기서 한 번만 계산 → "블록당 cap" 적용
  const naverQueriesExpandedAll = __expandNaverQueries(naverQueriesBase, {
    korean_core: qvfvKoreanCore,
    english_core: qvfvEnglishCore,
  });

  const __naverPerBlockCap =
    (__isSnippetReq ? __caps.naver_per_block_snippet : __caps.naver_per_block);

  let naverQueriesExpanded = Array.isArray(naverQueriesExpandedAll)
    ? naverQueriesExpandedAll.map((q) => String(q || "").trim()).filter(Boolean)
    : [];

  naverQueriesExpanded = naverQueriesExpanded.slice(0, Math.max(1, Math.trunc(__naverPerBlockCap)));

  // ✅ 아래 Naver 루프에서 naverQueries 변수를 쓰고 있으니, 여기서 확정해준다(ReferenceError 방지)
  const naverQueries = naverQueriesExpanded;

  // ─────────────────────────────
  // ✅ Naver 결과: 표시용(all)과 verify용(topK + whitelist + relevance) 분리
  // - 블록당 쿼리 cap + 요청 전체 budget(__naverBudget) 적용
  // ─────────────────────────────
  let naverItemsAll = [];

  // ✅ (FIX) request-level Naver call budget (logging) + __capConsume("naver") enforcement
  // - source of truth: __capState.calls_naver / __caps.naver
    let __naverBudgetLog = null;
  try {
    if (partial_scores && typeof partial_scores === "object") {
      if (!partial_scores.__naver_call_budget || typeof partial_scores.__naver_call_budget !== "object") {
        partial_scores.__naver_call_budget = {};
      }

      const b = partial_scores.__naver_call_budget;

      // per-request static fields
      b.is_snippet = __isSnippetReq;
      b.max = (Number.isFinite(__caps?.naver) ? Math.max(0, Math.trunc(__caps.naver)) : 999999);

      const usedNow = Number(__capState?.calls_naver || 0);
      const maxNow = Number(b.max || 0);

      // per-block snapshots (reset each block)
      b.used_before_block = usedNow;
      b.left_before_block = Math.max(0, maxNow - usedNow);
      b.used_last_block = 0;

      // ✅ 항상 "현재 used/left"를 채워둔다 (이 블록에서 0회 호출/early-stop이어도 undefined 방지)
      b.used = usedNow;
      b.left = Math.max(0, maxNow - usedNow);
      b.applied = true;

      __naverBudgetLog = b;
    }
  } catch {}

    // ✅ 실제 Naver 호출에 사용할 쿼리 리스트: naverQueries(블록당 cap 적용된 상태)
  if (__capState.early_stop) {
    try {
      if (partial_scores && typeof partial_scores === "object") {
        partial_scores.naver_skipped_by_early_stop = true;
      }
    } catch {}
  } else {
    for (const nq0 of naverQueries) {
      const nq = String(nq0 || "").trim();
      if (!nq) continue;

      // ✅ 요청 전체 cap / naver cap 모두 여기서 같이 enforcement
      if (!__capConsume("naver")) break;

      // ✅ 엔진별 쿼리 기록(호출한 것만)
      try { engineQueriesUsed.naver.push(nq); } catch {}

      // ✅ budget log update
      try {
        if (__naverBudgetLog && typeof __naverBudgetLog === "object") {
          __naverBudgetLog.used_last_block = Number(__naverBudgetLog.used_last_block || 0) + 1;

          const usedNow = Number(__capState?.calls_naver || 0);
          __naverBudgetLog.used = usedNow;
          __naverBudgetLog.left = Math.max(0, Number(__naverBudgetLog.max || 0) - usedNow);
        }
      } catch {}

      const { result } = await safeFetchTimed(
        "naver",
        (qq, ctx) => callNaver(qq, naverIdFinal, naverSecretFinal, ctx),
        nq,
        engineTimes,
        engineMetrics
      );
      if (Array.isArray(result) && result.length) naverItemsAll.push(...result);
    }
  }

    // ✅ budget snapshot after this block
  try {
    if (__naverBudgetLog && typeof __naverBudgetLog === "object") {
      const usedNow = Number(__capState?.calls_naver || 0);
      const maxNow = Number(__naverBudgetLog.max || 0);

      __naverBudgetLog.used_after_block = usedNow;
      __naverBudgetLog.left_after_block = Math.max(0, maxNow - usedNow);

      // ✅ current 값도 after snapshot으로 동기화 (최종 표시/호환 필드 안정화)
      __naverBudgetLog.used = usedNow;
      __naverBudgetLog.left = Math.max(0, maxNow - usedNow);
    }
  } catch {}

  naverItemsAll = dedupeByLink(naverItemsAll).slice(0, BLOCK_NAVER_MAX_ITEMS);

  try {
    if (partial_scores && typeof partial_scores === "object") {
      // ✅ 블록당 Naver 쿼리 cap + 실제 사용 쿼리 기록
      partial_scores.naver_queries_cap = {
        per_block_cap: Math.max(1, Math.trunc(__naverPerBlockCap)),
        used_queries: Array.isArray(naverQueries) ? naverQueries.slice(0, 12) : [],
        used_queries_count: Array.isArray(naverQueries) ? naverQueries.length : 0,
      };

      // ✅ request-level Naver call budget(블록/요청 전체) 스냅샷
      const __b = partial_scores.__naver_call_budget;
      if (__b && typeof __b === "object") {
        partial_scores.naver_call_budget = {
          is_snippet: !!__b.is_snippet,
          max: Number.isFinite(Number(__b.max)) ? Math.floor(Number(__b.max)) : null,
          used: Number.isFinite(Number(__b.used)) ? Math.floor(Number(__b.used)) : 0,
          left: Number.isFinite(Number(__b.left)) ? Math.floor(Number(__b.left)) : 0,

          // block-level snapshot
          used_last_block: Number.isFinite(Number(__b.used_last_block)) ? Math.floor(Number(__b.used_last_block)) : 0,
          left_before_block: Number.isFinite(Number(__b.left_before_block)) ? Math.floor(Number(__b.left_before_block)) : null,
          left_after_block: Number.isFinite(Number(__b.left_after_block)) ? Math.floor(Number(__b.left_after_block)) : null,

          applied: __b.applied === true,
        };

        // ✅ (호환/표시용) 남은 budget: 미정의 __naverBudget 대신 여기로 확정
        partial_scores.naver_budget_remaining =
          Number.isFinite(Number(__b.left)) ? Math.floor(Number(__b.left)) : null;
      } else {
        partial_scores.naver_call_budget = null;
        partial_scores.naver_budget_remaining = null;
      }

      // ✅ cap 상태/제한 스냅샷 (요청 전체)
      partial_scores.naver_calls_used_total = Number(__capState?.calls_naver || 0);

      partial_scores.engine_call_caps = {
        total: Number.isFinite(Number(__caps?.total)) ? Math.floor(Number(__caps.total)) : null,
        academic: Number.isFinite(Number(__caps?.academic)) ? Math.floor(Number(__caps.academic)) : null,
        gdelt: Number.isFinite(Number(__caps?.gdelt)) ? Math.floor(Number(__caps.gdelt)) : null,
        naver: Number.isFinite(Number(__caps?.naver)) ? Math.floor(Number(__caps.naver)) : null,
      };

      partial_scores.engine_call_used = {
        total: Number(__capState?.calls_total || 0),
        academic: Number(__capState?.calls_academic || 0),
        gdelt: Number(__capState?.calls_gdelt || 0),
        naver: Number(__capState?.calls_naver || 0),
      };
    }
  } catch {}

  // ✅ 확장된 쿼리를 기준으로 evidence 선택
  let naverItemsForVerify = pickTopNaverEvidenceForVerify({
    items: naverItemsAll,
    query,
    blockText: b?.text || "",
    naverQueries: naverQueriesExpanded,
    topK: BLOCK_NAVER_EVIDENCE_TOPK,
    minRelevance: NAVER_RELEVANCE_MIN,
  });

  // ----- fallback: strict 필터로 0개 나오면 그래도 뭔가 채워주기 -----
  if (
    (!Array.isArray(naverItemsForVerify) || naverItemsForVerify.length === 0) &&
    Array.isArray(naverItemsAll) &&
    naverItemsAll.length > 0
  ) {
    const __poolNoNews = Array.isArray(naverItemsAll)
      ? naverItemsAll.filter((r) => {
          const t = String(r?.type || r?.source_type || r?.kind || "").toLowerCase().trim();
          if (!t) return true;
          return t !== "news";
        })
      : [];

    const __poolPrefer = (__poolNoNews.length ? __poolNoNews : naverItemsAll).filter((r) => !!(r?.tier || r?.whitelisted));
    const __poolFinal = __poolPrefer.length > 0 ? __poolPrefer : naverItemsAll;

    naverItemsForVerify = topArr(__poolFinal, BLOCK_NAVER_EVIDENCE_TOPK);
  }

    // ----- gdelt / external / blocksForVerify -----
  const gdeltForVerify = topArr(gdPack.result, BLOCK_EVIDENCE_TOPK);

  // ✅ external 누적(early-stop/recency 계산용)
  // - __academicSingle / __gdeltSingle 은 globalPack 재사용이므로 "한 번만" 주입해서 중복을 막는다.
  if (__academicSingle) {
    if (
      Array.isArray(external.crossref) && external.crossref.length === 0 &&
      Array.isArray(crPack?.result) && crPack.result.length
    ) {
      external.crossref.push(...crPack.result);
    }
    if (
      Array.isArray(external.openalex) && external.openalex.length === 0 &&
      Array.isArray(oaPack?.result) && oaPack.result.length
    ) {
      external.openalex.push(...oaPack.result);
    }
  } else {
    external.crossref.push(...(crPack.result || []));
    external.openalex.push(...(oaPack.result || []));
  }

  external.wikidata.push(...(wdPack.result || []));

  if (__gdeltSingle) {
    if (
      Array.isArray(external.gdelt) && external.gdelt.length === 0 &&
      Array.isArray(gdPack?.result) && gdPack.result.length
    ) {
      external.gdelt.push(...gdPack.result);
    }
  } else {
    external.gdelt.push(...(gdPack.result || []));
  }

  external.naver.push(...(naverItemsAll || []));

  blocksForVerify.push({
    id: b.id,
    text: b.text,
    queries: {
      crossref: qCrossref,
      openalex: qOpenalex,
      wikidata: qWikidata,
      gdelt: qGdelt,
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

  // ✅ 블록 1개 끝난 시점에서도 early-stop 판단 (다음 블록 스킵용)
  try {
    const chk2 = __shouldEarlyStopApprox({
      cr: (external && Array.isArray(external.crossref)) ? external.crossref : [],
      oa: (external && Array.isArray(external.openalex)) ? external.openalex : [],
      wd: (external && Array.isArray(external.wikidata)) ? external.wikidata : [],
      gd: (external && Array.isArray(external.gdelt)) ? external.gdelt : [],
      nv: (external && Array.isArray(external.naver)) ? external.naver : [],
    });

    if (chk2 && chk2.ok) {
      __capState.early_stop = true;
      __capState.early_stop_reason = { where: "after_block", ...chk2 };
      break;
    }
  } catch {}
}

// ✅ cap/early-stop 로그
try {
  partial_scores.call_caps = {
    limits: __caps,
    used: {
      total: __capState.calls_total,
      academic: __capState.calls_academic,
      gdelt: __capState.calls_gdelt,
      naver: __capState.calls_naver,
    },
    early_stop: __capState.early_stop,
    early_stop_reason: __capState.early_stop_reason,
  };
} catch {}

if (__academicSingle) {
  external.crossref = Array.isArray(crossrefGlobalPack?.result) ? crossrefGlobalPack.result.slice() : [];
  external.openalex = Array.isArray(openalexGlobalPack?.result) ? openalexGlobalPack.result.slice() : [];
}
if (__gdeltSingle) {
  external.gdelt = Array.isArray(gdeltGlobalPack?.result) ? gdeltGlobalPack.result.slice() : [];
}

external.naver = dedupeByLink(external.naver).slice(0, NAVER_MULTI_MAX_ITEMS);

// ✅ finalize request-level budget log
try {
  if (partial_scores && typeof partial_scores === "object") {
    const b = partial_scores.__naver_call_budget;
    if (b && typeof b === "object") {
      b.used_final = Number(b.used || 0);
      b.left_final = Number(b.left || 0);
      b.applied = true;
    }
  }
} catch {}

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

// ✅ S-17 cache key (only QV/FV) — must be defined before cache get/set
// ✅ S-17 cache key (only QV/FV) — assign (NOT declare) to keep scope valid
if (safeMode === "qv" || safeMode === "fv") {
  __cacheKey =
    `v1|${safeMode}` +
    `|u:${hash16(String(authUser?.id || logUserId || ""))}` +
    `|q:${hash16(String(query || ""))}` +
    `|core:${hash16(String(userCoreText || core_text || req.body?.snippet_meta?.snippet_core || ""))}` +
    `|ua:${hash16(String(user_answer || ""))}`;
} else {
  __cacheKey = null;
}

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
// ✅ S-17b: 응답 직전 router_plan 재부착 (cache-hit path)
// - 최종 safeMode 반영 (stale 방지)
try {
  const __rp = __buildRouterPlanPublicFinal({
    safeMode,
    rawMode,
    routerPlan: __routerPlan,
    runLvExtra: __runLvExtra,
  });

  if (out.partial_scores && typeof out.partial_scores === "object") {
    out.partial_scores.router_plan = __rp;
  } else {
    out.partial_scores = { cache_hit: true, router_plan: __rp };
  }
} catch (_) {}
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

    const needle = String(b?.text || "").trim();
const years = extractYearTokens(needle);
const nums = extractQuantNumberTokens(needle);
const numsCompact = nums.map(normalizeNumToken);
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

// display-only는 evidence로 쓰지 않음(일관성)
const isDisplayOnly =
  (ev?.display_only === true) || (ev?._whitelist_display_only === true);
if (isDisplayOnly) continue;

const textCompact = String(text || "").replace(/[,\s]/g, "");

const hasYear = years.length
  ? years.some(y => text.includes(String(y)) || textCompact.includes(String(y)))
  : false;

const hasExactNum = numsCompact.length
  ? numsCompact.some(n => n && textCompact.includes(String(n)))
  : false;

const hasAnyNum = hasNumberLike(text);

if (!isWhitelisted) continue;

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

      let excerpt = extractExcerptContainingNumbers(pageText, needle, EVIDENCE_EXCERPT_CHARS);

if (!excerpt) {
  // ✅ 하드 드랍(continue) 금지: needle(숫자/연도)을 못 찾아도 evidence는 유지
  // - 대신 소프트 플래그 + 패널티 메타만 남김
  const _fallback = String(pageText || "").trim();
  excerpt = _fallback ? _fallback.slice(0, Math.max(200, EVIDENCE_EXCERPT_CHARS)) : null;

  // excerpt가 정말 없으면(페이지 텍스트 자체가 이상한 케이스)만 조용히 드랍
  if (!excerpt) continue;

  // ✅ 숫자(needle) 매칭 실패 소프트 플래그
  ev._soft_num_miss = true;
  ev._soft_num_miss_needles = [needle].filter(Boolean).slice(0, 6);
  ev._soft_num_miss_penalty = (typeof NUMERIC_SOFT_WARNING_PENALTY !== "undefined" ? NUMERIC_SOFT_WARNING_PENALTY : undefined);

  // ✅ numeric soft warning 누적(있으면 기록, 없으면 조용히 무시)
  try {
    if (Array.isArray(numeric_soft_warnings)) {
      const _u = String(ev?.source_url || ev?.link || "").trim();
      const _host = String(ev?.host || ev?.source_host || "").toLowerCase();
      numeric_soft_warnings.push({
        block_id: Number.isFinite(Number(b?.id)) ? Number(b.id) : null,
        url: _u || null,
        host: _host || null,
        needles: [needle].filter(Boolean).slice(0, 6),
        reason: "numeric_excerpt_not_found",
        action: "soft_keep",
      });
    }
  } catch (_) {}
}

      if (NAVER_STRICT_YEAR_MATCH && years.length) {
  const _hasYearInExcerpt = years.some((y) => excerpt.includes(String(y)));

  if (!_hasYearInExcerpt) {
    // ✅ 하드 드랍(continue) 금지: 소프트 플래그 + 패널티 메타만 남기고 evidence_text는 유지
    ev._soft_year_miss = true;
    ev._soft_year_miss_years = years.slice(0, 6);

    // ✅ "소프트 패널티" 값 기록(가중치/선정 로직에서 참고 가능)
    ev._soft_year_miss_penalty = NAVER_YEAR_MISS_PENALTY;

    // NOTE: year miss는 여기서 weight/score를 깎지 않고, S-13(soft_penalties)에서 일괄 패널티로만 반영

        // ✅ year soft warning 누적(있으면 기록, 없으면 조용히 무시)
    try {
      if (Array.isArray(year_soft_warnings)) {
        const _u = String(ev?.source_url || ev?.link || "").trim();
        const _host = String(ev?.host || ev?.source_host || "").toLowerCase();
        year_soft_warnings.push({
          block_id: Number.isFinite(Number(b?.id)) ? Number(b.id) : null,
          url: _u || null,
          host: _host || null,
          years: Array.isArray(ev._soft_year_miss_years) ? ev._soft_year_miss_years : [],
          penalty: ev._soft_year_miss_penalty,
        });
      }
    } catch (_) {}
  }
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
const year_soft_warnings = [];
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
    const claimText = String(b?.text || "");
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
// NOTE: year miss는 "블록 내 naver evidence가 전부 year-miss"인 경우에만 soft warning으로 집계
//       (일부 아이템만 miss인 혼합 케이스는 경고로 잡지 않음)
try {
  const evItems2 = Object.values(ev).filter(Array.isArray).flat();
  const total = evItems2.length;
  const yearMissItems = evItems2.filter((x) => x && x._soft_year_miss);
  const miss = yearMissItems.length;

  if (total > 0 && miss === total) {
    const years = Array.from(
      new Set(
        yearMissItems
          .map((x) => (Array.isArray(x._soft_year_miss_years) ? x._soft_year_miss_years : []))
          .flat()
          .filter((y) => Number.isFinite(Number(y)))
          .map((y) => Number(y))
      )
    ).slice(0, 8);

    year_soft_warnings.push({
      id: b?.id,
      text: String(b?.text || "").slice(0, 220),
      reason: "year_soft_miss_in_evidence",
      years,
      items: miss,
      total,
      action: "soft_keep",
    });
  }
} catch (_e) {}
    kept.push(b);
  }

  // blocksForVerify가 const여도 안전하게(배열 in-place 교체)
  blocksForVerify.splice(0, blocksForVerify.length, ...kept);

    partial_scores.evidence_prune = {
  before: kept.length + dropped.length,
  after: kept.length,
  dropped,
  numeric_soft_warnings,
  year_soft_warnings,
};
// ✅ E_eff (effective engines) helpers (DETAIL ONLY)
// - 최종 effective_engines/coverage_factor는 아래(9460: E_cov/E_eff 블록)에서 단일 소스로 확정
// - 여기서는 "counts/ratio/detail"만 기록 + exclusion_reasons 보강만 수행
try {
  const __counts = __calcEngineEvidenceCounts(blocksForVerify);
  const __requested = Array.isArray(engines_requested) ? engines_requested : [];
  const __eff = __getEffectiveEngines(__requested, __counts);

  // (detail) 최종값을 덮어쓰지 않도록 *_detail / *_ratio 로만 남김
  const __ratio01 =
    (__requested.length > 0)
      ? Math.min(1.0, Math.max(0.0, (__eff.length / __requested.length)))
      : 0.0;

  partial_scores.coverage_detail = {
    requested: __requested.length,
    effective: __eff.length,
    ratio_01: __ratio01,
    counts: __counts,
  };
  partial_scores.effective_engines_detail = __eff.slice();
  partial_scores.effective_engines_count_detail = __eff.length;
  partial_scores.coverage_ratio_01 = __ratio01;

  // ✅ engine_exclusion_reasons에 "no_effective_evidence" 동기화(coverage penalty target)
  if (engine_exclusion_reasons && typeof engine_exclusion_reasons === "object") {
    for (const e of __requested) {
      const c = (__counts?.[e] || 0);
      if (c > 0) continue;

      const arr = Array.isArray(engine_exclusion_reasons[e]) ? engine_exclusion_reasons[e] : [];
      const already = arr.some(r => (r?.code || r?.reason) === "no_effective_evidence");
      if (!already) {
        arr.push({
          code: "no_effective_evidence",
          details: { evidence_count: 0 },
          coverage_penalty_target: true,
        });
      }
      engine_exclusion_reasons[e] = arr;
    }
  }
} catch (_e) {}
}

// ✅ soft-year-miss summary (for logging / diagnostics)
try {
  if (
    (safeMode === "qv" || safeMode === "fv") &&
    partial_scores &&
    typeof partial_scores === "object" &&
    Array.isArray(blocksForVerify)
  ) {
    let __cnt = 0;
    const __samples = [];

    for (const b of blocksForVerify) {
      const bid = b?.id ?? null;
      const evs = b?.evidence?.naver;
      if (!Array.isArray(evs)) continue;

      for (const ev of evs) {
        if (!ev || !ev._soft_year_miss) continue;
        __cnt += 1;

        if (__samples.length < 20) {
          __samples.push({
            block_id: bid,
            where: ev._soft_year_miss_where ?? null,
            years: Array.isArray(ev._soft_year_miss_years) ? ev._soft_year_miss_years.slice(0, 6) : null,
            penalty: (typeof ev._soft_year_miss_penalty === "number" ? ev._soft_year_miss_penalty : null),
            url: ev?.url ?? ev?.link ?? null,
            host: ev?.host ?? ev?.source_host ?? null,
          });
        }
      }
    }

    partial_scores.naver_soft_year_miss = { count: __cnt, samples: __samples };
  }
} catch (_e) {}

// (log) numeric_evidence_match 직전: 숫자 claim 블록/엔진 개괄 로그
if ((safeMode === "qv" || safeMode === "fv") && Array.isArray(blocksForVerify) && blocksForVerify.length > 0) {
  try {
    const numericCandidates = [];

    for (const b of blocksForVerify) {
      const txt = String(b?.text || "");
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
  const __NUMERIC_PRUNE_ENGINES = new Set(["naver"]); // numeric prune은 naver에만 적용

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
          .map((x) => normalizeNumToken(x)) // "5,156" -> "5156"
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

  const numericPassForEvidence = (claimTokens, evidenceText) => {
    const evRaw = String(evidenceText || "");
    const evCompact = evRaw.replace(/[,\s]/g, ""); // "5,156" -> "5156" (+ 공백도 제거)

    const years = Array.isArray(claimTokens?.years) ? claimTokens.years : [];
    const nums = Array.isArray(claimTokens?.nums) ? claimTokens.nums : [];

    const needYear = years.length > 0;
    const needNum = nums.length > 0;

    const yearsHit = needYear
      ? years.some((y) => evRaw.includes(String(y)) || evCompact.includes(String(y)))
      : false;

    const numsHit = needNum
      ? nums.some((n) => {
          const s = String(n);
          return s && (evRaw.includes(s) || evCompact.includes(s));
        })
      : false;

    // 둘 다 필요한데 둘 다 미스면 fail
    // 하나만 필요하면 그 하나만 만족하면 pass
    const pass =
      (needYear && needNum) ? (yearsHit && numsHit)
      : needYear ? yearsHit
      : needNum ? numsHit
      : true;

    return { needYear, needNum, yearsHit, numsHit, pass };
  };

  let itemsBefore = 0;
  let itemsAfter = 0;

  const touched = [];
  const mismatchFallback = [];

  for (const b of blocksForVerify) {
    const claimText = String(b?.text || "").trim();
    if (!claimText) continue;

    // 숫자/연도 토큰이 없으면 이 블록은 스킵
    const claimTokens = extractNumericTokens(claimText);
    const needAny = (claimTokens.years.length > 0) || (claimTokens.nums.length > 0);
    if (!needAny) continue;

    // 엔진별(현재는 naver만)
    for (const eng of __NUMERIC_PRUNE_ENGINES) {
      const arr = b?.evidence?.[eng];
      if (!Array.isArray(arr) || arr.length === 0) continue;

      itemsBefore += arr.length;

      const kept = [];
      for (const ev of arr) {
        // evidence text blob (excerpt/title/desc/url/host)
        const evBlob = cleanEvidenceText(
          `${ev?.evidence_text || ""} ${ev?.title || ""} ${ev?.desc || ""} ${ev?.url || ev?.link || ev?.source_url || ""} ${ev?.host || ev?.source_host || ""}`
        );

        const r = numericPassForEvidence(claimTokens, evBlob);

        // trusted host 예외(통계/국제기구 등): excerpt가 빈약해도 하드 프룬에서는 보호
        let trusted = false;
        try {
          trusted = (typeof isTrustedNumericEvidenceItem === "function") ? !!isTrustedNumericEvidenceItem(ev) : false;
        } catch (_) {}

        // ✅ SOFT penalty product (중복 적용 방지)
        const baseTw =
          (typeof ev?._tier_weight_before_soft === "number" && Number.isFinite(ev._tier_weight_before_soft))
            ? ev._tier_weight_before_soft
            : (typeof ev?.tier_weight === "number" && Number.isFinite(ev.tier_weight))
              ? ev.tier_weight
              : 1.0;

        let penalty = 1.0;

        // year miss: 이미 numeric_fetch에서 soft flag가 찍혔을 수도 있으니 “있으면 그 값” 사용
        const yearMiss = r.needYear && !r.yearsHit;
        const yearPenalty =
          (typeof ev?._soft_year_miss_penalty === "number" && Number.isFinite(ev._soft_year_miss_penalty))
            ? ev._soft_year_miss_penalty
            : (yearMiss ? NAVER_YEAR_MISS_PENALTY : 1.0);

        if (yearMiss) {
          ev._soft_year_miss = true;
          ev._soft_year_miss_years = Array.isArray(ev._soft_year_miss_years) ? ev._soft_year_miss_years : claimTokens.years.slice(0, 6);
          ev._soft_year_miss_penalty = yearPenalty;
          penalty *= yearPenalty;
        }

        // numeric miss: SOFT warning 패널티
        const numMiss = r.needNum && !r.numsHit;
        const numPenalty =
          (typeof ev?._soft_numeric_miss_penalty === "number" && Number.isFinite(ev._soft_numeric_miss_penalty))
            ? ev._soft_numeric_miss_penalty
            : (numMiss ? NUMERIC_SOFT_WARNING_PENALTY : 1.0);

        if (numMiss) {
          ev._soft_numeric_miss = true;
          ev._soft_numeric_miss_nums = Array.isArray(ev._soft_numeric_miss_nums) ? ev._soft_numeric_miss_nums : claimTokens.nums.slice(0, 8);
          ev._soft_numeric_miss_penalty = numPenalty;
          penalty *= numPenalty;
        }

        // ✅ penalty가 실질적으로 있으면 기록만 남김 (tier_weight 직접 변경 금지: double-penalty 방지)
// - soft penalty는 Swap-in A/B에서 final truthscore_01에 "딱 1번"만 적용
if (penalty < 0.999999) {
  ev._tier_weight_before_soft = baseTw;

  // per-evidence soft penalty product 기록(나중에 Swap-in A의 geometric mean에도 쓰임)
  ev._soft_penalty_product = penalty;

  // debug-only: tier_weight에 반영했다면 이 정도였다는 참고값만 남김
  ev._tier_weight_soft_suggested = baseTw * penalty;

  // ❌ DO NOT APPLY:
  // ev.tier_weight = baseTw * penalty;

  touched.push({
    url: ev?.url || ev?.link || ev?.source_url || null,
    host: ev?.host || ev?.source_host || null,
    year_miss: !!yearMiss,
    num_miss: !!numMiss,
    penalty,
  });
}

        // ✅ STRICT=true일 때만 하드 프룬(단, trusted는 보호)
        const passOrTrusted = r.pass || trusted;
        if (STRICT_NUMERIC_PRUNE && !passOrTrusted) {
          mismatchFallback.push({
            url: ev?.url || ev?.link || ev?.source_url || null,
            host: ev?.host || ev?.source_host || null,
            reason: (yearMiss && numMiss) ? "year_and_num_miss" : yearMiss ? "year_miss" : numMiss ? "num_miss" : "mismatch",
            trusted: !!trusted,
          });
          continue;
        }

        kept.push(ev);
      }

      // write back
      b.evidence[eng] = kept;
      itemsAfter += kept.length;
    }
  }

  try {
    partial_scores.numeric_evidence_match = {
      strict_prune: STRICT_NUMERIC_PRUNE,
      items_before: itemsBefore,
      items_after: itemsAfter,
      pruned: Math.max(0, itemsBefore - itemsAfter),
      penalties_applied: touched.length,
      touched: touched.slice(0, 30),
      mismatch_fallback: mismatchFallback.slice(0, 30),
    };
  } catch (_e) {}
}

// ✅ URL canonical key: query/hash 제거 + https 통일 + trailing slash 제거
const __canonUrlKey = (u0) => {
  try {
    let s = String(u0 || "").trim();
    if (!s) return "";

    const h = s.indexOf("#");
    if (h >= 0) s = s.slice(0, h);

    const q = s.indexOf("?");
    if (q >= 0) s = s.slice(0, q);

    s = s.replace(/^http:\/\//i, "https://");
    s = s.replace(/\/+$/g, "");

    return s;
  } catch (_) {
    return String(u0 || "").trim();
  }
};

// ✅ NOTE: year/number soft-miss flags & penalties are stamped earlier (numeric_evidence_match / prune).
//          Swap-in A reads ev._soft_year_miss/_penalty and ev._soft_numeric_miss/_penalty directly.
//          Remove duplicate “stamp-to-blocks” steps to avoid duplication and confusion.


// ✅ Swap-in A: compute soft_penalty_factor (QV/FV evidence 기반 + numeric/year mismatch touch 포함)
// - year miss: ev._soft_year_miss_penalty (없으면 NAVER_YEAR_MISS_PENALTY fallback)
// - numeric miss: ev._soft_numeric_miss_penalty (없으면 NUMERIC_SOFT_WARNING_PENALTY fallback)
// - per-evidence: ev._soft_penalty_product 저장
// - overall factor: penalized evidence들의 geometric mean
// - IMPORTANT: numeric_evidence_match.touched / naver_soft_year_miss.samples 로 찍힌 penalty도 합산
try {
  if ((safeMode === "qv" || safeMode === "fv") && Array.isArray(blocksForVerify) && blocksForVerify.length > 0) {
    let sumLog = 0;
    let cnt = 0;
    let minP = null;
    let yearMiss = 0;
    let numMiss = 0;

    let itemsTotal = 0;
    let itemsUnknown = 0; // url이 없는 evidence 카운트(중복 제거 불가)

    const __known = new Set();   // "최종 evidence로 살아있는" url 집합(드랍 제외용)
    const __counted = new Set(); // 이미 penalty를 집계한 url 집합(이중 집계 방지)
    const __strictPrune = !!(numeric_evidence_match && numeric_evidence_match.strict_prune);
    const __keyOf = (x) => {
      const u = x?.url || x?.link || x?.href || x?.source_url || x?.sourceUrl || null;
      return (typeof u === "string" && u) ? u : null;
    };

    const __clamp01 = (v) => {
      const n = Number(v);
      if (!Number.isFinite(n)) return null;
      return Math.max(0.0, Math.min(1.0, n));
    };

    const __defaultYearPenalty = __clamp01((typeof NAVER_YEAR_MISS_PENALTY !== "undefined" ? NAVER_YEAR_MISS_PENALTY : null)) ?? 0.90;
    const __defaultNumPenalty  = __clamp01((typeof NUMERIC_SOFT_WARNING_PENALTY !== "undefined" ? NUMERIC_SOFT_WARNING_PENALTY : null)) ?? 0.95;

        // key canonicalize + (strict_prune일 때) "현재 살아있는 evidence"만 집계
    // - __known: 최종 blocks에서 살아있는 URL 집합
    // - __counted: 이미 penalty를 집계한 URL 집합(중복 집계 방지)
        const __accPenalty = (p, flags, keyRaw, opts) => {
  // key canonicalize
  const key = keyRaw ? __canonUrlKey(keyRaw) : null;
  const force = !!(opts && opts.force);

  // STRICT prune가 켜져 있으면: 기본은 "최종 blocks evidence에 살아있는 URL"만 집계
  // 단, touched/samples 등 “로그 기반 penalty”는 force로 우회 집계
  if (!force && __strictPrune && key && !__known.has(key)) return;

  // 이미 집계한 URL은 중복 집계 금지
  if (key && __counted.has(key)) return;
  if (key) __counted.add(key);

  itemsTotal += 1;

  const pp = __clamp01(p);
  if (pp == null) return;

  // "패널티"로 간주할 건 (0 < p < 1) 만
  if (pp > 0 && pp < 1) {
    sumLog += Math.log(pp);
    cnt += 1;
    if (minP == null || pp < minP) minP = pp;
  }

  if (flags?.year_miss) yearMiss += 1;
  if (flags?.num_miss) numMiss += 1;
};

        // 0) __known 채우기: 최종 blocks evidence에 "살아있는" URL만 모음
    for (const b of blocksForVerify) {
      const evs = Array.isArray(b?.evidence_items) ? b.evidence_items : (Array.isArray(b?.evidence) ? b.evidence : []);
      for (const ev of evs) {
        const k0 = __keyOf(ev);
        const k = k0 ? __canonUrlKey(k0) : null;
        if (k) __known.add(k);
      }
    }

        // 1) blocksForVerify 내부 evidence(ev) 기반 (URL canonical + 중복 집계 방지)
    for (const b of blocksForVerify) {
      const evs = Array.isArray(b?.evidence_items)
        ? b.evidence_items
        : (Array.isArray(b?.evidence) ? b.evidence : []);

      for (const ev of evs) {
        const key0 = __keyOf(ev);
        const key = key0 ? __canonUrlKey(key0) : null;

        // "최종 evidence로 살아있는" URL 집합 구성
        if (key) __known.add(key);
        else itemsUnknown += 1;

        const _y = !!ev?._soft_year_miss;
        const _n = !!ev?._soft_numeric_miss;

        // 기본은 1.0, 미스면 penalty 적용
        const py = _y ? (__clamp01(ev?._soft_year_miss_penalty) ?? __defaultYearPenalty) : 1.0;
        const pn = _n ? (__clamp01(ev?._soft_numeric_miss_penalty) ?? __defaultNumPenalty) : 1.0;

        const prod = Math.max(0.0, Math.min(1.0, py * pn));

        // per-evidence debug 저장
        if ((_y || _n) && typeof ev === "object" && ev) {
          try { ev._soft_penalty_product = Number(prod.toFixed(6)); } catch {}
        }

        __accPenalty(
          prod,
          { year_miss: _y, num_miss: _n },
          key0,
          { force: false }
        );
      }
    }

    // 2) numeric_evidence_match.touched 기반 (ev에 안 묻는 케이스 보완)
    if (numeric_evidence_match && Array.isArray(numeric_evidence_match.touched)) {
      for (const t of numeric_evidence_match.touched) {
        const key = (__keyOf(t) || (typeof t?.url === "string" ? t.url : null));
        __accPenalty(
  t?.penalty,
  { year_miss: !!t?.year_miss, num_miss: !!t?.num_miss },
  key,
  { force: true }
);
      }
    }

    // 3) naver_soft_year_miss.samples 기반 (year miss가 samples로만 남는 케이스 보완)
    if (naver_soft_year_miss && Array.isArray(naver_soft_year_miss.samples)) {
      for (const s of naver_soft_year_miss.samples) {
        const key = __keyOf(s) || (typeof s?.url === "string" ? s.url : null);
        __accPenalty(
  s?.penalty,
  { year_miss: true, num_miss: false },
  key,
  { force: true }
);
      }
    }

        // ✅ itemsTotal: "최종 살아있는 evidence" 기준으로 확정(중복 제거)
    // - url 없는 evidence는 itemsUnknown으로 보정
    itemsTotal = (__known ? __known.size : 0) + (itemsUnknown || 0);

    // geometric mean
    const factor = (cnt > 0) ? Math.exp(sumLog / cnt) : 1.0;

    partial_scores.soft_penalty_factor = Number(Math.max(0.0, Math.min(1.0, factor)).toFixed(6));
    partial_scores.soft_penalty_meta = {
      penalized_evidence_items: cnt,
      min_penalty: (minP == null) ? null : Number(minP.toFixed(6)),
      year_miss_items: yearMiss,
      num_miss_items: numMiss,
    };
    partial_scores.soft_penalties_overview = {
      items: itemsTotal,
      penalized: cnt,
      year_miss: yearMiss,
      num_miss: numMiss,
    };
  } else {
    // non QV/FV or no blocks
    partial_scores.soft_penalty_factor = 1.0;
    try {
      partial_scores.soft_penalty_meta = {
        penalized_evidence_items: 0,
        min_penalty: null,
        year_miss_items: 0,
        num_miss_items: 0,
      };
      partial_scores.soft_penalties_overview = {
        items: 0,
        penalized: 0,
        year_miss: 0,
        num_miss: 0,
      };
    } catch {}
  }
} catch (_) {
  try { partial_scores.soft_penalty_factor = 1.0; } catch {}
}

// ✅ FINALIZE: engines_requested / engines_used(E_eff) / engine_explain / engine_exclusion_reasons
{
  // requested 확정
  if (!Array.isArray(partial_scores.engines_requested) || partial_scores.engines_requested.length === 0) {
    partial_scores.engines_requested = Array.isArray(engines) ? engines.slice() : [];
  }

  const __requested = partial_scores.engines_requested.slice();
  // ✅ normalize engines_requested: include actually-called engines (calls>0)
try {
  partial_scores.engines_requested = normalizeEnginesRequested(
    partial_scores.engines_requested,
    partial_scores.engine_metrics
  );
} catch (_) {}

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

    // ✅ soft penalty/year/num miss 집계(엔진별) — QV/FV blocks evidence 기준
  const __collectBlockSoftMeta = (engineKey) => {
    const out = {
      items: 0,
      penalized: 0,
      year_miss: 0,
      num_miss: 0,
      avg_penalty: null, // geometric mean
      min_penalty: null,
    };
    if (!Array.isArray(blocksForVerify)) return out;

    let sumLog = 0;

    for (const b of blocksForVerify) {
      const arr = b?.evidence?.[engineKey];
      if (!Array.isArray(arr) || arr.length === 0) continue;

      for (const ev of arr) {
        out.items++;

        if (ev?._soft_year_miss) out.year_miss++;
        if (ev?._soft_numeric_miss) out.num_miss++;

        const p =
          (typeof ev?._soft_penalty_product === "number" && Number.isFinite(ev._soft_penalty_product))
            ? ev._soft_penalty_product
            : null;

        if (p != null && p < 0.999999) {
          out.penalized++;
          const pp = Math.max(1e-6, Math.min(1.0, p));
          sumLog += Math.log(pp);
          out.min_penalty = (out.min_penalty == null) ? pp : Math.min(out.min_penalty, pp);
        }
      }
    }

    if (out.penalized > 0) {
      out.avg_penalty = Math.exp(sumLog / out.penalized);
    }
    return out;
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

        const softMeta =
      (safeMode === "qv" || safeMode === "fv")
        ? __collectBlockSoftMeta(name)
        : null;

    __explain[name] = {
      used,
      ext_count: extCount,
      block_evidence_count: blockCount,
      ms,
      soft_meta: softMeta, // {items, penalized, year_miss, num_miss, avg_penalty, min_penalty}
    };
  }

  // ✅ 핵심: fallback으로 채우지 말 것(증거 0이면 engines_used = [])
  partial_scores.engines_used = __used;
  partial_scores.effective_engines = __used.slice();
  partial_scores.effective_engines_count = __used.length;

  // (옵션) excluded도 같이 남기고 싶으면
  partial_scores.engines_excluded = __requested.filter((x) => x && !__used.includes(x));

  partial_scores.engine_explain = __explain;

    // ✅ 전체 soft penalty 집계(옵션)
  if (safeMode === "qv" || safeMode === "fv") {
    try {
      let totalItems = 0, totalPen = 0, totalYear = 0, totalNum = 0;
      for (const k of Object.keys(__explain || {})) {
        const sm = __explain?.[k]?.soft_meta;
        if (!sm || typeof sm !== "object") continue;
        totalItems += (sm.items || 0);
        totalPen += (sm.penalized || 0);
        totalYear += (sm.year_miss || 0);
        totalNum += (sm.num_miss || 0);
      }
      partial_scores.soft_penalties_overview = {
        items: totalItems,
        penalized: totalPen,
        year_miss: totalYear,
        num_miss: totalNum,
      };
    } catch (_) {}
  }

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
  - IMPORTANT: Do NOT invent any URL, host, or title.
  - You may cite ONLY by copying an evidence item's host/title/url that already exists in input.external (the evidence pool).
  - If you cannot find a URL in input.external, omit citations entirely.

Rules:
- Never output any URL unless it appears in input.external. Never invent URLs.
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

verifyRawJson = ""; // ✅ reset (declared at handler-scope)

// ✅ 끝까지 실패했으면 기존 정책대로: verifyMeta 없이 외부엔진 기반으로만 진행
if (!verify || !String(verify).trim()) {
  verifyMeta = null;
  __irrelevant_urls = [];
  verifyRawJson = ""; // ✅ NEW
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

    verifyRawJson = jsonText; // ✅ NEW: 코드펜스/잡문 제거된 JSON만 내려줌
    verifyMeta = JSON.parse(jsonText);

// ✅ (optional) normalize if helper exists
if (typeof normalizeVerifyMeta === "function") {
  try {
    verifyMeta = normalizeVerifyMeta(verifyMeta, verifyEvidenceLookup);
  } catch (_) {}
}

// ✅ scrub hallucinated URLs using external evidence pool
try {
  const __allowed = collectExternalEvidenceUrls(external, {
  strictNaverWhitelist:
    (snippet_meta && snippet_meta.is_snippet === true) ||
    String(req.path || "") === "/api/verify-snippet",
});
scrubVerifyMetaUnknownUrls(verifyMeta, __allowed);
} catch (_) {}

// ✅ ensure verify_raw is always valid JSON of the FINAL verifyMeta
try {
  verifyRawJson = JSON.stringify(verifyMeta);
} catch (_) {
  verifyRawJson = jsonText; // fallback
}

// ✅ NEW(S-19): verifyMeta.evidence 엔진명 정합화(실제 evidence_counts=0 엔진 제거) + engine_adjust 리셋
try {
  const bf = Array.isArray(partial_scores?.blocks_for_verify)
    ? partial_scores.blocks_for_verify
    : [];

  const id2counts = new Map();
  for (const b of bf) {
    const id = Number.isFinite(Number(b?.id)) ? Number(b.id) : null;
    const counts = (b?.evidence_counts && typeof b.evidence_counts === "object") ? b.evidence_counts : null;
    if (id != null && counts) id2counts.set(id, counts);
  }

  const removed = { support: {}, conflict: {}, engine_adjust_reset: [] };

  if (verifyMeta && Array.isArray(verifyMeta.blocks)) {
    for (const vb of verifyMeta.blocks) {
      const bid = Number.isFinite(Number(vb?.id)) ? Number(vb.id) : null;
      const counts = (bid != null && id2counts.has(bid)) ? id2counts.get(bid) : null;

      const ev = (vb?.evidence && typeof vb.evidence === "object") ? vb.evidence : null;
      if (!counts || !ev) continue;

      const s0 = Array.isArray(ev.support) ? ev.support.filter(Boolean) : [];
      const c0 = Array.isArray(ev.conflict) ? ev.conflict.filter(Boolean) : [];

      const s1 = s0.filter((name) => Number(counts[String(name)] ?? 0) > 0);
      const c1 = c0.filter((name) => Number(counts[String(name)] ?? 0) > 0);

      const s1set = new Set(s1);
      const c1set = new Set(c1);

      for (const name of s0) {
        if (!s1set.has(name)) removed.support[name] = (removed.support[name] || 0) + 1;
      }
      for (const name of c0) {
        if (!c1set.has(name)) removed.conflict[name] = (removed.conflict[name] || 0) + 1;
      }

      vb.evidence = { ...ev, support: s1, conflict: c1 };
    }
  }

  // engine_adjust: block_evidence_count=0 엔진은 1.00으로 리셋
  if (verifyMeta && verifyMeta.engine_adjust && typeof verifyMeta.engine_adjust === "object") {
    const explain =
      (partial_scores?.engine_explain && typeof partial_scores.engine_explain === "object")
        ? partial_scores.engine_explain
        : null;

    if (explain) {
      for (const name of Object.keys(verifyMeta.engine_adjust)) {
        const info = explain[name];
        const bec = (info && typeof info.block_evidence_count === "number") ? info.block_evidence_count : 0;
        if (!(bec > 0)) {
          verifyMeta.engine_adjust[name] = 1.0;
          removed.engine_adjust_reset.push(name);
        }
      }
    }
  }

  // sanitized JSON 문자열도 만들어서 내려주기
  try {
  verifyRawJsonSanitized = verifyMeta ? JSON.stringify(verifyMeta, null, 2) : "";
} catch (_) {
  verifyRawJsonSanitized = "";
}

// ✅ ensure verify_raw reflects FINAL (post-S-19) verifyMeta
// ✅ S-19: lock verify_raw to FINAL verifyMeta (compact JSON)
try {
  if (verifyMeta) verifyRawJson = JSON.stringify(verifyMeta);
} catch (_) {
  // keep previous verifyRawJson as-is
}

if (partial_scores && typeof partial_scores === "object") {
  partial_scores.verify_sanitize = removed;
}
} catch (e) {
  if (DEBUG) console.warn("⚠️ verifyMeta sanitize error:", e?.message || e);
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

// ✅ E_eff(Effective engines): "실제로 유효 evidence가 남아있는" 엔진 개수 기반 coverage factor
// - enginesUsedSet(호출/사용 시도) 기준이 아니라 external[engine]의 "kept evidence" 기준으로 산출
// - klaw는 제외(법률 모드는 coverage 개념이 다름)
const enginesUsed = Array.from(enginesUsedSet).filter((e) => e && e !== "klaw");

// helper: evidence-like item 판정(엔진별 스키마가 달라도 최대한 안전하게)
function __isEvidenceLikeItem(x) {
  if (!x || typeof x !== "object") return false;

  // 명시적으로 버려진/제외된 것들은 제외
  if (x.pruned === true) return false;
  if (x.excluded === true) return false;
  if (x.irrelevant === true) return false;
  if (x.discarded === true) return false;

  const url = String(x.url || x.link || x.source_url || x.sourceUrl || x.href || "").trim();
  const host = String(x.host || x.source_host || x.sourceHost || x.domain || "").trim();
  const title = String(x.title || x.source_title || x.name || "").trim();
  const text = String(
    x.snippet || x.summary || x.text || x.evidence_text || x.evidenceText || ""
  ).trim();

  // 최소 하나라도 있으면 evidence로 간주(엔진별로 title/host만 있는 경우도 있음)
  return !!(url || host || title || text);
}

// helper: external[eng]에서 "evidence 배열" 최대한 안전하게 꺼내기
const __extractEvidenceArrayForEeff = (eng, ext) => {
  if (!ext || typeof ext !== "object") return [];
  const v = ext?.[eng];

  if (!v) return [];

  // 1) 이미 배열이면 그대로
  if (Array.isArray(v)) return v;

  // 2) 흔한 래핑 형태들
  if (Array.isArray(v?.items)) return v.items;
  if (Array.isArray(v?.results)) return v.results;
  if (Array.isArray(v?.data)) return v.data;
  if (Array.isArray(v?.evidence)) return v.evidence;
  if (Array.isArray(v?.sources)) return v.sources;

  // 3) { list: [...] } 류
  if (Array.isArray(v?.list)) return v.list;

  return [];
};

// 1) 엔진별 kept evidence 개수 계산
const engineEvidenceCountsFinal = {};
for (const eng of enginesUsed) {
  const arr = __extractEvidenceArrayForEeff(eng, external);
  const kept = Array.isArray(arr) ? arr.filter(__isEvidenceLikeItem) : [];
  engineEvidenceCountsFinal[eng] = kept.length;
}

// 2) E_eff = kept evidence가 1개 이상인 엔진들
const effEngines = enginesUsed.filter((eng) => (engineEvidenceCountsFinal[eng] || 0) > 0);
const E_eff = effEngines.length;

// (로그) 최종 산출 근거도 남김(나중에 디버깅/어드민 UI에서 유용)
partial_scores.engine_evidence_counts_final = engineEvidenceCountsFinal;

// ✅ coverage factor (QV/FV에만 의미있게 적용, DV/CV는 1.0 유지)
// ✅ coverage factor (QV/FV에만 의미있게 적용, DV/CV는 1.0 유지)
// - 기본값은 기존과 동일
// - ENV로 튜닝 가능:
//   COVERAGE_EFF_GE3=1.0
//   COVERAGE_EFF_2=0.96
//   COVERAGE_EFF_1=0.90
//   COVERAGE_EFF_0=0.85
//   COVERAGE_STRONG_OFFICIAL_MIN=0.97
const E_cov = (() => {
  if (!(safeMode === "qv" || safeMode === "fv")) return 1.0;

  const _num = (v, d) => {
    const n = Number(v);
    return Number.isFinite(n) ? n : d;
  };

  const F_GE3 = _num(process.env.COVERAGE_EFF_GE3, 1.0);
  const F_2   = _num(process.env.COVERAGE_EFF_2, 0.96);
  const F_1   = _num(process.env.COVERAGE_EFF_1, 0.90);
  const F_0   = _num(process.env.COVERAGE_EFF_0, 0.85);
  const STRONG_MIN = _num(process.env.COVERAGE_STRONG_OFFICIAL_MIN, 0.97);

  // 기본 f
  let f = 1.0;
  if (E_eff >= 3) f = F_GE3;
  else if (E_eff === 2) f = F_2;
  else if (E_eff === 1) f = F_1;
  else f = F_0;

  // ✅ 예외: 엔진이 1개여도 “강한 공식/통계/정부급” 근거면 감점 완화
  // - naver만 보지 않고 external 전체의 kept evidence를 스캔
  const hasStrongOfficial = (() => {
    try {
      const isOfficialHost = (host) => {
        const h = String(host || "").toLowerCase();
        if (!h) return false;
        if (h.includes("kosis.kr")) return true;
        if (h.endsWith(".go.kr")) return true;
        if (typeof hostLooksOfficial === "function" && hostLooksOfficial(h)) return true;
        return false;
      };

      // enginesUsed는 바로 위에서 "klaw 제외"로 만든 상태(너 코드 기준)
      for (const eng of Array.isArray(enginesUsed) ? enginesUsed : []) {
        const arr = (typeof __extractEvidenceArrayForEeff === "function")
          ? __extractEvidenceArrayForEeff(eng, external)
          : (Array.isArray(external?.[eng]) ? external[eng] : []);

        if (!Array.isArray(arr) || arr.length === 0) continue;

        // kept evidence만 대상으로
        for (const x of arr) {
          if (typeof __isEvidenceLikeItem === "function" && !__isEvidenceLikeItem(x)) continue;

          const host = String(x?.source_host || x?.host || x?.domain || "").toLowerCase();

          // tier_weight/tier/whitelisted는 naver에 많지만, 있으면 엔진 불문하고 활용
          const tw =
            (typeof x?.tier_weight === "number" && Number.isFinite(x.tier_weight))
              ? x.tier_weight
              : null;

          const tier = String(x?.tier || "").toLowerCase();
          const wl = (x?.whitelisted === true) || !!x?.tier;
          const inferred = x?.inferred === true;

          if (tw != null && tw >= 0.95) return true;
          if (tier === "tier1") return true;
          if (wl && !inferred && isOfficialHost(host)) return true;

          if (isOfficialHost(host)) return true;
        }
      }

      return false;
    } catch (_) {
      return false;
    }
  })();

  if (E_eff <= 1 && hasStrongOfficial) f = Math.max(f, STRONG_MIN);

  // 로그로 남김(디버깅/어드민)
  partial_scores.coverage_has_strong_official = !!hasStrongOfficial;

  // 안전 클램프(과도 튜닝 방지)
  f = Math.max(0.80, Math.min(1.0, f));
  return f;
})();

// (로그용) partial_scores에 남겨두면 디버깅 편함
partial_scores.effective_engines_used = enginesUsed;
partial_scores.effective_engines = effEngines;
// ✅ effective_engine_item_counts는 항상 정의(예전 런타임 ReferenceError 방지)
// - 우선: engine_evidence_counts_final(= kept evidence 기준)
// - fallback: blocksForVerify evidence 합
const effective_engine_item_counts = (() => {
  try {
    const keys = Array.isArray(effEngines) ? effEngines : [];
    const out = {};
    for (const k of keys) out[k] = 0;

    const finalCounts =
      (partial_scores && typeof partial_scores.engine_evidence_counts_final === "object")
        ? partial_scores.engine_evidence_counts_final
        : null;

    // 1) kept evidence 기준이 있으면 그걸 우선 사용
    if (finalCounts) {
      for (const k of keys) {
        const v = finalCounts?.[k];
        if (typeof v === "number" && Number.isFinite(v)) out[k] = v;
      }
      return out;
    }

    // 2) fallback: blocksForVerify evidence 합
    if (!Array.isArray(blocksForVerify)) return out;

    for (const b of blocksForVerify) {
      const ev = b?.evidence || {};
      for (const k of keys) {
        const arr = ev?.[k];
        if (Array.isArray(arr)) out[k] += arr.length;
      }
    }
    return out;
  } catch (_) {
    return null;
  }
})();

partial_scores.effective_engine_item_counts = effective_engine_item_counts;
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

// ✅ 기존 tier factor와 결합해서 최종 N 산출
// NOTE: year/number soft miss 패널티는 Swap-in A/B의 soft_penalty_factor로 "최종 TruthScore"에서만 반영한다.
//       여기(N factor)에서 다시 곱하면 이중 감점이 될 수 있음.
const __N_tier =
  (safeMode === "qv" || safeMode === "fv") &&
  useNaver &&
  typeof partial_scores.naver_tier_factor === "number" &&
  Number.isFinite(partial_scores.naver_tier_factor)
    ? partial_scores.naver_tier_factor
    : 1.0;

// ✅ naver_soft_miss는 "진단용"으로만 유지(점수에 직접 반영 X)
try { partial_scores.naver_soft_miss_applied_to_N = false; } catch {}

const N =
  (safeMode === "qv" || safeMode === "fv") && useNaver
    ? Math.max(0.85, Math.min(1.05, __N_tier))
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

// ✅ debug: coverage(E_cov)가 hybrid에 적용되었는지 표시
partial_scores.coverage_applied_in_hybrid = (safeMode === "qv" || safeMode === "fv");

    // 최종 TruthScore (0.6 ~ 0.97 범위)
    truthscore = hybrid; // 0~1

// ✅ Swap-in B (moved): soft_penalty_factor is applied later ONCE to truthscore_01
// - 여기서는 double-penalty 방지를 위해 truthscore에 곱하지 않는다.
// - 단, 디버그용 clamp 값만 남긴다.
try {
  const _isQvFv = (safeMode === "qv" || safeMode === "fv");

  const _spfRaw =
    _isQvFv &&
    typeof partial_scores?.soft_penalty_factor === "number" &&
    Number.isFinite(partial_scores.soft_penalty_factor)
      ? partial_scores.soft_penalty_factor
      : 1.0;

  const spf = Math.max(0.0, Math.min(1.0, _spfRaw));

  // (debug only)
  try { partial_scores.soft_penalty_factor_clamped = Number(spf.toFixed(6)); } catch {}
} catch (_) {}

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
    const baseForWeight =
  (typeof truthscore_01_final === "number" && Number.isFinite(truthscore_01_final))
    ? truthscore_01_final
    : (typeof truthscore_01 === "number" && Number.isFinite(truthscore_01))
      ? truthscore_01
      : (typeof hybrid === "number" && Number.isFinite(hybrid))
        ? hybrid
        : 0;

const engineTruth = Math.max(0, Math.min(1, baseForWeight * adj));

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

          // (A) post-hybrid safety smoothing (single source of truth)
      // - QV/FV에만 적용(DV/CV는 별도 validity 흐름)
      // - coverage_factor / soft_penalty_factor는 "risk 입력"으로만 사용
      // - 기본값: 스무딩이 점수를 올리는 방향은 금지(급상승 방지)
      // - soft_penalty_factor 곱감점은 (B)에서 1회만 수행

      const __truthscore_01_raw = (() => {
  // 1) Gemini verify 결과의 overall raw(가장 신뢰할 1순위)
  const v0 = verifyMeta?.overall?.overall_truthscore_raw;
  if (typeof v0 === "number" && Number.isFinite(v0)) return Number(v0);

  // 2) 혹시 raw가 아니라 overall_truthscore로 오는 변형 대비
  const v1 = verifyMeta?.overall?.overall_truthscore;
  if (typeof v1 === "number" && Number.isFinite(v1)) return Number(v1);

  // 3) 레거시/안전망 (있으면 사용)
  try {
    if (typeof truthscore_01_raw === "number" && Number.isFinite(truthscore_01_raw)) {
      return Number(truthscore_01_raw);
    }
  } catch (_) {}

  const v2 = partial_scores?.truthscore_01_raw;
  if (typeof v2 === "number" && Number.isFinite(v2)) return Number(v2);

  return 0;
})();

var truthscore_01 = __truthscore_01_raw; // ✅ smoothing에서 참조/대입할 변수 생성 (TDZ 방지)

      try {
        const __m0 = String(safeMode || "").toLowerCase();
        if (__m0 === "qv" || __m0 === "fv") {
          const __clamp01_ts = (x) =>
            Math.max(0, Math.min(1, Number.isFinite(x) ? x : 0));
          const __num_ts = (v, d) =>
            Number.isFinite(Number(v)) ? Number(v) : d;

          // inputs (risk-only)
          const coverage01 = __clamp01_ts(__num_ts(partial_scores?.coverage_factor, 1.0));
          const conflict01 = __clamp01_ts(
            __num_ts(partial_scores?.conflict_meta?.conflict_index, 0.0)
          );
          const softPenalty01 = __clamp01_ts(
            __num_ts(partial_scores?.soft_penalty_factor, 1.0)
          );
          const Eeff =
            Number.isFinite(partial_scores?.effective_engines_count)
              ? Math.max(0, Math.min(10, Math.trunc(partial_scores.effective_engines_count)))
              : null;

          // keep compat logs (optional)
          try {
            partial_scores.coverage_factor_raw = coverage01;
            partial_scores.coverage_factor_used_in_smoothing = coverage01; // risk-only
          } catch (_) {}

          // env knobs
          const TS_ENABLED =
            String(process.env.TRUTH_SMOOTH_ENABLED ?? "true").toLowerCase() !== "false";
          const TS_TARGET = __clamp01_ts(__num_ts(process.env.TRUTH_SMOOTH_TARGET, 0.5));
          const TS_STRENGTH = __clamp01_ts(__num_ts(process.env.TRUTH_SMOOTH_STRENGTH, 0.55));

          const W_CONFLICT = __clamp01_ts(__num_ts(process.env.TRUTH_SMOOTH_W_CONFLICT, 0.55));
          const W_COV = __clamp01_ts(__num_ts(process.env.TRUTH_SMOOTH_W_COV, 0.30));
          const W_SOFT = __clamp01_ts(__num_ts(process.env.TRUTH_SMOOTH_W_SOFT, 0.15));
          const W_EEFF = __clamp01_ts(__num_ts(process.env.TRUTH_SMOOTH_W_EEFF, 0.10));

          const MAX_ALPHA = __clamp01_ts(__num_ts(process.env.TRUTH_SMOOTH_MAX_ALPHA, 0.60));

          if (TS_ENABLED) {
            const weakEff =
              Eeff !== null && Eeff <= 1 ? 1.0 : Eeff !== null && Eeff === 2 ? 0.5 : 0.0;

            const risk = __clamp01_ts(
              W_CONFLICT * conflict01 +
                W_COV * (1 - coverage01) +
                W_SOFT * (1 - softPenalty01) +
                W_EEFF * weakEff
            );

            const alpha = Math.min(MAX_ALPHA, __clamp01_ts(TS_STRENGTH * risk));

            const before = __clamp01_ts(truthscore_01);
            const blended = __clamp01_ts((1 - alpha) * before + alpha * TS_TARGET);

            // 기본: 스무딩이 점수를 올리지 않게(급상승 방지)
            const allowIncrease =
              String(process.env.TRUTH_SMOOTH_ALLOW_INCREASE ?? "false").toLowerCase() === "true";
            const after = allowIncrease ? blended : Math.min(before, blended);

            truthscore_01 = Number(after.toFixed(4));

            partial_scores.truthscore_smoothing = {
              applied: true,
              version: "A-v3",
              raw: Number(__truthscore_01_raw.toFixed(4)),
              before,
              after: truthscore_01,
              target: TS_TARGET,
              strength: TS_STRENGTH,
              max_alpha: MAX_ALPHA,
              allow_increase: allowIncrease,
              weights: {
                conflict: W_CONFLICT,
                coverage: W_COV,
                soft: W_SOFT,
                E_eff: W_EEFF,
              },
              inputs: {
                coverage_factor: coverage01,
                conflict_index: conflict01,
                soft_penalty_factor: softPenalty01,
                effective_engines_count: Eeff,
              },
              risk,
              alpha,
              note:
                "risk-only smoothing; default forbids increasing score (anti-spike). soft_penalty_factor is applied once in (B).",
            };
          } else {
            partial_scores.truthscore_smoothing = { applied: false, disabled: true };
          }
        }
      } catch (_) {
        try {
          partial_scores.truthscore_smoothing = { applied: false, error: true };
        } catch {}
        truthscore_01 = __truthscore_01_raw;
      }

      // (B) apply soft_penalty_factor to final TruthScore (QV/FV only) - single multiplicative pass
      let softPenaltyFactor = 1.0;
      let softPenaltyApplied = false;
      let softPenaltiesOverview = null;

      var truthscore_01_final =
       (typeof truthscore_01 === "number" && Number.isFinite(truthscore_01))
    ? truthscore_01
    : (typeof __truthscore_01_raw === "number" && Number.isFinite(__truthscore_01_raw))
      ? __truthscore_01_raw
      : 0;

            try {
        if (safeMode === "qv" || safeMode === "fv") {
          const ps =
            (partial_scores && typeof partial_scores === "object") ? partial_scores : {};

          // soft penalty factor
          const spf =
            (ps && typeof ps.soft_penalty_factor === "number" && Number.isFinite(ps.soft_penalty_factor))
              ? Math.max(0.0, Math.min(1.0, ps.soft_penalty_factor))
              : 1.0;

          softPenaltyFactor = spf;

          softPenaltiesOverview =
            (ps && typeof ps.soft_penalties_overview === "object")
              ? ps.soft_penalties_overview
              : null;

          // 1) apply soft penalty (기존 동작 유지)
          if (
            spf < 0.999999 &&
            typeof truthscore_01_final === "number" &&
            Number.isFinite(truthscore_01_final)
          ) {
            const before01 = truthscore_01_final;
            const after01 = Math.max(0.0, Math.min(1.0, before01 * spf));

            truthscore_01_final = Number(after01.toFixed(4));

            softPenaltyApplied = {
              factor: spf,
              before_01: Number(before01.toFixed(4)),
              after_01: truthscore_01_final,
            };

            ps.truthscore_01_pre_soft = Number(before01.toFixed(4));
            ps.soft_penalty_applied = softPenaltyApplied;
          } else {
            ps.soft_penalty_applied = false;
          }

                    // 2) NOTE: additional smoothing removed (handled in (A) only)
        } else {
          try { partial_scores.soft_penalty_applied = false; } catch {}
          try { partial_scores.truthscore_smoothing = false; } catch {}
        }
      } catch (_) {
        try { partial_scores.soft_penalty_applied = false; } catch {}
        try { partial_scores.truthscore_smoothing = false; } catch {}
      }

      const truthscore_pct_final = Math.round(truthscore_01_final * 10000) / 100; // 2 decimals
      const truthscore_text_final = `${truthscore_pct_final.toFixed(2)}%`;

      // compat aliases (아래에서 truthscore_pct/text 참조가 남아있어도 안전)
      const truthscore_pct = truthscore_pct_final;
      const truthscore_text = truthscore_text_final;
      const normalizedPartial = partial_scores;
      const payload = {
       mode: safeMode,
       truthscore: truthscore_text_final,
       truthscore_pct: truthscore_pct_final,
       truthscore_01: truthscore_01_final,
       elapsed,

  // ??S-15: engines_used ?먮룞 ?곗텧(紐낆떆 ?몄텧)
  engines: (Array.isArray(partial_scores.engines_used) ? partial_scores.engines_used : engines),
    engines_requested:
    (partial_scores &&
      typeof partial_scores === "object" &&
      Array.isArray(partial_scores.engines_requested) &&
      partial_scores.engines_requested.length > 0)
      ? partial_scores.engines_requested
      : (Array.isArray(engines) ? engines : []),
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
verify_raw: verifyRawJson,
verify_raw_sanitized: verifyRawJsonSanitized || null,
gemini_verify_model: verifyModelUsed,
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

    const softPenaltyFactor =
    (typeof ps.soft_penalty_factor === "number" && Number.isFinite(ps.soft_penalty_factor))
      ? ps.soft_penalty_factor
      : null;

   // ⭐ 핵심: false도 그대로 노출해야 함 (기존 로직은 false → null로 바꿔버림)
  const softPenaltyApplied =
    Object.prototype.hasOwnProperty.call(ps, "soft_penalty_applied")
      ? ps.soft_penalty_applied
      : null;

  const softPenaltiesOverview =
    (ps.soft_penalties_overview && typeof ps.soft_penalties_overview === "object")
      ? ps.soft_penalties_overview
      : null;

  payload.diagnostics = {
    effective_engines: effEngines,
    effective_engines_count: effCount,
    coverage_factor: coverage,
    conflict_meta: conflictMeta,
    numeric_evidence_match_pre: numericPre,
    numeric_evidence_match: numericFinal,

    // ✅ Swap-in C: expose soft-penalty summary
    soft_penalty_factor: softPenaltyFactor,
    soft_penalty_applied: softPenaltyApplied,
    soft_penalties_overview: softPenaltiesOverview,
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
  let msg = vMessage;

  // ✅ Swap-in D: QV/FV에서 soft_penalty가 적용되었으면 이유 힌트 1줄 추가
  try {
    if (safeMode === "qv" || safeMode === "fv") {
      const spf =
        partial_scores &&
        typeof partial_scores.soft_penalty_factor === "number" &&
        Number.isFinite(partial_scores.soft_penalty_factor)
          ? partial_scores.soft_penalty_factor
          : 1.0;

      const ov = partial_scores && typeof partial_scores.soft_penalties_overview === "object"
        ? partial_scores.soft_penalties_overview
        : null;

      const yearMiss = ov && typeof ov.year_miss === "number" ? ov.year_miss : 0;
      const numMiss  = ov && typeof ov.num_miss === "number" ? ov.num_miss : 0;

      if (spf < 0.999999 && (yearMiss > 0 || numMiss > 0)) {
        const bits = [];
        if (yearMiss > 0) bits.push(`연도 불일치 ${yearMiss}건`);
        if (numMiss > 0) bits.push(`숫자 불일치 ${numMiss}건`);

        msg += ` (참고: 일부 근거에서 ${bits.join(", ")}로 감점이 적용될 수 있습니다.)`;
      }
    }
  } catch (_) {}

  payload.verdict_message_ko = msg;
// ✅ S-17b: 응답 직전 router_plan 재부착
// - 최종 safeMode 반영 (stale 방지)
try {
  if (__ps && typeof __ps === "object") {
    __ps.router_plan = __buildRouterPlanPublicFinal({
      safeMode,
      rawMode,
      routerPlan: __routerPlan,
      runLvExtra: __runLvExtra,
    });
  }
} catch (_) {}
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

// ✅ Admin 대시보드용 에러 기록 (early-return 전에 먼저 기록)
try {
  pushAdminError({
    type: "verify",
    code: e?.code || null,
    message: e?.message || String(e),
  });
} catch (_) {}

// ✅ Gemini rate limit (429) — 기존 정책 유지(200 + success:false)
if (e?.code === "GEMINI_RATE_LIMIT") {
  return res.status(200).json({
    success: false,
    code: "GEMINI_RATE_LIMIT",
    message: "Gemini 요청이 일시적으로 과도합니다(429). 잠시 후 재시도해 주세요.",
    timestamp: new Date().toISOString(),
    detail: e?.detail ?? e?.message ?? null,
  });
}

// ✅ Gemini 키링 모두 소진(쿼터/인증 등)도 코드 유지해서 그대로 반환
if (e?.code === "GEMINI_KEY_EXHAUSTED") {
  const st = typeof e?.httpStatus === "number" ? e.httpStatus : 200;
  return res.status(st).json(
    buildError(
      "GEMINI_KEY_EXHAUSTED",
      "Gemini 키를 사용할 수 없습니다. (쿼터/인증/키링 상태 확인)",
      e?.detail ?? e?.message
    )
  );
}

// ✅ Gemini key missing => 401
if (e?.code === "GEMINI_KEY_MISSING") {
  return res.status(401).json(
    buildError(
      "GEMINI_KEY_MISSING",
      "Gemini API 키가 없습니다. (앱 설정 저장/로그인 vault 또는 요청 body에 gemini_key 필요)",
      e?.detail ?? e?.message
    )
  );
}

// ✅ Gemini invalid/missing key safety-net (code가 안 붙는 케이스)
{
  const rawMsg =
    e?.response?.data?.error?.message ||
    e?.response?.data?.message ||
    e?.message ||
    "";
  const s = String(rawMsg);

  const isMissing =
    /api key.*missing|missing api key|no api key|api_key_missing/i.test(s);
  const isInvalid =
    /API key not valid|API_KEY_INVALID|invalid api key/i.test(s);

  if (isMissing) {
    return res.status(401).json(
      buildError(
        "GEMINI_KEY_MISSING",
        "Gemini API 키가 없습니다. (앱 설정 저장/로그인 vault 또는 요청 body에 gemini_key 필요)",
        e?.detail ?? rawMsg
      )
    );
  }

  if (isInvalid) {
    return res.status(401).json(
      buildError(
        "INVALID_GEMINI_KEY",
        "Gemini API 키가 유효하지 않습니다. 키를 다시 저장/교체하세요.",
        e?.detail ?? rawMsg
      )
    );
  }
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

// =======================================================
// ✅ Whitelist endpoints (admin/ops)
// - GET /api/check-whitelist?force=1
// - GET /api/admin/whitelist-status
// =======================================================
const ADMIN_TOKEN = String(process.env.ADMIN_TOKEN || "");
const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function __extractReqEmail(req) {
  try {
    // passport/google-oauth20 흔한 케이스들
    const u = req?.user || null;
    const s = req?.session || null;

    const e1 = u?.email;
    if (e1) return String(e1);

    const e2 = u?.emails?.[0]?.value;
    if (e2) return String(e2);

    const e3 = u?.profile?.emails?.[0]?.value;
    if (e3) return String(e3);

    const e4 = s?.user?.email;
    if (e4) return String(e4);

    return null;
  } catch {
    return null;
  }
}

async function requireAdminAccess(req, res, next) {
  try {
    const t = String(req.headers["x-admin-token"] || "").trim();

    const adminTok = String(process.env.ADMIN_TOKEN || "").trim();
    const diagTok = String(process.env.DIAG_ADMIN_TOKEN || process.env.DIAG_TOKEN || "").trim();
    const devTok = String(process.env.DEV_ADMIN_TOKEN || "").trim();

    // 1) header token 우선(ADMIN/DIAG/DEV)
    if (
      t &&
      ((adminTok && t === adminTok) || (diagTok && t === diagTok) || (devTok && t === devTok))
    ) {
      return next();
    }

    // 2) ADMIN_EMAILS allowlist (req.user/session OR Authorization: Bearer <jwt>)
    const emails = (ADMIN_EMAILS || [])
      .map((x) => String(x).trim().toLowerCase())
      .filter(Boolean);

    if (emails.length > 0) {
      // (A) req.user/session 기반
      const e0 = String(__extractReqEmail(req) || "").trim().toLowerCase();
      if (e0 && emails.includes(e0)) return next();

      // (B) Authorization: Bearer <jwt> 기반 (curl도 여기서 통과)
      try {
        const au = await getSupabaseAuthUser(req); // Bearer 토큰으로 supabase.auth.getUser()
        const aemail = String(au?.email || "").trim().toLowerCase();
        if (aemail && emails.includes(aemail)) return next();
      } catch (_) {}
    }

    // 3) 로컬/개발 편의: 운영이 아니면 설정 없을 때 통과
    if (!isProd && !adminTok && !diagTok && !devTok && (ADMIN_EMAILS || []).length === 0) {
      return next();
    }
  } catch (_) {}

  return res.status(403).json({
    success: false,
    code: "ADMIN_ONLY",
    message:
      "Admin access required. Set ADMIN_TOKEN/DEV_ADMIN_TOKEN/DIAG_ADMIN_TOKEN (x-admin-token) or ADMIN_EMAILS.",
  });
}

// GET /api/admin/whitelist-status
app.get("/api/admin/whitelist-status", requireAdminAccess, (req, res) => {
  try {
    const meta =
      (typeof getNaverWhitelistMeta === "function")
        ? getNaverWhitelistMeta()
        : null;

    const update_last =
      globalThis.__NAVER_WL_UPDATE_LAST ||
      (typeof globalThis._WL_LAST_UPDATE_RESULT !== "undefined" ? globalThis._WL_LAST_UPDATE_RESULT : null) ||
      null;

    const last_check =
      (typeof globalThis.__wl_last_result !== "undefined")
        ? globalThis.__wl_last_result
        : null;

    return res.json({
      success: true,
      now: new Date().toISOString(),
      meta,
      last_check,
      update_last,
      auto_update: NAVER_WHITELIST_AUTO_UPDATE,
      interval_min: NAVER_WHITELIST_UPDATE_INTERVAL_MIN,
      remote_url_set: !!NAVER_WHITELIST_REMOTE_URL,
    });
  } catch (e) {
    return res
      .status(500)
      .json(buildError("INTERNAL_SERVER_ERROR", "서버 내부 오류가 발생했습니다.", String(e?.message || e)));
  }
});

// ✅ Diag: force/trigger whitelist update (prod guarded)
app.post("/api/admin/whitelist/update", requireDiag, async (req, res) => {
  try {
    const b = getJsonBody(req) || {};
    const force = String(b.force || req.query?.force || "").trim() === "1";
    const reason = String(b.reason || "admin_trigger").trim() || "admin_trigger";

    const fn =
      (typeof updateNaverWhitelistIfNeeded === "function")
        ? updateNaverWhitelistIfNeeded
        : (typeof globalThis.updateNaverWhitelistIfNeeded === "function")
          ? globalThis.updateNaverWhitelistIfNeeded
          : null;

    if (!fn) throw new Error("updateNaverWhitelistIfNeeded is not defined");

    const r = await fn({ force, reason });
    return res.json(buildSuccess(r));
  } catch (e) {
    return res.status(500).json(buildError("INTERNAL_ERROR", String(e?.message || e)));
  }
});

// ✅ Diag: last update result (prod guarded)
app.get("/api/admin/whitelist/update/last", requireDiag, (req, res) => {
  try {
    const last =
      globalThis.__NAVER_WL_UPDATE_LAST ||
      { updated: false, reason: "no_history" };

    return res.json(buildSuccess(last));
  } catch (e) {
    return res.status(500).json(buildError("INTERNAL_ERROR", String(e?.message || e)));
  }
});

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

      // ✅ user_id NOT NULL 대응: 가능하면 Bearer/Supabase auth로 해석
      let logUserId = null;
      try {
        const auth_user = await getSupabaseAuthUser(req);
        const bearer_token = getBearerToken(req);

        logUserId = await resolveLogUserId({
          user_id: b?.user_id ?? null,
          user_email: b?.user_email ?? null,
          user_name: b?.user_name ?? null,
          auth_user,
          bearer_token,
        });
      } catch (_) {
        // fallback: body user_id만이라도
        logUserId = b?.user_id ?? null;
      }

      // ✅ sources 컬럼(문자열/JSON 혼재 가능)에는 최소 진단정보를 넣어둠
      const srcObj = {
        mode: "translate",
        error: {
          code: e?.code || null,
          message: e?.message || String(e),
          detail: e?.detail || null,
          fatal: !!e?._fatal,
          httpStatus: e?.httpStatus || null,
        },
      };

      await supabase.from("verification_logs").insert([
        {
          user_id: logUserId, // NOT NULL이면 반드시 채워야 함
          question: textRaw ? String(textRaw).slice(0, 500) : null,
          status: "translate_error",
          truth_score: null,
          cross_score: null,
          adjusted_score: null,
          engines: null,
          keywords: null,
          elapsed: null,
          model_main: null,
          model_eval: null,
          gemini_model: null,
          sources: JSON.stringify(srcObj),
          error: e?.message || String(e),
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

// ✅ Diag: whitelist detailed meta (prod guarded)
app.get("/api/admin/whitelist/status", requireDiag, (req, res) => {
  try {
    return res.json(buildSuccess(getNaverWhitelistMeta()));
  } catch (e) {
    return res.status(500).json(buildError("INTERNAL_ERROR", String(e?.message || e)));
  }
});

// ✅ Legacy compat: /api/check-whitelist (prod guarded)
app.get("/api/check-whitelist", requireDiag, (req, res) => {
  try {
    const meta = getNaverWhitelistMeta();
    return res.json(
      buildSuccess({
        updated: true,
        daysPassed: meta.daysPassed ?? null,
        ...meta,
      })
    );
  } catch (e) {
    return res.status(500).json(buildError("INTERNAL_ERROR", String(e?.message || e)));
  }
});

app.get("/api/admin/errors/recent", requireDiag, (req, res) => {
  try {
    const limitRaw = parseInt(String(req.query?.limit ?? "50"), 10);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 50;

    const items = adminRecentErrors.slice().reverse().slice(0, limit);

    return res.json(
      buildSuccess({
        total: adminRecentErrors.length,
        limit,
        items,
      })
    );
  } catch (e) {
    return res.status(500).json(buildError("INTERNAL_ERROR", String(e?.message || e)));
  }
});

// ✅ Health check (Render / uptime / external monitor)
app.get("/api/health", (req, res) => {
  return res.status(200).json({
    success: true,
    ok: true,
    ts: new Date().toISOString(),
  });
});

// ─────────────────────────────
// ✅ (선택 권장) API 404도 JSON으로 통일
//   - /api/* 중 라우트에 매칭 안 되면 여기로 옴
// ─────────────────────────────
app.use("/api", (req, res, next) => {
  try {
    // ✅ allow admin routes to pass through
    // NOTE: mounted on "/api", so req.path is like "/admin/status"
    const sub = String(req.path || "");
    if (sub.startsWith("/admin/")) return next();

    return res.status(404).json(
      buildError(
        "API_NOT_FOUND",
        "존재하지 않는 API입니다.",
        { method: req.method, path: req.originalUrl }
      )
    );
  } catch (_) {
    return res.status(404).json(
      buildError("API_NOT_FOUND", "존재하지 않는 API입니다.", {
        method: req?.method,
        path: req?.originalUrl || req?.url,
      })
    );
  }
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

// ─────────────────────────────
// Server listen (robust): print listen errors + dev auto-port fallback
// ─────────────────────────────
const _HOST = String(process.env.HOST || "0.0.0.0").trim();

// PORT가 문자열로 들어와도 안전하게 숫자로
function _parsePort(v, fallback = 3000) {
  const n = Number.parseInt(String(v ?? "").trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const _PORT0 = _parsePort(process.env.PORT, 3000);

// ✅ Render health check (must be plain /health if Render is configured so)
app.get("/health", (req, res) => {
  return res.status(200).json({
    ok: true,
    ts: new Date().toISOString(),
  });
});

function _startServer(port, attempt = 0) {
  const server = app.listen(port, _HOST, () => {
    console.log(`🚀 Cross-Verified AI Proxy v18.4.0-pre running on ${_HOST}:${port}`);
    console.log("🔹 LV 모듈 외부화 (/src/modules/klaw_module.js)");
    console.log("🔹 Translation 모듈 활성화 (DeepL + Gemini Flash-Lite Fallback)");
    console.log("🔹 Naver 서버 직접 호출 (Region 제한 해제)");
    console.log("🔹 Supabase + Gemini 2.5 (Flash / Pro / Lite) 정상 동작");
  });

  server.on("error", (e) => {
    const code = e?.code || "UNKNOWN";
    const msg = e?.message || String(e);

    // ✅ 개발환경이면 포트 충돌 시 자동으로 다음 포트로 시도
    if (!isProd && code === "EADDRINUSE" && attempt < 10) {
      const nextPort = port + 1;
      console.error(`💥 listen ${_HOST}:${port} failed (${code}) -> retry on ${nextPort}`);
      setTimeout(() => _startServer(nextPort, attempt + 1), 150);
      return;
    }

    console.error("💥 listen failed:", {
      code,
      message: msg,
      host: _HOST,
      port,
      isProd,
    });
    process.exit(1);
  });

  return server;
}

_startServer(_PORT0);