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
import crypto from "crypto";              // ✅ ADD: 암호화/키ID/UUID
import "express-async-errors";

// ✅ LV (법령검증) 모듈 외부화
import { fetchKLawAll } from "./src/modules/klaw_module.js";

// ✅ 번역모듈 (DeepL + Gemini Flash-Lite fallback)
import { translateText } from "./src/modules/translateText.js";

dotenv.config();

const isProd = process.env.NODE_ENV === "production";
const DEBUG = process.env.DEBUG === "true";

// ✅ ADD: Secrets 암호화(서버 마스터키) + Pacific 리셋 TZ
const SETTINGS_ENC_KEY_B64 = (process.env.SETTINGS_ENC_KEY_B64 || "").trim(); // base64(32bytes)
const GEMINI_RESET_TZ = process.env.GEMINI_RESET_TZ || "America/Los_Angeles"; // 태평양 시간(PT)
const PACIFIC_INFO_TTL_MS = parseInt(process.env.PACIFIC_INFO_TTL_MS || "300000", 10); // 5분 캐시
const GEMINI_KEYRING_MAX = parseInt(process.env.GEMINI_KEYRING_MAX || "10", 10);

const app = express();



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
  const url =
    process.env.SUPABASE_DATABASE_URL ||
    process.env.DATABASE_URL ||
    process.env.DATABASE_URL_INTERNAL ||
    "";

  const u = String(url).trim();

  if (!/^postgres(ql)?:\/\//i.test(u)) {
    throw new Error("DATABASE_URL must start with postgres:// or postgresql://");
  }
  if (/^postgres(ql)?:\/\/https?:\/\//i.test(u)) {
    throw new Error("DATABASE_URL is malformed (contains https:// after protocol)");
  }
  if (u.includes("onrender.com")) {
    throw new Error("DATABASE_URL must be a Postgres URL (Supabase), not a Render app URL");
  }

  // ✅ 추가: Render Postgres 호스트 차단 (dpg-xxx.oregon-postgres.render.com 등)
  try {
    const host = new URL(u).hostname || "";
    if (host.includes("render.com") || host.includes("postgres.render.com")) {
      throw new Error("DATABASE_URL points to Render Postgres. Use SUPABASE_DATABASE_URL instead.");
    }
  } catch {}

  return u;
}

const DB_URL = pickDatabaseUrl();

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

    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    proxy: isProd,

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

// 🔹 (옵션) Pro(verify) 입력 JSON 길이
const VERIFY_INPUT_CHARS = parseInt(process.env.VERIFY_INPUT_CHARS || "12000", 10);

// 모드별 override (안 주면 VERIFY_INPUT_CHARS 사용)
const VERIFY_INPUT_CHARS_QV = parseInt(process.env.VERIFY_INPUT_CHARS_QV || String(VERIFY_INPUT_CHARS), 10);
const VERIFY_INPUT_CHARS_FV = parseInt(process.env.VERIFY_INPUT_CHARS_FV || String(VERIFY_INPUT_CHARS), 10);
const VERIFY_INPUT_CHARS_DV = parseInt(process.env.VERIFY_INPUT_CHARS_DV || String(VERIFY_INPUT_CHARS), 10);
const VERIFY_INPUT_CHARS_CV = parseInt(process.env.VERIFY_INPUT_CHARS_CV || String(VERIFY_INPUT_CHARS), 10);

// 타임아웃/실패 시 “더 줄인” 2차 시도 상한
const VERIFY_INPUT_CHARS_MIN = parseInt(process.env.VERIFY_INPUT_CHARS_MIN || "16000", 10);

// verify에 보낼 블록 수 상한(1차/2차)
const MAX_VERIFY_BLOCKS = parseInt(process.env.MAX_VERIFY_BLOCKS || "6", 10);
const MAX_VERIFY_BLOCKS_MIN = parseInt(process.env.MAX_VERIFY_BLOCKS_MIN || "2", 10);

function getVerifyInputCharsByMode(mode) {
  const m = String(mode || "").toLowerCase();
  if (m === "qv") return VERIFY_INPUT_CHARS_QV;
  if (m === "fv") return VERIFY_INPUT_CHARS_FV;
  if (m === "dv") return VERIFY_INPUT_CHARS_DV;
  if (m === "cv") return VERIFY_INPUT_CHARS_CV;
  return VERIFY_INPUT_CHARS;
}

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
  const s0 = tryStr(input);
  if (s0) return s0;

  const toMeta = (m) => {
    if (!m || typeof m !== "object") return null;
    return {
      effective_engines: m.effective_engines ?? null,
      engines_requested: m.engines_requested ?? null,
      engines_used: m.engines_used ?? null,
    };
  };

  const cutArr = (v, n) => (Array.isArray(v) ? v.slice(0, n) : []);

  const pickTitle = (x) => {
    if (!x || typeof x !== "object") return null;
    const t = x.title ?? x.display_name ?? x.name ?? x.label ?? x.headline ?? null;
    if (Array.isArray(t)) return t[0] ?? null;
    return t ? String(t).slice(0, 160) : null;
  };

  const pickUrl = (x) => {
    if (!x) return null;
    if (typeof x === "string") {
      return x.startsWith("http://") || x.startsWith("https://") ? x : null;
    }
    if (typeof x.source_url === "string" && x.source_url) return x.source_url;
    if (typeof x.url === "string" && x.url) return x.url;
    if (typeof x.link === "string" && x.link) return x.link;
    if (typeof x.html_url === "string" && x.html_url) return x.html_url;
    if (typeof x.id === "string" && x.id.startsWith("http")) return x.id;
    const doi = x.DOI || x.doi;
    if (typeof doi === "string" && doi) return `https://doi.org/${doi}`;
    return null;
  };

  const pickPublishedAt = (x) => {
    if (!x || typeof x !== "object") return null;
    return (
      x.published_at ||
      x.publication_date ||
      x.published_date ||
      x.seendate ||
      x.published ||
      x.created_at ||
      x.updated_at ||
      null
    );
  };

  const slimEvItem = (engine, it) => {
    if (!it) return null;

    if (typeof it !== "object") {
      const url = pickUrl(it);
      const host = url ? _hostFromUrlish(url) : null;
      return {
        evidence_id: null,
        engine,
        title: null,
        source_url: url,
        source_host: host,
        published_at: null,
        age_days: null,
        tier: null,
        naver_type: null,
        evidence_text: null,
        value: String(it).slice(0, 280),
      };
    }

    const source_url = it.source_url || pickUrl(it);
    const source_host = it.source_host || (source_url ? _hostFromUrlish(source_url) : null);

    return {
      evidence_id: it.evidence_id || null,
      engine: it.engine || engine,
      title: it.title ? String(it.title).slice(0, 160) : pickTitle(it),
      source_url: source_url || null,
      source_host: source_host || null,
      published_at: it.published_at || pickPublishedAt(it),
      age_days: typeof it.age_days === "number" ? it.age_days : null,
      tier: typeof it.tier === "number" ? it.tier : null,
      naver_type: it.naver_type || null,
      evidence_text: it.evidence_text ? String(it.evidence_text).slice(0, 600) : null,
    };
  };

  const slimEvs = (engine, arr, topK) =>
    cutArr(arr, topK)
      .map((x) => slimEvItem(engine, x))
      .filter(Boolean);

  // NOTE: BLOCK_EVIDENCE_TOPK / BLOCK_NAVER_EVIDENCE_TOPK 가 파일 어딘가에 const로 있어도,
  // 함수 호출 시점에는 초기화가 끝나 있으니 안전.
  const BLOCK_TOPK = typeof BLOCK_EVIDENCE_TOPK === "number" ? BLOCK_EVIDENCE_TOPK : 2;
  const NAVER_TOPK = typeof BLOCK_NAVER_EVIDENCE_TOPK === "number" ? BLOCK_NAVER_EVIDENCE_TOPK : 2;

  const slimBlocks = Array.isArray(input?.blocks)
    ? input.blocks.map((b) => {
        const ev = (b && typeof b === "object" ? b.evidence : null) || {};
        return {
          id: b?.id ?? null,
          text: String(b?.text || "").slice(0, 280),

          // queries는 “추적/설명”용 (토큰 아끼려면 더 줄여도 됨)
          queries: b?.queries
            ? {
                crossref: b.queries.crossref ? String(b.queries.crossref).slice(0, 120) : null,
                openalex: b.queries.openalex ? String(b.queries.openalex).slice(0, 120) : null,
                wikidata: b.queries.wikidata ? String(b.queries.wikidata).slice(0, 120) : null,
                gdelt: b.queries.gdelt ? String(b.queries.gdelt).slice(0, 120) : null,
                naver: Array.isArray(b.queries.naver)
                  ? b.queries.naver.slice(0, 3).map((q) => String(q).slice(0, 120))
                  : b.queries.naver
                    ? [String(b.queries.naver).slice(0, 120)]
                    : null,
              }
            : null,

          evidence: {
            crossref: slimEvs("crossref", ev.crossref, BLOCK_TOPK),
            openalex: slimEvs("openalex", ev.openalex, BLOCK_TOPK),
            wikidata: slimEvs("wikidata", ev.wikidata, BLOCK_TOPK),
            gdelt: slimEvs("gdelt", ev.gdelt, BLOCK_TOPK),
            naver: slimEvs("naver", ev.naver, NAVER_TOPK),
            github: slimEvs("github", ev.github, BLOCK_TOPK),
          },
        };
      })
    : [];

const toMeta = (m) => {
  if (!m || typeof m !== "object") return null;
  return {
    effective_engines: m.effective_engines ?? null,
    engines_requested: m.engines_requested ?? null,
    engines_used: m.engines_used ?? null,
  };
};

  // 1) meta만 남기고(partial_scores는 절대 넣지 않음) + external은 truncate
  const slim1 = {
    mode: input?.mode,
    query: input?.query,
    core_text: input?.core_text ? String(input.core_text).slice(0, 2000) : "",
    blocks: slimBlocks,
    external: { truncated: true },
    meta: toMeta(input?.meta),
  };

  const s1 = tryStr(slim1);
  if (s1) return s1;

  // 2) 더 줄이기
  const slimmer = {
    mode: slim1.mode,
    query: slim1.query,
    core_text: slim1.core_text,
    blocks: slimBlocks.slice(0, 3),
    external: { truncated: true, reason: "too_large" },
    meta: slim1.meta,
  };

  const s2 = tryStr(slimmer);
  if (s2) return s2;

  // 3) 진짜 최종: 최소 JSON
  return JSON.stringify({
  mode: input?.mode || null,
  query: input?.query || null,
  core_text: input?.core_text ? String(input.core_text).slice(0, 1500) : "",
  meta: toMeta(input?.meta),
  truncated: true,
});
}

const pickUrl = (x) => {
  if (!x) return null;
  if (typeof x === "string") return (x.startsWith("http://") || x.startsWith("https://")) ? x : null;

  // 공통
  if (typeof x.source_url === "string" && x.source_url) return x.source_url;
  if (typeof x.url === "string" && x.url) return x.url;
  if (typeof x.link === "string" && x.link) return x.link;
  if (typeof x.html_url === "string" && x.html_url) return x.html_url;

  // openalex/wikidata에서 id가 URL인 경우
  if (typeof x.id === "string" && x.id.startsWith("http")) return x.id;

  // crossref DOI
  const doi = x.DOI || x.doi;
  if (typeof doi === "string" && doi) return `https://doi.org/${doi}`;

  return null;
};

const pickPublishedAt = (x) => {
  if (!x || typeof x === "string") return null;
  return (
    x.published_at ||
    x.publication_date ||
    x.published_date ||
    x.seendate ||
    x.published ||
    x.created_at ||
    x.updated_at ||
    null
  );
};

const slimGeneric = (engine, arr, n) =>
  cutArr(arr, n).map((x) => {
    const source_url = x?.source_url || pickUrl(x);
    const source_host = x?.source_host || (source_url ? _hostFromUrlish(source_url) : null);

    return {
      evidence_id: x?.evidence_id || null,
      engine,
      title: x?.title || pickTitle(x),
      source_url,
      source_host,
      published_at: pickPublishedAt(x),
      age_days: (typeof x?.age_days === "number" ? x.age_days : null),
    };
  });

const evTopK = Math.min(3, (Number.isFinite(BLOCK_EVIDENCE_TOPK) ? BLOCK_EVIDENCE_TOPK : 3));
const naverTopK = Math.min(3, (Number.isFinite(BLOCK_NAVER_EVIDENCE_TOPK) ? BLOCK_NAVER_EVIDENCE_TOPK : 3));

const slimCrossref = slimGeneric("crossref", ev.crossref, evTopK).map((o, i) => ({
  ...o,
  doi: (ev.crossref?.[i]?.DOI || ev.crossref?.[i]?.doi || null),
}));

const slimOpenalex = slimGeneric("openalex", ev.openalex, evTopK).map((o, i) => ({
  ...o,
  openalex_id: (typeof ev.openalex?.[i]?.id === "string" ? ev.openalex[i].id : null),
  year: (typeof ev.openalex?.[i]?.publication_year === "number" ? ev.openalex[i].publication_year : null),
}));

const slimWikidata = slimGeneric("wikidata", ev.wikidata, 5).map((o, i) => ({
  ...o,
  entity: (ev.wikidata?.[i]?.id || ev.wikidata?.[i]?.qid || ev.wikidata?.[i]?.entity || null),
}));

const slimGdelt = slimGeneric("gdelt", ev.gdelt, evTopK).map((o, i) => ({
  ...o,
  source: (ev.gdelt?.[i]?.source || ev.gdelt?.[i]?.domain || null),
}));

const slimNaver = cutArr(ev.naver, naverTopK).map((x) => {
  const source_url = x?.source_url || x?.link || pickUrl(x);
  return {
    evidence_id: x?.evidence_id || null,
    engine: "naver",
    title: x?.title || pickTitle(x),
    source_url,
    source_host: x?.source_host || (source_url ? _hostFromUrlish(source_url) : null),
    naver_type: x?.naver_type || null,
    tier: x?.tier || null,
    published_at: pickPublishedAt(x),
    age_days: (typeof x?.age_days === "number" ? x.age_days : null),
  };
});

return {
  id: b?.id ?? null,
  text: String(b?.text || "").slice(0, 280),

  // ✅ 디버깅/설명용: queries 유지(크기 제한)
  queries: b?.queries
    ? {
        crossref: b.queries.crossref ? String(b.queries.crossref).slice(0, 120) : null,
        openalex: b.queries.openalex ? String(b.queries.openalex).slice(0, 120) : null,
        wikidata: b.queries.wikidata ? String(b.queries.wikidata).slice(0, 120) : null,
        gdelt: b.queries.gdelt ? String(b.queries.gdelt).slice(0, 120) : null,
        naver: Array.isArray(b.queries.naver)
          ? b.queries.naver.slice(0, 3).map((q) => String(q).slice(0, 120))
          : b.queries.naver
            ? [String(b.queries.naver).slice(0, 120)]
            : null,
      }
    : null,

  evidence: {
    crossref: mapSlim(ev.crossref),
    openalex: mapSlim(ev.openalex),
    wikidata: mapSlim(ev.wikidata),
    gdelt: mapSlim(ev.gdelt),
    naver: mapSlim(ev.naver),
    github: mapSlim(ev.github),
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
  external: { truncated: true, reason: "too_large" },
  meta: slim1.meta,
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
// ✅ S-11-1) Conflict pool 보존/요약용 헬퍼
//  - “응답/verify 입력”은 슬림하게 유지하되,
//  - conflictIndex 계산용 raw conflict 풀은 절대 유실되지 않게 별도로 뽑아둔다.
// ─────────────────────────────

function s11_pickUrlAny(x) {
  if (!x) return null;
  if (typeof x === "string") {
    return (x.startsWith("http://") || x.startsWith("https://")) ? x : null;
  }
  if (typeof x.source_url === "string" && x.source_url) return x.source_url;
  if (typeof x.url === "string" && x.url) return x.url;
  if (typeof x.link === "string" && x.link) return x.link;
  if (typeof x.html_url === "string" && x.html_url) return x.html_url;
  if (typeof x.id === "string" && x.id.startsWith("http")) return x.id;

  const doi = x.DOI || x.doi;
  if (typeof doi === "string" && doi) return `https://doi.org/${doi}`;
  return null;
}

function s11_hostFromUrlish(url) {
  const u = String(url || "").trim();
  if (!u) return null;

  // 기존 헬퍼가 있으면 그걸 우선 사용
  try {
    if (typeof _hostFromUrlish === "function") return _hostFromUrlish(u);
  } catch {}

  try {
    const h = new URL(u).hostname || "";
    return h ? h.replace(/^www\./i, "") : null;
  } catch {
    return null;
  }
}

function s11_pickTitleAny(x) {
  if (!x || typeof x !== "object") return null;
  const t = x.title ?? x.display_name ?? x.name ?? x.label ?? x.headline ?? null;
  if (Array.isArray(t)) return t[0] ? String(t[0]).slice(0, 180) : null;
  return t ? String(t).slice(0, 180) : null;
}

function s11_slimEvidenceItem(it) {
  // conflict pool은 “크기/토큰” 때문에 슬림한 형태로만 보존
  if (!it) return null;

  if (typeof it !== "object") {
    const url = s11_pickUrlAny(it);
    const host = url ? s11_hostFromUrlish(url) : null;
    return {
      engine: null,
      title: null,
      source_url: url,
      source_host: host,
      published_at: null,
      age_days: null,
      tier: null,
      naver_type: null,
      value: String(it).slice(0, 280),
    };
  }

  const url = it.source_url || s11_pickUrlAny(it);
  const host = it.source_host || (url ? s11_hostFromUrlish(url) : null);

  return {
    engine: it.engine || null,
    title: it.title ? String(it.title).slice(0, 180) : s11_pickTitleAny(it),
    source_url: url || null,
    source_host: host || null,
    published_at: it.published_at || it.publication_date || it.published_date || it.seendate || it.published || it.created_at || it.updated_at || null,
    age_days: (typeof it.age_days === "number" ? it.age_days : null),
    tier: (typeof it.tier === "number" ? it.tier : null),
    naver_type: it.naver_type || null,
    evidence_id: it.evidence_id || null,
  };
}

function s11_collectConflictItemsFromVerifyMeta(vm) {
  // vm.blocks[].evidence_items.conflict + (있으면) vm.evidence_items.conflict 까지 긁어서 “raw conflict pool” 생성
  const raw = [];
  if (!vm || typeof vm !== "object") return raw;

  const blocks = Array.isArray(vm.blocks) ? vm.blocks : [];
  for (const b of blocks) {
    const arr = b?.evidence_items?.conflict;
    if (Array.isArray(arr)) raw.push(...arr);
  }

  const top = vm?.evidence_items?.conflict;
  if (Array.isArray(top)) raw.push(...top);

  // 슬림 + dedupe(가능한 범위에서)
  const out = [];
  const seen = new Set();

  for (const it of raw) {
    const slim = s11_slimEvidenceItem(it);
    if (!slim) continue;

    const key = [
      slim.engine || "",
      slim.source_host || "",
      slim.source_url || "",
      slim.title || "",
    ].join("|");

    if (seen.has(key)) continue;
    seen.add(key);
    out.push(slim);
  }

  return out;
}

function s11_countByHost(items) {
  const m = {};
  for (const it of (Array.isArray(items) ? items : [])) {
    const h = String(it?.source_host || "").trim();
    if (!h) continue;
    m[h] = (m[h] || 0) + 1;
  }
  return m;
}

// ✅ S-11-1 메인: “응답/verifyMeta 슬림”과 별개로 raw conflict pool 요약을 만들어 둔다.
// - 호출부에서: const conflictPool = s11_buildConflictPoolSummary(verifyMetaRaw);
// - 그리고 S-9 cap 이후에도 conflictPool은 그대로 유지
function s11_buildConflictPoolSummary(vmRaw) {
  const items = s11_collectConflictItemsFromVerifyMeta(vmRaw);
  const by_host = s11_countByHost(items);
  const hostEntries = Object.entries(by_host).sort((a, b) => b[1] - a[1]);

  const counts = { support: 0, conflict: 0, irrelevant: 0, blocks: 0 };
  const blocksArr = Array.isArray(vmRaw?.blocks) ? vmRaw.blocks : [];
  counts.blocks = blocksArr.length;

  for (const b of blocksArr) {
    const ei = b?.evidence_items && typeof b.evidence_items === 'object' ? b.evidence_items : null;
    if (!ei) continue;

    counts.support += Array.isArray(ei.support) ? ei.support.length : 0;
    counts.conflict += Array.isArray(ei.conflict) ? ei.conflict.length : 0;
    counts.irrelevant += Array.isArray(ei.irrelevant) ? ei.irrelevant.length : 0;
  }

  return {
    counts,
    conflict_by_host: Object.fromEntries(hostEntries),
    conflict_hosts_top: hostEntries.map(([h]) => h),
    items: DEBUG ? items : undefined, // ��� ��ุ, DEBUG�� items����
  };
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

function calcCompositeRecency({
  mode,
  recency_need = null,
  gdelt = [],
  naver = [],
  crossref = [],
  openalex = [],
  github = [],
  wikidata = [],
}) {
  // ✅ 엔진별 기본 반감기(t½, days) — 서버 고정 기본값(ENV로 덮어쓰기 가능)
  const BASE_T_HALF_DAYS = {
    gdelt: Number(process.env.RECENCY_T_HALF_GDELT_DAYS ?? "21"),
    naver: Number(process.env.RECENCY_T_HALF_NAVER_DAYS ?? "21"),
    crossref: Number(process.env.RECENCY_T_HALF_CROSSREF_DAYS ?? String(365 * 5)),
    openalex: Number(process.env.RECENCY_T_HALF_OPENALEX_DAYS ?? String(365 * 5)),
    github: Number(process.env.RECENCY_T_HALF_GITHUB_DAYS ?? "180"),
    wikidata: Number(process.env.RECENCY_T_HALF_WIKIDATA_DAYS ?? String(365 * 10)),
  };

  const halfLifeDecay = (days, halfLifeDays) => {
    const d = Number.isFinite(days) ? Math.max(0, days) : 0;
    const h = Number.isFinite(halfLifeDays) && halfLifeDays > 0 ? halfLifeDays : 365;
    // decay = 0.5^(days / t½)
    return Math.pow(0.5, d / h);
  };

  const scoreFromDates = (dateMsList, halfLifeDays, floor = 0.5, span = 0.45) => {
    const ts = (Array.isArray(dateMsList) ? dateMsList : []).filter((t) => t && Number.isFinite(t));
    if (!ts.length) return null;

    const now = Date.now();
    const scores = ts.map((t) => {
      const days = (now - t) / (1000 * 60 * 60 * 24);
      const decay = halfLifeDecay(days, halfLifeDays);
      return floor + span * clamp01(decay);
    });

    return scores.reduce((s, v) => s + v, 0) / scores.length;
  };

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
    wCode = dvcvCodeW; wPaper = dvcvPaperW; wNews = dvcvNewsW; floor = dvcvFloor;
  } else {
    wNews = qvfvNewsW; wPaper = qvfvPaperW; wCode = 0; floor = qvfvFloor;
  }

  // ✅ recency_need 라벨은 “반감기 스케일(=감쇠 속도)”에만 반영
  const rn = String(recency_need || "").trim().toLowerCase();
  const rnLevel = ["high", "medium", "low"].includes(rn) ? rn : "medium";

  let hlNewsMul = 1.0, hlPaperMul = 1.0, hlCodeMul = 1.0, floorDelta = 0.0;
  if (rnLevel === "high") {
    hlNewsMul = 0.60; hlPaperMul = 0.85; hlCodeMul = 0.85; floorDelta = -0.04;
  } else if (rnLevel === "low") {
    hlNewsMul = 1.60; hlPaperMul = 1.15; hlCodeMul = 1.15; floorDelta = +0.03;
  }

  floor = clamp01(floor + floorDelta);

  const tHalf = {
    gdelt: Math.max(1, BASE_T_HALF_DAYS.gdelt * hlNewsMul),
    naver: Math.max(1, BASE_T_HALF_DAYS.naver * hlNewsMul),
    crossref: Math.max(1, BASE_T_HALF_DAYS.crossref * hlPaperMul),
    openalex: Math.max(1, BASE_T_HALF_DAYS.openalex * hlPaperMul),
    github: Math.max(1, BASE_T_HALF_DAYS.github * hlCodeMul),
    wikidata: Math.max(1, BASE_T_HALF_DAYS.wikidata * hlPaperMul),
  };

  // gdelt: a.date 기반
  const gdeltTs = (Array.isArray(gdelt) ? gdelt : [])
    .map((a) => (a?.date ? new Date(a.date).getTime() : null))
    .filter((t) => t && Number.isFinite(t));

  // naver: naver_type==="news" && pubDate 기반
  const naverTs = (Array.isArray(naver) ? naver : [])
    .filter((it) => it?.naver_type === "news" && it?.pubDate)
    .map((it) => parseNaverPubDate(it.pubDate))
    .filter((t) => t && Number.isFinite(t));

  // papers: 연도 기반(엔진별 분리)
  const nowY = new Date().getFullYear();
  const crossYears = (Array.isArray(crossref) ? crossref : [])
    .map(extractPaperYear)
    .filter((y) => Number.isFinite(y) && y >= 1900 && y <= nowY + 1);

  const openYears = (Array.isArray(openalex) ? openalex : [])
    .map(extractPaperYear)
    .filter((y) => Number.isFinite(y) && y >= 1900 && y <= nowY + 1);

  const bestYearScore = (years, halfLifeDays) => {
    if (!Array.isArray(years) || !years.length) return null;
    const bestY = Math.max(...years);
    const ageYears = Math.max(0, nowY - bestY);
    const days = ageYears * 365.25;
    const decay = halfLifeDecay(days, halfLifeDays);
    return 0.85 + 0.15 * clamp01(decay);
  };

  const githubTs = (Array.isArray(github) ? github : [])
    .map((r) => (r?.updated ? new Date(r.updated).getTime() : null))
    .filter((t) => t && Number.isFinite(t));

  const wikidataTs = (Array.isArray(wikidata) ? wikidata : [])
    .map((x) => (
      x?.modified ? new Date(x.modified).getTime()
      : x?.updated ? new Date(x.updated).getTime()
      : null
    ))
    .filter((t) => t && Number.isFinite(t));

  const score_gdelt = gdeltTs.length ? scoreFromDates(gdeltTs, tHalf.gdelt, 0.5, 0.45) : null;
  const score_naver = naverTs.length ? scoreFromDates(naverTs, tHalf.naver, 0.5, 0.45) : null;
  const score_crossref = crossYears.length ? bestYearScore(crossYears, tHalf.crossref) : null;
  const score_openalex = openYears.length ? bestYearScore(openYears, tHalf.openalex) : null;

  const score_github = githubTs.length
    ? (() => {
        const now = Date.now();
        const daysList = githubTs.map((t) => (now - t) / (1000 * 60 * 60 * 24));
        const decays = daysList.map((d) => halfLifeDecay(d, tHalf.github));
        const decay = decays.reduce((s, v) => s + v, 0) / decays.length;
        return 0.8 + 0.2 * clamp01(decay);
      })()
    : null;

  // wikidata: 존재하면 아주 약하게만(없으면 null)
  const score_wikidata = wikidataTs.length
    ? (() => {
        const newest = Math.max(...wikidataTs);
        const days = (Date.now() - newest) / (1000 * 60 * 60 * 24);
        const decay = halfLifeDecay(days, tHalf.wikidata);
        return 0.9 + 0.1 * clamp01(decay);
      })()
    : null;

  // ✅ 가중치 분배(엔진별) — 존재하는 신호에만 분배
  const hasGdelt = typeof score_gdelt === "number";
  const hasNaver = typeof score_naver === "number";
  const newsDen = (hasGdelt ? 1 : 0) + (hasNaver ? 1 : 0);

  const hasCross = typeof score_crossref === "number";
  const hasOpen = typeof score_openalex === "number";
  const paperDen = (hasCross ? 1 : 0) + (hasOpen ? 1 : 0);

  const hasGithub = typeof score_github === "number";

  const wGdelt = newsDen > 0 ? (wNews * (hasGdelt ? 1 : 0) / newsDen) : 0;
  const wNaver = newsDen > 0 ? (wNews * (hasNaver ? 1 : 0) / newsDen) : 0;

  const wCrossref = paperDen > 0 ? (wPaper * (hasCross ? 1 : 0) / paperDen) : 0;
  const wOpenalex = paperDen > 0 ? (wPaper * (hasOpen ? 1 : 0) / paperDen) : 0;

  const wGithub = hasGithub ? wCode : 0;

  // 신호가 없으면 “중립(약하게만)” 값
  const neutralNews = 0.95;
  const neutralPaper = 0.95;
  const neutralCode = 0.90;

  const sGdelt = hasGdelt ? score_gdelt : neutralNews;
  const sNaver = hasNaver ? score_naver : neutralNews;

  const sCross = hasCross ? score_crossref : neutralPaper;
  const sOpen = hasOpen ? score_openalex : neutralPaper;

  const sGithub = hasGithub ? score_github : neutralCode;

  // ✅ overall = 1 - Σ w_e*(1-score_e)
  const overall =
    1
    - wGdelt * (1 - sGdelt)
    - wNaver * (1 - sNaver)
    - wCrossref * (1 - sCross)
    - wOpenalex * (1 - sOpen)
    - wGithub * (1 - sGithub);

  const clamped = Math.max(floor, clamp01(overall));

  return {
    overall: clamped,
    detail: {
      engine_scores: {
        gdelt: score_gdelt,
        naver: score_naver,
        crossref: score_crossref,
        openalex: score_openalex,
        github: score_github,
        wikidata: score_wikidata,
      },
      weights_engine: {
        gdelt: wGdelt,
        naver: wNaver,
        crossref: wCrossref,
        openalex: wOpenalex,
        github: wGithub,
      },
      weights_group: { wNews, wPaper, wCode, floor },
      half_life_days: tHalf,
      recency_need: {
        raw: recency_need,
        level: rnLevel,
        half_life_multipliers: { hlNewsMul, hlPaperMul, hlCodeMul },
        floorDelta,
      },
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

// ─────────────────────────────
// ✅ Evidence ID 부여 + 역매핑(추적) 유틸
// ─────────────────────────────
function _inferSourceUrl(engine, item) {
  if (!item) return null;
  if (typeof item === "string") return item.startsWith("http") ? item : null;

  if (engine === "naver") return item.source_url || item.link || item.url || null;
  if (engine === "gdelt") return item.url || item.source_url || item.link || null;

  // crossref/openalex/wikidata 등 공통 heuristics
  const u =
    item.source_url ||
    item.url ||
    item.link ||
    item.URL ||
    (Array.isArray(item.url) ? item.url[0] : null) ||
    (Array.isArray(item.link) && item.link[0] && item.link[0].URL ? item.link[0].URL : null);

  if (u) return u;

  // DOI가 있으면 doi.org로 구성
  const doi = item.DOI || item.doi || null;
  if (doi && typeof doi === "string") return `https://doi.org/${doi}`;

  // openalex id가 URL인 경우
  const id = item.id || item.openalex_id || null;
  if (id && typeof id === "string" && id.startsWith("http")) return id;

  return null;
}

function _inferTitle(engine, item) {
  if (!item) return null;
  if (typeof item === "string") return null;
  return (
    item.title ||
    item.display_name ||
    item.name ||
    item.label ||
    item.headline ||
    null
  );
}

// block.evidence[engine][] 각 item에 evidence_id/engine/source_url/source_host/title을 붙임
function attachEvidenceIdsToBlock(block) {
  if (!block || typeof block !== "object") return block;
  const bid = block.id ?? "x";
  const ev = block.evidence && typeof block.evidence === "object" ? block.evidence : null;
  if (!ev) return block;

  for (const [engine, arr] of Object.entries(ev)) {
    if (!Array.isArray(arr)) continue;

    ev[engine] = arr.map((it, idx) => {
      const evidence_id = `b${bid}:${engine}:${idx + 1}`;
      const source_url = _inferSourceUrl(engine, it);
      const source_host = source_url ? _hostFromUrlish(source_url) : null;
      const title = _inferTitle(engine, it);

      if (it && typeof it === "object") {
        return {
          ...it,
          evidence_id,
          engine,
          source_url: it.source_url || source_url,
          source_host: it.source_host || source_host,
          title: it.title || title,
        };
      }

      // 문자열/기타 타입도 안전하게 object로 감쌈
      return {
        evidence_id,
        engine,
        value: it,
        source_url,
        source_host,
        title,
      };
    });
  }

  return block;
}

// ─────────────────────────────
// ✅ verifyInput을 확 줄이기 위한 Slim 유틸 (필드 화이트리스트)
//   - Gemini verify에는 “필요한 최소 필드”만 전달
//   - 서버 내부 계산/로그(partial_scores, 원본 evidence)는 그대로 유지
// ─────────────────────────────
function slimEvidenceItemForVerify(it) {
  if (!it || typeof it !== "object") return null;

  return {
    evidence_id: it.evidence_id || null,
    engine: it.engine || null,

    // verify 출력/설명에 필요한 최소 필드
    title: it.title ? String(it.title).slice(0, 160) : null,
    source_url: it.source_url || null,
    source_host: it.source_host || null,

    // 시의성/샘플링에 도움 되는 최소 메타
    age_days: (typeof it.age_days === "number" ? it.age_days : null),
    published_at: it.published_at || null,

    // authority 관련 최소 필드
    tier: (typeof it.tier === "number" ? it.tier : null),
    naver_type: it.naver_type || null,
  };
evidence_text: it.evidence_text ? String(it.evidence_text).slice(0, 600) : null,
}

function slimBlockForVerifyLLM(b) {
  const ev = (b && b.evidence && typeof b.evidence === "object") ? b.evidence : {};
  const mapSlim = (arr) => (Array.isArray(arr) ? arr.map(slimEvidenceItemForVerify).filter(Boolean) : []);

  return {
    id: b?.id ?? null,
    text: String(b?.text || "").slice(0, 280),
    evidence: {
      crossref: mapSlim(ev.crossref),
      openalex: mapSlim(ev.openalex),
      wikidata: mapSlim(ev.wikidata),
      gdelt: mapSlim(ev.gdelt),
      naver: mapSlim(ev.naver),
      github: mapSlim(ev.github),
    },
  };
}

// ─────────────────────────────
// ✅ verify evidence 샘플러: 권위/신선도/유사도 우선으로 줄이기
// ─────────────────────────────
function scoreEvidenceItemForVerify(engine, it) {
  if (!it) return 0;

  // 기본 점수
  let s = 0;

  // 1) authority tier (있으면 최우선)
  const tier = (typeof it?.tier === "number" ? it.tier : null);
  if (tier !== null) {
    // tier가 낮을수록(1=최상) 점수 높게
    if (tier <= 1) s += 30;
    else if (tier === 2) s += 18;
    else if (tier === 3) s += 10;
    else s += 4;
  }

  // 2) naver_type: 뉴스/백과/공식 문서 우대(있을 때만)
  const nt = String(it?.naver_type || "").toLowerCase();
  if (engine === "naver" && nt) {
    if (nt.includes("news")) s += 10;
    else if (nt.includes("encyc") || nt.includes("dict")) s += 8;
    else if (nt.includes("web")) s += 4;
  }

  // 3) recency: age_days 낮을수록 우대
  const age = (typeof it?.age_days === "number" ? it.age_days : null);
  if (age !== null) {
    if (age <= 7) s += 10;
    else if (age <= 30) s += 6;
    else if (age <= 180) s += 3;
    else s += 1;
  }

  // 4) evidence_id/URL/host가 있으면 reliability 가점(추적 가능성)
  if (it?.evidence_id) s += 2;
  if (it?.source_url) s += 2;
  if (it?.source_host) s += 1;

  // 5) 최소 타이틀 존재
  if (it?.title) s += 1;

  return s;
}

function sampleEvidenceForVerify(engine, arr, k) {
  const items = Array.isArray(arr) ? arr : [];
  if (items.length <= k) return items;

  // 점수 기반 정렬
  const ranked = items
    .map((it, idx) => ({ it, idx, score: scoreEvidenceItemForVerify(engine, it) }))
    .sort((a, b) => (b.score - a.score) || (a.idx - b.idx))
    .map((x) => x.it);

  // 1개는 “최고 권위/최고점”
  const out = ranked.slice(0, k);

  // 다양성: host 중복 최소화(가능하면)
  const seenHost = new Set();
  const uniqOut = [];
  for (const it of out) {
    const h = it?.source_host ? String(it.source_host).toLowerCase() : null;
    if (h && seenHost.has(h)) continue;
    if (h) seenHost.add(h);
    uniqOut.push(it);
    if (uniqOut.length >= k) break;
  }
  // uniq 부족하면 원본 out로 보충
  if (uniqOut.length < k) {
    for (const it of out) {
      if (uniqOut.includes(it)) continue;
      uniqOut.push(it);
      if (uniqOut.length >= k) break;
    }
  }

  return uniqOut;
}

// blocksForVerify 전체에서 evidence_id -> 최소 메타 lookup 생성
function buildEvidenceLookupFromBlocks(blocks) {
  const map = {};
  const arr = Array.isArray(blocks) ? blocks : [];
  for (const b of arr) {
    const ev = b?.evidence || {};
    for (const [engine, items] of Object.entries(ev)) {
      if (!Array.isArray(items)) continue;
      for (const it of items) {
        const id = it?.evidence_id;
        if (!id) continue;
        if (!map[id]) {
          map[id] = {
            evidence_id: id,
            engine: it?.engine || engine,
            source_url: it?.source_url || it?.link || it?.url || null,
            source_host: it?.source_host || (it?.source_url ? _hostFromUrlish(it.source_url) : null),
            title: it?.title || null,
          };
        }
      }
    }
  }
  return map;
}

// ─────────────────────────────
// ✅ verifyMeta 안전 보정: evidence_ids 누락/불완전 자동 복구
// ─────────────────────────────
function normalizeVerifyMetaWithEvidenceIds(verifyMeta, evidenceLookup) {
    const report = {
    applied: false,
    blocks_total: 0,
    blocks_fixed: 0,
    ids_injected: 0,
    ids_from_items: 0,
    ids_from_lookup_by_url: 0,

    // ✅ 새로 추가: lookup에 없는(환각/오타) evidence_id 제거 카운트
    invalid_ids_dropped: 0,
    invalid_ids_dropped_by_kind: { support: 0, conflict: 0, irrelevant: 0 },

    warnings: [],
  };

  if (!verifyMeta || typeof verifyMeta !== "object" || !Array.isArray(verifyMeta.blocks)) {
    report.warnings.push("verifyMeta.blocks not array");
    return { meta: verifyMeta, report };
  }

  report.applied = true;
  report.blocks_total = verifyMeta.blocks.length;

  const normalizeUrlKey = (u) => {
    if (!u || typeof u !== "string") return null;
    const s = u.trim();
    if (!s) return null;
    try {
      const x = new URL(s);
      x.hash = ""; // fragment 제거

      // 흔한 트래킹 파라미터 제거
      const drop = new Set(["utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid"]);
      for (const k of Array.from(x.searchParams.keys())) {
        if (drop.has(k)) x.searchParams.delete(k);
      }

      // trailing slash 통일
      const normPath = x.pathname.replace(/\/+$/, "");
      x.pathname = normPath || "/";

      // key는 origin+path+sorted query(자동 정렬은 아니지만 URL이 보통 안정적)
      return x.toString();
    } catch {
      // URL 파싱 실패면 원문으로라도 매칭
      return s;
    }
  };

  // url(norm) -> evidence_id reverse index (lookup 기반)
  const urlToId = {};
  if (evidenceLookup && typeof evidenceLookup === "object") {
    for (const [id, v] of Object.entries(evidenceLookup)) {
      const u = v?.source_url;
      const key = normalizeUrlKey(u);
      if (key && !urlToId[key]) urlToId[key] = id;
    }
  }

  const ensureIdsObj = (blk) => {
    if (!blk.evidence_ids || typeof blk.evidence_ids !== "object") {
      blk.evidence_ids = { support: [], conflict: [], irrelevant: [] };
      return;
    }
    if (!Array.isArray(blk.evidence_ids.support)) blk.evidence_ids.support = [];
    if (!Array.isArray(blk.evidence_ids.conflict)) blk.evidence_ids.conflict = [];
    if (!Array.isArray(blk.evidence_ids.irrelevant)) blk.evidence_ids.irrelevant = [];
  };

  const pickIdsFromItems = (items) => {
    const out = [];
    const arr = Array.isArray(items) ? items : [];
    for (const it of arr) {
      const id = it?.evidence_id;
      if (id && typeof id === "string") out.push(id);
    }
    return out;
  };

    const pickIdsFromItemsByUrl = (items) => {
    const out = [];
    const arr = Array.isArray(items) ? items : [];
    for (const it of arr) {
      const u = it?.source_url || it?.url || it?.link || null;
      const key = normalizeUrlKey(u);
      if (key && urlToId[key]) out.push(urlToId[key]);
    }
    return out;
  };

  const uniq = (arr, limit = 16) => {
    const set = new Set();
    const out = [];
    for (const x of (Array.isArray(arr) ? arr : [])) {
      const s = String(x || "").trim();
      if (!s) continue;
      if (set.has(s)) continue;
      set.add(s);
      out.push(s);
      if (out.length >= limit) break;
    }
    return out;
  };

  const hasLookup = evidenceLookup && typeof evidenceLookup === "object";

  // (선택) lookup이 없을 때 warning 남기기
  if (!hasLookup) report.warnings.push("evidenceLookup missing; invalid id filtering skipped");

  const filterValidIds = (ids, kind) => {
    const arr = Array.isArray(ids) ? ids : [];
    if (!hasLookup) {
      // lookup이 없으면 필터링 못함(기존 동작 유지)
      return { kept: arr, dropped: [] };
    }

    const kept = [];
    const dropped = [];

    for (const x of arr) {
      const id = String(x || "").trim();
      if (!id) continue;
      if (evidenceLookup[id]) kept.push(id);
      else dropped.push(id);
    }

    return { kept: uniq(kept, 12), dropped: uniq(dropped, 12) };
  };

  for (const blk of verifyMeta.blocks) {
    if (!blk || typeof blk !== "object") continue;

    ensureIdsObj(blk);

    const before = {
      s: blk.evidence_ids.support.length,
      c: blk.evidence_ids.conflict.length,
      i: blk.evidence_ids.irrelevant.length,
    };

    const evItems = blk.evidence_items || null;

    // 1) evidence_items에 evidence_id가 있으면 그걸 1순위로 채움
    if (before.s === 0) {
      const ids = pickIdsFromItems(evItems?.support);
      if (ids.length) {
        blk.evidence_ids.support = uniq(ids, 12);
        report.ids_injected += blk.evidence_ids.support.length;
        report.ids_from_items += blk.evidence_ids.support.length;
      }
    }
    if (before.c === 0) {
      const ids = pickIdsFromItems(evItems?.conflict);
      if (ids.length) {
        blk.evidence_ids.conflict = uniq(ids, 12);
        report.ids_injected += blk.evidence_ids.conflict.length;
        report.ids_from_items += blk.evidence_ids.conflict.length;
      }
    }
    if (before.i === 0) {
      const ids = pickIdsFromItems(evItems?.irrelevant);
      if (ids.length) {
        blk.evidence_ids.irrelevant = uniq(ids, 12);
        report.ids_injected += blk.evidence_ids.irrelevant.length;
        report.ids_from_items += blk.evidence_ids.irrelevant.length;
      }
    }

    // 2) evidence_id가 없으면 source_url로 lookup 매칭(2순위)
    if ((blk.evidence_ids.support?.length || 0) === 0) {
      const ids = pickIdsFromItemsByUrl(evItems?.support);
      if (ids.length) {
        blk.evidence_ids.support = uniq(ids, 12);
        report.ids_injected += blk.evidence_ids.support.length;
        report.ids_from_lookup_by_url += blk.evidence_ids.support.length;
      }
    }
    if ((blk.evidence_ids.conflict?.length || 0) === 0) {
      const ids = pickIdsFromItemsByUrl(evItems?.conflict);
      if (ids.length) {
        blk.evidence_ids.conflict = uniq(ids, 12);
        report.ids_injected += blk.evidence_ids.conflict.length;
        report.ids_from_lookup_by_url += blk.evidence_ids.conflict.length;
      }
    }
    if ((blk.evidence_ids.irrelevant?.length || 0) === 0) {
      const ids = pickIdsFromItemsByUrl(evItems?.irrelevant);
      if (ids.length) {
        blk.evidence_ids.irrelevant = uniq(ids, 12);
        report.ids_injected += blk.evidence_ids.irrelevant.length;
        report.ids_from_lookup_by_url += blk.evidence_ids.irrelevant.length;
      }
    }

       // ✅ 3) invalid evidence_ids drop (lookup에 없는 값 제거)
    let droppedAny = false;

    const fs = filterValidIds(blk.evidence_ids.support, "support");
    const fc = filterValidIds(blk.evidence_ids.conflict, "conflict");
    const fi = filterValidIds(blk.evidence_ids.irrelevant, "irrelevant");

    if (fs.dropped.length || fc.dropped.length || fi.dropped.length) {
      droppedAny = true;

      // 블록에 "무엇이 드롭됐는지" 소량만 남김(너무 커지지 않게)
      blk.invalid_evidence_ids_dropped = {
        support: fs.dropped.slice(0, 8),
        conflict: fc.dropped.slice(0, 8),
        irrelevant: fi.dropped.slice(0, 8),
      };

      const ds = fs.dropped.length;
      const dc = fc.dropped.length;
      const di = fi.dropped.length;

      report.invalid_ids_dropped += (ds + dc + di);
      report.invalid_ids_dropped_by_kind.support += ds;
      report.invalid_ids_dropped_by_kind.conflict += dc;
      report.invalid_ids_dropped_by_kind.irrelevant += di;

      // 실제 evidence_ids는 “유효한 것만” 유지
      blk.evidence_ids.support = fs.kept;
      blk.evidence_ids.conflict = fc.kept;
      blk.evidence_ids.irrelevant = fi.kept;
    }

    const after = {
      s: blk.evidence_ids.support.length,
      c: blk.evidence_ids.conflict.length,
      i: blk.evidence_ids.irrelevant.length,
    };

    const fixed =
      (before.s === 0 && after.s > 0) ||
      (before.c === 0 && after.c > 0) ||
      (before.i === 0 && after.i > 0) ||
      droppedAny;

    if (fixed) report.blocks_fixed += 1;
  }

  return { meta: verifyMeta, report };
}

// ─────────────────────────────
// S-11-1) Raw conflict pool helpers (compute BEFORE response caps)
// ─────────────────────────────
function _deepCloneJson(obj) {
  try {
    return obj == null ? obj : JSON.parse(JSON.stringify(obj));
  } catch {
    return null;
  }
}

function _pushArray(dst, v) {
  if (!dst) return;
  if (!v) return;
  if (Array.isArray(v)) dst.push(...v);
  else dst.push(v);
}

function _getEvidenceHost(ev) {
  const h = ev?.host || ev?.source_host || ev?.sourceHost || null;
  if (h) return _stripWww(String(h));

  const u = ev?.url || ev?.source_url || ev?.sourceUrl || ev?.link || null;
  return u ? _stripWww(_hostFromUrlish(u)) : "";
}

function _collectVerifyMetaPools(vm) {
  const blocks = Array.isArray(vm?.blocks) ? vm.blocks : [];
  const pools = {
    support: [],
    conflict: [],
    irrelevant: [],
    by_host: {}, // conflict host distribution
    counts: { support: 0, conflict: 0, irrelevant: 0, blocks: blocks.length },
  };

  for (const b of blocks) {
    const ei = b?.evidence_items || {};
    const es = Array.isArray(ei.support) ? ei.support : [];
    const ec = Array.isArray(ei.conflict) ? ei.conflict : [];
    const eiIr = Array.isArray(ei.irrelevant) ? ei.irrelevant : [];

    const s = b?.supportItems ?? b?.support_items ?? b?.support ?? b?.supports ?? [];
    const c =
      b?.conflictItems ??
      b?.conflict_items ??
      b?.conflict ??
      b?.contradict ??
      b?.contradicts ??
      [];
    const i = b?.irrelevantItems ?? b?.irrelevant_items ?? b?.irrelevant ?? b?.irrelevants ?? [];

    _pushArray(pools.support, s);
    _pushArray(pools.support, es);
    _pushArray(pools.conflict, c);
    _pushArray(pools.conflict, ec);
    _pushArray(pools.irrelevant, i);
    _pushArray(pools.irrelevant, eiIr);
  }

  const topEi = vm?.evidence_items || {};
  if (topEi && typeof topEi === "object") {
    _pushArray(pools.support, Array.isArray(topEi.support) ? topEi.support : []);
    _pushArray(pools.conflict, Array.isArray(topEi.conflict) ? topEi.conflict : []);
    _pushArray(pools.irrelevant, Array.isArray(topEi.irrelevant) ? topEi.irrelevant : []);
  }

  pools.counts.support = pools.support.length;
  pools.counts.conflict = pools.conflict.length;
  pools.counts.irrelevant = pools.irrelevant.length;

  for (const ev of pools.conflict) {
    const host = _getEvidenceHost(ev);
    if (!host) continue;
    pools.by_host[host] = (pools.by_host[host] || 0) + 1;
  }

  return pools;
}

function buildRawConflictPoolSummary(rawVerifyMeta, maxHosts = 12) {
  const pools = _collectVerifyMetaPools(rawVerifyMeta || {});
  const hostEntries = Object.entries(pools.by_host).sort((a, b) => b[1] - a[1]);

  return {
    counts: pools.counts,
    conflict_by_host: Object.fromEntries(hostEntries.slice(0, maxHosts)),
    conflict_hosts_top: hostEntries.slice(0, maxHosts).map(([h]) => h),
  };
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

// ─────────────────────────────
// ✅ Authority override (실제 근거 도메인 기반)
// ─────────────────────────────
const AUTHORITY_DOMAINS = [
  "kostat.go.kr",
  "data.go.kr",
  "mois.go.kr",
  "oecd.org",
  "un.org",
  "unstats.un.org",
  "worldbank.org",
  "imf.org",
  "law.go.kr",
];

function isAuthorityHost(host) {
  const h = _stripWww(host);
  if (!h) return false;
  return AUTHORITY_DOMAINS.some((d) => _hostMatchesDomain(h, d));
}

function computeAuthoritySignalsFromNaverItems(items) {
  const list = Array.isArray(items) ? items : [];
  const hits = [];

  for (const it of list) {
    const host = _stripWww(
      String(it?.source_host || _hostFromUrlish(it?.source_url || it?.link || ""))
    );

    const tier = String(it?.tier || "").trim();
    const whitelisted = !!it?.whitelisted;

    const isTier1Authority = whitelisted && tier === "tier1";
    const isExplicitAuthority = isAuthorityHost(host);

    if (host && (isTier1Authority || isExplicitAuthority)) {
      hits.push({
        host,
        tier: tier || null,
        whitelisted,
        naver_type: it?.naver_type || null,
        source_url: it?.source_url || it?.link || null,
      });
    }
  }

  // host 기준 dedupe
  const seen = new Set();
  const uniqHits = [];
  for (const h of hits) {
    if (seen.has(h.host)) continue;
    seen.add(h.host);
    uniqHits.push(h);
  }

  const tier1Count = uniqHits.filter((x) => x.tier === "tier1").length;

  return {
    has_authority: uniqHits.length > 0,
    authority_count: uniqHits.length,
    tier1_count: tier1Count,
    authority_hosts: uniqHits.slice(0, 8).map((x) => x.host),
    authority_examples: uniqHits.slice(0, 3),
  };
}

function computeAuthoritySignalsFromBlocks(blocks, fallbackNaver = []) {
  const arr = Array.isArray(blocks) ? blocks : [];
  const pool = [];

  for (const b of arr) {
    const n = b?.evidence?.naver;
    if (Array.isArray(n) && n.length) pool.push(...n);
  }

  if (!pool.length && Array.isArray(fallbackNaver) && fallbackNaver.length) {
    pool.push(...fallbackNaver);
  }

  return computeAuthoritySignalsFromNaverItems(pool);
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
async function fetchCrossref(q) {
  const { data } = await axios.get(
    `https://api.crossref.org/works?query=${encodeURIComponent(q)}&rows=3`,
    { timeout: HTTP_TIMEOUT_MS }
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

async function fetchOpenAlex(q) {
  const { data } = await axios.get(
    `https://api.openalex.org/works?search=${encodeURIComponent(q)}&per_page=3`,
    { timeout: HTTP_TIMEOUT_MS }
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

  let data;
try {
  const resp = await axios.get(
    `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&per_page=3`,
    { headers, timeout: HTTP_TIMEOUT_MS }
  );
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

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${gemini_key}`;

    const timeoutMs = getGeminiTimeoutMs(model, opts);
     const { data } = await axios.post(url, payload, { timeout: timeoutMs });

  const text = extractGeminiText(data);
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

async function fetchReadableText(url, timeoutMs = 5000) {
  try {
    const r = await axios.get(url, {
      timeout: timeoutMs,
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
  const minRelBase = Number.isFinite(minRelevance) ? minRelevance : 0.15;

  // env로 미세튜닝 가능
  const WEB_TIER_MAX = (() => {
    const v = parseInt(process.env.NAVER_WEB_TIER_MAX || "3", 10);
    return Number.isFinite(v) ? v : 3;
  })();

  const WEB_REL_BONUS = (() => {
    const v = parseFloat(process.env.NAVER_WEB_REL_BONUS || "0.10");
    return Number.isFinite(v) ? v : 0.10;
  })();

  const PER_HOST_MAX = (() => {
    const v = parseInt(process.env.NAVER_EVID_PER_HOST || "1", 10);
    return Number.isFinite(v) ? Math.max(1, v) : 1;
  })();

  const TIER1_PER_HOST_MAX = (() => {
    const v = parseInt(process.env.NAVER_EVID_PER_HOST_TIER1 || "2", 10);
    return Number.isFinite(v) ? Math.max(1, v) : 2;
  })();

  const kw = extractKeywords([query, blockText, ...(naverQueries || [])].join(" "), 14);
  const needNum = hasNumberLike(blockText) || hasNumberLike(query);

  const scored = [];

  for (const it of list) {
    if (!it || typeof it !== "object") continue;

    const url = String(it?.source_url || it?.link || "").trim();
    if (!url) continue;
    if (!isSafeExternalHttpUrl(url)) continue;

    const host = _stripWww(String(it?.source_host || _hostFromUrlish(url) || "").trim().toLowerCase());
    if (!host) continue;

    const type = String(it?.naver_type || "").trim().toLowerCase();
    if (!allowNews && type === "news") continue;

    const tierStr = String(it?.tier || "").trim().toLowerCase(); // "tier1" ~ "tier5"
    const m = tierStr.match(/tier(\d)/);
    const tierNum = m ? parseInt(m[1], 10) : null;

    const isWhitelisted = !!it?.whitelisted || (tierStr.startsWith("tier") && tierNum != null);
    const isAuthority = isAuthorityHost(host);

    // ✅ hard filter 핵심: (whitelist or authority)만 evidence 후보로
    if (!isWhitelisted && !isAuthority) continue;

    // ✅ web은 저티어(4~5) 제거(단, authority host는 예외)
    if (type === "web" && !isAuthority) {
      if (tierNum != null && tierNum > WEB_TIER_MAX) continue;
    }

    const text = `${it?.title || ""} ${it?.desc || ""}`;
    const rel = keywordHitRatio(text, kw);

    // ✅ web은 관련도 기준을 더 올림
    const minRel = type === "web" ? Math.min(0.95, minRelBase + WEB_REL_BONUS) : minRelBase;
    if (rel < minRel) continue;

    const baseW =
      (typeof it?.tier_weight === "number" && Number.isFinite(it.tier_weight) ? it.tier_weight : 1) *
      (typeof it?.type_weight === "number" && Number.isFinite(it.type_weight) ? it.type_weight : 1);

    const hasNum = hasNumberLike(text);
    const numFactor = needNum ? (hasNum ? 1.15 : 0.8) : 1.0;

    const score = baseW * (0.6 + 0.4 * rel) * numFactor;

    scored.push({
      it: {
        ...it,
        source_url: it?.source_url || url,
        source_host: it?.source_host || host,
      },
      score,
      host,
      tierNum,
    });
  }

  scored.sort((a, b) => b.score - a.score);

  // ✅ 동일 host 과다중복 방지(다양성 확보)
  const picked = [];
  const hostCount = {};

  for (const s of scored) {
    if (picked.length >= K) break;

    const h = s.host || "unknown";
    const limit = (s.tierNum === 1 ? TIER1_PER_HOST_MAX : PER_HOST_MAX);

    hostCount[h] = hostCount[h] || 0;
    if (hostCount[h] >= limit) continue;

    hostCount[h] += 1;
    picked.push(s.it);
  }

  return picked;
}

async function preprocessQVFVOneShot({ mode, query, core_text, gemini_key, modelName, userId }) {
  // mode: "qv" | "fv"
  // QV: 답변 생성 + 답변 기준 블록/쿼리 생성
  // FV: core_text(사실문장) 기준 블록/쿼리 생성 (답변 생성 X)

  const baseCore = (core_text || query || "").toString().trim();

 const prompt = `
너는 Cross-Verified AI의 "전처리 엔진"이다.
목표:
- (QV) 한국어 답변(answer_ko) 생성 → 그 답변에서 “그대로 복사한 문장”으로 의미블록(blocks) 구성 → 블록별 외부검증 엔진 쿼리 생성
- (FV) core_text(사실문장)에서 “그대로 복사한 문장”으로 의미블록(blocks) 구성 → 블록별 외부검증 엔진 쿼리 생성 (답변 생성 X)

[입력]
- mode: ${mode}                // "qv" | "fv"
- user_query: ${query}
- core_text(FV에서만 사용): ${mode === "fv" ? baseCore : ""}

[검증 대상 텍스트 정의(핵심)]
- mode=="qv": 검증 대상 텍스트 = answer_ko (네가 방금 생성한 답변 전체)
- mode=="fv": 검증 대상 텍스트 = core_text

[절대 규칙 — 위반하면 실패]
1) 출력은 JSON 1개만. (설명/접두어/접미어/코드블록/마크다운/줄바꿈 코멘트 모두 금지)
2) JSON은 반드시 double quote(")만 사용하고, trailing comma 금지.
3) blocks는 반드시 1~${QVFV_MAX_BLOCKS}개.
4) block.text는 반드시 “검증 대상 텍스트”에서 문장을 그대로 복사해서 사용(의역/요약/새 주장 추가 금지).
   - QV: answer_ko 안의 문장을 그대로 복사해야 함(= block.text가 answer_ko에 포함되어야 함)
   - FV: core_text 안의 문장을 그대로 복사해야 함
5) naver 쿼리에는 '+'를 절대 포함하지 말 것.

[QV 규칙]
- 질문에 대해 최선의 한국어 답변(answer_ko)을 6~10문장으로 작성한다.
- 웹검색/브라우징/실시간 조회를 했다고 주장하지 말라.
- 확실하지 않은 고유명사/수치/날짜는 단정하지 말고 '불확실'로 표시한다.

[FV 규칙]
- answer_ko는 반드시 "" (빈 문자열).

[blocks 규칙]
- 각 블록은 "주장/수치/조건" 단위로 1~2문장씩 묶는다.
- 각 block.text는 30~260자 내로 유지(너무 짧거나 너무 길면 실패).
- id는 1부터 순서대로.
- engine_queries는 각 엔진에 맞게 작성:
  - crossref/openalex/gdelt: 영어 키워드/짧은 구문(2~10단어, 90자 이내)
  - wikidata: 한국어 엔티티/명사 중심
  - naver: 한국어 검색어 1~${BLOCK_NAVER_MAX_QUERIES}개(각 30자 이내, '+' 절대 금지)

[출력 JSON 스키마]
{
  "answer_ko": "...",          // FV는 ""
  "topic": "...",              // 질문 토픽(짧게)
  "question_type": "other",    // fact|howto|opinion|explain|compare|other
  "recency_need": "medium",    // high|medium|low
  "korean_core": "...",        // 한국어 핵심(짧게)
  "english_core": "...",       // 영어 핵심(짧게)
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

  const topic = String(parsed?.topic || "").trim();
  const question_type_raw = String(parsed?.question_type || "").trim().toLowerCase();
  const recency_need_raw = String(parsed?.recency_need || "").trim().toLowerCase();

  const question_type = ["fact","howto","opinion","explain","compare","other"].includes(question_type_raw)
    ? question_type_raw
    : "other";

  const recency_need = ["high","medium","low"].includes(recency_need_raw)
    ? recency_need_raw
    : "medium";

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

 let blocks_source = (mode === "qv" ? "answer_ko" : "core_text");
let blocks_rebuilt = false;

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

// ✅ (S-8) QV에서는 blocks.text가 반드시 answer_ko에서 “그대로 복사된 문장”이어야 함
// - 모델이 규칙을 어기면, 서버가 answer_ko를 2개로 쪼개서 blocks를 재구성
try {
  if (mode === "qv") {
    const target = normSpace(answer_ko || "");
    if (target && Array.isArray(blocks) && blocks.length > 0) {
      const hasBad = blocks.some((b) => {
        const t = normSpace(b?.text || "");
        if (!t) return false;
        return !target.includes(t);
      });

      if (hasBad) {
        const [a, b] = splitIntoTwoParts(target);

        const tA = clipBlockText(String(a || "").trim(), 260);
        const tB = clipBlockText(String(b || "").trim(), 260);

        const rebuilt = [
          tA
            ? {
                id: 1,
                text: tA,
                engine_queries: {
                  crossref: english_core,
                  openalex: english_core,
                  wikidata: korean_core,
                  gdelt: english_core,
                  naver: fallbackNaverQueryFromText(korean_core).slice(0, BLOCK_NAVER_MAX_QUERIES),
                },
              }
            : null,
          tB
            ? {
                id: 2,
                text: tB,
                engine_queries: {
                  crossref: english_core,
                  openalex: english_core,
                  wikidata: korean_core,
                  gdelt: english_core,
                  naver: fallbackNaverQueryFromText(korean_core).slice(0, BLOCK_NAVER_MAX_QUERIES),
                },
              }
            : null,
        ].filter(Boolean);

        if (rebuilt.length > 0) {
          blocks = rebuilt;
          blocks_source = "answer_ko(rebuilt)";
          blocks_rebuilt = true;
        }
      }
    }
  }
} catch (e) {
  if (DEBUG) console.warn("⚠️ (S-8) qv blocks verbatim guard failed:", e?.message || e);
}

    return {
    answer_ko: (mode === "qv" ? (answer_ko || "") : ""),
    topic,
    question_type,
    recency_need,
    korean_core,
    english_core,
    blocks_source,
    blocks_rebuilt,
    blocks, // ✅ 최종 blocks
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
        topic: pre.topic ?? null,
        question_type: pre.question_type ?? null,
        recency_need: pre.recency_need ?? null,
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
      (qq) => callNaver(qq, naverIdFinal, naverSecretFinal),
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

  const bfv = {
  id: b.id,
  text: b.text,
  queries: {
    crossref: qCrossref,
    openalex: qOpenalex,
    wikidata: qWikidata,
    gdelt: qGdelt,
    naver: naverQueries,
  },
  evidence: {
    crossref: topArr(crPack.result, BLOCK_EVIDENCE_TOPK),
    openalex: topArr(oaPack.result, BLOCK_EVIDENCE_TOPK),
    wikidata: topArr(wdPack.result, 5),
    gdelt: gdeltForVerify,
    naver: naverItemsForVerify,
  },
};

// ✅ evidence_id/source_url/source_host/title 부착
attachEvidenceIdsToBlock(bfv);

// ✅ verify 입력 축소: 엔진별 근거를 “권위/신선도 우선”으로 K개만 남김
const K_VERIFY_EVID = parseInt(process.env.VERIFY_EVID_TOPK || "2", 10);
const kE = Number.isFinite(K_VERIFY_EVID) ? Math.max(1, K_VERIFY_EVID) : 2;

bfv.evidence.crossref = sampleEvidenceForVerify("crossref", bfv.evidence.crossref, kE);
bfv.evidence.openalex = sampleEvidenceForVerify("openalex", bfv.evidence.openalex, kE);
bfv.evidence.wikidata = sampleEvidenceForVerify("wikidata", bfv.evidence.wikidata, Math.min(2, kE));
bfv.evidence.gdelt = sampleEvidenceForVerify("gdelt", bfv.evidence.gdelt, kE);
bfv.evidence.naver = sampleEvidenceForVerify("naver", bfv.evidence.naver, Math.max(1, kE));

blocksForVerify.push(bfv);

// (관측) 각 블록별 verify-evidence 사이즈 기록(응답엔 요약만)
// ✅ DEBUG일 때만 생성/누적(운영에서는 메모리/CPU 낭비 방지)
if (DEBUG) {
  if (!partial_scores.verify_evidence_sampling) partial_scores.verify_evidence_sampling = [];
  partial_scores.verify_evidence_sampling.push({
    block_id: bfv.id,
    topk: kE,
    counts: {
      crossref: (bfv.evidence.crossref || []).length,
      openalex: (bfv.evidence.openalex || []).length,
      wikidata: (bfv.evidence.wikidata || []).length,
      gdelt: (bfv.evidence.gdelt || []).length,
      naver: (bfv.evidence.naver || []).length,
    },
  });
}
}

// ✅ 운영에서는 sampling 로그는 아예 제거
if (!DEBUG) partial_scores.verify_evidence_sampling = null;

// ✅ external.naver는 스코어/시그널(권위/티어)용이므로: 안전URL + (whitelist/authority)만 남김
external.naver = Array.isArray(external.naver)
  ? external.naver.filter((it) => {
      const url = String(it?.source_url || it?.link || "").trim();
      if (!url || !isSafeExternalHttpUrl(url)) return false;

      const host = _stripWww(String(it?.source_host || _hostFromUrlish(url) || "").trim().toLowerCase());
      const tierStr = String(it?.tier || "").trim().toLowerCase();
      const isWhitelisted = !!it?.whitelisted || tierStr.startsWith("tier");
      const isAuthority = host ? isAuthorityHost(host) : false;

      return isWhitelisted || isAuthority;
    })
  : [];

external.naver = dedupeByLink(external.naver).slice(0, NAVER_MULTI_MAX_ITEMS);

qvfvBlocksForVerifyFull = blocksForVerify;

// ✅ Authority signals (실제 근거 출처 기반)
partial_scores.authority_signals = computeAuthoritySignalsFromBlocks(blocksForVerify, external.naver);

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

const blocksForVerifySlim = blocksForVerify.map((x) => ({
  id: x.id,
  text: String(x.text || "").slice(0, 240), // ✅ 운영 payload 줄이기(원하면 120까지 더 줄여도 됨)
  queries: x.queries,
  evidence_counts: {
    crossref: (x.evidence?.crossref || []).length,
    openalex: (x.evidence?.openalex || []).length,
    wikidata: (x.evidence?.wikidata || []).length,
    gdelt: (x.evidence?.gdelt || []).length,
    naver: (x.evidence?.naver || []).length,
  },
}));

// ✅ 항상 내보내는 요약(가벼움)
const totalEvidenceCounts = { crossref: 0, openalex: 0, wikidata: 0, gdelt: 0, naver: 0 };
for (const b of blocksForVerifySlim) {
  const c = b?.evidence_counts || {};
  totalEvidenceCounts.crossref += (c.crossref || 0);
  totalEvidenceCounts.openalex += (c.openalex || 0);
  totalEvidenceCounts.wikidata += (c.wikidata || 0);
  totalEvidenceCounts.gdelt += (c.gdelt || 0);
  totalEvidenceCounts.naver += (c.naver || 0);
}

partial_scores.blocks_for_verify_summary = {
  blocks_total: blocksForVerifySlim.length,
  sample_block_ids: blocksForVerifySlim.slice(0, 6).map((b) => b?.id ?? null),
  total_evidence_counts: totalEvidenceCounts,
  detail_included: !!DEBUG,
};

// ✅ DEBUG일 때만 상세 제공
partial_scores.blocks_for_verify = DEBUG ? blocksForVerifySlim : null;

const rec = calcCompositeRecency({
  mode: safeMode,
  recency_need: qvfvPre?.recency_need,
  gdelt: external.gdelt,
  naver: external.naver,
  crossref: external.crossref,
  openalex: external.openalex,
  wikidata: external.wikidata,
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

// ✅ 엔진별 유효 evidence 개수 집계 + E_eff 정의 (verify irrelevant 반영: 1단계 naver만)
const engineNamesForEff = ["crossref", "openalex", "wikidata", "gdelt", "naver", "github"];
const effectiveCounts = {};

for (const name of engineNamesForEff) {
  effectiveCounts[name] = 0;
}

// ✅ blocks_for_verify는 운영에서 null이 될 수 있으므로,
//    항상 존재하는 blocksForVerifySlim(요약본) 기준으로 집계한다.
const eeffBlocks = Array.isArray(blocksForVerifySlim)
  ? blocksForVerifySlim
  : Array.isArray(partial_scores.blocks_for_verify)
    ? partial_scores.blocks_for_verify
    : [];

// ✅ verify 2차 irrelevant(3단계: evidence_id 단위) → 해당 evidence_id만 E_eff에서 제외
//    - evidence_items.irrelevant[].evidence_id 기반(정밀)
//    - vb.evidence.irrelevant 엔진명 기반은 fallback(통째 제외)으로만 사용
const PRUNE_ENGINES = ["naver", "gdelt"];

// 정밀(prune 대상 evidence_id)
const irrelevantEvidenceIdsByEngine = {};
for (const eng of PRUNE_ENGINES) irrelevantEvidenceIdsByEngine[eng] = new Set();

// fallback(엔진 전체를 블록에서 통째 제외)
const irrelevantBlockIdsByEngine = {};
for (const eng of PRUNE_ENGINES) irrelevantBlockIdsByEngine[eng] = new Set();

try {
  if ((safeMode === "qv" || safeMode === "fv") && verifyMeta && Array.isArray(verifyMeta.blocks)) {
    for (const vb of verifyMeta.blocks) {
      const bid = vb?.id;

      // 1) evidence_items.irrelevant: [{ evidence_id, engine, ... }]
      const irrItems = Array.isArray(vb?.evidence_items?.irrelevant) ? vb.evidence_items.irrelevant : [];
      for (const it of irrItems) {
        const eng = it?.engine ? String(it.engine).trim().toLowerCase() : null;
        const id = it?.evidence_id ? String(it.evidence_id).trim() : null;
        if (!id) continue;
        if (eng && irrelevantEvidenceIdsByEngine[eng]) irrelevantEvidenceIdsByEngine[eng].add(id);
      }

      // 2) (혹시 있을 수 있는) evidence_ids.irrelevant: ["b1:naver:1", ...] 또는 [{evidence_id, engine}, ...]
      const irrIds = vb?.evidence_ids?.irrelevant;
      if (Array.isArray(irrIds)) {
        for (const x of irrIds) {
          if (!x) continue;
          if (typeof x === "string") {
            const id = x.trim();
            // 엔진 추정: "b{bid}:{engine}:{n}"
            const m = id.match(/^b[^:]+:([a-z0-9_-]+):/i);
            const eng = m ? String(m[1]).trim().toLowerCase() : null;
            if (eng && irrelevantEvidenceIdsByEngine[eng]) irrelevantEvidenceIdsByEngine[eng].add(id);
          } else if (typeof x === "object") {
            const id = x?.evidence_id ? String(x.evidence_id).trim() : null;
            const eng = x?.engine ? String(x.engine).trim().toLowerCase() : null;
            if (id && eng && irrelevantEvidenceIdsByEngine[eng]) irrelevantEvidenceIdsByEngine[eng].add(id);
          }
        }
      }

      // 3) fallback: evidence.irrelevant 엔진명 배열
      const irrEng = Array.isArray(vb?.evidence?.irrelevant) ? vb.evidence.irrelevant : [];
      const irrEngNames = irrEng.map((s) => String(s).trim().toLowerCase());
      if (bid != null) {
        for (const eng of PRUNE_ENGINES) {
          if (irrEngNames.includes(eng)) irrelevantBlockIdsByEngine[eng].add(String(bid));
        }
      }
    }
  }
} catch (e) {
  if (DEBUG) console.warn("⚠️ build irrelevantEvidenceIdsByEngine failed:", e?.message || e);
}

const prunedEvidenceByEngine = {};
for (const eng of PRUNE_ENGINES) prunedEvidenceByEngine[eng] = 0;

for (const blk of eeffBlocks) {
  const ec = blk?.evidence_counts || {};
  const evObj = blk?.evidence && typeof blk.evidence === "object" ? blk.evidence : {};
  const bid = blk?.id;
  const bidKey = bid != null ? String(bid) : null;

  for (const name of engineNamesForEff) {
    const cnt = ec[name];
    if (!(typeof cnt === "number" && cnt > 0)) continue;

    let pruned = 0;

    // ✅ 1) 정밀 prune: evidence_id 단위로 제외
    if (irrelevantEvidenceIdsByEngine && irrelevantEvidenceIdsByEngine[name] && Array.isArray(evObj[name])) {
      for (const it of evObj[name]) {
        const id = it?.evidence_id ? String(it.evidence_id).trim() : "";
        if (id && irrelevantEvidenceIdsByEngine[name].has(id)) pruned += 1;
      }
    }

    // ✅ 2) fallback prune(엔진명만 있을 때): 블록 통째 제외
    if (pruned === 0 && bidKey && irrelevantBlockIdsByEngine && irrelevantBlockIdsByEngine[name]) {
      if (irrelevantBlockIdsByEngine[name].has(bidKey)) pruned = cnt;
    }

    if (pruned > 0) prunedEvidenceByEngine[name] = (prunedEvidenceByEngine[name] || 0) + pruned;

    const kept = Math.max(0, cnt - pruned);
    if (kept > 0) effectiveCounts[name] += kept;
  }
}

partial_scores.verify_irrelevant_prune = {
  applied: PRUNE_ENGINES.some((e) => (prunedEvidenceByEngine[e] || 0) > 0),
  removed_items_by_engine: prunedEvidenceByEngine,
  removed_ids_sample: Object.fromEntries(
    PRUNE_ENGINES.map((e) => [e, Array.from(irrelevantEvidenceIdsByEngine[e] || []).slice(0, 12)])
  ),
  blocks_fallback_by_engine: Object.fromEntries(
    PRUNE_ENGINES.map((e) => [e, Array.from(irrelevantBlockIdsByEngine[e] || []).slice(0, 50)])
  ),
};

// (관측) E_eff 집계가 어떤 입력을 기준으로 했는지 남김
partial_scores.eeff_basis = {
  blocks: eeffBlocks.length,
  source: Array.isArray(blocksForVerifySlim) ? "blocksForVerifySlim" : "partial_scores.blocks_for_verify",
};

const effectiveEngines = Object.entries(effectiveCounts)
  .filter(([_, cnt]) => typeof cnt === "number" && cnt > 0)
  .map(([name]) => name);

// partial_scores에 E_eff 관련 정보 저장
partial_scores.effective_engine_counts = effectiveCounts;
partial_scores.effective_engines = effectiveEngines;

        // ✅ 엔진별 호출/0건/스킵/전부-prune를 명확히 남기는 요약(설명가능성 강화)
    const engineCoverageStats = {};

    const requestedArr = Array.isArray(partial_scores.engines_requested)
      ? partial_scores.engines_requested
      : [];

    const usedArr = Array.isArray(partial_scores.engines_used)
      ? partial_scores.engines_used
      : [];

    const excludedMap =
      partial_scores.engines_excluded && typeof partial_scores.engines_excluded === "object"
        ? partial_scores.engines_excluded
        : {};

    const engineQueries = partial_scores.engine_queries || {};
    const engineMetrics2 = partial_scores.engine_metrics || {};

    const hasQueryFor = (eng) => {
      const v = engineQueries?.[eng];
      if (Array.isArray(v)) return v.some((s) => String(s || "").trim().length > 0);
      if (typeof v === "string") return v.trim().length > 0;
      return false;
    };

    const callsFor = (eng) => {
      const c = engineMetrics2?.[eng]?.calls;
      return typeof c === "number" && Number.isFinite(c) ? c : 0;
    };

    const excludedReasonFor = (eng) => {
      const r = excludedMap?.[eng]?.reason;
      return r ? String(r) : null;
    };

    const designedToCall = [];
    const called = [];
    const skippedNoQuery = [];
    const noCalls = [];
    const calledNoResults = [];
    const calledAllPruned = [];

    for (const name of engineNamesForEff) {
      const requested = requestedArr.includes(name);
      const has_query = hasQueryFor(name);
      const calls = callsFor(name);
      const excluded_reason = excludedReasonFor(name);
      const used = usedArr.includes(name);

      const totalResults =
        partial_scores.engine_results &&
        typeof partial_scores.engine_results[name] === "number"
          ? partial_scores.engine_results[name]
          : null;

      const effEv =
        typeof effectiveCounts?.[name] === "number" && Number.isFinite(effectiveCounts[name])
          ? effectiveCounts[name]
          : 0;

      const in_E_eff = effectiveEngines.includes(name);

      // ✅ “호출했고 결과도 있었는데, 최종 유효근거가 0” = 전부 irrelevant로 prune된 케이스
      const all_pruned_irrelevant =
        requested &&
        has_query &&
        calls > 0 &&
        typeof totalResults === "number" &&
        totalResults > 0 &&
        (!effEv || effEv <= 0) &&
        !in_E_eff;

      let call_state = "not_requested";
      if (requested) {
        if (!has_query && excluded_reason === "no_query") call_state = "skipped_no_query";
        else if (excluded_reason === "no_calls") call_state = "no_calls";
        else if (excluded_reason === "no_results") call_state = "called_no_results";
        else if (calls > 0) call_state = "called";
        else call_state = "unknown";
      }

      // ✅ called인데 all_pruned면 상태를 더 구체화
      if (call_state === "called" && all_pruned_irrelevant) {
        call_state = "called_results_but_all_pruned_irrelevant";
      }

      // ✅ coverage 패널티 타겟(합의 #7)
      // - 설계상 호출 대상(designed_to_call = requested && has_query)만 coverage 평가 대상으로 본다
      // - skipped_no_query는 패널티 대상 아님
      const designed_to_call = requested && has_query;
      const coverage_penalty_target = designed_to_call;

      if (designed_to_call) designedToCall.push(name);
      if (calls > 0) called.push(name);
      if (call_state === "skipped_no_query") skippedNoQuery.push(name);
      if (call_state === "no_calls") noCalls.push(name);
      if (call_state === "called_no_results") calledNoResults.push(name);
      if (call_state === "called_results_but_all_pruned_irrelevant") calledAllPruned.push(name);

      engineCoverageStats[name] = {
        requested,
        has_query,
        designed_to_call,
        coverage_penalty_target,

        calls,
        excluded_reason, // "no_query" | "no_calls" | "no_results" | null
        call_state,      // + "called_results_but_all_pruned_irrelevant"

        used,            // results>0 기준(engines_used)
        total_results: totalResults,

        effective_evidence: effEv,
        in_E_eff,

        all_pruned_irrelevant,
      };
    }

    partial_scores.engine_coverage_stats = engineCoverageStats;

    // ✅ 한 눈에 “스킵 vs 호출실패 vs 0건 vs 전부-prune”이 보이도록 요약도 제공
    partial_scores.engine_call_summary = {
      requested: requestedArr,
      designed_to_call: designedToCall, // 쿼리 존재(=전처리 기준 호출 대상)
      called,                           // calls>0
      used: usedArr,                    // results>0
      excluded: excludedMap,

      // ✅ S-10: by_engine 포함 (S-2/S-3가 이걸 참조 가능)
      by_engine: engineCoverageStats,

      counts: {
        requested: requestedArr.length,
        designed_to_call: designedToCall.length,
        called: called.length,
        used: usedArr.length,
        skipped_no_query: skippedNoQuery.length,
        no_calls: noCalls.length,
        called_no_results: calledNoResults.length,
        called_results_but_all_pruned_irrelevant: calledAllPruned.length,
        effective_engines: Array.isArray(effectiveEngines) ? effectiveEngines.length : 0,
      },
      lists: {
        skipped_no_query: skippedNoQuery,
        no_calls: noCalls,
        called_no_results: calledNoResults,
        called_results_but_all_pruned_irrelevant: calledAllPruned,
      },
    };

// ✅ (S-2) 엔진별 요약 로그(설명가능성): 호출/결과/유효근거/평균 age_days
try {
  const engineResults3 =
    (partial_scores.engine_results && typeof partial_scores.engine_results === "object")
      ? partial_scores.engine_results
      : {};

  const effCounts3 =
    (partial_scores.effective_engine_counts && typeof partial_scores.effective_engine_counts === "object")
      ? partial_scores.effective_engine_counts
      : {};

  const callStats =
    (partial_scores.engine_call_summary &&
      typeof partial_scores.engine_call_summary === "object" &&
      partial_scores.engine_call_summary.by_engine &&
      typeof partial_scores.engine_call_summary.by_engine === "object")
        ? partial_scores.engine_call_summary.by_engine
        : {};

  const avgAgeDays = (arr) => {
    const a = Array.isArray(arr) ? arr : [];
    const nums = a
      .map((x) => (typeof x?.age_days === "number" && Number.isFinite(x.age_days) ? x.age_days : null))
      .filter((v) => typeof v === "number");

    if (!nums.length) return null;
    const avg = nums.reduce((s, v) => s + v, 0) / nums.length;
    return Math.round(avg * 100) / 100;
  };

  const enginesToExplain = Array.isArray(engineNamesForEff)
    ? engineNamesForEff
    : ["crossref", "openalex", "wikidata", "gdelt", "naver", "github"];

  const out = {};

  for (const eng of enginesToExplain) {
    const raw = (typeof engineResults3[eng] === "number" && Number.isFinite(engineResults3[eng]))
      ? engineResults3[eng]
      : null;

    const kept = (typeof effCounts3[eng] === "number" && Number.isFinite(effCounts3[eng]))
      ? effCounts3[eng]
      : null;

    // external.* 배열이 존재할 때만 평균 age 계산
    const extArr =
      (typeof external === "object" && external && Array.isArray(external[eng]))
        ? external[eng]
        : null;

    out[eng] = {
      call_state: callStats?.[eng]?.call_state ?? null,
      calls: (typeof callStats?.[eng]?.calls === "number" ? callStats[eng].calls : null),
      results_raw: raw,
      effective_kept: kept,
      pruned_irrelevant: (typeof raw === "number" && typeof kept === "number") ? Math.max(0, raw - kept) : null,
      avg_age_days: extArr ? avgAgeDays(extArr) : null,
    };
  }

  partial_scores.engine_explain = out;
} catch (e) {
  if (DEBUG) console.warn("⚠️ engine_explain failed:", e?.message || e);
  partial_scores.engine_explain = { applied: false, error: e?.message || "unknown" };
}
// ✅ (S-3) E_eff(Effective engines) 제외 사유를 엔진별로 확정 기록
// - "설계상 안 부른 엔진" vs "부르려 했는데 0건" vs "부르긴 했는데 전부 irrelevant로 prune" 구분
try {
  const cs =
    (partial_scores.engine_call_summary && typeof partial_scores.engine_call_summary === "object")
      ? partial_scores.engine_call_summary
      : {};

  const byEngine =
    (cs.by_engine && typeof cs.by_engine === "object")
      ? cs.by_engine
      : {};

  const requested = Array.isArray(cs.requested) ? cs.requested : [];
  const designedToCall = Array.isArray(cs.designed_to_call) ? cs.designed_to_call : [];
  const called = Array.isArray(cs.called) ? cs.called : [];
  const used = Array.isArray(cs.used) ? cs.used : [];

  const skippedNoQuery = Array.isArray(cs?.lists?.skipped_no_query) ? cs.lists.skipped_no_query : [];
  const noCalls = Array.isArray(cs?.lists?.no_calls) ? cs.lists.no_calls : [];
  const calledNoResults = Array.isArray(cs?.lists?.called_no_results) ? cs.lists.called_no_results : [];

  const engineResults =
    (partial_scores.engine_results && typeof partial_scores.engine_results === "object")
      ? partial_scores.engine_results
      : {};

  const effCounts =
    (partial_scores.effective_engine_counts && typeof partial_scores.effective_engine_counts === "object")
      ? partial_scores.effective_engine_counts
      : {};

  const effectiveEngines = Array.isArray(partial_scores.effective_engines)
    ? partial_scores.effective_engines
    : [];

  // 엔진 후보 목록(가능한 넓게)
  const union = new Set([
    ...requested,
    ...designedToCall,
    ...called,
    ...used,
    ...effectiveEngines,
    ...Object.keys(engineResults || {}),
    ...Object.keys(effCounts || {}),
    ...Object.keys(byEngine || {}),
  ]);

  const prunedAllIrrelevant = [];
  const excluded = {};
  const included = {};

  // "called && results_raw > 0 && effective_kept == 0" => 전부 irrelevant로 prune된 케이스
  for (const eng of union) {
    const raw = (typeof engineResults?.[eng] === "number" && Number.isFinite(engineResults[eng]))
      ? engineResults[eng]
      : null;

    const kept = (typeof effCounts?.[eng] === "number" && Number.isFinite(effCounts[eng]))
      ? effCounts[eng]
      : null;

    const isPrunedAll =
      (typeof raw === "number" && raw > 0) &&
      (typeof kept === "number" && kept === 0);

    if (isPrunedAll) prunedAllIrrelevant.push(eng);
  }

  for (const eng of union) {
    const entry = {
      call_state: byEngine?.[eng]?.call_state ?? null,
      in_requested: requested.includes(eng),
      designed_to_call: designedToCall.includes(eng),
      called: called.includes(eng),
      used_results_gt0: used.includes(eng),
      effective_engine: effectiveEngines.includes(eng),
      results_raw: (typeof engineResults?.[eng] === "number" ? engineResults[eng] : null),
      effective_kept: (typeof effCounts?.[eng] === "number" ? effCounts[eng] : null),
      reason: null,
      excluded_from_E_eff: false,
      coverage_penalty_target: null, // true/false/null
    };

    // ✅ 우선순위 높은 reason부터 확정
    if (skippedNoQuery.includes(eng)) {
      // 설계상 안 부른 엔진(쿼리/전처리상 no_query)
      entry.reason = "design_skipped_no_query";
      entry.excluded_from_E_eff = true;        // E_eff엔 당연히 없음
      entry.coverage_penalty_target = false;   // ✅ coverage 패널티 대상 아님(합의 #7)
    } else if (noCalls.includes(eng)) {
      // 설계상 호출 대상이었는데, 실제 호출 자체가 안 됨(오류/타임아웃/구현 등)
      entry.reason = "designed_but_no_calls";
      entry.excluded_from_E_eff = true;
      entry.coverage_penalty_target = true;    // ✅ coverage 패널티 대상(합의 #7)
    } else if (calledNoResults.includes(eng)) {
      // 호출은 했는데 0건
      entry.reason = "called_but_zero_results";
      entry.excluded_from_E_eff = true;
      entry.coverage_penalty_target = true;    // ✅ coverage 패널티 대상(합의 #7)
    } else if (prunedAllIrrelevant.includes(eng)) {
      // 호출했고 결과도 있는데, 필터/판정 후 유효근거 0
      entry.reason = "called_results_but_all_pruned_irrelevant";
      entry.excluded_from_E_eff = true;
      entry.coverage_penalty_target = true;    // ✅ coverage 패널티 대상(합의 #7) — “부르긴 했는데 유효 0”
    } else if (effectiveEngines.includes(eng)) {
      entry.reason = "effective_included";
      entry.excluded_from_E_eff = false;
      entry.coverage_penalty_target = false;
    } else {
      // 여기에 걸리면 케이스가 애매한 것(미요청/미대상/기타)
      entry.reason = "other_or_not_applicable";
      entry.excluded_from_E_eff = true;
      entry.coverage_penalty_target = null;
    }

    if (entry.excluded_from_E_eff) excluded[eng] = entry;
    else included[eng] = entry;
  }

  partial_scores.engine_exclusion_reasons = {
    effective_engines: effectiveEngines,
    excluded,
    included,
    lists: {
      design_skipped_no_query: skippedNoQuery,
      designed_but_no_calls: noCalls,
      called_but_zero_results: calledNoResults,
      called_results_but_all_pruned_irrelevant: prunedAllIrrelevant,
    },
    counts: {
      union_total: union.size,
      effective: effectiveEngines.length,
      excluded: Object.keys(excluded).length,
      excluded_no_query: skippedNoQuery.length,
      excluded_no_calls: noCalls.length,
      excluded_zero_results: calledNoResults.length,
      excluded_all_pruned: prunedAllIrrelevant.length,
    },
  };
} catch (e) {
  if (DEBUG) console.warn("⚠️ engine_exclusion_reasons failed:", e?.message || e);
  partial_scores.engine_exclusion_reasons = { applied: false, error: e?.message || "unknown" };
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
          (qq) => fetchGitHub(qq, githubTokenFinal),
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
let verifyMetaRaw = null;

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
// ✅ (B-5) 권위 출처 우선(통계청/UN/OECD 등)으로 budget 배분
if (
  NAVER_NUMERIC_FETCH &&
  (safeMode === "qv" || safeMode === "fv") &&
  Array.isArray(blocksForVerify) &&
  blocksForVerify.length > 0
) {
  let budget = NAVER_NUMERIC_FETCH_MAX;

  const MAX_PER_BLOCK = Math.max(1, parseInt(process.env.NAVER_EVIDENCE_TEXT_PER_BLOCK || "2", 10));
  const MAX_PER_HOST = Math.max(1, parseInt(process.env.NAVER_EVIDENCE_TEXT_PER_HOST || "2", 10));

  const fetchedUrls = new Set();
  const hostCount = {};

  let attempts = 0;
  let success = 0;
  let auth_attempts = 0;
  let auth_success = 0;

  // 숫자/팩트 블록만 대상으로
  const numericBlocks = blocksForVerify.filter(
    (b) => hasNumberLike(b?.text) || hasNumberLike(query)
  );

  const buildCandidates = (b) => {
    const raw = Array.isArray(b?.evidence?.naver) ? b.evidence.naver.slice(0, 3) : [];

    // url/host/authority/tier info를 미리 계산해 정렬
    const cand = raw
      .map((ev) => {
        const url = ev?.source_url || ev?.link;
        if (!url) return null;
        if (!isSafeExternalHttpUrl(url)) return null;

        const hostRaw = ev?.source_host || _hostFromUrlish(url);
        const host = hostRaw ? _stripWww(String(hostRaw).trim().toLowerCase()) : null;

        const isAuth = host ? isAuthorityHost(host) : false;

        // tier: "tier1"~ 같은 문자열을 숫자로
        const tierStr = String(ev?.tier || "").trim().toLowerCase();
        const m = tierStr.match(/tier(\d)/);
        const tierNum = m ? parseInt(m[1], 10) : null;

        return { ev, url, host, isAuth, tierNum };
      })
      .filter(Boolean);

    // 정렬: authority 우선 → tier1 우선 → 기타
    cand.sort((a, b2) => {
      if (a.isAuth !== b2.isAuth) return a.isAuth ? -1 : 1; // true 먼저
      const ta = Number.isFinite(a.tierNum) ? a.tierNum : 99;
      const tb = Number.isFinite(b2.tierNum) ? b2.tierNum : 99;
      if (ta !== tb) return ta - tb; // 1이 먼저
      return 0;
    });

    return cand;
  };

  // ✅ 2-pass: (1) authority만 먼저 채우고 (2) 남으면 나머지 채움
  for (const pass of ["authority", "all"]) {
    for (const b of numericBlocks) {
      if (budget <= 0) break;

      let blockFetched = 0;
      const candidates = buildCandidates(b);

      for (const c of candidates) {
        if (budget <= 0) break;
        if (blockFetched >= MAX_PER_BLOCK) break;

        const ev = c.ev;
        if (ev?.evidence_text) continue;

        const url = c.url;
        if (fetchedUrls.has(url)) continue;

        const host = c.host || "unknown";
        hostCount[host] = hostCount[host] || 0;
        if (hostCount[host] >= MAX_PER_HOST) continue;

        // pass 1에서는 authority만
        if (pass === "authority" && !c.isAuth) continue;

        // ✅ fetch 1회 시도 = budget 1 소모(성공/실패 무관)
        attempts += 1;
        if (c.isAuth) auth_attempts += 1;

        let pageText = "";
        try {
          pageText = await fetchReadableText(url, NAVER_FETCH_TIMEOUT_MS);
        } catch (e) {
          if (DEBUG) console.warn("⚠️ naver evidence_text fetch fail:", e?.message || e);
          budget -= 1;
          continue;
        }

        budget -= 1;

        const excerpt = extractExcerptContainingNumbers(
          pageText,
          b?.text || "",
          EVIDENCE_EXCERPT_CHARS
        );

        if (excerpt) {
          ev.evidence_text = excerpt;

          fetchedUrls.add(url);
          hostCount[host] += 1;

          blockFetched += 1;
          success += 1;
          if (c.isAuth) auth_success += 1;
        }
      }
    }

    if (budget <= 0) break;
  }

  // ✅ 관측용(요약만)
  partial_scores.naver_evidence_text_fetch = {
    enabled: true,
    attempts,
    success,
    auth_attempts,
    auth_success,
    unique_urls: fetchedUrls.size,
    remaining_budget: budget,
    per_block_max: MAX_PER_BLOCK,
    per_host_max: MAX_PER_HOST,
  };
if (!DEBUG) partial_scores.naver_evidence_text_fetch = { ...(partial_scores.naver_evidence_text_fetch || {}), sample: null };
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

// ✅ verify 입력 축소 파라미터
const MAX_VERIFY_BLOCKS = parseInt(process.env.MAX_VERIFY_BLOCKS || "6", 10);
const MAX_VERIFY_BLOCKS_MIN = parseInt(process.env.MAX_VERIFY_BLOCKS_MIN || "2", 10);

const maxVerifyBlocks = Number.isFinite(MAX_VERIFY_BLOCKS) ? Math.max(0, MAX_VERIFY_BLOCKS) : 6;
const maxVerifyBlocksMin = Number.isFinite(MAX_VERIFY_BLOCKS_MIN) ? Math.max(0, MAX_VERIFY_BLOCKS_MIN) : 2;

// ✅ verify에 보낼 blocks: 상한 적용 + slim 변환
const blocksForVerifyForLLM_raw = Array.isArray(blocksForVerify)
  ? blocksForVerify.slice(0, maxVerifyBlocks)
  : [];

const blocksForVerifyForLLM =
  (typeof slimBlockForVerifyLLM === "function")
    ? blocksForVerifyForLLM_raw.map(slimBlockForVerifyLLM)
    : blocksForVerifyForLLM_raw;

const verifyInputMaxChars = getVerifyInputCharsByMode(safeMode);

partial_scores.verify_blocks_limit = {
  requested: Array.isArray(blocksForVerify) ? blocksForVerify.length : 0,
  used: blocksForVerifyForLLM.length,
  max: maxVerifyBlocks,
};

const verifyInput = {
  mode: safeMode,
  query,
  core_text: coreText,
  blocks: blocksForVerifyForLLM,
  external,

  // ✅ partial_scores는 verify에 안 넣는다(입력 비대화/timeout 원인)
  meta: {
    effective_engines: partial_scores.effective_engines || null,
    engines_requested: partial_scores.engines_requested || null,
    engines_used: partial_scores.engines_used || null,
  },
};

// ✅ 2차(타임아웃 시) 더 줄인 입력
const verifyInputMini = {
  ...verifyInput,
  blocks: blocksForVerifyForLLM.slice(0, Math.min(blocksForVerifyForLLM.length, maxVerifyBlocksMin)),
};

// ✅ lookup은 “verify에 실제로 보낸 blocks” 기준으로 1번만 생성(중복 선언 금지)
const verifyEvidenceLookup = buildEvidenceLookupFromBlocks(blocksForVerifyForLLM);

// (디버그/관측용) lookup 규모만 남김
partial_scores.verify_evidence_lookup_stats = {
  size: Object.keys(verifyEvidenceLookup || {}).length,
  sample_ids: Object.keys(verifyEvidenceLookup || {}).slice(0, 8),
};

// ✅ (S-9) verifyMeta 응답 크기 안정화용 캡
// - Gemini가 evidence_items를 많이/길게 뿌려도 서버가 강제로 줄임
// - conflict(상충)는 절대 “0으로 만들지” 않도록 total-cap에서도 마지막까지 보호
const VERIFY_META_ITEMS_PER_KIND = (() => {
  const v = parseInt(process.env.VERIFY_META_ITEMS_PER_KIND || "", 10);
  if (Number.isFinite(v) && v > 0) return Math.min(5, v);
  // 운영 기본값: 1 / DEBUG: 2
  return DEBUG ? 2 : 1;
})();

const VERIFY_META_ITEMS_TOTAL = (() => {
  const v = parseInt(process.env.VERIFY_META_ITEMS_TOTAL || "", 10);
  if (Number.isFinite(v) && v > 0) return Math.min(30, v);
  // 운영 기본값: 4 / DEBUG: 8
  return DEBUG ? 8 : 4;
})();

const VERIFY_META_EVID_TEXT_MAX = (() => {
  const v = parseInt(process.env.VERIFY_META_EVID_TEXT_MAX || "", 10);
  if (Number.isFinite(v) && v >= 0) return Math.min(1200, v);
  // 운영 기본값(0=제거) / DEBUG는 260자까지만 유지
  return DEBUG ? 260 : 0;
})();

      const verifyPromptTemplate = `
당신은 "Cross-Verified AI" 시스템의 메타 검증 엔진입니다.

목표:
- 하나의 요청으로 아래 작업을 모두 수행합니다.
  1) (필요한 경우에만) core_text를 의미 단위 블록으로 나누기
  2) 각 블록을 외부 검증엔진 결과 및 blocks[i].evidence와 비교하여 부분 TruthScore(0~1) 계산
  3) 전체 문장/코드에 대한 종합 TruthScore(0~1 구간, raw) 계산
  4) 각 검증엔진별로 이번 질의에 대한 국소 보정값(0.9~1.1) 제안

[입력 JSON]
__VERIFY_INPUT_JSON__

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
      (각 요소는 id, text, evidence(crossref/openalex/wikidata/gdelt/naver) 를 포함)
    - DV/CV: 서버에서 비워둘 수 있음([])
- external: crossref / openalex / wikidata / gdelt / naver / github / klaw 등 외부 엔진 결과
- meta: 서버가 참고용으로 넣은 요약 메타
    (예: effective_engines, engines_requested, engines_used)

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

     - 또한 blocks[i].evidence 안에 들어있는 "개별 근거 항목" 중에서:
       * evidence_items.support / conflict / irrelevant 배열에 “대표 근거”를 객체로 포함하십시오.
       * (중요) conflict(상충) 근거가 있다면, conflict evidence_items는 “절대 비워두지 마십시오”.

     - 개수 제한(응답 크기 안정화):
       * 각 종류(support/conflict/irrelevant)당 최대 ${VERIFY_META_ITEMS_PER_KIND}개
       * 세 종류 합계(총합) 최대 ${VERIFY_META_ITEMS_TOTAL}개

     - 객체 필드(필수): evidence_id, engine, source_url, source_host, title
       (선택): published_at 또는 age_days, evidence_text(있으면)

     ⚠️ 입력에 없는 URL/host/title/evidence_id를 새로 만들어내지 마십시오.
     ⚠️ evidence_items에는 반드시 evidence_id를 포함하세요.
     - evidence_id는 입력 blocks[i].evidence[*].evidence_id 중에서만 선택하세요.

3. 종합 TruthScore(overall_truthscore_raw, 0~1)
   - 블록별 점수와 evidence의 시의성/권위/일관성 및 meta를 종합하여
     0~1 사이의 overall_truthscore_raw를 계산하십시오.
   - 이 값은 "순수 0~1 척도"이며, 서버에서는
     truthscore = overall_truthscore_raw
     와 같이 0~1 범위 그대로 사용합니다.
   - overall_truthscore_raw가 1에 가까울수록 전체 내용이 매우 잘 뒷받침됨을 의미합니다.

4. 엔진별 보정 제안(engine_adjust)
   - external과 입력 JSON의 evidence 및 meta를 종합하여,
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
  "conflict": ["wikidata"],
  "irrelevant": []
},
"evidence_ids": {
  "support": ["b1:naver:1"],
  "conflict": ["b1:wikidata:1"],
  "irrelevant": []
},
"evidence_items": {
  "support": [
    {
      "evidence_id": "b1:naver:1",
      "engine": "naver",
      "source_url": "https://...",
      "source_host": "kostat.go.kr",
      "title": "..."
    }
  ],
  "conflict": [
    {
      "evidence_id": "b1:wikidata:1",
      "engine": "wikidata",
      "source_url": "https://...",
      "source_host": "wikidata.org",
      "title": "..."
    }
  ],
  "irrelevant": []
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

// ✅ verifyPrompt / verifyPromptMini 생성 (template placeholder 치환)
const verifyInputJson = safeVerifyInputForGemini(verifyInput, verifyInputMaxChars);
const verifyPrompt = verifyPromptTemplate.replace("__VERIFY_INPUT_JSON__", verifyInputJson);

const verifyInputJsonMini = safeVerifyInputForGemini(
  verifyInputMini,
  Math.min(verifyInputMaxChars, VERIFY_INPUT_CHARS_MIN)
);
const verifyPromptMini = verifyPromptTemplate.replace("__VERIFY_INPUT_JSON__", verifyInputJsonMini);

// ✅ verify evidence_id 역매핑용 lookup(verify 전에 반드시 생성)
//    (중요) verify에 실제로 보낸 blocks 기준으로 생성해야 정합성이 맞음
const verifyEvidenceLookup = buildEvidenceLookupFromBlocks(blocksForVerifyForLLM);

// (디버그/관측용) lookup 규모만 남김(전체 map은 응답에 싣지 말자)
partial_scores.verify_evidence_lookup_stats = {
  size: Object.keys(verifyEvidenceLookup || {}).length,
  sample_ids: Object.keys(verifyEvidenceLookup || {}).slice(0, 8),
};

      // ✅ verify는 모델 실패/빈문자 발생이 있어서 fallback 시도
const verifyPayload = { contents: [{ parts: [{ text: verifyPrompt }] }] };

// 1순위: verifyModel, 2순위: flash, 3순위: flash-lite
const verifyModelCandidates = [
  verifyModel,
  "gemini-2.5-flash",
  "gemini-2.5-flash-lite",
].filter((v, i, a) => v && a.indexOf(v) === i);

let lastVerifyErr = null;
const isTimeoutish = (e) => {
  const msg = String(e?.message || "").toLowerCase();
  return (
    msg.includes("timeout") ||
    msg.includes("timed out") ||
    msg.includes("deadline") ||
    msg.includes("aborted") ||
    msg.includes("etimedout") ||
    msg.includes("exceeded")
  );
};

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
// ✅ 1차 verify가 타임아웃/빈응답이면: 더 작은 입력으로 2차 시도(verifyPromptMini)
if ((!verify || !verify.trim()) && isTimeoutish(lastVerifyErr)) {
  partial_scores.verify_retry = {
    attempted: true,
    reason: "timeout_or_empty",
    last_error: lastVerifyErr?.message || "unknown",
    max_chars: Math.min(verifyInputMaxChars, VERIFY_INPUT_CHARS_MIN),
    max_blocks: MAX_VERIFY_BLOCKS_MIN,
  };

  const verifyPayloadMini = { contents: [{ parts: [{ text: verifyPromptMini }] }] };

  let lastVerifyErr2 = null;
  const t_retry = Date.now();
  try {
    for (const m of verifyModelCandidates) {
      try {
        verify = await fetchGeminiRotating({
          userId: logUserId,
          keyHint: gemini_key,
          model: m,
          payload: verifyPayloadMini,
          opts: { label: `verify-mini:${m}`, minChars: 20 },
        });
        verifyModelUsed = m; // ✅ retry 성공 모델 기록
        break;
      } catch (e2) {
        const status2 = e2?.response?.status;
        if (status2 === 429) throw e2; // ✅ 쿼터 소진은 즉시 상위로
        lastVerifyErr2 = e2;
      }
    }
  } finally {
    const ms = Date.now() - t_retry;
    recordTime(geminiTimes, "verify_retry_ms", ms);
    recordMetric(geminiMetrics, "verify_retry", ms);
  }

  if ((!verify || !verify.trim())) {
    partial_scores.verify_retry = {
      ...(partial_scores.verify_retry || {}),
      success: false,
      last_error2: lastVerifyErr2?.message || "unknown",
    };
  } else {
    partial_scores.verify_retry = {
      ...(partial_scores.verify_retry || {}),
      success: true,
    };
  }
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
    verifyMetaRaw = _deepCloneJson(verifyMeta);

    const __lookup =
      (typeof verifyEvidenceLookup !== "undefined" && verifyEvidenceLookup)
        ? verifyEvidenceLookup
        : null;

    // ✅ verifyMeta 안전 보정: evidence_ids 누락 시 evidence_items/lookup으로 복구
    try {
      const norm = normalizeVerifyMetaWithEvidenceIds(verifyMeta, __lookup);
      verifyMeta = norm.meta;
      partial_scores.verify_normalization = norm.report;
    } catch (e) {
      partial_scores.verify_normalization = { applied: false, error: e?.message || "normalize_failed" };
    }

// ✅ (S-9) verifyMeta evidence_items “강제 캡” + evidence_text 제거/절단
// - 운영 응답 크기 안정화
// - conflict(상충) evidence_items는 total-cap에서도 “마지막까지” 보호
try {
  const maxKind = VERIFY_META_ITEMS_PER_KIND;
  const maxTotal = VERIFY_META_ITEMS_TOTAL;
  const maxText = VERIFY_META_EVID_TEXT_MAX;

  let beforeTotal = 0;
  let afterTotal = 0;
  const rawConflictItems = s11_collectConflictItemsFromVerifyMeta(verifyMetaRaw);
  const rawConflictCount = rawConflictItems.length;

  const countEvidenceItemsTotal = (vm) => {
    if (!vm || typeof vm !== "object") return 0;
    let total = 0;

    const blocksArr = Array.isArray(vm.blocks) ? vm.blocks : [];
    for (const b of blocksArr) {
      const eiObj =
        b?.evidence_items && typeof b.evidence_items === "object"
          ? b.evidence_items
          : null;
      if (!eiObj) continue;

      for (const k of ["support", "conflict", "irrelevant"]) {
        const arr = Array.isArray(eiObj[k]) ? eiObj[k] : [];
        total += arr.length;
      }
    }

    return total;
  };

  if (verifyMeta && Array.isArray(verifyMeta.blocks)) {
    for (const blk of verifyMeta.blocks) {
      const ei = blk?.evidence_items && typeof blk.evidence_items === "object" ? blk.evidence_items : null;
      if (!ei) continue;

      // 1) per-kind cap + 필드 정리
      for (const k of ["support", "conflict", "irrelevant"]) {
        const arr0 = Array.isArray(ei[k]) ? ei[k] : [];
        beforeTotal += arr0.length;

        const arr = arr0
          .filter((x) => x && typeof x === "object")
          .filter((x) => {
            const id = x.evidence_id ? String(x.evidence_id).trim() : "";
            return !!id;
          })
          .slice(0, maxKind)
          .map((x) => {
            const o = { ...x };

            // 운영: evidence_text 제거(또는 maxText==0이면 제거)
            if (maxText === 0) {
              if (Object.prototype.hasOwnProperty.call(o, "evidence_text")) delete o.evidence_text;
            } else {
              if (typeof o.evidence_text === "string") {
                o.evidence_text = o.evidence_text.slice(0, maxText);
              }
            }

            // 불필요하게 큰 필드(혹시 모델이 뱉으면) 정리
            if (!DEBUG) {
              if (Object.prototype.hasOwnProperty.call(o, "raw")) delete o.raw;
              if (Object.prototype.hasOwnProperty.call(o, "html")) delete o.html;
              if (Object.prototype.hasOwnProperty.call(o, "content")) delete o.content;
              if (Object.prototype.hasOwnProperty.call(o, "snippet")) delete o.snippet;
            }

            return o;
          });

        ei[k] = arr;
      }

      // 2) total cap (conflict는 최대한 보호)
      const getLen = () =>
        (Array.isArray(ei.support) ? ei.support.length : 0) +
        (Array.isArray(ei.conflict) ? ei.conflict.length : 0) +
        (Array.isArray(ei.irrelevant) ? ei.irrelevant.length : 0);

      while (getLen() > maxTotal) {
        // 먼저 irrelevant 줄이기
        if (Array.isArray(ei.irrelevant) && ei.irrelevant.length > 0) {
          ei.irrelevant.pop();
          continue;
        }
        // 다음 support 줄이기
        if (Array.isArray(ei.support) && ei.support.length > 0) {
          ei.support.pop();
          continue;
        }
        // conflict는 “1개는 남긴다” (있다면)
        if (Array.isArray(ei.conflict) && ei.conflict.length > 1) {
          ei.conflict.pop();
          continue;
        }
        break;
      }

      afterTotal += getLen();
    }
  }

  if (verifyMeta && rawConflictCount > 0) {
    const cappedConflictItems = s11_collectConflictItemsFromVerifyMeta(verifyMeta);
    if (Array.isArray(cappedConflictItems) && cappedConflictItems.length === 0) {
      const fallback = rawConflictItems[0];
      if (fallback) {
        verifyMeta.blocks = Array.isArray(verifyMeta.blocks) ? verifyMeta.blocks : [];
        let targetBlk =
          verifyMeta.blocks.find(
            (b) => b?.evidence_items && Array.isArray(b.evidence_items.conflict)
          ) || verifyMeta.blocks[0];

        if (!targetBlk) {
          targetBlk = {};
          verifyMeta.blocks.push(targetBlk);
        }

        if (!targetBlk.evidence_items || typeof targetBlk.evidence_items !== "object") {
          targetBlk.evidence_items = {};
        }
        if (!Array.isArray(targetBlk.evidence_items.conflict)) {
          targetBlk.evidence_items.conflict = [];
        }

        if (targetBlk.evidence_items.conflict.length === 0) {
          targetBlk.evidence_items.conflict.push(fallback);
        } else {
          targetBlk.evidence_items.conflict.unshift(fallback);
        }

        const getLenRestore = () =>
          (Array.isArray(targetBlk.evidence_items.support) ? targetBlk.evidence_items.support.length : 0) +
          (Array.isArray(targetBlk.evidence_items.conflict) ? targetBlk.evidence_items.conflict.length : 0) +
          (Array.isArray(targetBlk.evidence_items.irrelevant) ? targetBlk.evidence_items.irrelevant.length : 0);

        targetBlk.evidence_items.conflict = targetBlk.evidence_items.conflict.slice(0, Math.max(1, maxKind));

        while (getLenRestore() > maxTotal) {
          if (Array.isArray(targetBlk.evidence_items.irrelevant) && targetBlk.evidence_items.irrelevant.length > 0) {
            targetBlk.evidence_items.irrelevant.pop();
            continue;
          }
          if (Array.isArray(targetBlk.evidence_items.support) && targetBlk.evidence_items.support.length > 0) {
            targetBlk.evidence_items.support.pop();
            continue;
          }
          if (Array.isArray(targetBlk.evidence_items.conflict) && targetBlk.evidence_items.conflict.length > 1) {
            targetBlk.evidence_items.conflict.pop();
            continue;
          }
          break;
        }
      }
    }
  }

  afterTotal = countEvidenceItemsTotal(verifyMeta);

  partial_scores.verify_meta_evidence_items_cap = {
    applied: true,
    per_kind: maxKind,
    total: maxTotal,
    evidence_text_max: maxText,
    before_total_items: beforeTotal,
    after_total_items: afterTotal,
  };
} catch (e) {
  if (DEBUG) console.warn("⚠️ (S-9) verifyMeta evidence_items cap failed:", e?.message || e);
  partial_scores.verify_meta_evidence_items_cap = {
    applied: false,
    error: e?.message || "unknown",
  };
}

    // ✅ (B-7) verifyMeta evidence_items 자동 보강:
    // - Gemini가 engine/source_url/source_host/title 등을 누락해도
    //   서버 verifyEvidenceLookup(정답)으로 채워 넣는다.
    // - evidence_id가 있는 항목만 보강(없으면 그대로 둠)
    try {
      if (verifyMeta && Array.isArray(verifyMeta.blocks) && __lookup) {
        let filled = 0;

        for (const blk of verifyMeta.blocks) {
          const ei =
            blk?.evidence_items && typeof blk.evidence_items === "object"
              ? blk.evidence_items
              : null;
          if (!ei) continue;

          for (const k of ["support", "conflict", "irrelevant"]) {
            if (!Array.isArray(ei[k])) continue;

            ei[k] = ei[k].map((x) => {
              if (!x) return x;

              // (방어) 문자열이면 evidence_id일 수도/URL일 수도 있음
              if (typeof x === "string") {
                const s = x.trim();
                if (s.startsWith("http://") || s.startsWith("https://")) return x;

                if (s && Object.prototype.hasOwnProperty.call(__lookup, s)) {
                  const ref = __lookup[s];
                  if (ref && typeof ref === "object") {
                    filled += 1;
                    return {
                      evidence_id: s,
                      engine: ref.engine || null,
                      source_url: ref.source_url || null,
                      source_host: ref.source_host || null,
                      title: ref.title || null,
                      ...(ref.published_at ? { published_at: ref.published_at } : {}),
                      ...(Number.isFinite(ref.age_days) ? { age_days: ref.age_days } : {}),
                      ...(Number.isFinite(ref.tier) ? { tier: ref.tier } : {}),
                      ...(ref.naver_type ? { naver_type: ref.naver_type } : {}),
                    };
                  }
                }
                return x;
              }

              // 객체면 “빈 필드만” lookup으로 채움
              if (typeof x !== "object") return x;

              const id = x.evidence_id ? String(x.evidence_id).trim() : "";
              if (!id) return x;

              const ref = Object.prototype.hasOwnProperty.call(__lookup, id)
                ? __lookup[id]
                : null;

              if (!ref || typeof ref !== "object") return x;

              const next = { ...x };
              let changed = false;

              if (!next.engine && ref.engine) { next.engine = ref.engine; changed = true; }
              if (!next.source_url && ref.source_url) { next.source_url = ref.source_url; changed = true; }
              if (!next.source_host && ref.source_host) { next.source_host = ref.source_host; changed = true; }
              if (!next.title && ref.title) { next.title = ref.title; changed = true; }
              if (!next.published_at && ref.published_at) { next.published_at = ref.published_at; changed = true; }
              if (!Number.isFinite(next.age_days) && Number.isFinite(ref.age_days)) { next.age_days = ref.age_days; changed = true; }
              if (!Number.isFinite(next.tier) && Number.isFinite(ref.tier)) { next.tier = ref.tier; changed = true; }
              if (!next.naver_type && ref.naver_type) { next.naver_type = ref.naver_type; changed = true; }

              if (changed) filled += 1;
              return next;
            });
          }
        }

        partial_scores.verify_lookup_fill = { applied: filled > 0, filled_items: filled };
      }
    } catch (e) {
      if (DEBUG) console.warn("⚠️ verify_lookup_fill failed:", e?.message || e);
      partial_scores.verify_lookup_fill = { applied: false, error: e?.message || "unknown" };
    }

  } catch {
    verifyMeta = null;
    verifyMetaRaw = null;
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

const truthscoreEnginesArr =
  (safeMode === "qv" || safeMode === "fv") && Array.isArray(partial_scores.effective_engines)
    ? partial_scores.effective_engines
    : (Array.isArray(partial_scores.engines_used) ? partial_scores.engines_used : engines);

partial_scores.truthscore_engines_basis =
  (safeMode === "qv" || safeMode === "fv") && Array.isArray(partial_scores.effective_engines)
    ? "effective_engines"
    : (Array.isArray(partial_scores.engines_used) ? "engines_used" : "engines");

const enginesUsedSet = new Set(Array.isArray(truthscoreEnginesArr) ? truthscoreEnginesArr : []);

// ✅ TruthScore에 실제로 반영된 엔진(가벼운 요약)
partial_scores.truthscore_engines_used = Array.isArray(truthscoreEnginesArr) ? truthscoreEnginesArr : [];

// ✅ (S-7) 엔진 전역 보정계수도 TruthScore 기준 엔진으로 재계산(E_eff 반영)
// - QV/FV: effective_engines(검증 evidence>0)만으로 보정 재계산
// - DV/CV: 기존 engines_used 기준(블록기반 E_eff와 성격이 달라서)
try {
  const baseEnginesForCorrection = Array.isArray(truthscoreEnginesArr) ? truthscoreEnginesArr : [];
  const enginesForCorrection = baseEnginesForCorrection.filter((x) => x !== "klaw");

  // 기존 값 보관(디버깅/설명가능성용)
  partial_scores.engine_factor_pre_eff = partial_scores.engine_factor;
  partial_scores.engine_factor_engines_pre_eff = partial_scores.engine_factor_engines;

  if (enginesForCorrection.length > 0) {
    engineFactor = computeEngineCorrectionFactor(enginesForCorrection, engineStatsMap); // 0.9~1.1
  } else {
    engineFactor = 1.0;
  }

  // ✅ “최종 적용된” 값으로 갱신
  partial_scores.engine_factor = engineFactor;
  partial_scores.engine_factor_engines = enginesForCorrection;
  partial_scores.engine_factor_basis = partial_scores.truthscore_engines_basis;
} catch (e) {
  if (DEBUG) console.warn("⚠️ engine_factor(E_eff) recompute failed:", e?.message || e);
  // 실패 시 기존 engineFactor 유지
  partial_scores.engine_factor_basis = partial_scores.truthscore_engines_basis;
}

const useGdelt = enginesUsedSet.has("gdelt");
const useNaver = enginesUsedSet.has("naver");

// ✅ (S-7) recency도 TruthScore 기준 엔진(=E_eff)에 없는 엔진은 “무시”해서 재계산
let R_t =
  (safeMode === "qv" || safeMode === "fv" || safeMode === "dv" || safeMode === "cv") &&
  typeof partial_scores.recency === "number"
    ? Math.max(0, Math.min(1, partial_scores.recency))
    : 1.0;

try {
  const rd = partial_scores.recency_detail;
  const weightsEngine = rd && typeof rd.weights_engine === "object" ? rd.weights_engine : null;
  const scoresEngine = rd && typeof rd.engine_scores === "object" ? rd.engine_scores : null;
  const floor = rd?.weights_group && typeof rd.weights_group.floor === "number" ? rd.weights_group.floor : null;

  // ✅ QV/FV에 한해 “effective_engines 기반 제외”를 적용 (DV/CV는 engines_used 기반이라 동일)
  const applyEffFilter = (safeMode === "qv" || safeMode === "fv") && partial_scores.truthscore_engines_basis === "effective_engines";

  if (applyEffFilter && weightsEngine && scoresEngine) {
    let penalty = 0;

    for (const [eng, wRaw] of Object.entries(weightsEngine)) {
      const w = (typeof wRaw === "number" && Number.isFinite(wRaw)) ? wRaw : 0;
      if (w <= 0) continue;

      // E_eff에 없으면 recency 기여 “제외”
      if (!enginesUsedSet.has(eng)) continue;

      const sRaw = scoresEngine[eng];
      const s = (typeof sRaw === "number" && Number.isFinite(sRaw)) ? clamp01(sRaw) : 1.0;
      penalty += w * (1 - s);
    }

    const rtEff = 1 - penalty;
    const floor2 = (typeof floor === "number" && Number.isFinite(floor)) ? clamp01(floor) : 0;
    const rtClamped = Math.max(floor2, clamp01(rtEff));

    partial_scores.recency_pre_eff = partial_scores.recency;
    partial_scores.recency = rtClamped; // ✅ 최종 TruthScore용 recency로 갱신
    partial_scores.recency_eff_meta = {
      applied: true,
      basis: "effective_engines",
      floor: floor2,
      pre: Math.max(0, Math.min(1, R_t)),
      post: rtClamped,
    };

    R_t = rtClamped;
  } else {
    partial_scores.recency_eff_meta = {
      applied: false,
      basis: partial_scores.truthscore_engines_basis,
    };
  }
} catch (e) {
  if (DEBUG) console.warn("⚠️ recency(E_eff) recompute failed:", e?.message || e);
  partial_scores.recency_eff_meta = {
    applied: false,
    basis: partial_scores.truthscore_engines_basis,
    error: e?.message || "unknown",
  };
}

const N =
  (safeMode === "qv" || safeMode === "fv") &&
  useNaver &&
  typeof partial_scores.naver_tier_factor === "number"
    ? Math.max(0.9, Math.min(1.05, partial_scores.naver_tier_factor))
    : 1.0;

//// Coverage Cₜ: E_eff 기반 포화 함수 + 권위출처 예외 + 설명가능성(메타/스코프)
let C_t = 1.0;

const coverageBasis = Array.isArray(partial_scores.effective_engines)
  ? "effective_engines"
  : Array.isArray(partial_scores.engines_used)
    ? "engines_used"
    : "engines";

// E_eff가 있으면 그걸, 없으면 engines_used / engines를 사용
const effEnginesArr = Array.isArray(partial_scores.effective_engines)
  ? partial_scores.effective_engines
  : Array.isArray(partial_scores.engines_used)
    ? partial_scores.engines_used
    : engines;

const effCounts =
  partial_scores.effective_engine_counts && typeof partial_scores.effective_engine_counts === "object"
    ? partial_scores.effective_engine_counts
    : null;

let totalEffEvidence = 0;
if (Array.isArray(effEnginesArr) && effEnginesArr.length > 0 && effCounts) {
  for (const name of effEnginesArr) {
    const cnt = effCounts[name];
    if (typeof cnt === "number" && cnt > 0) totalEffEvidence += cnt;
  }
}

// ✅ coverage 패널티 대상 엔진 집합(=설계상 호출 대상) — no_query 스킵은 제외
const engineCallSummary =
  partial_scores.engine_call_summary && typeof partial_scores.engine_call_summary === "object"
    ? partial_scores.engine_call_summary
    : null;

const designedToCallArr = Array.isArray(engineCallSummary?.designed_to_call)
  ? engineCallSummary.designed_to_call
  : null;

const designedToCallCount = Array.isArray(designedToCallArr) ? designedToCallArr.length : 0;
const effectiveEngineCount = Array.isArray(partial_scores.effective_engines) ? partial_scores.effective_engines.length : 0;

const engineCoverageRatio =
  designedToCallCount > 0 ? (effectiveEngineCount / designedToCallCount) : null;

const N_SAT = 10;  // evidence 개수 기준 포화 구간
const C_T_MIN = 0.4; // evidence가 있을 때 최소 하한(너무 과도한 벌점 방지)
const C_T_ZERO = Number(process.env.COVERAGE_C_T_ZERO ?? "0.25"); // evidence 0일 때(호출 실패/0건) 하한

let coverageRaw = null;
let coverageRawEvidence = null;
let coverageRawEngine = null;

let C_t_base = 1.0;

let coverageEvaluated = true;              // ✅ coverage를 “평가했는지”
let coverageUnavailableReason = null;      // ✅ 미평가면 사유

// ✅ mode가 coverage를 적용하는지(기본: qv/fv/dv/cv만)
const coverageModeApplicable =
  (safeMode === "qv" || safeMode === "fv" || safeMode === "dv" || safeMode === "cv");

// ✅ (개편) 증거 “2개 이하 벌점” 같은 계단식 패널티 폐기
// - evidence 수는 포화함수(sat log)로 점진 반영
// - “설계상 호출 대상 엔진(designed_to_call)” 대비 E_eff 비율도 함께 반영
// - 설계상 호출 대상이 없으면 coverage 미평가(패널티 없음)
// - 호출 대상이 있는데 evidence 0이면 C_T_ZERO로 페널티(합의 #7)
if (!coverageModeApplicable) {
  coverageEvaluated = false;
  coverageUnavailableReason = "mode_not_applicable";
  coverageRaw = null;
  coverageRawEvidence = null;
  coverageRawEngine = null;
  C_t_base = C_t; // 1.0 유지
} else if (!designedToCallCount || designedToCallCount <= 0) {
  coverageEvaluated = false;
  coverageUnavailableReason = "no_designed_engines";
  coverageRaw = null;
  coverageRawEvidence = null;
  coverageRawEngine = null;
  C_t_base = C_t; // 1.0 유지
} else {
  // evidence 포화(sat log)
  coverageRawEvidence = Math.log(1 + totalEffEvidence) / Math.log(1 + N_SAT);

  // 엔진 커버리지 포화(설계상 호출 대상 대비 E_eff)
  coverageRawEngine = Math.log(1 + effectiveEngineCount) / Math.log(1 + designedToCallCount);

  // 가중 결합(ENV로 조정 가능)
  let wEvidence = Number(process.env.COVERAGE_W_EVIDENCE ?? "0.75");
  let wEngine = Number(process.env.COVERAGE_W_ENGINE ?? "0.25");
  if (!Number.isFinite(wEvidence) || !Number.isFinite(wEngine) || wEvidence < 0 || wEngine < 0 || (wEvidence + wEngine) <= 0) {
    wEvidence = 0.75;
    wEngine = 0.25;
  }
  const wSum = wEvidence + wEngine;
  wEvidence = wEvidence / wSum;
  wEngine = wEngine / wSum;

  coverageRaw = wEvidence * Math.max(0, Math.min(1, coverageRawEvidence))
              + wEngine * Math.max(0, Math.min(1, coverageRawEngine));

  // evidence가 있으면 기존 최소하한(너무 급락 방지), 없으면 C_T_ZERO로 페널티
  const floor = (totalEffEvidence > 0)
    ? C_T_MIN
    : (Number.isFinite(C_T_ZERO) ? Math.max(0, Math.min(1, C_T_ZERO)) : 0.25);

  C_t_base = Math.max(floor, Math.min(1.0, coverageRaw));
  C_t = C_t_base;

  partial_scores.coverage_weights = { wEvidence, wEngine };
}

// ✅ (B-6) naver evidence_text fetch로 확인된 authority host를 authority_signals에 보강
// - evidence_text가 붙은 항목은 “본문 발췌로 확인”된 케이스라 신뢰 신호로 강하게 취급
try {
  if (partial_scores.authority_signals && typeof partial_scores.authority_signals === "object") {
    const as = partial_scores.authority_signals;

    let text_verified_authority_count = 0;
    const text_verified_authority_hosts = new Set();

    if (Array.isArray(blocksForVerifySlim)) {
      for (const b of blocksForVerifySlim) {
        const naverArr = Array.isArray(b?.evidence?.naver) ? b.evidence.naver : [];
        for (const ev of naverArr) {
          if (!ev || typeof ev !== "object") continue;
          if (!ev.evidence_text) continue;

          const host = ev.source_host ? _stripWww(String(ev.source_host).toLowerCase()) : null;
          if (host && isAuthorityHost(host)) {
            text_verified_authority_count += 1;
            text_verified_authority_hosts.add(host);
          }
        }
      }
    }

    as.text_verified_authority_count = text_verified_authority_count;
    as.text_verified_authority_hosts = Array.from(text_verified_authority_hosts).slice(0, 30);

    // has_authority가 false/미정이어도, 본문발췌로 authority가 잡히면 true로 올림
    if (text_verified_authority_count > 0) {
      as.has_authority = true;
    }

    // tier1_count가 없으면(또는 0이면), 본문발췌 authority가 있으면 최소 1로 보정(override 트리거용)
    if (!Number.isFinite(as.tier1_count) || as.tier1_count <= 0) {
      if (text_verified_authority_count > 0) as.tier1_count = 1;
    }
  }
} catch (e) {
  if (DEBUG) console.warn("⚠️ authority_signals(text_verified) patch failed:", e?.message || e);
}

// ✅ Authority override: 실제 근거 출처(도메인/티어) 기반으로 Cₜ 하한 보정
const auth = partial_scores.authority_signals || null;

partial_scores.authority_override = {
  applied: false,
  floor: null,
  tier1_count: auth?.tier1_count ?? 0,
  authority_hosts: Array.isArray(auth?.authority_hosts) ? auth.authority_hosts : [],
};

if (coverageEvaluated && auth && auth.has_authority) {
  // tier1(최상위) 근거가 있으면 더 강하게 “저표본 패널티 면제”
  const floor = (auth.tier1_count && auth.tier1_count > 0) ? 0.80 : 0.72;

  C_t = Math.max(C_t, floor);

  partial_scores.authority_override = {
    applied: true,
    floor,
    tier1_count: auth.tier1_count || 0,
    authority_hosts: Array.isArray(auth.authority_hosts) ? auth.authority_hosts : [],
  };
}

// 로그에서 볼 수 있도록 저장
partial_scores.coverage = C_t;

// ✅ UI/로그용(해석용): coverage를 실제로 평가했는지
partial_scores.coverage_eval = coverageEvaluated ? C_t : null;   // evidence 기반 평가값(미평가면 null)

// ✅ UI/로그용: coverage “미평가” 플래그(패널티 오해 방지)
partial_scores.coverage_unavailable = !coverageEvaluated;        // true면 “coverage 미평가”
partial_scores.coverage_unavailable_reason = coverageUnavailableReason;

// ✅ coverage 계산 “왜 이렇게 나왔는지” 메타
partial_scores.coverage_meta = {
  basis: coverageBasis,
  evaluated: coverageEvaluated,
  unavailable_reason: coverageUnavailableReason,

  N_SAT,
  C_T_MIN,
  C_T_ZERO,

  total_eff_evidence: totalEffEvidence,
  designed_to_call_count: designedToCallCount,
  effective_engine_count: effectiveEngineCount,
  engine_coverage_ratio: engineCoverageRatio,

  raw_evidence: coverageRawEvidence,
  raw_engine: coverageRawEngine,
  raw_combined: coverageRaw,

  weights: partial_scores.coverage_weights || null,

  C_t_base,
  C_t_final: C_t,
  coverage_eval: coverageEvaluated ? C_t : null,
  authority_override: partial_scores.authority_override,
};

// ✅ coverage 계산 스코프(어떤 집합/상태 기준인지)
// ✅ 항상 내보내는 coverage 스코프 요약(가벼움)
partial_scores.coverage_scope_summary = {
  basis: coverageBasis,
  designed_to_call: Array.isArray(designedToCallArr) ? designedToCallArr : [],
  designed_to_call_count: designedToCallCount,
  total_eff_evidence: totalEffEvidence,
  eff_engines: Array.isArray(effEnginesArr) ? effEnginesArr : [],
  effective_engines_count: Array.isArray(partial_scores.effective_engines) ? partial_scores.effective_engines.length : null,
};

// ✅ DEBUG일 때만 상세 스코프 제공(응답 크기 방지)
partial_scores.coverage_scope = DEBUG
  ? {
      eff_engines: Array.isArray(effEnginesArr) ? effEnginesArr : [],
      effective_engine_counts: effCounts || {},
      engines_requested: Array.isArray(partial_scores.engines_requested) ? partial_scores.engines_requested : null,
      engines_used: Array.isArray(partial_scores.engines_used) ? partial_scores.engines_used : null,
      effective_engines: Array.isArray(partial_scores.effective_engines) ? partial_scores.effective_engines : null,
      engine_call_summary: partial_scores.engine_call_summary || null,
    }
  : null;


// ✅ ConflictIndex: support vs conflict 비율로 상충 정도를 0~1로 계산 (TruthScore와 분리)
// ✅ ConflictIndex 분리 + 상세 분해(블록별/엔진별)
let conflictIndex = null;

// verifyMeta.blocks[].evidence.support/conflict 는 보통 ["crossref","naver"] 같은 “엔진명 문자열 배열”로 옴.
// 그래서 문자열을 engine으로 인식 + 별칭/URL도 정규화해서 by_engine 분해가 정확해지도록 함.
const KNOWN_ENGINES = new Set([
  "crossref",
  "openalex",
  "wikidata",
  "gdelt",
  "naver",
  "github",
  "klaw",
]);

const normalizeEngineName = (v) => {
  if (!v) return "unknown";
  let s = String(v).trim().toLowerCase();
  if (!s) return "unknown";

  // URL이면 host 기반으로 추정
  if (s.startsWith("http://") || s.startsWith("https://")) {
    try {
      const u = new URL(s);
      const host = (u.hostname || "").toLowerCase();
      if (!host) return "unknown";
      if (host.includes("openalex")) return "openalex";
      if (host.includes("crossref")) return "crossref";
      if (host.includes("wikidata") || host.includes("wikipedia")) return "wikidata";
      if (host.includes("gdelt")) return "gdelt";
      if (host.includes("naver")) return "naver";
      if (host.includes("github")) return "github";
      if (host.includes("law.go.kr")) return "klaw";
      return "unknown";
    } catch {
      // URL parse 실패면 아래 별칭 처리로 진행
    }
  }

  // 별칭/표기 흔들림 정리
  const aliasMap = {
    "open alex": "openalex",
    "open-alex": "openalex",
    "open_alex": "openalex",

    "cross ref": "crossref",
    "cross-ref": "crossref",
    "cross_ref": "crossref",

    "wiki": "wikidata",
    "wikidata.org": "wikidata",
    "wikipedia": "wikidata",

    "g-delt": "gdelt",
    "gdeltproject": "gdelt",

    "naver news": "naver",

    "k-law": "klaw",
    "k_law": "klaw",
    "law.go.kr": "klaw",
    "klaw": "klaw",
  };

  if (aliasMap[s]) s = aliasMap[s];

  // "engine: crossref" 같은 형태도 방어
  s = s.replace(/^engine\s*:\s*/i, "").trim();

  return KNOWN_ENGINES.has(s) ? s : "unknown";
};

const inferEngineFromEvidenceItem = (item) => {
  if (!item) return "unknown";

  // ✅ support/conflict가 문자열 배열인 경우가 가장 흔함
  if (typeof item === "string") return normalizeEngineName(item);

  // object 형태인 경우(확장 대비)
  const cand =
    item.engine ||
    item.source_engine ||
    item.provider ||
    item.source ||
    item.origin ||
    item.engine_name;

  if (cand && typeof cand === "string") {
    return normalizeEngineName(cand);
  }

  const url = item.source_url || item.url || item.link;
  if (url && typeof url === "string") {
    return normalizeEngineName(url);
  }

  return "unknown";
};

const bump = (obj, key, field, inc = 1) => {
  if (!obj[key]) obj[key] = { support: 0, conflict: 0, irrelevant: 0, total: 0, conflict_index: null };
  obj[key][field] += inc;
  obj[key].total += inc;
};

if (verifyMeta && Array.isArray(verifyMeta.blocks)) {
  let totalSupport = 0;
  let totalConflict = 0;
  let totalIrrelevant = 0;

 const byBlock = [];
const byEngine = {};
const byHost = {};

const inferUrlFromEvidenceItem = (item) => {
  if (!item) return null;
  if (typeof item === "string") {
    // URL이면 사용, 엔진명 문자열이면 null
    return (item.startsWith("http://") || item.startsWith("https://")) ? item : null;
  }
  return item.source_url || item.url || item.link || null;
};

const inferHostFromEvidenceItem = (item) => {
  if (!item) return null;

  // 1) 명시 host
  const h1 = (typeof item === "object" && item.source_host) ? String(item.source_host) : null;
  if (h1) return _stripWww(h1.toLowerCase());

  // 2) URL로부터 host 추출
  const url = inferUrlFromEvidenceItem(item);
  const h2 = url ? _hostFromUrlish(url) : null;
  return h2 ? _stripWww(String(h2).toLowerCase()) : null;
};

const bumpHost = (obj, host, field, inc = 1) => {
  const h = host ? _stripWww(String(host).toLowerCase()) : null;
  if (!h) return;
  if (!obj[h]) obj[h] = { support: 0, conflict: 0, irrelevant: 0, total: 0, conflict_index: null };
  obj[h][field] += inc;
  obj[h].total += inc;
};

const uniqHosts = (items, limit = 8) => {
  const arr = Array.isArray(items) ? items : [];
  const set = new Set();
  const out = [];
  for (const it of arr) {
    const h = inferHostFromEvidenceItem(it);
    if (!h) continue;
    if (set.has(h)) continue;
    set.add(h);
    out.push(h);
    if (out.length >= limit) break;
  }
  return out;
};

  for (let i = 0; i < verifyMeta.blocks.length; i++) {
    const blk = verifyMeta.blocks[i] || {};
    const ev = blk && blk.evidence ? blk.evidence : {};

    const supportArr = Array.isArray(ev.support) ? ev.support : [];
const conflictArr = Array.isArray(ev.conflict) ? ev.conflict : [];
const irrelevantArr = Array.isArray(ev.irrelevant) ? ev.irrelevant : [];

// ✅ 새 포맷: url/host/title 포함 “근거 아이템들”
const evItems = (blk && typeof blk === "object") ? blk.evidence_items : null;
const supportItems = Array.isArray(evItems?.support) ? evItems.support : [];
const conflictItems = Array.isArray(evItems?.conflict) ? evItems.conflict : [];
const irrelevantItems = Array.isArray(evItems?.irrelevant) ? evItems.irrelevant : [];

// ✅ host(도메인) 단위 집계는 evidence_items로만 계산(없으면 집계 없음)
for (const it of supportItems) bumpHost(byHost, inferHostFromEvidenceItem(it), "support", 1);
for (const it of conflictItems) bumpHost(byHost, inferHostFromEvidenceItem(it), "conflict", 1);
for (const it of irrelevantItems) bumpHost(byHost, inferHostFromEvidenceItem(it), "irrelevant", 1);


    const suppCount = supportArr.length;
    const confCount = conflictArr.length;
    const irrCount = irrelevantArr.length;

    totalSupport += suppCount;
    totalConflict += confCount;
    totalIrrelevant += irrCount;

    // 엔진별 분해: evidence item에 engine 필드가 없으면 unknown으로 집계
    for (const it of supportArr) {
      const eng = inferEngineFromEvidenceItem(it);
      bump(byEngine, eng, "support", 1);
    }
    for (const it of conflictArr) {
      const eng = inferEngineFromEvidenceItem(it);
      bump(byEngine, eng, "conflict", 1);
    }
    for (const it of irrelevantArr) {
      const eng = inferEngineFromEvidenceItem(it);
      bump(byEngine, eng, "irrelevant", 1);
    }

    const denomBlk = suppCount + confCount;
    const blkConflictIndex = denomBlk > 0 ? (confCount / denomBlk) : null;

   const uniqTop = (arr, limit = 8) => {
  const set = new Set();
  const out = [];
  for (const x of arr) {
    const n = normalizeEngineName(x);
    if (n === "unknown") continue;
    if (set.has(n)) continue;
    set.add(n);
    out.push(n);
    if (out.length >= limit) break;
  }
  return out;
};

byBlock.push({
  index: typeof blk.index === "number" ? blk.index : i,
  block_id: blk.block_id ?? null,
  title: blk.title ?? null,
  support: suppCount,
  conflict: confCount,
  irrelevant: irrCount,
  conflict_index: blkConflictIndex,

  // ✅ 디버깅용: 어떤 엔진이 support/conflict로 찍혔는지
  support_engines: uniqTop(supportArr, 8),
  conflict_engines: uniqTop(conflictArr, 8),
  irrelevant_engines: uniqTop(irrelevantArr, 8),
});
  support_hosts: uniqHosts(supportItems, 8),
  conflict_hosts: uniqHosts(conflictItems, 8),
  irrelevant_hosts: uniqHosts(irrelevantItems, 8),
  }

  // 엔진별 conflict_index 계산
  for (const [eng, stats] of Object.entries(byEngine)) {
    const denomEng = (stats.support || 0) + (stats.conflict || 0);
    stats.conflict_index = denomEng > 0 ? ((stats.conflict || 0) / denomEng) : null;
  }

  const denom = totalSupport + totalConflict;
  conflictIndex = denom > 0 ? (totalConflict / denom) : null;

  // 기존 필드 유지
  partial_scores.conflict_index = conflictIndex;

  // ✅ 상세 로그(너무 커지지 않게 block은 상위 30개까지만)
  const byBlockSorted = [...byBlock].sort((a, b) => (b.conflict || 0) - (a.conflict || 0));
  const topConflictBlocks = byBlockSorted.slice(0, 10);

  // engine도 conflict 많은 순으로 정렬한 리스트 제공
  const byEngineList = Object.entries(byEngine)
    .map(([engine, v]) => ({ engine, ...v }))
    .sort((a, b) => (b.conflict || 0) - (a.conflict || 0));

// host별 conflict_index 계산 + 보기 좋은 리스트
for (const [host, stats] of Object.entries(byHost)) {
  const denomHost = (stats.support || 0) + (stats.conflict || 0);
  stats.conflict_index = denomHost > 0 ? ((stats.conflict || 0) / denomHost) : null;
}

const byHostList = Object.entries(byHost)
  .map(([host, v]) => ({ host, ...v }))
  .sort((a, b) => (b.conflict || 0) - (a.conflict || 0));

const topConflictHosts = byHostList.slice(0, 10);

  const conflictDetail = {
  totals: {
    support: totalSupport,
    conflict: totalConflict,
    irrelevant: totalIrrelevant,
    denom_support_conflict: totalSupport + totalConflict,
    conflict_index: conflictIndex,
  },
  by_block: byBlock.slice(0, 30),
  top_conflict_blocks: topConflictBlocks,
  by_engine: byEngine,
  by_engine_list: byEngineList,
  by_host: byHost,
  by_host_list: byHostList,
  top_conflict_hosts: topConflictHosts,
  notes: {
    engine_infer: "evidence item에 engine/source_engine/provider 등이 없으면 unknown으로 집계됨",
    detail_included_only_when_debug: true,
  },
};

// ✅ 항상 내보내는 “요약”(응답 크기 안정화)
partial_scores.conflict_summary = {
  totals: conflictDetail.totals,
  top_conflict_blocks: (conflictDetail.top_conflict_blocks || []).slice(0, 5).map((b) => ({
    index: b.index,
    block_id: b.block_id ?? null,
    title: b.title ?? null,
    support: b.support,
    conflict: b.conflict,
    irrelevant: b.irrelevant,
    conflict_index: b.conflict_index,
    conflict_engines: b.conflict_engines || [],
    conflict_hosts: b.conflict_hosts || [],
    conflict_evidence_samples: b.conflict_evidence_samples ? b.conflict_evidence_samples.slice(0, 2) : [],
  })),
  top_conflict_engines: (conflictDetail.by_engine_list || []).slice(0, 8).map((e) => ({
    engine: e.engine,
    support: e.support,
    conflict: e.conflict,
    irrelevant: e.irrelevant,
    conflict_index: e.conflict_index,
  })),
  top_conflict_hosts: (conflictDetail.top_conflict_hosts || []).slice(0, 8).map((h) => ({
    host: h.host,
    support: h.support,
    conflict: h.conflict,
    irrelevant: h.irrelevant,
    conflict_index: h.conflict_index,
  })),
  detail_included: !!DEBUG,
};

// ✅ DEBUG일 때만 풀 디테일 제공
partial_scores.conflict_detail = DEBUG ? conflictDetail : null;
} else {
  partial_scores.conflict_index = null;
  partial_scores.conflict_summary = null; // ✅ 추가
  partial_scores.conflict_detail = null;
}

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
      const rawHybrid = R_t * combined * C * C_t;
      hybrid = Math.max(0, Math.min(1, rawHybrid));
    } else {
      // QV/FV:
      // - GDELT 시의성 Rₜ
      // - Naver 티어 팩터 N
      // - 엔진 보정 C
      // - Gemini 종합 스코어 G
      const rawHybrid = R_t * N * G * C * C_t;
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
// ⑥ 로그 및 DB 반영 (점수 계산 이후 / E_eff 반영)
// ─────────────────────────────

// ✅ 엔진 weight 업데이트는 E_eff(=effective_engines) 우선
const enginesForWeight = Array.isArray(partial_scores.effective_engines)
  ? partial_scores.effective_engines.filter((x) => x !== "klaw")
  : Array.isArray(partial_scores.engines_used)
    ? partial_scores.engines_used.filter((x) => x !== "klaw")
    : Array.isArray(engines)
      ? engines.filter((x) => x !== "klaw")
      : [];

// ✅ “호출은 됐는데(used에 있었는데) 최종 유효근거 0이라 빠진 엔진”을 로그로 남김
const excludedNoEffectiveEvidence =
  Array.isArray(partial_scores.engines_used) && Array.isArray(partial_scores.effective_engines)
    ? partial_scores.engines_used.filter((e) => !partial_scores.effective_engines.includes(e))
    : [];

partial_scores.engine_weight_meta = {
  basis: Array.isArray(partial_scores.effective_engines)
    ? "effective_engines"
    : Array.isArray(partial_scores.engines_used)
      ? "engines_used"
      : "engines",
  engines_for_weight: enginesForWeight,
  excluded_no_effective_evidence: excludedNoEffectiveEvidence,
};

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
const conflictPoolSummary = verifyMetaRaw ? s11_buildConflictPoolSummary(verifyMetaRaw) : null;
const conflictCounts = conflictPoolSummary?.counts || null;
const conflictByHost = conflictPoolSummary?.conflict_by_host || null;
const conflictHostsTop = conflictPoolSummary?.conflict_hosts_top || null;
const conflictIndexRaw =
  conflictCounts && typeof conflictCounts.conflict === "number"
    ? (() => {
        const denom = (conflictCounts.support || 0) + (conflictCounts.conflict || 0);
        return denom > 0 ? conflictCounts.conflict / denom : null;
      })()
    : null;

// ✅ ConflictIndex(상충도) — TruthScore와 분리된 “불확실성 지표”
const __conf01 =
  typeof conflictIndexRaw === "number"
    ? Math.max(0, Math.min(1, conflictIndexRaw))
    : (typeof normalizedPartial?.conflict_index === "number" &&
      Number.isFinite(normalizedPartial.conflict_index)
        ? Math.max(0, Math.min(1, normalizedPartial.conflict_index))
        : null);

const __confPct =
  typeof __conf01 === "number" ? Math.round(__conf01 * 10000) / 100 : null;

const __confLevel =
  typeof __conf01 === "number"
    ? (__conf01 >= 0.6 ? "high" : __conf01 >= 0.3 ? "medium" : "low")
    : null;

const __uncertainty01 = __conf01;
const __uncertaintyPct =
  typeof __uncertainty01 === "number" ? Math.round(__uncertainty01 * 10000) / 100 : null;

const payload = {
  mode: safeMode,

  // ✅ TruthScore (그대로)
  truthscore: truthscore_text,
  truthscore_pct,
  truthscore_01: Number(truthscore.toFixed(4)),

  // ✅ ConflictIndex (분리)
  conflict_index_pct: __confPct,
  conflict_index_01: __conf01,
  conflict_level: __confLevel,
  conflict_counts: conflictCounts || null,
  conflict_by_host: conflictByHost || null,
  conflict_hosts_top: conflictHostsTop || null,
  conflict_summary: normalizedPartial?.conflict_summary ?? null,
  uncertainty_01: __uncertainty01,
  uncertainty_pct: __uncertaintyPct,

  // ✅ UI/로그용 “불확실성 요약”(TruthScore와 분리)
  uncertainty: {
    conflict_index_01: __conf01,
    conflict_index_pct: __confPct,
    conflict_level: __confLevel,
    uncertainty_01: __uncertainty01,
    uncertainty_pct: __uncertaintyPct,

    coverage_unavailable: !!normalizedPartial?.coverage_unavailable,
    coverage_unavailable_reason: normalizedPartial?.coverage_unavailable_reason ?? null,

    authority_override: normalizedPartial?.authority_override ?? null,
  },

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

if (DEBUG && conflictPoolSummary) {
  payload.conflict_pool_summary = {
    counts: conflictCounts || { support: 0, conflict: 0, irrelevant: 0, blocks: 0 },
    conflict_by_host: conflictByHost || {},
    conflict_hosts_top: conflictHostsTop || [],
  };
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

    const r1 = await c.query("SELECT NOW() as now");
    const r2 = await c.query("select to_regclass('public.session_store') as session_store");

    c.release();

    return res.json(
      buildSuccess({
        message: "✅ DB 연결 성공",
        time: r1.rows[0].now,
        session_store: r2.rows[0].session_store, // ✅ 'session_store'면 정상, null이면 없음/스키마 다름
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

app.get("/health", async (_, res) => {
  let pac = { pt_date: null, next_reset_utc: null };
  try { pac = await getPacificResetInfoCached(); } catch {}
  return res.status(200).json({
    status: "ok",
    version: "v18.4.0-pre",
    uptime: process.uptime().toFixed(2) + "s",
    region: REGION,
    pacific_pt_date: pac.pt_date,
    pacific_next_reset_utc: pac.next_reset_utc,
    timestamp: new Date().toISOString(),
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
app.get("/api/test-session", async (req, res) => {
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
