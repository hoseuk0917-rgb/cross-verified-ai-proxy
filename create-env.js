// ✅ create-env.js
// Render Secrets와 충돌하지 않는 안전한 로컬용 .env.local 생성기

import fs from "fs";

const safeEnv = {
  // --- 기본 서버 설정 ---
  PORT: 3000,
  NODE_ENV: "production",
  APP_VERSION: "v12.1.2",
  DEV_MODE: "false",

  // --- 모델 구조 ---
  VERIFY_PREPROCESS_MODEL: "gemini-2.5-flash-lite",
  DEFAULT_MODEL: "gemini-2.5-flash",
  VERIFY_EVALUATOR_MODEL: "gemini-2.5-pro",
  GEMINI_TEST_MODEL: "gemini-2.5-flash-lite",
  ALLOW_MODEL_OVERRIDE: "true",
  VERIFY_TIMEOUT_MS: "20000",
  TRUTH_LAMBDA_BASE: "1.0",

  // --- 서버 로그 및 핑 정책 ---
  PING_INTERVAL_SEC: "660",
  LOG_HEALTH_PINGS: "true",
  LOG_REQUESTS: "true",
  LOG_LEVEL: "info",

  // --- CORS 허용 도메인 ---
  ALLOWED_ORIGINS:
    "https://cross-verified-ai.onrender.com,https://cross-verified-ai-proxy.onrender.com",
  ALLOW_FALLBACK_ORIGIN: "true",

  // --- API 제한 ---
  RATE_LIMIT_WINDOW_MS: "900000",
  RATE_LIMIT_MAX_REQUESTS: "100",
  MAX_REQUEST_BODY_MB: "5",
};

const fileContent = Object.entries(safeEnv)
  .map(([k, v]) => `${k}=${v}`)
  .join("\n");

fs.writeFileSync(".env.local", fileContent);
console.log("✅ .env.local 생성 완료 (민감정보 제외)");
