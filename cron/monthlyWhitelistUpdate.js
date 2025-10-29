/**
 * Cross-Verified AI
 * Monthly Whitelist Auto Evaluation + Auto-Approval (v10.3.0)
 * 정책 반영:
 * - 매월 화이트리스트 자동 갱신 (누적 저장 금지)
 * - 최근 3회 로그만 유지
 * - 평균 대비 30% 이상 기사량 증가 시 Tier3 자동 승격
 * - 관리자 이메일 자동 알림
 * Author: KAIA | 고호석
 */

import fs from "fs";
import axios from "axios";
import nodemailer from "nodemailer";
import path from "path";

// ==================================================
// 경로 설정
// ==================================================
const WHITELIST_PATH = path.resolve("./data/naver_whitelist.json");
const LOG_PATH = path.resolve("./logs/whitelist-refresh.log");

// ==================================================
// 환경 변수
// ==================================================
const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID;
const NAVER_CLIENT_SECRET = process.env.NAVER_CLIENT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_APP_PASSWORD = process.env.ADMIN_APP_PASSWORD;

// ==================================================
// 유효성 검사
// ==================================================
if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
  console.error("❌ NAVER API Key 설정 누락: NAVER_CLIENT_ID / NAVER_CLIENT_SECRET 확인 필요");
  process.exit(1);
}

// ==================================================
// NAVER 뉴스 기사 수 조회
// ==================================================
async function fetchNewsCount(domain) {
  const query = `site:${domain}`;
  try {
    const res = await axios.get("https://openapi.naver.com/v1/search/news.json", {
      params: { query, display: 100, sort: "date" },
      headers: {
        "X-Naver-Client-Id": NAVER_CLIENT_ID,
        "X-Naver-Client-Secret": NAVER_CLIENT_SECRET,
      },
    });
    return res.data.total || 0;
  } catch (err) {
    console.error(`[ERROR] ${domain}:`, err.message);
    return 0;
  }
}

// ==================================================
// 화이트리스트 평가 로직
// ==================================================
async function evaluateWhitelist() {
  console.log("📊 [Whitelist] 월간 갱신 시작...");

  const whitelist = JSON.parse(fs.readFileSync(WHITELIST_PATH, "utf8"));
  const allDomains = Object.values(whitelist.tiers).flatMap((t) => t.domains);

  // 병렬로 기사 수 조회
  const results = await Promise.allSettled(
    allDomains.map(async (domain) => {
      const count = await fetchNewsCount(domain);
      return { domain, count };
    })
  );

  const avgCount =
    results.reduce((sum, r) => sum + (r.value?.count || 0), 0) / results.length;

  const promoted = results
    .filter((r) => r.value && r.value.count > avgCount * 1.3)
    .map((r) => r.value.domain);

  // Tier3 자동 승격
  whitelist.tiers.tier3.domains = [
    ...new Set([...whitelist.tiers.tier3.domains, ...promoted]),
  ];
  whitelist.lastUpdate = new Date().toISOString().split("T")[0];

  // 기존 데이터 덮어쓰기
  fs.writeFileSync(WHITELIST_PATH, JSON.stringify(whitelist, null, 2));

  // 로그 갱신
  const logEntry = `[${new Date().toISOString()}] Auto-approved ${promoted.length} domains: ${promoted.join(", ")}`;
  fs.appendFileSync(LOG_PATH, logEntry + "\n");

  // ✅ 최근 3회만 유지
  try {
    const logs = fs.readFileSync(LOG_PATH, "utf8").trim().split("\n");
    if (logs.length > 3) {
      const trimmed = logs.slice(logs.length - 3).join("\n") + "\n";
      fs.writeFileSync(LOG_PATH, trimmed);
      console.log(`🧹 Log trimmed to last 3 entries`);
    }
  } catch (err) {
    console.warn("⚠️ Log rotation skipped:", err.message);
  }

  // 관리자 이메일 알림
  if (ADMIN_EMAIL && ADMIN_APP_PASSWORD) {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: ADMIN_EMAIL, pass: ADMIN_APP_PASSWORD },
    });

    await transporter.sendMail({
      from: ADMIN_EMAIL,
      to: ADMIN_EMAIL,
      subject: `[Cross-Verified AI] 화이트리스트 자동 갱신 완료`,
      text: `이번 달 자동 갱신이 완료되었습니다.\n\n승격된 언론사 수: ${promoted.length}\n갱신일: ${whitelist.lastUpdate}\n\n승격 목록:\n${promoted.join(", ")}`,
    });

    console.log(`📧 이메일 발송 완료 → ${ADMIN_EMAIL}`);
  }

  console.log(`✅ 자동 갱신 완료 (승격 ${promoted.length}건)`);
}

// ==================================================
// 실행
// ==================================================
evaluateWhitelist();
