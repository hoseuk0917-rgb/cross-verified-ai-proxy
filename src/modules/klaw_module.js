// =======================================================
// K-Law Module (Full Extended Hybrid) — v18.4.0
// (v16.6 ~ v17.5 기능 100% 복원 + 누락 블록 재추가)
// - 유의어/오타/명사결합 확장
// - XML → JSON Fallback 파서
// - 한·영 병렬 질의(옵션)
// - 가중치 병합 스코어 (관련도·빈도·유사도)
// - Supabase 로깅(옵션, .env 존재 시)
// - Verbose Debug(옵션)
// =======================================================

import fs from "fs";
import path from "path";
import axios from "axios";
import xml2js from "xml2js";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

// ── 환경
dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEBUG = (process.env.DEBUG_MODE === "true");

// ── 설정 파일 로드 (유의어/제거어) - 반드시 프로젝트 루트 기준 ./config 유지
const TERMS_PATH = path.resolve(process.cwd(), "config", "klaw_terms.json");
const GENERIC_PATH = path.resolve(process.cwd(), "config", "generic_filter.json");

// 안전 로드
function safeLoadJSON(p, fallback = {}) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf-8"));
  } catch {
    if (DEBUG) console.warn(`⚠️ config load fail: ${p} → using fallback`);
    return fallback;
  }
}
const synonymMap = safeLoadJSON(TERMS_PATH, {});
const genericWords = safeLoadJSON(GENERIC_PATH, {
  allow: [], conditional: [], exclude: []
});

// ── 선택적 Supabase 로깅 (있으면 사용, 없으면 Skip)
let supabase = null;
(async () => {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  if (url && key) {
    const { createClient } = await import("@supabase/supabase-js");
    supabase = createClient(url, key, { auth: { persistSession: false } });
    if (DEBUG) console.log("🔗 Supabase logging enabled for K-Law module");
  }
})();

// ── DeepL + LibreTranslate 번역기 (옵션) — ONLY IF KEYS PROVIDED
async function translateText(text, target = "en") {
  if (!text || !target) return text;

  // 1) DeepL (우선)
  const DEEPL_KEY = process.env.DEEPL_KEY;
  if (DEEPL_KEY) {
    try {
      const r = await axios.post(
        "https://api-free.deepl.com/v2/translate",
        new URLSearchParams({ text, target_lang: target.toUpperCase() }),
        { headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `DeepL-Auth-Key ${DEEPL_KEY}` }, timeout: 10000 }
      );
      const t = r?.data?.translations?.[0]?.text;
      if (t) return t;
    } catch (e) {
      if (DEBUG) console.warn("⚠️ DeepL fail:", e.message);
    }
  }

  // 2) LibreTranslate (폴백)
  const LIBRE_URL = process.env.LIBRE_URL || "https://libretranslate.com/translate";
  try {
    const r2 = await axios.post(
      LIBRE_URL,
      { q: text, target },
      { headers: { "Content-Type": "application/json" }, timeout: 10000 }
    );
    const t2 = r2?.data?.translatedText;
    if (t2) return t2;
  } catch (e) {
    if (DEBUG) console.warn("⚠️ LibreTranslate fail:", e.message);
  }
  return text;
}

// ── 간단 NER Hybrid (품사/빈도 유사 로직 대체)
// - 허용목록(genericWords.allow), 조건어(genericWords.conditional), 제거어(genericWords.exclude)
// - 빈도 기반 필터 + 길이 제한 + 숫자 제거
function tokenizeKOEN(s = "") {
  return (s || "")
    .replace(/[^\uAC00-\uD7A3A-Za-z0-9\s]/g, " ")
    .split(/\s+/)
    .map(w => w.trim())
    .filter(w => w.length >= 2 && !/^[0-9]+$/.test(w));
}

function countFreq(arr) {
  const m = new Map();
  for (const a of arr) m.set(a, (m.get(a) || 0) + 1);
  return m;
}

function bigramJoin(tokens) {
  const out = [];
  for (let i = 0; i < tokens.length - 1; i++) {
    const pair = tokens[i] + tokens[i + 1];
    if (pair.length > 3) out.push(pair);
  }
  return out;
}

// Bigram 유사도
function ngramSimilarity(a, b) {
  if (!a || !b) return 0;
  const A = new Set(a.match(/.{1,2}/g));
  const B = new Set(b.match(/.{1,2}/g));
  const inter = [...A].filter(x => B.has(x)).length;
  const union = new Set([...A, ...B]).size;
  return union ? inter / union : 0;
}

// Levenshtein Distance
function levenshtein(a = "", b = "") {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// 유의어/오타/명사결합 기반 Core Term 추출 (NER-lite)
function extractCoreTerms(query) {
  const raw = tokenizeKOEN(query);
  const freq = countFreq(raw);
  const base = [];

  for (let i = 0; i < raw.length; i++) {
    const w = raw[i];
    if (!w) continue;
    if (genericWords.exclude?.includes(w)) continue;
    // 조건어는 끝단어일 때만
    if (genericWords.conditional?.includes(w) && i !== raw.length - 1) continue;
    // 허용어 가점 반영(빈도 + 허용어 여부)
    const boost = genericWords.allow?.includes(w) ? 1.25 : 1.0;
    if ((freq.get(w) || 0) * boost >= 1) base.push(w);
  }

  // 유의어/오타 확장
  const expanded = new Set(base);
  for (const w of base) {
    if (synonymMap[w]) for (const s of synonymMap[w]) expanded.add(s);
    for (const key of Object.keys(synonymMap)) {
      const lv = levenshtein(w, key);
      const ng = ngramSimilarity(w, key);
      if (lv <= 1 && ng >= 0.7) expanded.add(key);
    }
  }

  // 명사 결합
  for (const b of bigramJoin(base)) expanded.add(b);

  // 정렬 (길이↓, 빈도↓)
  const ordered = [...expanded].sort((a, b) => {
    const fa = freq.get(a) || 0, fb = freq.get(b) || 0;
    if (b.length !== a.length) return b.length - a.length;
    return fb - fa;
  });

  // 최대 10개
  return ordered.slice(0, 10);
}

// 영문 질의 확장(옵션): 핵심 단어만 대상, 번역기 키 없으면 원문 유지
async function buildBilingualQueries(queryKOR, enableEN = true) {
  const termsKO = extractCoreTerms(queryKOR);
  const qKO = Array.from(new Set([queryKOR, ...termsKO])).slice(0, 8);
  if (!enableEN) return { qKO, qEN: [] };

  // 번역 키가 없을 수 있으므로 실패해도 조용히 패스
  const qEN = [];
  for (const t of qKO) {
    const tr = await translateText(t, "en");
    if (tr && tr !== t) qEN.push(tr);
  }
  // 중복 제거
  const uniqEN = Array.from(new Set(qEN)).slice(0, 8);
  return { qKO, qEN: uniqEN };
}

// XML → JSON Fallback 파서
async function xmlToJSON(xml) {
  return new Promise((resolve, reject) => {
    xml2js.parseString(xml, { explicitArray: false }, (err, res) => {
      if (err) return reject(err);
      resolve(res);
    });
  });
}

// K-Law API 호출기 (JSON 선호, 실패 시 XML Fallback)
async function callKLaw(OC, target, query) {
  const base = "http://www.law.go.kr/DRF/lawSearch.do";
  const urlJSON = `${base}?OC=${OC}&target=${target}&type=JSON&mobileYn=Y&query=${encodeURIComponent(query)}`;
  const urlXML = `${base}?OC=${OC}&target=${target}&type=XML&mobileYn=Y&query=${encodeURIComponent(query)}`;

  // JSON 시도
  try {
    const { data } = await axios.get(urlJSON, { timeout: 10000 });
    return data;
  } catch (e) {
    if (DEBUG) console.warn(`⚠️ JSON fail(${target}):`, e.message);
  }

  // XML Fallback
  try {
    const { data } = await axios.get(urlXML, { timeout: 12000 });
    const j = await xmlToJSON(data);
    return j || {};
  } catch (e) {
    if (DEBUG) console.warn(`⚠️ XML fail(${target}):`, e.message);
    return {};
  }
}

// 결과 Push 헬퍼
function pushItem(section, 구분, 제목, 요약, 링크, 부처, 시행일자, 관련도) {
  section.push({
    구분, 제목, 요약, 링크, 부처, 시행일자,
    관련도
  });
}

// 점수 계산: 관련도(키워드 일치) + 제목 유사도 + 간단 빈도 가중
function scoreItem(title = "", matchedTerm = "", baseRel = 1) {
  const sim = ngramSimilarity(String(title), String(matchedTerm));
  return Math.max(0.5, Math.min(2.0, baseRel + sim)); // 0.5 ~ 2.0
}

// 중복제거 + 정렬
function dedupeAndSort(list = []) {
  const seen = new Set();
  const out = [];
  for (const i of list) {
    const key = `${i.제목}#${i.링크 || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(i);
  }
  // 관련도 ↓, 시행일자 ↓ (가능하면)
  out.sort((a, b) => {
    const r = (b.관련도 || 0) - (a.관련도 || 0);
    if (r !== 0) return r;
    const da = a.시행일자 ? Number(a.시행일자.replace(/[^\d]/g, "")) : 0;
    const db = b.시행일자 ? Number(b.시행일자.replace(/[^\d]/g, "")) : 0;
    return db - da;
  });
  return out;
}
// === Part 2/2 계속 ===

// 메인: 한·영 병렬 질의 + 4타겟(law, art, interpretation, prec) 통합
// 옵션 enableEN: 영문 병렬 질의 사용 여부 (기본 true)
// options.verbose: 단계 로그
// options.limitPerTarget: 타겟별 상위 N개 반환 (기본 40)
export async function fetchKLawAll(OC, query, options = {}) {
  const enableEN = (options.enableEN !== false); // 기본 true
  const verbose = !!options.verbose || DEBUG;
  const limitPerTarget = Number.isFinite(options.limitPerTarget) ? options.limitPerTarget : 40;

  if (verbose) console.log("🔎 [K-Law] start:", { query, enableEN, limitPerTarget });

  if (!OC || !query) {
    return {
      success: false,
      message: "❌ OC(인증키) 또는 query 누락",
      resultCount: 0,
      result: { law: [], art: [], interpretation: [], prec: [] }
    };
  }

  // 1) 핵심어 + 한·영 병렬 질의 생성
  const { qKO, qEN } = await buildBilingualQueries(query, enableEN);
  if (verbose) console.log("🧩 Queries:", { qKO, qEN });

  const targets = ["law", "art", "interpretation", "prec"];
  const result = { law: [], art: [], interpretation: [], prec: [] };

  // 2) 순차/부분 병렬 호출 (과부하 방지)
  const allQueries = [...qKO, ...qEN];
  for (const kw of allQueries) {
    for (const t of targets) {
      const data = await callKLaw(OC, t, kw);
      const section = [];

      if (t === "law" && data?.LawSearch?.law) {
        const arr = Array.isArray(data.LawSearch.law) ? data.LawSearch.law : [data.LawSearch.law];
        for (const i of arr) {
          const title = i["법령명한글"] || i["법령명"] || i["title"] || "";
          const score = scoreItem(title, kw, 1.2); // 법령은 기본 가중 조금 더
          pushItem(section,
            "법령",
            title,
            i["공포번호"] ? `공포번호 ${i["공포번호"]}, 시행 ${i["시행일자"]}` : "",
            `https://www.law.go.kr/법령/${encodeURIComponent(title)}`,
            i["소관부처명"],
            i["시행일자"],
            score
          );
        }
      }

      if (t === "art" && data?.LawSearch?.article) {
        const arr = Array.isArray(data.LawSearch.article) ? data.LawSearch.article : [data.LawSearch.article];
        for (const i of arr) {
          const title = i.articleName || i.lawName || "";
          const score = scoreItem(title, kw, 1.0);
          pushItem(section,
            "조문",
            title,
            (i.content || "").slice(0, 200),
            `https://www.law.go.kr/법령/${i.lawId}`,
            "", "",
            score
          );
        }
      }

      if (t === "interpretation" && data?.LawSearch?.interpretation) {
        const arr = Array.isArray(data.LawSearch.interpretation) ? data.LawSearch.interpretation : [data.LawSearch.interpretation];
        for (const i of arr) {
          const title = i.title || "";
          const score = scoreItem(title, kw, 1.05);
          pushItem(section,
            "법령해석",
            title,
            (i.opinion || "").slice(0, 200),
            `https://www.law.go.kr/LSW/admInterpretP.do?admInterpretSeq=${i.interpretationSeq}`,
            "", "",
            score
          );
        }
      }

      if (t === "prec" && data?.LawSearch?.prec) {
        const arr = Array.isArray(data.LawSearch.prec) ? data.LawSearch.prec : [data.LawSearch.prec];
        for (const i of arr) {
          const title = i.caseName || "";
          const score = scoreItem(title, kw, 1.1);
          pushItem(section,
            "판례",
            title,
            (i.caseSummary || "").slice(0, 200),
            `https://www.law.go.kr/LSW/precInfoP.do?precSeq=${i.precSeq}`,
            "", "",
            score
          );
        }
      }

      result[t].push(...section);

      // API 과부하 방지 (짧은 딜레이)
      await new Promise(r => setTimeout(r, 160));
    }
  }

  // 3) 중복 제거 + 정렬 + 상한
  for (const t of targets) {
    result[t] = dedupeAndSort(result[t]).slice(0, limitPerTarget);
  }

  // 4) Supabase 로깅 (옵션)
  let total = Object.values(result).flat().length;
  if (supabase) {
    try {
      await supabase.from("klaw_logs").insert([{
        query,
        query_ko: JSON.stringify(qKO),
        query_en: JSON.stringify(qEN),
        total_results: total,
        created_at: new Date()
      }]);
    } catch (e) {
      if (DEBUG) console.warn("⚠️ klaw_logs insert fail:", e.message);
    }
  }

  if (verbose) console.log("✅ [K-Law] done:", { total });

  return {
    success: true,
    query,
    queries: { ko: qKO, en: qEN },
    resultCount: total,
    result
  };
}
