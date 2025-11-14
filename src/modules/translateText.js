// src/modules/translateText.js
// =======================================================
// Cross-Verified AI — Translation Module
// DeepL (우선) + LibreTranslate Fallback
// - text: 원문 텍스트
// - targetLang: "EN" / "KO" / null (null이면 자동결정)
// - deepl_key: 요청 본문에서 넘어온 DeepL 키 (선택)
// =======================================================

import axios from "axios";

/**
 * 언어 자동 감지 (아주 단순 버전)
 * - 한글 포함: ko
 * - 알파벳 위주: en
 * - 그 외: en (기본)
 */
function detectLangSimple(text = "") {
  const hasKorean = /[가-힣]/.test(text);
  const hasLatin = /[A-Za-z]/.test(text);

  if (hasKorean && !hasLatin) return "KO";
  if (!hasKorean && hasLatin) return "EN";
  if (hasKorean && hasLatin) {
    // 한영 섞여 있으면, 길이에 따라 결정
    const koCount = (text.match(/[가-힣]/g) || []).length;
    const enCount = (text.match(/[A-Za-z]/g) || []).length;
    return koCount >= enCount ? "KO" : "EN";
  }
  return "EN";
}

/**
 * DeepL을 사용한 번역 (실패 시 에러 throw)
 * - deeplKey: 요청에서 넘어온 키 우선, 없으면 환경변수 사용
 */
async function translateWithDeepL(text, targetLang, deeplKey) {
  const key = deeplKey || process.env.DEEPL_API_KEY;
  if (!key) throw new Error("DEEPL_KEY_MISSING");

  const apiUrl = process.env.DEEPL_API_URL || "https://api-free.deepl.com/v2/translate";

  // DeepL은 한국어를 KO 로, 영어를 EN 으로 사용
  const target = (targetLang || "EN").toUpperCase();

  const params = new URLSearchParams();
  params.append("auth_key", key);
  params.append("text", text);
  params.append("target_lang", target);

  const res = await axios.post(apiUrl, params);
  const translated = res?.data?.translations?.[0]?.text;
  if (!translated) throw new Error("DEEPL_EMPTY_RESULT");

  return {
    text: translated,
    engine: "deepl",
    target,
  };
}

/**
 * LibreTranslate Fallback
 * - 무료 / 공개 인스턴스 (기본값: libretranslate.de)
 * - 환경변수 LIBRE_TRANSLATE_URL 있으면 그쪽을 우선 사용
 */
async function translateWithLibre(text, targetLang) {
  const baseUrl =
    process.env.LIBRE_TRANSLATE_URL || "https://libretranslate.de/translate";

  // LibreTranslate 는 언어코드가 소문자: "en", "ko"
  const target = (targetLang || "EN").toUpperCase();
  const targetLower = target.toLowerCase();

  // src는 자동 감지 대신 간단 로직 사용
  const srcLang = detectLangSimple(text).toLowerCase();

  const res = await axios.post(
    baseUrl,
    {
      q: text,
      source: srcLang === targetLower ? "auto" : srcLang,
      target: targetLower,
      format: "text",
    },
    {
      headers: {
        "Content-Type": "application/json",
      },
      timeout: 15000,
    }
  );

  const translated = res?.data?.translatedText;
  if (!translated) throw new Error("LIBRE_EMPTY_RESULT");

  return {
    text: translated,
    engine: "libre",
    target,
  };
}

/**
 * 통합 번역 함수
 * - 1순위: DeepL (요청에서 넘긴 deepl_key 또는 환경변수)
 * - 2순위: LibreTranslate (공개 인스턴스 또는 환경변수)
 * - 전부 실패시: 원문 그대로 반환 (engine: "none")
 */
export async function translateText(text, targetLang = null, deepl_key = null) {
  if (!text || !text.trim()) {
    return {
      text: "",
      engine: "none",
      target: targetLang || "EN",
    };
  }

  // 타겟 언어 자동 결정:
  // - 원문이 한글이면 EN
  // - 원문이 영어면 KO
  let target = targetLang;
  if (!target) {
    const src = detectLangSimple(text);
    target = src === "KO" ? "EN" : "KO";
  }
  const normalizedTarget = target.toUpperCase();

  // 1️⃣ DeepL 시도
  try {
    const deeplResult = await translateWithDeepL(
      text,
      normalizedTarget,
      deepl_key
    );
    return deeplResult;
  } catch (e) {
    // 키 없음, 한도초과 등 어떤 이유든 Fallback 으로 내려보냄
    if (process.env.DEBUG_MODE === "true") {
      console.warn("⚠️ DeepL 실패, Libre로 Fallback:", e.message);
    }
  }

  // 2️⃣ LibreTranslate 시도
  try {
    const libreResult = await translateWithLibre(text, normalizedTarget);
    return libreResult;
  } catch (e) {
    if (process.env.DEBUG_MODE === "true") {
      console.warn("⚠️ LibreTranslate 실패, 원문 반환:", e.message);
    }
  }

  // 3️⃣ 전부 실패시 원문 그대로
  return {
    text,
    engine: "none",
    target: normalizedTarget,
  };
}
