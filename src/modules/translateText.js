// src/modules/translateText.js
// =======================================================
// Cross-Verified AI — Translation Module
// DeepL (우선) + Gemini 2.5 Flash-Lite Fallback
// - text: 원문 텍스트
// - targetLang: "EN" / "KO" / null (null이면 자동 결정)
// - deepl_key: 요청 본문에서 넘어온 DeepL 키 (선택)
// - gemini_key: 선택적으로 넘길 Gemini 키 (없으면 환경변수 사용)
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

  const apiUrl =
    process.env.DEEPL_API_URL || "https://api-free.deepl.com/v2/translate";

  const target = (targetLang || "EN").toUpperCase(); // DeepL: EN / KO

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
 * Gemini 2.5 Flash-Lite를 사용한 번역 (DeepL 실패 시 폴백)
 * - geminiKey: 요청에서 넘어온 키 우선, 없으면 환경변수 사용
 *   (예: process.env.GEMINI_TRANSLATION_KEY)
 */
async function translateWithGeminiFlashLite(text, targetLang, geminiKey) {
  const key = geminiKey || process.env.GEMINI_TRANSLATION_KEY;
  if (!key) throw new Error("GEMINI_TRANSLATION_KEY_MISSING");

  const target = (targetLang || "EN").toUpperCase();

  // 원문 언어 추정 (프롬프트에 힌트로만 사용)
  const srcLang = detectLangSimple(text);

  const prompt = [
    "역할: 전문 번역기.",
    "- 설명, 해석, 요약을 추가하지 말 것.",
    "- 코드/수식은 가능한 한 그대로 유지.",
    "- 문체는 원문 톤을 유지.",
    "",
    `[원문 언어: ${srcLang}, 목표 언어: ${target}]`,
    "아래 텍스트를 자연스럽게 번역해줘:",
    "----",
    text,
    "----",
  ].join("\n");

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=${key}`;

  const res = await axios.post(
    url,
    {
      contents: [
        {
          parts: [{ text: prompt }],
        },
      ],
    },
    { timeout: 40000 }
  );

  const translated =
    res?.data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
  if (!translated) throw new Error("GEMINI_TRANSLATION_EMPTY_RESULT");

  return {
    text: translated,
    engine: "gemini-flash-lite",
    target,
  };
}

/**
 * 통합 번역 함수
 * - 1순위: DeepL (요청에서 넘긴 deepl_key 또는 환경변수)
 * - 2순위: Gemini 2.5 Flash-Lite (요청에서 넘긴 gemini_key 또는 환경변수)
 * - 전부 실패시: 원문 그대로 반환 (engine: "none")
 */
export async function translateText(
  text,
  targetLang = null,
  deepl_key = null,
  gemini_key = null
) {
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
    if (process.env.DEBUG_MODE === "true") {
      console.warn("⚠️ DeepL 실패, Gemini Flash-Lite로 Fallback:", e.message);
    }
  }

  // 2️⃣ Gemini Flash-Lite 시도
  try {
    const geminiResult = await translateWithGeminiFlashLite(
      text,
      normalizedTarget,
      gemini_key
    );
    return geminiResult;
  } catch (e) {
    if (process.env.DEBUG_MODE === "true") {
      console.warn(
        "⚠️ Gemini Flash-Lite 번역 실패, 원문 그대로 반환:",
        e.message
      );
    }
  }

  // 3️⃣ 전부 실패시 원문 그대로
  return {
    text,
    engine: "none",
    target: normalizedTarget,
  };
}
