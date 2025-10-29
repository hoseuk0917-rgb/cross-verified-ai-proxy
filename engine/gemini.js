/**
 * engine/gemini.js
 * Cross-Verified AI Proxy v10.2.1
 * - Gemini 2.5 Flash / Pro / Lite 지원
 * - Fail-Grace 로직 (개별 Key 단위)
 * - 앱 레벨 Key-Rotation 신호 전달
 */

const axios = require("axios");

/**
 * Google Gemini 호출 (Fail-Grace 대응)
 */
module.exports = {
  async callGemini({ apiKey, model = "gemini-2.5-flash", prompt }) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

    try {
      const response = await axios.post(
        url,
        {
          contents: [{ role: "user", parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.7,
            maxOutputTokens: 2048,
          },
        },
        { timeout: 15000 }
      );

      const text =
        response.data?.candidates?.[0]?.content?.parts?.[0]?.text ||
        "⚠️ No response text.";

      return {
        success: true,
        state: "ok",
        text,
        model,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      const status = error.response?.status || 500;
      const message =
        error.response?.data?.error?.message || error.message || "Unknown error";
      const resetTime = getNextPacificMidnight();

      // ⚠️ Rate limit 초과 or Timeout → Fail-Grace
      if (status === 429 || error.code === "ECONNABORTED") {
        return {
          success: false,
          state: "fail_grace",
          code: status === 429 ? 429 : "TIMEOUT",
          error:
            status === 429
              ? "Rate limit exceeded for this key"
              : "Request timeout",
          retryAfter: resetTime,
        };
      }

      // 🔴 기타 오류 → 일반 Error
      return {
        success: false,
        state: "error",
        code: status,
        error: message,
      };
    }
  },

  /**
   * 키워드 추출 (간단한 로컬 로직)
   */
  async extractKeywords(text) {
    try {
      const words = text
        .replace(/[^\w\s]/gi, "")
        .split(/\s+/)
        .filter((w) => w.length > 2)
        .slice(0, 10);
      return { success: true, keywords: words };
    } catch (err) {
      return { success: false, keywords: [] };
    }
  },

  /**
   * Gemini API Key 유효성 검증
   */
  async validateApiKey(apiKey) {
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash?key=${apiKey}`;
      const res = await axios.get(url, { timeout: 8000 });
      const valid = !!res.data?.name;
      return { success: true, valid };
    } catch (error) {
      return {
        success: false,
        valid: false,
        error: error.response?.data?.error?.message || error.message,
      };
    }
  },
};

/**
 * ⏰ 태평양 자정 리셋 타임 계산 (UTC-8)
 */
function getNextPacificMidnight() {
  const now = new Date();
  const utcOffsetMinutes = 8 * 60; // PST 기준
  const pacificNow = new Date(now.getTime() - utcOffsetMinutes * 60 * 1000);
  pacificNow.setUTCHours(24, 0, 0, 0);
  return pacificNow.toISOString();
}
