// engine/gemini.js
const axios = require("axios");

module.exports = {
  /**
   * 실제 Google Gemini API 호출
   */
  async callGemini({ apiKey, model = "gemini-1.5-pro", prompt, temperature = 0.7, maxTokens = 2048 }) {
    try {
      console.log(`[Gemini Engine] Calling real Gemini API: ${model}`);

      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        {
          contents: [
            {
              role: "user",
              parts: [{ text: prompt }]
            }
          ],
          generationConfig: {
            temperature,
            maxOutputTokens: maxTokens
          }
        },
        { headers: { "Content-Type": "application/json" } }
      );

      const text = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "⚠️ No response text.";
      return { success: true, text };
    } catch (error) {
      console.error("[Gemini Engine] API Error:", error.response?.data || error.message);
      return { success: false, error: error.response?.data || error.message };
    }
  },

  /**
   * 키워드 추출 (간단한 로컬 로직)
   */
  async extractKeywords(text) {
    try {
      console.log(`[Gemini Engine] Extracting keywords`);
      const words = text
        .replace(/[^\w\s]/gi, "")
        .split(" ")
        .filter(w => w.length > 2)
        .slice(0, 10);
      return { success: true, keywords: words };
    } catch (err) {
      console.error("[Gemini Engine] Keyword extraction error:", err);
      return { success: false, keywords: [] };
    }
  },

  /**
   * Gemini API Key 유효성 검증
   */
  async validateApiKey(apiKey) {
    try {
      const testUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest?key=${apiKey}`;
      const res = await axios.get(testUrl);
      const valid = !!res.data?.name;
      return { success: true, valid };
    } catch (error) {
      console.error("[Gemini Engine] API key validation failed:", error.response?.data || error.message);
      return { success: false, valid: false, error: error.message };
    }
  }
};
