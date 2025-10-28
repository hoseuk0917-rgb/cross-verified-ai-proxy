// engine/gemini.js
module.exports = {
  async callGemini({ apiKey, model, prompt }) {
    console.log(`[Gemini Engine] Called model=${model} prompt=${prompt}`);
    return { success: true, text: `Simulated Gemini output for: ${prompt}` };
  },

  async extractKeywords(text) {
    console.log(`[Gemini Engine] Extracting keywords from text: ${text}`);
    return { success: true, keywords: text.split(' ').slice(0, 5) };
  },

  async validateApiKey(apiKey) {
    console.log(`[Gemini Engine] Validating API key`);
    return { success: true, valid: !!apiKey };
  }
};
