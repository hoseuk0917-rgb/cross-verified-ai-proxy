/**
 * engine/verification.js
 * v10.3.0 — 사용자 입력형 API 키 구조
 * - req.body.keys.* 값이 우선
 * - fallback으로 process.env.* 사용
 */

const axios = require("axios");

async function safeFetch(fn, name) {
  try {
    const data = await fn();
    return { engine: name, success: true, hits: data.hits || 0, data };
  } catch (err) {
    return { engine: name, success: false, hits: 0, error: err.message };
  }
}

module.exports = {
  async verifySingleEngine(engine, query, keys = {}) {
    switch (engine.toLowerCase()) {
      case "crossref": return safeFetch(() => crossrefSearch(query), "CrossRef");
      case "openalex": return safeFetch(() => openalexSearch(query), "OpenAlex");
      case "gdelt": return safeFetch(() => gdeltSearch(query), "GDELT");
      case "wikidata": return safeFetch(() => wikidataSearch(query), "Wikidata");
      case "github": return safeFetch(() => githubSearch(query, keys), "GitHub");
      case "k-law": return safeFetch(() => klawSearch(query, keys), "K-Law");
      case "naver": return safeFetch(() => naverSearch(query, keys), "Naver");
      default:
        return { success: false, error: `Invalid engine name: ${engine}` };
    }
  },

  async verifyAllEngines(query, keys = {}) {
    const results = await Promise.allSettled([
      safeFetch(() => crossrefSearch(query), "CrossRef"),
      safeFetch(() => openalexSearch(query), "OpenAlex"),
      safeFetch(() => gdeltSearch(query), "GDELT"),
      safeFetch(() => wikidataSearch(query), "Wikidata"),
      safeFetch(() => githubSearch(query, keys), "GitHub"),
      safeFetch(() => klawSearch(query, keys), "K-Law"),
      safeFetch(() => naverSearch
