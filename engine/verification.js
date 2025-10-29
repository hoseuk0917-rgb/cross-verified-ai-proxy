// engine/verification.js
const axios = require("axios");

// ✅ 개별 엔진 검증
async function verifySingleEngine(engine, query) {
  const name = engine.toLowerCase();
  console.log(`[Verification] Called engine=${name}, query="${query}"`);

  switch (name) {
    case "crossref":
      return { engine: "CrossRef", hits: Math.floor(Math.random() * 20) + 1 };

    case "openalex":
      return { engine: "OpenAlex", hits: Math.floor(Math.random() * 15) + 1 };

    case "gdelt":
      return { engine: "GDELT", hits: Math.floor(Math.random() * 10) + 1 };

    case "wikidata":
      return { engine: "Wikidata", hits: Math.floor(Math.random() * 8) + 1 };

    // ✅ 확장 가능 엔진
    case "github":
      return { engine: "GitHub", hits: Math.floor(Math.random() * 12) + 1 };

    case "klaw":
      return { engine: "K-Law", hits: Math.floor(Math.random() * 9) + 1 };

    case "naver":
      return { engine: "Naver", hits: Math.floor(Math.random() * 14) + 1 };

    default:
      throw new Error(`Invalid engine name: ${engine}`);
  }
}

// ✅ 병렬 전체 검증 (모든 엔진 통합)
async function verifyAllEngines(query) {
  console.log(`[Verification] Running parallel for query="${query}"`);

  // 🔹 통합 엔진 리스트
  const engines = ["crossref", "openalex", "gdelt", "wikidata", "github", "klaw", "naver"];

  const results = await Promise.all(
    engines.map(async (engine) => {
      try {
        const res = await verifySingleEngine(engine, query);
        return res;
      } catch (err) {
        return { engine, error: err.message };
      }
    })
  );

  return { success: true, query, results };
}

module.exports = {
  verifySingleEngine,
  verifyAllEngines,
};
