// engine/verification.js
const axios = require("axios");

async function verifySingleEngine(engine, query) {
  console.log(`[Verification] Called engine=${engine}, query="${query}"`);

  switch (engine.toLowerCase()) {
    case "crossref":
      return { engine: "CrossRef", hits: Math.floor(Math.random() * 20) + 1 };
    case "openalex":
      return { engine: "OpenAlex", hits: Math.floor(Math.random() * 15) + 1 };
    case "gdelt":
      return { engine: "GDELT", hits: Math.floor(Math.random() * 10) + 1 };
    case "wikidata":
      return { engine: "Wikidata", hits: Math.floor(Math.random() * 8) + 1 };
    default:
      throw new Error("Invalid engine name");
  }
}

async function verifyAllEngines(query) {
  console.log(`[Verification] Running parallel for query="${query}"`);

  const engines = ["CrossRef", "OpenAlex", "GDELT", "Wikidata"];
  const results = await Promise.all(
    engines.map(async (engine) => {
      const hits = Math.floor(Math.random() * 20) + 1;
      return { engine, hits };
    })
  );

  return { success: true, query, results };
}

// ✅ 반드시 객체 형태로 내보내기
module.exports = {
  verifySingleEngine,
  verifyAllEngines,
};
