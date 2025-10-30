// engine/verification.js
// 각 검증엔진 호출 모듈 (단순 시뮬레이션 버전)
import fetch from "node-fetch";

export async function verifyEngines(query) {
  try {
    const engines = [
      "CrossRef", "OpenAlex", "GDELT",
      "Wikidata", "GitHub", "KLaw", "Naver"
    ];

    const results = await Promise.all(
      engines.map(async (engine) => {
        try {
          const response = await fakeFetch(engine, query);
          return { engine, success: true, hits: response.hits };
        } catch {
          return { engine, success: false, hits: 0 };
        }
      })
    );

    return results;
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function fakeFetch(engine, query) {
  // 실제 연결 시 API 호출로 교체 가능
  const simulatedHits = Math.floor(Math.random() * 5);
  await new Promise((r) => setTimeout(r, 150));
  return { hits: simulatedHits };
}
