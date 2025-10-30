// engine/truthscore.js
// TruthScore 계산 모듈 (v10.4.2)
export function calculateTruthScore(results) {
  try {
    const weights = {
      CrossRef: 0.25,
      OpenAlex: 0.20,
      GDELT: 0.15,
      Wikidata: 0.13,
      Naver: 0.12,
      KLaw: 0.10,
      GitHub: 0.00 // GitHub은 가중치 없음
    };

    let numerator = 0;
    let denominator = 0;

    for (const r of results) {
      const w = weights[r.engine] || 0;
      const Qi = r.success ? 1 : 0; // 성공한 요청만 반영
      const Vi = r.hits && r.hits > 0 ? 1 : 0;
      numerator += Qi * Vi * w;
      denominator += Qi * w;
    }

    const truthScore = denominator > 0 ? numerator / denominator : 0;

    return {
      success: true,
      truthScore: Number(truthScore.toFixed(3)),
      totalEngines: results.length,
      details: results
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
