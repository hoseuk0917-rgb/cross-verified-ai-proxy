// engine/truthscore.js
// TruthScore 계산 모듈 (v10.5.0)
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
    const breakdown = [];

    for (const r of results) {
      const w = weights[r.engine] || 0;
      const Qi = r.success ? 1 : 0;
      const Vi = r.hits && r.hits > 0 ? 1 : 0;
      const score = Qi * Vi * w;

      numerator += score;
      denominator += Qi * w;

      breakdown.push({
        engine: r.engine,
        weight: w,
        success: r.success,
        hits: r.hits,
        partialScore: Number(score.toFixed(3))
      });
    }

    const truthScore = denominator > 0 ? numerator / denominator : 0;

    return {
      success: true,
      truthScore: Number(truthScore.toFixed(3)),
      totalEngines: results.length,
      breakdown
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
