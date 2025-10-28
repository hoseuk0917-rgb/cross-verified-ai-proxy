// engine/truthscore.js
module.exports = {
  INITIAL_WEIGHTS: {
    crossref: 0.25,
    openalex: 0.2,
    gdelt: 0.15,
    wikidata: 0.13,
    klaw: 0.15,
    github: 0.12
  },
  DELTA_W_INITIAL: 0.05,

  calculateTruthScore(engines) {
    if (!Array.isArray(engines) || engines.length === 0)
      return { success: false, error: "No engines data" };

    let numerator = 0, denominator = 0;
    engines.forEach(e => {
      const q = e.quality || 0;
      const v = e.keywordMatch || 0;
      const w = e.weight || 1.0;
      numerator += q * v * w;
      denominator += q * w;
    });

    const truthScore = denominator ? numerator / denominator : 0;
    const percentage = (truthScore * 100).toFixed(2);
    const label =
      truthScore >= 0.9 ? "높은 신뢰도" :
      truthScore >= 0.7 ? "불확실" :
      truthScore >= 0.5 ? "경고" : "낮은 신뢰도";
    const icon =
      truthScore >= 0.9 ? "🟢" :
      truthScore >= 0.7 ? "❔" :
      truthScore >= 0.5 ? "⚠️" : "❌";

    return {
      success: true,
      truthScore,
      percentage,
      icon,
      label
    };
  }
};
