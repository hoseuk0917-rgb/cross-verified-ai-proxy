// engine/truthscore.js
module.exports = {
  INITIAL_WEIGHTS: {
    crossref: 1.0,
    openalex: 0.9,
    gdelt: 0.8,
    wikidata: 0.85,
    github: 0.75,
    klaw: 0.9
  },
  DELTA_W_INITIAL: 0.1,

  calculateTruthScore(engines) {
    console.log(`[TruthScore Engine] Calculating truth score...`);
    const total = engines.reduce((sum, e) => sum + (e.quality || 0), 0);
    const score = Math.min(1.0, total / (engines.length || 1));
    return { success: true, truthScore: score };
  }
};
