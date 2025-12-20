// score_post_case1.cjs
const fs = require("fs");
const path = require("path");

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function exists(p) {
  return fs.existsSync(p);
}

const dir = __dirname;
const labelsPath = path.join(dir, "labels_case2.json");
if (!exists(labelsPath)) throw new Error("Missing labels_case2.json");

const labelsDoc = readJson(labelsPath);
const goldVerdict = (labelsDoc.gold_overall_verdict || "").trim();
const requireNumber = !!labelsDoc.require_number;

// supports both formats:
// 1) labels: {E1:"SUPPORT", ...}
// 2) support_ids/contradict_ids/noise_ids arrays
const gold = (() => {
  if (labelsDoc.labels && typeof labelsDoc.labels === "object") return labelsDoc.labels;

  const out = {};
  for (const id of (labelsDoc.support_ids || [])) out[String(id)] = "SUPPORT";
  for (const id of (labelsDoc.contradict_ids || [])) out[String(id)] = "CONTRADICT";
  for (const id of (labelsDoc.noise_ids || [])) out[String(id)] = "NOISE";
  return out;
})();

const PROVIDERS = ["groq", "gemini", "cf"];
const N = 10;

function normVerdict(v) {
  v = String(v || "").trim().toUpperCase();
  if (v === "SUPPORTED" || v === "CONTRADICTED" || v === "INSUFFICIENT") return v;
  return "UNKNOWN";
}

function setOf(arr) {
  const s = new Set();
  if (Array.isArray(arr)) for (const x of arr) s.add(String(x));
  return s;
}

function scoreEvidence(usedIds) {
  // label classes: SUPPORT / CONTRADICT / NOISE
  // We score: did the model avoid NOISE? did it include SUPPORT/CONTRADICT?
  const used = setOf(usedIds);

  let usedSupport = 0, usedContradict = 0, usedNoise = 0, usedUnknown = 0;
  for (const id of used) {
    const lab = (gold[id] || "").toUpperCase();
    if (lab === "SUPPORT") usedSupport++;
    else if (lab === "CONTRADICT") usedContradict++;
    else if (lab === "NOISE") usedNoise++;
    else usedUnknown++;
  }

  // totals
  let totalSupport = 0, totalContradict = 0, totalNoise = 0;
  for (const id of Object.keys(gold)) {
    const lab = (gold[id] || "").toUpperCase();
    if (lab === "SUPPORT") totalSupport++;
    else if (lab === "CONTRADICT") totalContradict++;
    else if (lab === "NOISE") totalNoise++;
  }

  // simple rates
  const picked = used.size;
  const noiseRate = picked ? (usedNoise / picked) : 0;

  // recall-like for support/contradict (how many of available did it pick)
  const supportRecall = totalSupport ? (usedSupport / totalSupport) : 0;
  const contradictRecall = totalContradict ? (usedContradict / totalContradict) : 0;

  return {
    picked,
    usedSupport,
    usedContradict,
    usedNoise,
    usedUnknown,
    noiseRate,
    supportRecall,
    contradictRecall
  };
}

function hasNumber(s) {
  s = String(s || "");

  // 의미있는 큰 숫자만:
  //  - 콤마 큰 수: 51,234,567
  //  - 5자리 이상: 51234
  //  - 한국식 단위: 5천만 / 5100만 / 1.2억
  //  - 한자 단위(변형): 萬/亿/億 등
  return /(\d{1,3}(,\d{3})+|\d{5,}|\d+(?:\.\d+)?\s*(천만|만|억|萬|亿|億))/g.test(s);
}

function summarizeProvider(p) {
  const rows = [];
  for (let i = 1; i <= N; i++) {
    const fp = path.join(dir, `post_json_${p}_${i}.json`);
    if (!exists(fp)) {
      rows.push({ run: i, ok: false, err: "missing post_json" });
      continue;
    }
    let o;
    try { o = readJson(fp); }
    catch { rows.push({ run: i, ok: false, err: "bad json file" }); continue; }

    const verdict = normVerdict(o.verdict);
    const conf = Number(o.confidence_01 || 0);
    const used = Array.isArray(o.evidence_used) ? o.evidence_used : [];
    const ev = scoreEvidence(used);
    const ans = String(o.final_answer_ko || "");
    const ansHasNumber = hasNumber(ans);
    const strictOk = (verdict === normVerdict(goldVerdict)) && (!requireNumber || ansHasNumber);
    rows.push({
      run: i,
      ok: true,
      verdict,
      conf,
      picked: ev.picked,
      usedSupport: ev.usedSupport,
      usedContradict: ev.usedContradict,
      usedNoise: ev.usedNoise,
      noiseRate: ev.noiseRate,
      supportRecall: ev.supportRecall,
      contradictRecall: ev.contradictRecall,
      ansLen: ans.length,
      ansHasNumber,
      strictOk
    });
  }

  // aggregate
  const okRows = rows.filter(r => r.ok);
  const n = okRows.length;

  const verdictCounts = {};
  for (const r of okRows) verdictCounts[r.verdict] = (verdictCounts[r.verdict] || 0) + 1;

  const avg = (k) => n ? (okRows.reduce((a,r)=>a+(Number(r[k])||0),0)/n) : 0;

  const verdictAcc = goldVerdict
    ? (okRows.filter(r => r.verdict === normVerdict(goldVerdict)).length / n)
    : null;
  
  const strictAcc = goldVerdict
  ? (okRows.filter(r => r.strictOk).length / n)
  : null;

  return { rows, n, verdictCounts, verdictAcc, strictAcc, avg };
}

console.log("=== SCORE POST CASE2 ===");
console.log("case_id:", labelsDoc.case_id || "(missing)");
console.log("gold_overall_verdict:", goldVerdict || "(missing)");
console.log("");

for (const p of PROVIDERS) {
  const S = summarizeProvider(p);

  console.log(`== ${p.toUpperCase()} ==`);
  console.log("ok_runs:", `${S.n}/${N}`);
  console.log("verdict_counts:", JSON.stringify(S.verdictCounts));
  if (S.verdictAcc != null) console.log("verdict_accuracy:", S.verdictAcc.toFixed(3));
  if (S.strictAcc != null) console.log("strict_accuracy:", S.strictAcc.toFixed(3));

  console.log(
    "avg_conf:", S.avg("conf").toFixed(3),
    "avg_picked:", S.avg("picked").toFixed(2),
    "avg_usedNoise:", S.avg("usedNoise").toFixed(2),
    "avg_noiseRate:", S.avg("noiseRate").toFixed(3),
    "avg_supportRecall:", S.avg("supportRecall").toFixed(3),
    "avg_contradictRecall:", S.avg("contradictRecall").toFixed(3),
    "avg_ansLen:", S.avg("ansLen").toFixed(1),
    "ans_has_number_rate:", (S.n ? (S.rows.filter(r=>r.ok && r.ansHasNumber).length / S.n) : 0).toFixed(3)
  );

  // print anomalies
  const bad = S.rows.filter(r =>
  !r.ok ||
  r.verdict === "UNKNOWN" ||
  r.ansLen < 20 ||
  r.picked === 0 ||
  (requireNumber && r.ok && !r.ansHasNumber)
);
  if (bad.length) {
    console.log("-- anomalies --");
    for (const r of bad) {
      console.log(JSON.stringify(r));
    }
  }
  console.log("");
}

