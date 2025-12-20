const fs = require("fs");
const path = require("path");

const dir = __dirname;
const src = fs.readFileSync(path.join(dir, "kw_caseA.txt"), "utf8");

// evidence 원문 전체 텍스트(간단히 전체에서 검사)
const evidenceText = src;

function exists(p) { return fs.existsSync(p); }
function readJson(p) { return JSON.parse(fs.readFileSync(p, "utf8")); }

function stripCodeFence(s) {
  s = String(s || "").trim();
  if (s.startsWith("```")) {
    s = s.replace(/^```[a-zA-Z]*\s*/,"").replace(/```$/,"").trim();
  }
  return s;
}

function extractAssistantContent(groqResp) {
  const c = groqResp?.choices?.[0]?.message?.content ?? "";
  return String(c);
}

function parseModelJson(text) {
  const t = stripCodeFence(text);
  return JSON.parse(t);
}

function extractNumbersFromEvidence(text) {
  const re = /(\d{1,3}(,\d{3})+|\d{5,}|\d+\s*(천만|만|억)|\d+\.\d+)/g;
  const m = text.match(re) || [];
  return Array.from(new Set(m.map(x=>x.trim())));
}

const evNums = extractNumbersFromEvidence(evidenceText);

const N = 10;
let foundAny = false;

for (let i=1; i<=N; i++) {
  const fp = path.join(dir, `out_groq_kw_${i}.json`);
  if (!exists(fp)) continue;
  foundAny = true;

  const raw = readJson(fp);
  const httpMeta = raw?.error ? "ERR" : "OK";

  let out;
  try {
    out = parseModelJson(extractAssistantContent(raw));
  } catch (e) {
    console.log(`[${i}] PARSE_FAIL`, e.message);
    continue;
  }

  const numbers = Array.isArray(out.numbers) ? out.numbers.map(String) : [];
  const quotes  = Array.isArray(out.quotes)  ? out.quotes.map(String)  : [];
  const terms   = Array.isArray(out.terms)   ? out.terms.map(String)   : [];
  const entities= Array.isArray(out.entities)? out.entities.map(String): [];

  // 1) quotes/terms/entities가 evidence에 실제로 존재하는지
  const inEvidence = (s) => s && evidenceText.includes(s);

  const quoteOk = quotes.length ? (quotes.filter(inEvidence).length / quotes.length) : 0;
  const termOk  = terms.length ? (terms.filter(inEvidence).length / terms.length) : 0;
  const entOk   = entities.length ? (entities.filter(inEvidence).length / entities.length) : 0;

  // 2) 숫자: precision(환각) / recall(놓침)
  const numPrecision = numbers.length ? (numbers.filter(inEvidence).length / numbers.length) : 1;
  const numRecall = evNums.length ? (evNums.filter(n => numbers.includes(n)).length / evNums.length) : 0;

  console.log(
    `[${i}] quotes_ok=${quoteOk.toFixed(2)} terms_ok=${termOk.toFixed(2)} ent_ok=${entOk.toFixed(2)} ` +
    `num_prec=${numPrecision.toFixed(2)} num_recall=${numRecall.toFixed(2)} ` +
    `nums_out=${numbers.length} quotes_out=${quotes.length}`
  );
}

if (!foundAny) {
  console.log("No out_groq_kw_#.json found. Run run_groq_kw.cmd first.");
}
