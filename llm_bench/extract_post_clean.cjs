// extract_post_clean.cjs
const fs = require("fs");

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function stripFences(s) {
  if (s == null) return "";

  // ✅ if already an object, stringify safely
  if (typeof s === "object") {
    try { return JSON.stringify(s); } catch { return String(s); }
  }

  s = String(s).trim();

  // ```json ... ``` or ``` ... ```
  const m = s.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  if (m) s = m[1].trim();

  // stray backticks
  s = s.replace(/^`+|`+$/g, "").trim();

  // ✅ slice to JSON object/array if there is any leading/trailing noise
  const iObj = s.indexOf("{"), jObj = s.lastIndexOf("}");
  const iArr = s.indexOf("["), jArr = s.lastIndexOf("]");
  if (iObj >= 0 && jObj > iObj && (iArr < 0 || iObj < iArr)) {
    s = s.slice(iObj, jObj + 1);
  } else if (iArr >= 0 && jArr > iArr) {
    s = s.slice(iArr, jArr + 1);
  }

  // ✅ trailing commas (best-effort)
  s = s.replace(/,\s*([}\]])/g, "$1");

  return s.trim();
}

function tryParse(text) {
  const cleaned = stripFences(text);
  try {
    return { ok: true, obj: JSON.parse(cleaned), cleaned };
  } catch (e) {
    return { ok: false, err: String(e), cleaned };
  }
}

// --- provider extractors ---
function groqText(j) {
  return j?.choices?.[0]?.message?.content ?? "";
}
function geminiText(j) {
  const parts = j?.candidates?.[0]?.content?.parts ?? [];
  return parts.map(p => p?.text ?? "").join("");
}
function cfText(j) {
  const r = j?.result;
  if (r == null) return "";

  if (typeof r === "string") return r;

  const cand = r?.response ?? r?.output ?? r?.text ?? r;
  if (typeof cand === "string") return cand;

  try { return JSON.stringify(cand); }
  catch { return String(cand); }
}

function writePretty(path, obj) {
  fs.writeFileSync(path, JSON.stringify(obj, null, 2), "utf8");
}

function summarize(label, parsed) {
  if (!parsed.ok) {
    console.log(`[${label}] JSON: FAIL  -> ${parsed.err}`);
    console.log(`--- ${label} cleaned (first 500) ---`);
    console.log(parsed.cleaned.slice(0, 500));
    console.log("");
    return;
  }
  const o = parsed.obj;
  const verdict = o.verdict ?? "(missing verdict)";
  const conf = o.confidence_01 ?? "(missing confidence_01)";
  const used = Array.isArray(o.evidence_used) ? o.evidence_used.length : 0;
  const nextq = Array.isArray(o.next_queries) ? o.next_queries.length : 0;
  const koLen = (o.final_answer_ko ?? "").length;
  console.log(`[${label}] JSON: OK  verdict=${verdict}  conf=${conf}  evidence_used=${used}  next_queries=${nextq}  final_ko_len=${koLen}`);
}

// --- main ---
// --- main ---
const run = process.argv[2]; // e.g. "1"
const groqPath = run ? `./out_groq_post_${run}.json` : "./out_groq_post.json";
const gemPath  = run ? `./out_gemini_post_${run}.json` : "./out_gemini_post.json";
const cfPath   = run ? `./out_cf_post_${run}.json` : "./out_cf_post.json";

const groqRaw = readJson(groqPath);
const gemRaw  = readJson(gemPath);
const cfRaw   = readJson(cfPath);

const g = tryParse(groqText(groqRaw));
const m = tryParse(geminiText(gemRaw));
const c = tryParse(cfText(cfRaw));

summarize("GROQ", g);
summarize("GEMINI", m);
summarize("CF", c);

const suf = run ? `_${run}` : "";
if (g.ok) writePretty(`./post_json_groq${suf}.json`, g.obj);
if (m.ok) writePretty(`./post_json_gemini${suf}.json`, m.obj);
if (c.ok) writePretty(`./post_json_cf${suf}.json`, c.obj);

console.log("Wrote: post_json_*.json (only if OK)");
