// extract_pre_clean.cjs
const fs = require("fs");

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function stripFences(s) {
  if (s == null) return "";

  // ✅ if already an object, stringify it safely
  if (typeof s === "object") {
    try { return JSON.stringify(s); } catch { return String(s); }
  }

  s = String(s).trim();

  const m = s.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  if (m) s = m[1].trim();

  s = s.replace(/^`+|`+$/g, "").trim();

  const iObj = s.indexOf("{"), jObj = s.lastIndexOf("}");
  const iArr = s.indexOf("["), jArr = s.lastIndexOf("]");
  if (iObj >= 0 && jObj > iObj && (iArr < 0 || iObj < iArr)) {
    s = s.slice(iObj, jObj + 1);
  } else if (iArr >= 0 && jArr > iArr) {
    s = s.slice(iArr, jArr + 1);
  }

  s = s.replace(/,\s*([}\]])/g, "$1");

  return s.trim();
}

function mustJsonParse(label, text) {
  const cleaned = stripFences(text);
  try {
    const obj = JSON.parse(cleaned);
    return { ok: true, obj, cleaned };
  } catch (e) {
    return { ok: false, err: e, cleaned };
  }
}

function getCfText(j) {
  // Workers AI responses vary; handle common shapes (string OR object)
  const r = j?.result;
  if (r == null) return "";

  if (typeof r === "string") return r;

  const cand = r?.response ?? r?.output ?? r?.text ?? r;
  if (typeof cand === "string") return cand;

  try { return JSON.stringify(cand); }
  catch { return String(cand); }
}

function getGroqText(j) {
  return j?.choices?.[0]?.message?.content ?? "";
}

function getGeminiText(j) {
  const parts = j?.candidates?.[0]?.content?.parts ?? [];
  return parts.map(p => p?.text ?? "").join("");
}

function writePretty(path, obj) {
  fs.writeFileSync(path, JSON.stringify(obj, null, 2), "utf8");
}

const run = process.argv[2]; // e.g. "1"
const groqPath = run ? `./out_groq_pre_${run}.json` : "./out_groq_pre.json";
const gemPath  = run ? `./out_gemini_pre_${run}.json` : "./out_gemini_pre.json";
const cfPath   = run ? `./out_cf_pre_${run}.json` : "./out_cf_pre.json";

const groqRaw = readJson(groqPath);
const gemRaw  = readJson(gemPath);
const cfRaw   = readJson(cfPath);

const groqText = getGroqText(groqRaw);
const gemText  = getGeminiText(gemRaw);
const cfText   = getCfText(cfRaw);

const g = mustJsonParse("GROQ", groqText);
const m = mustJsonParse("GEMINI", gemText);
const c = mustJsonParse("CF", cfText);

console.log("GROQ parse:", g.ok ? "OK" : "FAIL");
console.log("GEMINI parse:", m.ok ? "OK" : "FAIL");
console.log("CF parse:", c.ok ? "OK" : "FAIL");

if (!g.ok) console.log("\n[GROQ cleaned]\n" + g.cleaned);
if (!m.ok) console.log("\n[GEMINI cleaned]\n" + m.cleaned);
if (!c.ok) console.log("\n[CF cleaned]\n" + c.cleaned);

if (g.ok) writePretty("./pre_json_groq.json", g.obj);
if (m.ok) writePretty("./pre_json_gemini.json", m.obj);
if (c.ok) writePretty("./pre_json_cf.json", c.obj);

console.log("Wrote: pre_json_*.json (only for OK parses)");
