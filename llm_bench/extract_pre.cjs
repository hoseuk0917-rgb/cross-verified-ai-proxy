// extract_pre.cjs
const fs = require("fs");

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function safeParseJson(text) {
  try { return { ok: true, obj: JSON.parse(text) }; }
  catch (e) { return { ok: false, err: String(e) }; }
}

function extractGroq(path) {
  const j = readJson(path);
  const t = (j.choices?.[0]?.message?.content ?? "").trim();
  return t;
}

function extractGemini(path) {
  const j = readJson(path);
  const parts = j.candidates?.[0]?.content?.parts ?? [];
  const t = parts.map(p => p.text ?? "").join("").trim();
  return t;
}

function extractCloudflare(path) {
  const j = readJson(path);
  // 다양한 형태 대응: result가 string/object/array일 수 있음
  const r = j.result ?? j;
  if (typeof r === "string") return r.trim();
  if (r && typeof r === "object" && typeof r.response === "string") return r.response.trim();
  return JSON.stringify(r, null, 2);
}

function main() {
  const groq = fs.existsSync("out_groq_pre.json") ? extractGroq("out_groq_pre.json") : "";
  const gem  = fs.existsSync("out_gemini_pre.json") ? extractGemini("out_gemini_pre.json") : "";
  const cf   = fs.existsSync("out_cf_pre.json") ? extractCloudflare("out_cf_pre.json") : "";

  if (groq) {
    console.log("=== GROQ RAW ===");
    console.log(groq);
    const p = safeParseJson(groq);
    console.log(p.ok ? "GROQ JSON: OK" : `GROQ JSON: FAIL (${p.err})`);
  }

  if (gem) {
    console.log("\n=== GEMINI RAW ===");
    console.log(gem);
    const p = safeParseJson(gem);
    console.log(p.ok ? "GEMINI JSON: OK" : `GEMINI JSON: FAIL (${p.err})`);
  }

  if (cf) {
    console.log("\n=== CF RAW ===");
    console.log(cf);
    const p = safeParseJson(cf);
    console.log(p.ok ? "CF JSON: OK" : `CF JSON: (not-json or envelope)`);
  }
}

main();
