// build_post_case1.cjs
const fs = require("fs");
const path = require("path");

const dir = __dirname;

const tplPath = path.join(dir, "post_prompt_template_case1.txt");
const prePath = path.join(dir, "pre_json_selected.json");
const evPath  = path.join(dir, "evidence_case1.json");
const outPath = path.join(dir, "post_prompt_case1.txt");

for (const p of [tplPath, prePath, evPath]) {
  if (!fs.existsSync(p)) throw new Error("Missing: " + p);
}

const tpl = fs.readFileSync(tplPath, "utf8");
const pre = fs.readFileSync(prePath, "utf8").trim();
const ev  = fs.readFileSync(evPath, "utf8").trim();

let out = tpl.replaceAll("__PRE_JSON__", pre).replaceAll("__EVIDENCE__", ev);
fs.writeFileSync(outPath, out, "utf8");

console.log("OK: wrote post_prompt_case1.txt");
