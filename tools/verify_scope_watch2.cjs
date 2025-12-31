const fs = require("fs");

const file = process.argv[2] || "server.js";
const startLine = parseInt(process.argv[3] || "10121", 10);

const s = fs.readFileSync(file, "utf8");

// startLine 오프셋
let idx = 0;
let cur = 1;
while (cur < startLine && idx < s.length) {
  const nl = s.indexOf("\n", idx);
  if (nl === -1) { idx = s.length; break; }
  idx = nl + 1;
  cur++;
}

let line = startLine;
let col = 0;

let depth = 0;        // ✅ verifyCoreHandler 내부만: 0에서 시작
let started = false;

const mode = ["code"]; // code | line | block | sq | dq | tpl_text | tpl_expr
let esc = false;
const tplExprMarkers = []; // depth snapshot at `${` entry

const top = () => mode[mode.length - 1];
const push = (m) => mode.push(m);
const pop = () => mode.pop();

const watch = [
  "const verifyCoreHandler",
  "Whitelist endpoints",
  "const ADMIN_TOKEN",
  'app.post("/api/verify"',
  'app.post("/api/verify-snippet"',
  'app.post("/api/lv"',
  'app.post("/api/uv"',
  'app.get("/api/health"',
  "app.use(\"/api\"",
];

let curLineText = "";
function logIfHit() {
  const t = curLineText;
  for (const w of watch) {
    if (t.includes(w)) {
      console.log(`[HIT] line=${line} depth=${depth} :: ${w}`);
      break;
    }
  }
}

for (let p = idx; p < s.length; p++) {
  const ch = s[p];
  const nx = s[p + 1];

  if (ch === "\n") {
    logIfHit();
    curLineText = "";
    line++; col = 0;
    if (top() === "line") pop();
    continue;
  }
  col++;
  curLineText += ch;

  // line comment
  if (top() === "line") continue;

  // block comment
  if (top() === "block") {
    if (ch === "*" && nx === "/") { pop(); p++; col++; }
    continue;
  }

  // strings
  if (top() === "sq") {
    if (!esc && ch === "\\") { esc = true; continue; }
    if (!esc && ch === "'") pop();
    esc = false;
    continue;
  }
  if (top() === "dq") {
    if (!esc && ch === "\\") { esc = true; continue; }
    if (!esc && ch === '"') pop();
    esc = false;
    continue;
  }

  // template literal text
  if (top() === "tpl_text") {
    if (!esc && ch === "\\") { esc = true; continue; }

    // enter ${ ... }
    if (!esc && ch === "$" && nx === "{") {
      // `${`에서의 `{`를 depth로 친다
      depth++; started = true;
      tplExprMarkers.push(depth);
      push("tpl_expr");
      p++; col++;
      esc = false;
      continue;
    }

    // close template literal
    if (!esc && ch === "`") { pop(); esc = false; continue; }

    esc = false;
    continue;
  }

  // template expression: behaves like code, but we need to know when it ends
  // (we exit tpl_expr when depth returns to marker-1 via a `}`)
  // NOTE: tpl_expr 자체는 아래의 code 로직으로 처리됨

  // open comments (only in code/tpl_expr)
  if (ch === "/" && nx === "/") { push("line"); p++; col++; continue; }
  if (ch === "/" && nx === "*") { push("block"); p++; col++; continue; }

  // open strings/templates
  if (ch === "'") { push("sq"); continue; }
  if (ch === '"') { push("dq"); continue; }
  if (ch === "`") { push("tpl_text"); continue; }

  // braces
  if (ch === "{") { depth++; started = true; continue; }

  if (ch === "}") {
    if (!started) continue;
    depth--;

    // close tpl_expr if we returned to marker-1
    if (top() === "tpl_expr") {
      const marker = tplExprMarkers[tplExprMarkers.length - 1];
      if (marker && depth === marker - 1) {
        tplExprMarkers.pop();
        pop(); // back to tpl_text
      }
    }

    if (depth === 0) {
      console.log(`[CLOSE] verifyCoreHandler closes at line=${line} col=${col}`);
      process.exit(0);
    }
    if (depth < 0) {
      console.log(`[ERR] depth went negative at line=${line} col=${col}`);
      process.exit(2);
    }
    continue;
  }
}

console.log(`[EOF] depth=${depth} (no close found) mode=${top()}`);
process.exit(1);
