const fs = require("fs");

const file = process.argv[2] || "server.js";
const startLine = parseInt(process.argv[3] || "10121", 10);

const s = fs.readFileSync(file, "utf8");
const lines = s.split(/\r?\n/);

let idx = 0;
for (let i = 0; i < startLine - 1; i++) idx += (lines[i]?.length ?? 0) + 1;

let depth = 0;          // ✅ 여기서 0으로 시작 (verifyCoreHandler 내부만 추적)
let mode = "code";      // code | line | block | sq | dq | tpl
let esc = false;

let line = startLine;

const watch = [
  "Whitelist endpoints",
  "const ADMIN_TOKEN",
  "app.get(\"/api/admin",
  "app.post(\"/api/admin",
  "app.post(\"/api/verify\"",
  "app.post(\"/api/verify-snippet\"",
  "app.get(\"/api/health\"",
  "app.use(\"/api\"",
];

function logIfHit(text) {
  for (const w of watch) {
    if (text.includes(w)) {
      console.log(`[HIT] line=${line} depth=${depth} :: ${w}`);
      break;
    }
  }
}

let curLineText = "";

for (let p = idx; p < s.length; p++) {
  const ch = s[p];
  const nx = s[p + 1];

  if (ch === "\n") {
    logIfHit(curLineText);
    curLineText = "";
    line++;
    if (mode === "line") mode = "code";
    continue;
  } else {
    curLineText += ch;
  }

  if (mode === "line") continue;
  if (mode === "block") { if (ch === "*" && nx === "/") { mode = "code"; p++; } continue; }

  if (mode === "sq") { if (!esc && ch === "\\") { esc = true; continue; } if (!esc && ch === "'") mode = "code"; esc = false; continue; }
  if (mode === "dq") { if (!esc && ch === "\\") { esc = true; continue; } if (!esc && ch === '"') mode = "code"; esc = false; continue; }
  if (mode === "tpl") { if (!esc && ch === "\\") { esc = true; continue; } if (!esc && ch === "`") mode = "code"; esc = false; continue; }

  if (ch === "/" && nx === "/") { mode = "line"; p++; continue; }
  if (ch === "/" && nx === "*") { mode = "block"; p++; continue; }
  if (ch === "'") { mode = "sq"; continue; }
  if (ch === '"') { mode = "dq"; continue; }
  if (ch === "`") { mode = "tpl"; continue; }

  if (ch === "{") depth++;
  else if (ch === "}") {
    depth--;
    if (depth === 0) {
      console.log(`[CLOSE] verifyCoreHandler closes at line=${line}`);
      process.exit(0);
    }
    if (depth < 0) {
      console.log(`[ERR] depth went negative at line=${line}`);
      process.exit(2);
    }
  }
}

console.log(`[EOF] depth=${depth} (no close found)`);
process.exit(1);
