const fs = require("fs");

const file = process.argv[2] || "server.js";
const s = fs.readFileSync(file, "utf8");
const lines = s.split(/\r?\n/);

// 간단 렉서: 주석/문자열/템플릿을 대충 무시하고, 라인 시작 시점의 depth를 기록
let depth = 0;
let mode = "code"; // code | line | block | sq | dq | tpl
let esc = false;

function isTopCode(){ return mode === "code"; }

for (let i = 0; i < lines.length; i++) {
  const ln = i + 1;
  const line = lines[i];
  const lineStartDepth = depth;

  // "첫 줄" 후보면 출력 (라인 시작 depth 포함)
  if (isTopCode()) {
    const t = line.trim();
    if (
      /^function\s+[A-Za-z0-9_$]+\s*\(/.test(t) ||
      /^(const|let|var)\s+[A-Za-z0-9_$]+\s*=\s*(async\s*)?\(.*\)\s*=>\s*\{/.test(t) ||
      /^(app|router)\.(use|get|post|put|delete|patch)\s*\(/.test(t)
    ) {
      const short = t.length > 140 ? (t.slice(0, 140) + "…") : t;
      console.log(`${String(ln).padStart(6)}  depth=${String(lineStartDepth).padStart(3)}  ${short}`);
    }
  }

  // depth 업데이트(간단 스캔)
  for (let p = 0; p < line.length; p++) {
    const ch = line[p];
    const nx = line[p + 1];

    if (mode === "line") break;
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
    else if (ch === "}") depth--;
  }
  if (mode === "line") mode = "code";
}

console.log("EOF_DEPTH", depth, "EOF_MODE", mode);
