const fs = require("fs");

const file = process.argv[2] || "server.js";
const s = fs.readFileSync(file, "utf8");

let line = 1, col = 0;

const stack = []; // { kind, line, col }
const mode = [];  // "code" | "line" | "block" | "sq" | "dq" | "tpl"
mode.push("code");

let esc = false;

const top = () => mode[mode.length - 1];
const push = (m) => mode.push(m);
const pop = () => mode.pop();

function pushTok(kind) { stack.push({ kind, line, col }); }
function popTok(kind) {
  for (let i = stack.length - 1; i >= 0; i--) {
    if (stack[i].kind === kind) {
      stack.splice(i, 1);
      return true;
    }
  }
  return false;
}

for (let i = 0; i < s.length; i++) {
  const ch = s[i];
  const nx = s[i + 1];

  if (ch === "\n") { line++; col = 0; if (top() === "line") pop(); continue; }
  col++;

  if (top() === "line") continue;

  if (top() === "block") {
    if (ch === "*" && nx === "/") { pop(); i++; col++; }
    continue;
  }

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

  if (top() === "tpl") {
    if (!esc && ch === "\\") { esc = true; continue; }
    if (!esc && ch === "`") { pop(); esc = false; continue; }
    // 템플릿 안의 ${ ... } 는 코드로 진입
    if (!esc && ch === "$" && nx === "{") { pushTok("{"); i++; col++; esc = false; continue; }
    esc = false;
    continue;
  }

  // code
  if (ch === "/" && nx === "/") { push("line"); i++; col++; continue; }
  if (ch === "/" && nx === "*") { push("block"); i++; col++; continue; }
  if (ch === "'") { push("sq"); continue; }
  if (ch === '"') { push("dq"); continue; }
  if (ch === "`") { push("tpl"); continue; }

  if (ch === "{") pushTok("{");
  else if (ch === "}") { if (!popTok("{")) console.log(`UNMATCHED } at ${line}:${col}`); }

  else if (ch === "(") pushTok("(");
  else if (ch === ")") { if (!popTok("(")) console.log(`UNMATCHED ) at ${line}:${col}`); }

  else if (ch === "[") pushTok("[");
  else if (ch === "]") { if (!popTok("[")) console.log(`UNMATCHED ] at ${line}:${col}`); }
}

if (mode.length !== 1 || top() !== "code") {
  console.log("EOF_MODE_NOT_CODE:", mode);
}

if (stack.length === 0) {
  console.log("OK: no unclosed tokens");
  process.exit(0);
}

console.log("UNCLOSED TOKENS (last 30):");
for (const t of stack.slice(-30)) {
  console.log(`- ${t.kind} opened at ${t.line}:${t.col}`);
}
process.exit(1);
