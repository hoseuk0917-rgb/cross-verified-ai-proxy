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

let depth = 0;
let started = false;

const mode = ["code"]; // code | line | block | sq | dq | tpl_text | tpl_expr
const tplExprMarkers = [];
let esc = false;

const top = () => mode[mode.length - 1];
const push = (m) => mode.push(m);
const pop = () => mode.pop();

for (let p = idx; p < s.length; p++) {
  const ch = s[p];
  const nx = s[p + 1];

  if (ch === "\n") {
    line++; col = 0;
    if (top() === "line") pop();
    continue;
  }
  col++;

  if (top() === "line") continue;

  if (top() === "block") {
    if (ch === "*" && nx === "/") { pop(); p++; col++; }
    continue;
  }

  if (top() === "sq") {
    if (!esc && ch === "\\") { esc = true; continue; }
    if (!esc && ch === "'") { pop(); }
    esc = false;
    continue;
  }

  if (top() === "dq") {
    if (!esc && ch === "\\") { esc = true; continue; }
    if (!esc && ch === '"') { pop(); }
    esc = false;
    continue;
  }

  if (top() === "tpl_text") {
    if (!esc && ch === "\\") { esc = true; continue; }

    if (!esc && ch === "$" && nx === "{") {
      depth++; started = true;
      tplExprMarkers.push(depth);
      push("tpl_expr");
      p++; col++;
      esc = false;
      continue;
    }

    if (!esc && ch === "`") { pop(); esc = false; continue; }

    esc = false;
    continue;
  }

  if (ch === "/" && nx === "/") { push("line"); p++; col++; continue; }
  if (ch === "/" && nx === "*") { push("block"); p++; col++; continue; }

  if (ch === "'") { push("sq"); continue; }
  if (ch === '"') { push("dq"); continue; }
  if (ch === "`") { push("tpl_text"); continue; }

  if (ch === "{") { depth++; started = true; continue; }

  if (ch === "}") {
    if (!started) continue;
    depth--;

    if (top() === "tpl_expr") {
      const marker = tplExprMarkers[tplExprMarkers.length - 1];
      if (marker && depth === marker - 1) {
        tplExprMarkers.pop();
        pop();
      }
    }

    if (depth === 0) {
      console.log(`MATCH_CLOSE_LINE ${line} COL ${col}`);
      process.exit(0);
    }
    continue;
  }
}

console.log("NO_MATCH_CLOSE_FOUND (reached EOF)");
process.exit(1);
