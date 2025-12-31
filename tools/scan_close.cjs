@'
const fs = require("fs");

const file = process.argv[2] || "server.js";
const startLine = parseInt(process.argv[3] || "10121", 10);

const s = fs.readFileSync(file, "utf8");

// CRLF 안전: '\n' 찾아가며 startLine 오프셋 계산
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

// global brace depth from startLine
let depth = 0;
let started = false;

// mode stack: code | line | block | sq | dq | tpl_text | tpl_expr
const mode = ["code"];

// for tpl_expr end detection: push marker = depth AFTER consuming '${' ('{' counted)
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

  // line comment
  if (top() === "line") continue;

  // block comment
  if (top() === "block") {
    if (ch === "*" && nx === "/") { pop(); p++; col++; }
    continue;
  }

  // single-quote
  if (top() === "sq") {
    if (!esc && ch === "\\") { esc = true; continue; }
    if (!esc && ch === "'") { pop(); }
    esc = false;
    continue;
  }

  // double-quote
  if (top() === "dq") {
    if (!esc && ch === "\\") { esc = true; continue; }
    if (!esc && ch === '"') { pop(); }
    esc = false;
    continue;
  }

  // template text
  if (top() === "tpl_text") {
    if (!esc && ch === "\\") { esc = true; continue; }

    if (!esc && ch === "$" && nx === "{") {
      // count '{' for ${ ... }
      depth++; started = true;
      tplExprMarkers.push(depth); // marker = depth after '{'
      push("tpl_expr");
      p++; col++; // consume '{'
      esc = false;
      continue;
    }

    if (!esc && ch === "`") { pop(); esc = false; continue; }

    esc = false;
    continue;
  }

  // tpl expr behaves like code, but closes back to tpl_text when matching the ${ brace closes
  // (we detect by marker and depth after decrement)
  if (top() === "tpl_expr") {
    // allow nested strings/templates/comments inside expr
  }

  // enter comments (code or tpl_expr)
  if (ch === "/" && nx === "/") { push("line"); p++; col++; continue; }
  if (ch === "/" && nx === "*") { push("block"); p++; col++; continue; }

  // enter strings/templates (code or tpl_expr)
  if (ch === "'") { push("sq"); continue; }
  if (ch === '"') { push("dq"); continue; }
  if (ch === "`") { push("tpl_text"); continue; }

  // braces (code or tpl_expr)
  if (ch === "{") {
    depth++; started = true;
    continue;
  }

  if (ch === "}") {
    if (!started) continue;
    depth--;

    // if we're in tpl_expr and this '}' closed the `${` brace, return to tpl_text
    if (top() === "tpl_expr") {
      const marker = tplExprMarkers[tplExprMarkers.length - 1];
      // marker was depth AFTER '{'. After closing '}', depth should be marker-1.
      if (marker && depth === marker - 1) {
        tplExprMarkers.pop();
        pop(); // pop tpl_expr -> back to tpl_text
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
'@ | Set-Content .\tools\scan_close2.cjs -Encoding UTF8
