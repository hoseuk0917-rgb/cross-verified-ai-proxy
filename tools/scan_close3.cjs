@'
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

const mode = ["code"]; // code | line | block | sq | dq | tpl_text | tpl_expr | regex
const tplExprMarkers = [];
let esc = false;

let rxInClass = false;   // regex [...]
let rxEsc = false;

const top = () => mode[mode.length - 1];
const push = (m) => mode.push(m);
const pop = () => mode.pop();

// 직전 "의미있는" 문자 (공백/개행 제외)
let prevSig = "";      // char
let prevWasValue = false; // 값 토큰 직후면 true (division 가능성 ↑, regex 시작 가능성 ↓)

const isWS = (ch) => ch === " " || ch === "\t" || ch === "\r" || ch === "\n";

const markValue = () => { prevWasValue = true; };
const markOp = () => { prevWasValue = false; };

const canStartRegexByPrev = (ch) => {
  // 이전이 값이 아니면 regex 시작 가능성이 큼
  if (!prevWasValue) return true;
  // 값 직후라도 이런 문자면 regex 시작 가능
  return ch === "(" || ch === "{" || ch === "[" || ch === "," || ch === ":" || ch === ";" || ch === "?" || ch === "!" || ch === "=";
};

for (let p = idx; p < s.length; p++) {
  const ch = s[p];
  const nx = s[p + 1];

  if (ch === "\n") {
    line++; col = 0;
    if (top() === "line") pop();
    prevSig = "\n";
    // 개행은 연산자 컨텍스트로 보는 편이 regex 감지에 안전
    markOp();
    continue;
  }
  col++;

  // ===== modes =====
  if (top() === "line") { continue; }

  if (top() === "block") {
    if (ch === "*" && nx === "/") { pop(); p++; col++; }
    continue;
  }

  if (top() === "sq") {
    if (!esc && ch === "\\") { esc = true; continue; }
    if (!esc && ch === "'") { pop(); markValue(); }
    esc = false;
    continue;
  }

  if (top() === "dq") {
    if (!esc && ch === "\\") { esc = true; continue; }
    if (!esc && ch === '"') { pop(); markValue(); }
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
      markOp();
      continue;
    }

    if (!esc && ch === "`") { pop(); esc = false; markValue(); continue; }

    esc = false;
    continue;
  }

  if (top() === "regex") {
    // regex body: / ... /flags
    if (rxEsc) { rxEsc = false; continue; }
    if (ch === "\\") { rxEsc = true; continue; }
    if (ch === "[" && !rxInClass) { rxInClass = true; continue; }
    if (ch === "]" && rxInClass) { rxInClass = false; continue; }

    if (ch === "/" && !rxInClass) {
      pop(); // end regex body
      // flags consume (gimsuyd etc)
      while (/[a-z]/i.test(s[p + 1] || "")) { p++; col++; }
      markValue();
      continue;
    }
    continue;
  }

  // ===== code mode handlers =====
  if (ch === "/" && nx === "/") { push("line"); p++; col++; continue; }
  if (ch === "/" && nx === "*") { push("block"); p++; col++; continue; }

  if (ch === "'") { push("sq"); markOp(); continue; }
  if (ch === '"') { push("dq"); markOp(); continue; }
  if (ch === "`") { push("tpl_text"); markOp(); continue; }

  // regex literal start detection (heuristic)
  if (ch === "/") {
    // comment는 위에서 걸러졌고, 여기 오면 regex or division
    const prev = prevSig;
    if (canStartRegexByPrev(prev)) {
      push("regex");
      rxInClass = false;
      rxEsc = false;
      markOp();
      continue;
    } else {
      // division
      markOp();
      prevSig = ch;
      continue;
    }
  }

  // braces count (only in code/tpl_expr)
  if (ch === "{") { depth++; started = true; markOp(); prevSig = ch; continue; }

  if (ch === "}") {
    if (!started) { prevSig = ch; continue; }
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
    markValue();
    prevSig = ch;
    continue;
  }

  // 아주 단순 토큰 컨텍스트 업데이트 (regex/division 판별 안정화용)
  if (!isWS(ch)) prevSig = ch;

  if (/[A-Za-z0-9_$]/.test(ch)) {
    // 식별자/숫자 진행중이면 값 쪽으로
    markValue();
  } else if (")]}".includes(ch)) {
    markValue();
  } else if ("(,[;:+-*%&|^!~?=<>".includes(ch)) {
    markOp();
  }
}

console.log("NO_MATCH_CLOSE_FOUND (reached EOF)");
process.exit(1);
'@ | Set-Content .\tools\scan_close3.cjs -Encoding UTF8
