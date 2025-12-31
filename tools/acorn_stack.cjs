const fs = require("fs");
const acorn = require("acorn");

const file = process.argv[2] || "server.js";
const src = fs.readFileSync(file, "utf8");

const stack = []; // { kind, line, col }

function push(kind, loc) {
  stack.push({ kind, line: loc.line, col: loc.column + 1 });
}
function popExpect(kind) {
  if (!stack.length) return { ok: false, got: kind, expected: null };
  const top = stack[stack.length - 1];

  // '}' 는 템플릿 ${...} 우선으로 닫기
  if (kind === "}" && top.kind === "${") { stack.pop(); return { ok: true }; }

  const pairs = { "}": "{", ")": "(", "]": "[" };
  const want = pairs[kind] || null;

  if (want && top.kind === want) { stack.pop(); return { ok: true }; }
  return { ok: false, got: kind, expected: want, top };
}

const opts = {
  ecmaVersion: "latest",
  sourceType: "module",
  allowHashBang: true,
  locations: true,
};

let tok;
try {
  tok = acorn.tokenizer(src, opts);
} catch (e) {
  console.error("[ACORN_INIT_ERROR]", e.message);
  process.exit(2);
}

function dump(reason, errLoc) {
  console.error(reason);
  if (errLoc) console.error(`AT ${errLoc.line}:${errLoc.column + 1}`);
  console.error("STACK (last 30):");
  for (const t of stack.slice(-30)) {
    console.error(`- ${t.kind} opened at ${t.line}:${t.col}`);
  }
}

try {
  while (true) {
    const t = tok.getToken();
    const lab = t.type.label;

    if (lab === "eof") break;

    if (lab === "{" || lab === "(" || lab === "[") push(lab, t.loc.start);
    else if (lab === "}" || lab === ")" || lab === "]") {
      const r = popExpect(lab);
      if (!r.ok) {
        dump(`[MISMATCH] got ${lab} but top was ${r.top ? r.top.kind : "EMPTY"}`, t.loc.start);
        process.exit(1);
      }
    } else if (lab === "${") {
      // acorn: template expr start
      push("${", t.loc.start);
    }
  }

  if (stack.length) {
    dump("[UNCLOSED] reached EOF with unclosed tokens", { line: 0, column: 0 });
    process.exit(1);
  }

  console.log("OK: balanced (acorn tokenizer)");
  process.exit(0);

} catch (e) {
  // SyntaxError 등
  const loc = e.loc || null;
  dump(`[SYNTAX_ERROR] ${e.message}`, loc);
  process.exit(1);
}
