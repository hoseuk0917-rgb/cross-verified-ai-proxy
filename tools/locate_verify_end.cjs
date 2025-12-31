const fs = require("fs");
const acorn = require("acorn");
const walk = require("acorn-walk");

const file = process.argv[2] || "server.js";
const src = fs.readFileSync(file, "utf8");

const ast = acorn.parse(src, {
  ecmaVersion: "latest",
  sourceType: "module",
  locations: true,
  allowHashBang: true,
});

let found = null;

walk.simple(ast, {
  VariableDeclarator(node) {
    if (node?.id?.type === "Identifier" && node.id.name === "verifyCoreHandler") {
      const init = node.init;
      if (init && (init.type === "ArrowFunctionExpression" || init.type === "FunctionExpression")) {
        // 함수 바디 블록의 loc가 핵심
        const body = init.body;
        if (body && body.type === "BlockStatement") {
          found = {
            declStart: node.loc.start,
            declEnd: node.loc.end,
            bodyStart: body.loc.start,
            bodyEnd: body.loc.end,
          };
        }
      }
    }
  }
});

if (!found) {
  console.log("NOT_FOUND verifyCoreHandler");
  process.exit(2);
}

console.log("verifyCoreHandler decl  :", found.declStart.line + ":" + found.declStart.column, "->", found.declEnd.line + ":" + found.declEnd.column);
console.log("verifyCoreHandler body  :", found.bodyStart.line + ":" + found.bodyStart.column, "->", found.bodyEnd.line + ":" + found.bodyEnd.column);
console.log("CLOSE_BRACE_LINE", found.bodyEnd.line, "COL", found.bodyEnd.column);
