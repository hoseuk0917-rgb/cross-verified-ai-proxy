import fs from "fs";

const base = (process.argv[2] || "").replace(/\/+$/, "");
const casesPath = process.argv[3] || "tests/cases.smoke.jsonl";
const jwt = process.env.JWT || "";

if (!base) {
  console.error("Usage: node scripts/run-tests.mjs <BASE_URL> <cases.jsonl>");
  process.exit(2);
}

const sleep = (ms) => new Promise((r) => setTimeout(r), ms);

function readJsonl(p) {
  const lines = fs.readFileSync(p, "utf-8").split(/\r?\n/).filter(Boolean);
  return lines.map((ln, i) => {
    try { return JSON.parse(ln); }
    catch (e) { throw new Error(`JSON parse error at line ${i + 1}: ${e.message}`); }
  });
}

function pick(obj, path, def = null) {
  try {
    return path.split(".").reduce((a, k) => (a && a[k] !== undefined ? a[k] : undefined), obj) ?? def;
  } catch { return def; }
}

function resolveEnvValue(v) {
  if (typeof v === "string") {
    const m = v.match(/^\$ENV:([A-Z0-9_]+)$/i);
    if (m) return process.env[m[1]] ?? "";
  }
  return v;
}

function deepResolveEnv(x) {
  if (x == null) return x;
  if (typeof x === "string") return resolveEnvValue(x);
  if (Array.isArray(x)) return x.map(deepResolveEnv);
  if (typeof x === "object") {
    const out = {};
    for (const [k, v] of Object.entries(x)) out[k] = deepResolveEnv(v);
    return out;
  }
  return x;
}

function getMode(j) {
  return (pick(j, "data.mode") ?? pick(j, "mode") ?? "").toString().toLowerCase();
}
function getEnginesUsed(j) {
  const d = pick(j, "data", {});
  return d.engines_used || d.enginesUsed || d.engines || [];
}
function getTruth01(j) {
  const d = pick(j, "data", {});
  const v = d.truthscore_01;
  if (typeof v === "number") return v;
  if (typeof v === "string" && v.trim()) return Number(v);
  const pct = d.truthscore_pct;
  if (typeof pct === "number") return pct / 100;
  return null;
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function fetchWithTimeout(url, options, timeoutMs = 120000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    return res;
  } finally {
    clearTimeout(t);
  }
}

function applyExpect({ exp, resStatus, json, rawText }) {
  // http exact
  if (exp.http != null) {
    assert(resStatus === exp.http, `http expected ${exp.http} got ${resStatus}`);
  }
  // http any-of
  if (Array.isArray(exp.http_any_of)) {
    assert(exp.http_any_of.includes(resStatus), `http expected any of ${exp.http_any_of} got ${resStatus}`);
  }

  // success
  if (exp.success != null) {
    assert(Boolean(json?.success) === Boolean(exp.success), `success expected ${exp.success} got ${json?.success}`);
  }

  // mode exact / any-of
  if (exp.mode) {
    assert(getMode(json) === String(exp.mode).toLowerCase(), `mode expected ${exp.mode} got ${getMode(json)}`);
  }
  if (Array.isArray(exp.mode_any_of)) {
    const m = getMode(json);
    assert(exp.mode_any_of.map(String).map((x)=>x.toLowerCase()).includes(m), `mode expected any of ${exp.mode_any_of} got ${m}`);
  }

  // engines_used_min
  if (exp.engines_used_min != null) {
    const eu = getEnginesUsed(json);
    assert(Array.isArray(eu), `engines_used is not array`);
    assert(eu.length >= exp.engines_used_min, `engines_used_min expected >=${exp.engines_used_min} got ${eu.length} (${JSON.stringify(eu)})`);
  }

  // engines_used_any
  if (Array.isArray(exp.engines_used_any)) {
    const eu = new Set(getEnginesUsed(json));
    const okAny = exp.engines_used_any.some((x) => eu.has(x));
    assert(okAny, `engines_used_any expected one of ${exp.engines_used_any} got ${JSON.stringify([...eu])}`);
  }

  // path_exists
  if (Array.isArray(exp.path_exists)) {
    for (const p of exp.path_exists) {
      const v = pick(json, p, undefined);
      assert(v !== undefined, `path_exists failed: ${p}`);
    }
  }

  // path_equals
  if (typeof exp.path_equals === "object" && exp.path_equals) {
    for (const [p, expected] of Object.entries(exp.path_equals)) {
      const v = pick(json, p, undefined);
      assert(v === expected, `path_equals failed: ${p} expected=${JSON.stringify(expected)} got=${JSON.stringify(v)}`);
    }
  }

  // truthscore_min
  if (exp.truthscore_min != null) {
    const ts = getTruth01(json);
    assert(ts != null && Number.isFinite(ts), `truthscore_01 missing`);
    assert(ts >= exp.truthscore_min, `truthscore_min expected >=${exp.truthscore_min} got ${ts}`);
  }

  // error_code (buildError 형태 대응)
  if (exp.error_code) {
    const code = (json?.code ?? json?.error?.code ?? json?.data?.code ?? "").toString();
    assert(code === exp.error_code, `error_code expected ${exp.error_code} got ${code}`);
  }

  // raw_contains
  if (Array.isArray(exp.raw_contains)) {
    for (const s of exp.raw_contains) {
      assert(rawText.includes(String(s)), `raw_contains failed: ${s}`);
    }
  }
}

async function runOne(tc) {
  // skip if env missing
  if (Array.isArray(tc.skip_if_env_missing) && tc.skip_if_env_missing.length > 0) {
    for (const k of tc.skip_if_env_missing) {
      if (!process.env[k] || !String(process.env[k]).trim()) {
        return { skipped: true, skipReason: `env ${k} missing` };
      }
    }
  }

  const url = base + tc.endpoint;
  const method = (tc.method || "POST").toUpperCase();
  const noAuth = !!tc.no_auth;

  const headersResolved = deepResolveEnv(tc.headers && typeof tc.headers === "object" ? tc.headers : {});
  const headers = {
    "Content-Type": "application/json",
    ...headersResolved,
  };

  if (!noAuth && jwt) headers["Authorization"] = `Bearer ${jwt}`;

  const bodyResolved = deepResolveEnv(tc.body ?? {});
  const timeoutMs = tc.timeout_ms ?? 120000;

  const res = await fetchWithTimeout(url, {
    method,
    headers,
    body: method === "GET" ? undefined : JSON.stringify(bodyResolved),
  }, timeoutMs);

  const text = await res.text();
  let j = null;
  try { j = JSON.parse(text); } catch { /* ignore */ }

  const exp = tc.expect || {};
  applyExpect({ exp, resStatus: res.status, json: j, rawText: text });

  // conditional expectations
  if (Array.isArray(exp.expect_if)) {
    for (const rule of exp.expect_if) {
      const cond = rule?.if;
      const thenExp = rule?.then;
      if (!cond || !thenExp) continue;

      const actual = pick(j, cond.path, undefined);
      const ok =
        (Object.prototype.hasOwnProperty.call(cond, "eq") && actual === cond.eq) ||
        (Array.isArray(cond.in) && cond.in.includes(actual));

      if (ok) {
        applyExpect({ exp: thenExp, resStatus: res.status, json: j, rawText: text });
      }
    }
  }

  return { skipped: false, status: res.status, json: j, raw: text };
}

async function main() {
  const cases = readJsonl(casesPath);
  let pass = 0;
  let skip = 0;

  for (const tc of cases) {
    const name = tc.name || "(no-name)";
    const t0 = Date.now();
    try {
      const out = await runOne(tc);
      const dt = ((Date.now() - t0) / 1000).toFixed(1);

      if (out.skipped) {
        console.log(`⏭️  SKIP ${name} (${dt}s) -> ${out.skipReason}`);
        skip++;
      } else {
        console.log(`✅ ${name} (${dt}s)`);
        pass++;
      }
    } catch (e) {
      const dt = ((Date.now() - t0) / 1000).toFixed(1);
      console.log(`❌ ${name} (${dt}s) -> ${e.message}`);
    }
    await sleep(tc.delay_ms ?? 200);
  }

  console.log(`\nDONE pass=${pass} skip=${skip} total=${cases.length}`);
  // 실패가 1개라도 있으면 exit 1 (pass+skip != total 이면 실패)
  process.exit((pass + skip) === cases.length ? 0 : 1);
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(2);
});
