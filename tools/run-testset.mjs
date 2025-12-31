// tools/run-testset.mjs
// Usage:
//   node tools/run-testset.mjs testsets/smoke.core.json
//
// Env:
//   BASE_URL=https://cross-verified-ai-proxy.onrender.com   (default: http://localhost:10000)
//   JWT=<your supabase bearer jwt>                         (required for /api/verify)
//   TIMEOUT_MS=90000                                       (default 90000)
//   PAUSE_MS=250                                           (default 250)
//   OUT_DIR=reports                                        (default reports)

import fs from "fs";
import path from "path";

function mustEnv(name) {
  const v = String(process.env[name] || "").trim();
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

function readJson(fp) {
  const raw = fs.readFileSync(fp, "utf-8");
  return JSON.parse(raw);
}

function nowStamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return (
    d.getFullYear() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    "-" +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  );
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchWithTimeout(url, opts, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: ctrl.signal });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
    return { ok: res.ok, status: res.status, text, json };
  } finally {
    clearTimeout(t);
  }
}

function pickDataShape(json) {
  // your API: { success:true, data:{...} } or buildError(...) etc
  if (!json || typeof json !== "object") return { success: false, data: null, error: "NON_JSON" };
  if (json.success === true && json.data) return { success: true, data: json.data, error: null };
  if (json.success === false) return { success: false, data: null, error: json.code || json.message || "ERROR" };
  // fallback
  return { success: !!json.success, data: json.data ?? null, error: json.code || json.message || null };
}

function short(v, n = 160) {
  const s = String(v ?? "");
  if (s.length <= n) return s;
  return s.slice(0, n) + "…";
}

async function main() {
  const testsetPath = process.argv[2];
  if (!testsetPath) {
    console.error("Usage: node tools/run-testset.mjs <testset.json>");
    process.exit(1);
  }

  const BASE_URL = String(process.env.BASE_URL || "http://localhost:10000").replace(/\/+$/, "");
  const JWT = mustEnv("JWT");
  const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS || "90000", 10);
  const PAUSE_MS = parseInt(process.env.PAUSE_MS || "250", 10);
  const OUT_DIR = String(process.env.OUT_DIR || "reports");

  const set = readJson(testsetPath);
  const cases = Array.isArray(set.cases) ? set.cases : [];
  if (!cases.length) throw new Error("testset has no cases[].");

  fs.mkdirSync(OUT_DIR, { recursive: true });

  const results = [];
  console.log(`BASE_URL=${BASE_URL}`);
  console.log(`cases=${cases.length} timeout=${TIMEOUT_MS}ms pause=${PAUSE_MS}ms\n`);

  for (let i = 0; i < cases.length; i++) {
    const c = cases[i];
    const endpoint = String(c.endpoint || "/api/verify");
    const url = `${BASE_URL}${endpoint}`;

    const body = c.body || {};
    const headers = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${JWT}`
    };

    const t0 = Date.now();
    let resp;
    let err = null;

    try {
      resp = await fetchWithTimeout(
        url,
        { method: "POST", headers, body: JSON.stringify(body) },
        TIMEOUT_MS
      );
    } catch (e) {
      err = e;
      resp = null;
    }

    const ms = Date.now() - t0;

    const row = {
      id: c.id || `case_${i + 1}`,
      name: c.name || "",
      endpoint,
      ms,
      http: resp ? resp.status : null,
      ok: resp ? resp.ok : false,
      error: err ? (err.message || String(err)) : null,
      parsed: resp ? pickDataShape(resp.json) : { success: false, data: null, error: "NO_RESPONSE" },
      raw_snippet: resp ? short(resp.text, 500) : null
    };

    // console summary
    const d = row.parsed.data || {};
    const mode = d.mode ?? body.mode ?? null;
    const truth = d.truthscore ?? d.truthscore_pct ?? d.truthscore_01 ?? null;
    const engines = Array.isArray(d.engines_used) ? d.engines_used : (Array.isArray(d.engines) ? d.engines : null);
    const pre = d.partial_scores?.qvfv_pre?.provider || d.partial_scores?.qvfv_pre?.pre_provider || null;

    console.log(
      `[${i + 1}/${cases.length}] ${row.id} ${row.name}`
    );
    console.log(
      `  HTTP=${row.http} ms=${row.ms} mode=${mode} truth=${truth} engines=${engines ? JSON.stringify(engines) : "null"} pre=${pre}`
    );

    if (!row.ok || row.parsed.success !== true) {
      console.log(`  ❌ error=${row.parsed.error || row.error || "unknown"}`);
      console.log(`  raw=${row.raw_snippet}`);
    } else {
      console.log(`  ✅ ok`);
    }
    console.log("");

    results.push(row);

    if (PAUSE_MS > 0 && i < cases.length - 1) {
      await sleep(PAUSE_MS);
    }
  }

  const out = {
    meta: {
      base_url: BASE_URL,
      testset: testsetPath,
      ran_at: new Date().toISOString(),
      timeout_ms: TIMEOUT_MS,
      pause_ms: PAUSE_MS
    },
    results
  };

  const outPath = path.join(OUT_DIR, `testset-${nowStamp()}.json`);
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2), "utf-8");
  console.log(`Saved: ${outPath}`);
}

main().catch((e) => {
  console.error("FATAL:", e?.stack || e);
  process.exit(1);
});
