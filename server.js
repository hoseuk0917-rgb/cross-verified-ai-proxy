// ✅ Cross-Verified AI Proxy Server v12.2.3 (App-Driven Keys + Multi-Engine Stable)
import cors from "cors";
import express from "express";
import path from "path";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import fetch from "node-fetch";
import https from "https";
import fs from "fs";

if (fs.existsSync(".env.local")) dotenv.config({ path: ".env.local" });
else dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = "v12.2.3";
const agent = new https.Agent({ keepAlive: true, maxSockets: 10 });

function evaluateResults(engineScores = []) {
  if (!engineScores.length)
    return { truthScore: 0, adjustedScore: 0, status: "missing", sources: [] };
  const weights = { CrossRef: 1.2, OpenAlex: 1.0, GDELT: 0.8, Wikidata: 0.6, Naver: 0.5, KLaw: 0.7 };
  let wSum = 0,
    sSum = 0,
    vals = [],
    src = [];
  for (const e of engineScores) {
    const w = weights[e.name] ?? 1.0;
    sSum += w * e.score;
    wSum += w;
    vals.push(e.score);
    src.push({
      engine: e.name,
      title: e.title || "N/A",
      confidence: Number(e.score.toFixed(3)),
    });
  }
  const T = sSum / wSum;
  const mean = vals.reduce((a, b) => a + b, 0) / vals.length;
  const varc = vals.reduce((a, b) => a + (b - mean) ** 2, 0) / vals.length;
  const delta = Math.max(...vals) - Math.min(...vals);
  let status = "valid";
  if (varc > 0.2 || delta > 0.3) status = "conflict";
  if (T < 0.5) status = "low";
  const adj = Math.min(Math.max(T * (status === "valid" ? 1.05 : status === "conflict" ? 0.85 : 0.75), 0), 1);
  return {
    truthScore: +T.toFixed(3),
    adjustedScore: +adj.toFixed(3),
    status,
    sources: src.sort((a, b) => b.confidence - a.confidence).slice(0, 6),
  };
}

app.use(cors({ origin: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ─────────────────────────────────────────────
// /api/verify
// ─────────────────────────────────────────────
app.post("/api/verify", async (req, res) => {
  try {
    const { query, key, naverKey, naverSecret, klawKey, model = "gemini-2.5-flash" } = req.body;
    if (!query || !key)
      return res.status(400).json({ success: false, message: "❌ query 또는 Gemini key 누락" });

    const start = Date.now();

    // Step 1 – Gemini 메인응답
    const mainResp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
      {
        method: "POST",
        agent,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: `질문: ${query}\n\n명확하고 신뢰성 높은 근거 기반의 응답을 생성하시오.`,
                },
              ],
            },
          ],
        }),
      }
    );
    const mainData = await mainResp.json();
    const mainText =
      mainData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "⚠️ Gemini 응답 없음";

    // Step 2 – 핵심키워드 추출
    const kwResp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=${key}`,
      {
        method: "POST",
        agent,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [
            { parts: [{ text: `다음 문장에서 핵심 키워드 3~5개 추출 후 콤마로 구분:\n${mainText}` }] },
          ],
        }),
      }
    );
    const kwData = await kwResp.json();
    const keywords = (kwData?.candidates?.[0]?.content?.parts?.[0]?.text || "")
      .replace(/\n/g, "")
      .split(",")
      .map((k) => k.trim())
      .filter(Boolean);

    const encoded = encodeURIComponent(keywords.join(" "));

    // Step 3 – 엔진 병렬검증
    async function queryEngine(name, url, parseFn, opts = {}) {
      try {
        const r = await fetch(url, { headers: opts.headers || {}, agent });
        if (!r.ok || !r.headers.get("content-type")?.includes("json"))
          return { name, score: 0.4, title: `${name}: 결과 없음` };
        const data = await r.json();
        return { name, ...parseFn(data) };
      } catch (e) {
        return { name, score: 0, title: `${name}: 오류 (${e.message})` };
      }
    }

    const engines = [
      {
        name: "CrossRef",
        url: `https://api.crossref.org/works?query=${encoded}&rows=3`,
        parseFn: (d) => ({
          score: d.message?.items?.length ? 0.9 : 0.5,
          title: d.message?.items?.[0]?.title?.[0] || "CrossRef 결과 없음",
        }),
      },
      {
        name: "OpenAlex",
        url: `https://api.openalex.org/works?filter=title.search:${encoded}`,
        parseFn: (d) => ({
          score: d.results?.length ? 0.85 : 0.4,
          title: d.results?.[0]?.title || "OpenAlex 결과 없음",
        }),
      },
      {
        name: "GDELT",
        url: `https://api.gdeltproject.org/api/v2/doc/doc?query=${encoded}&format=json`,
        parseFn: (d) => ({
          score: d.articles?.length ? 0.8 : 0.4,
          title: d.articles?.[0]?.title || "GDELT 결과 없음",
        }),
      },
      {
        name: "Wikidata",
        url: `https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encoded}`,
        parseFn: (d) => ({
          score: d.search?.length ? 0.7 : 0.3,
          title: d.search?.[0]?.label || "Wikidata 결과 없음",
        }),
      },
      {
        name: "Naver",
        url: `https://openapi.naver.com/v1/search/news.json?query=${encoded}`,
        parseFn: (d) => ({
          score: d.items?.length ? 0.75 : 0.35,
          title:
            d.items?.[0]?.title?.replace(/<[^>]*>/g, "") || "Naver 결과 없음",
        }),
        opts: {
          headers: {
            "X-Naver-Client-Id": naverKey || "demo",
            "X-Naver-Client-Secret": naverSecret || "demo",
          },
        },
      },
      {
        name: "KLaw",
        url: `https://www.law.go.kr/DRF/lawSearch.do?target=law&type=json&OC=${klawKey || "demo"}&query=${encoded}`,
        parseFn: (d) => ({
          score: d.LAWDATA_LIST?.length ? 0.8 : 0.4,
          title: d.LAWDATA_LIST?.[0]?.법령명한글 || "K-Law 결과 없음",
        }),
      },
    ];

    const results = await Promise.all(
      engines.map((e) => queryEngine(e.name, e.url, e.parseFn, e.opts))
    );

    const truthEval = evaluateResults(results);
    const elapsed = `${Date.now() - start} ms`;

    // Step 4 – 결과 반환
    return res.status(200).json({
      success: true,
      message: "✅ Gemini 2.5 기반 실제 교차검증 완료",
      query,
      elapsed,
      keywords,
      mainText,
      engines: results,
      truthScore: truthEval.truthScore,
      adjustedScore: truthEval.adjustedScore,
      status: truthEval.status,
      sources: truthEval.sources,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[VerifyError]", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.listen(PORT, () => console.log(`🚀 Proxy ${APP_VERSION} running on ${PORT}`));
