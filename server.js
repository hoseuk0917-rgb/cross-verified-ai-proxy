// ✅ Cross-Verified AI Proxy Server v12.2.0-test
// Gemini 2.5 기반 교차검증 체인 (실제 작동 테스트버전)

import cors from "cors";
import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import fetch from "node-fetch";
import https from "https";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const agent = new https.Agent({ keepAlive: true });

app.use(cors({ origin: true }));
app.use(express.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ extended: true }));

// TruthScore 계산 함수
function evaluateResults(results) {
  if (!results?.length) return { truthScore: 0, adjustedScore: 0, status: "missing" };
  const avg = results.reduce((a, b) => a + b.score, 0) / results.length;
  let status = "valid";
  if (avg < 0.4) status = "low";
  else if (avg < 0.6) status = "moderate";
  const adjusted = Math.min(1, Math.max(0, avg * (status === "low" ? 0.8 : 1.05)));
  return { truthScore: avg, adjustedScore: adjusted, status };
}
// ✅ /api/verify (2.5 체인 테스트)
app.post("/api/verify", async (req, res) => {
  const { query, model, key } = req.body || {};
  if (!query || !key) return res.status(400).json({ success: false, message: "❌ query 또는 key 누락" });

  const start = Date.now();
  const MODEL_FLASH = "gemini-2.5-flash";
  const MODEL_PRO = "gemini-2.5-pro";

  // Gemini 요청 함수 (2.5 → 1.5 폴백)
  async function askGemini(m, prompt) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${key}`;
    const payload = { contents: [{ parts: [{ text: prompt }] }] };
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (!r.ok) {
      const fallback = m.includes("flash") ? "gemini-1.5-flash" : "gemini-1.5-pro";
      const rr = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${fallback}:generateContent?key=${key}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload)
      });
      return rr.json();
    }
    return r.json();
  }

  try {
    // ① 응답 생성
    const mainPrompt = `질문: ${query}\n\n정확하고 근거 기반의 답변을 5문장 이내로 작성하세요.`;
    const mainData = await askGemini(MODEL_FLASH, mainPrompt);
    const mainText = mainData?.candidates?.[0]?.content?.parts?.[0]?.text || "(응답 없음)";

    // ② 키워드 추출
    const keyPrompt = `다음 문장에서 핵심 키워드 3~5개를 콤마(,)로 구분해 나열:\n${mainText}`;
    const keyData = await askGemini(MODEL_FLASH, keyPrompt);
    const keywords = (keyData?.candidates?.[0]?.content?.parts?.[0]?.text || "")
      .split(",").map(k => k.trim()).filter(Boolean);

    const encoded = encodeURIComponent(keywords.join(" "));
    // ③ 외부 엔진 3종 호출
    const engines = [
      { name: "OpenAlex", url: `https://api.openalex.org/works?search=${encoded}`, score: 0.0 },
      { name: "Wikidata", url: `https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encoded}`, score: 0.0 },
      { name: "GDELT", url: `https://api.gdeltproject.org/api/v2/doc/doc?query=${encoded}&format=json`, score: 0.0 }
    ];
    const results = [];
    for (const e of engines) {
      try {
        const r = await fetch(e.url);
        const d = await r.json();
        const s = d?.results?.length || d?.search?.length || d?.articles?.length ? 0.8 : 0.4;
        results.push({ name: e.name, score: s, title: e.name + " 결과" });
      } catch { results.push({ name: e.name, score: 0.3 }); }
    }

    const truth = evaluateResults(results);

    // ④ 최종 평가 (Pro)
    const evalPrompt = `
[질문] ${query}
[응답] ${mainText}
[키워드] ${keywords.join(", ")}
[엔진 결과] ${results.map(r => `${r.name}:${r.score.toFixed(2)}`).join(", ")}
이 응답의 신뢰성을 5문장으로 요약평가하세요.`;
    const evalData = await askGemini(MODEL_PRO, evalPrompt);
    const evalText = evalData?.candidates?.[0]?.content?.parts?.[0]?.text || "(평가 없음)";

    res.json({
      success: true,
      elapsed: `${Date.now() - start} ms`,
      mainText,
      evalText,
      keywords,
      engines: results,
      ...truth
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.listen(PORT, () => console.log(`🚀 Cross-Verified AI v12.2.0-test (2.5) running on ${PORT}`));
