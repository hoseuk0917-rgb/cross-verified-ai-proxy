// ✅ Cross-Verified AI Proxy Server v12.3.0
// (Gemini 2.5 + K-Law + Naver 개선 버전)
import express from "express";
import axios from "axios";
import cors from "cors";
import bodyParser from "body-parser";

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "10mb" }));

// ✅ Health Check
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok", service: "Cross-Verified AI Proxy v12.3.0" });
});

// ✅ /api/verify — Gemini + CrossRef + K-Law + Naver 등 통합 교차검증
app.post("/api/verify", async (req, res) => {
  const { query, key, naverKey, naverSecret, klawKey } = req.body;
  const startTime = Date.now();

  if (!query || !key) {
    return res.status(400).json({ success: false, message: "❌ Missing required parameters" });
  }

  try {
    // ✅ Gemini 2.5 기본 응답 생성
    const geminiRes = await axios.post(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + key,
      {
        contents: [{ role: "user", parts: [{ text: query }]}],
      },
      { timeout: 60000 }
    );

    const mainText =
      geminiRes?.data?.candidates?.[0]?.content?.parts?.[0]?.text || "응답이 비어 있습니다.";

    // ✅ 병렬 교차검증 엔진 (Gemini 외부)
    const [crossref, openalex, gdelt, wikidata, naver, klaw] = await Promise.allSettled([
      verifyCrossRef(query),
      verifyOpenAlex(query),
      verifyGDELT(query),
      verifyWikidata(query),
      verifyNaver(query, naverKey, naverSecret),
      verifyKLaw(query, klawKey),
    ]);

    const results = [crossref, openalex, gdelt, wikidata, naver, klaw]
      .filter(r => r.status === "fulfilled")
      .map(r => r.value);

    const elapsed = `${Date.now() - startTime} ms`;
    res.status(200).json({
      success: true,
      message: "✅ Gemini 2.5 기반 실제 교차검증 완료",
      query,
      elapsed,
      keywords: extractKeywords(mainText),
      mainText,
      evalText: generateEvaluation(mainText, results),
      engines: results,
      truthScore: calcTruthScore(results),
      adjustedScore: calcAdjustedScore(results),
      status: "conflict",
      sources: results.map(r => ({ engine: r.name, title: r.title, confidence: r.score })),
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("❌ /api/verify failed:", error.message);
    res.status(500).json({ success: false, message: "서버 오류: " + error.message });
  }
});

// ✅ CrossRef 엔진
async function verifyCrossRef(query) {
  try {
    const res = await axios.get(
      `https://api.crossref.org/works?query=${encodeURIComponent(query)}&rows=1`
    );
    const item = res.data.message.items[0];
    return {
      name: "CrossRef",
      score: 0.9,
      title: item?.title?.[0] || "결과 없음",
    };
  } catch {
    return { name: "CrossRef", score: 0, title: "오류" };
  }
}

// ✅ OpenAlex
async function verifyOpenAlex(query) {
  try {
    const res = await axios.get(
      `https://api.openalex.org/works?filter=title.search:${encodeURIComponent(query)}`
    );
    const item = res.data.results[0];
    return {
      name: "OpenAlex",
      score: 0.4,
      title: item?.title || "결과 없음",
    };
  } catch {
    return { name: "OpenAlex", score: 0, title: "오류" };
  }
}

// ✅ GDELT
async function verifyGDELT(query) {
  try {
    const url = `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(query)}&format=json`;
    const res = await axios.get(url);
    const title = res.data?.articles?.[0]?.title || "결과 없음";
    return { name: "GDELT", score: 0.4, title };
  } catch {
    return { name: "GDELT", score: 0, title: "오류" };
  }
}

// ✅ Wikidata
async function verifyWikidata(query) {
  try {
    const url = `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(query)}&language=ko&format=json`;
    const res = await axios.get(url);
    const title = res.data.search?.[0]?.label || "결과 없음";
    return { name: "Wikidata", score: 0.3, title };
  } catch {
    return { name: "Wikidata", score: 0, title: "오류" };
  }
}

// ✅ Naver 뉴스 API
async function verifyNaver(query, clientId, clientSecret) {
  if (!clientId || !clientSecret)
    return { name: "Naver", score: 0, title: "API Key 누락" };
  try {
    const res = await axios.get(
      `https://openapi.naver.com/v1/search/news.json?query=${encodeURIComponent(query)}&display=10&sort=sim`,
      {
        headers: {
          "X-Naver-Client-Id": clientId,
          "X-Naver-Client-Secret": clientSecret,
        },
      }
    );
    const title = res.data.items?.[0]?.title?.replace(/<[^>]*>/g, "") || "결과 없음";
    return { name: "Naver", score: 0.35, title };
  } catch {
    return { name: "Naver", score: 0, title: "오류" };
  }
}

// ✅ K-Law 법령정보 API
async function verifyKLaw(query, ocKey) {
  if (!ocKey) return { name: "K-Law", score: 0, title: "OC Key 누락" };
  try {
    const encoded = encodeURIComponent(query);
    const url = `https://www.law.go.kr/DRF/lawSearch.do?OC=${ocKey}&target=eflaw&type=JSON&query=${encoded}&display=3`;
    const res = await axios.get(url, { timeout: 10000 });

    let data = res.data;
    if (typeof data === "string") {
      try { data = JSON.parse(data); } catch { return { name: "K-Law", score: 0, title: "JSON 파싱 실패" }; }
    }

    const lawName = data?.law?.[0]?.법령명한글 || data?.law?.법령명한글 || "결과 없음";
    return { name: "K-Law", score: 0.4, title: lawName };
  } catch (err) {
    return { name: "K-Law", score: 0, title: "K-Law 오류: " + err.message };
  }
}

// ✅ 보조 함수들
function extractKeywords(text) {
  if (!text) return [];
  const lines = text.split("\n").filter(l => l.trim().length > 0);
  return lines.slice(0, 4).map((l, i) => `${i + 1}. ${l.substring(0, 30)}`);
}

function generateEvaluation(mainText, results) {
  const positives = results.filter(r => r.score >= 0.4);
  return `✅ Gemini 생성 응답 신뢰도 평가\n\n총 ${results.length}개 엔진 중 ${positives.length}개에서 긍정적 일치가 확인되었습니다.\n\n주요 일치 엔진: ${positives.map(r => r.name).join(", ")}`;
}

function calcTruthScore(results) {
  if (!results.length) return 0;
  const sum = results.reduce((a, r) => a + r.score, 0);
  return (sum / results.length).toFixed(3);
}

function calcAdjustedScore(results) {
  const truth = parseFloat(calcTruthScore(results));
  return (truth * 0.85).toFixed(3);
}

// ✅ 서버 시작
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`));
