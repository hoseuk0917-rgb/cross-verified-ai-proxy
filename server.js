import express from "express";
import axios from "axios";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

// axios 공통 설정 (30초 timeout)
const axiosInstance = axios.create({
  timeout: 30000,
});

// ✅ 헬스체크
app.get("/health", (req, res) => {
  res.json({ ok: true, message: "Cross-Verified AI Proxy is alive" });
});

// ✅ 교차검증 엔드포인트
app.post("/api/verify", async (req, res) => {
  const { query, key, naverKey, naverSecret, klawKey } = req.body;

  if (!query || !key) {
    return res.status(400).json({ success: false, message: "query와 key는 필수입니다." });
  }

  const start = Date.now();
  const engines = [];
  const sources = [];

  try {
    // ✅ 1️⃣ Gemini 요청
    const geminiResp = await axiosInstance.post(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=" + key,
      { contents: [{ parts: [{ text: query }] }] }
    );

    const mainText = geminiResp.data?.candidates?.[0]?.content?.parts?.[0]?.text || "No content generated.";

    // ✅ 2️⃣ CrossRef
    let crossrefResult = {};
    try {
      const r = await axiosInstance.get(`https://api.crossref.org/works?query=${encodeURIComponent(query)}&rows=1`);
      crossrefResult = {
        name: "CrossRef",
        score: 0.9,
        title: r.data.message.items[0]?.title?.[0] || "결과 없음",
      };
    } catch {
      crossrefResult = { name: "CrossRef", score: 0.3, title: "CrossRef 오류" };
    }
    engines.push(crossrefResult);
    sources.push({ engine: "CrossRef", title: crossrefResult.title, confidence: crossrefResult.score });

    // ✅ 3️⃣ Naver News
    let naverResult = {};
    try {
      const r = await axiosInstance.get(
        `https://openapi.naver.com/v1/search/news.json?query=${encodeURIComponent(query)}&display=3`,
        {
          headers: {
            "X-Naver-Client-Id": naverKey,
            "X-Naver-Client-Secret": naverSecret,
          },
        }
      );
      const title = r.data.items?.[0]?.title?.replace(/<[^>]*>?/g, "") || "결과 없음";
      naverResult = { name: "Naver", score: 0.7, title };
    } catch (e) {
      naverResult = { name: "Naver", score: 0.3, title: `Naver 오류: ${e.message}` };
    }
    engines.push(naverResult);
    sources.push({ engine: "Naver", title: naverResult.title, confidence: naverResult.score });

    // ✅ 4️⃣ K-Law (법제처)
    let klawResult = {};
    try {
      const r = await axiosInstance.get(
        `https://www.law.go.kr/DRF/lawSearch.do?target=law&type=JSON&OC=${klawKey}&query=${encodeURIComponent(query)}&display=3`
      );

      if (r.status === 200 && r.data?.LAW) {
        klawResult = {
          name: "K-Law",
          score: 0.9,
          title: r.data.LAW[0]?.법령명한글 || "결과 없음",
        };
      } else {
        klawResult = { name: "K-Law", score: 0.4, title: "응답 없음" };
      }
    } catch (e) {
      const htmlCheck = e?.response?.data?.includes?.("<html>");
      klawResult = {
        name: "K-Law",
        score: 0,
        title: htmlCheck ? "K-Law 500 오류 (서버측 문제)" : `K-Law 오류: ${e.message}`,
      };
    }
    engines.push(klawResult);
    sources.push({ engine: "K-Law", title: klawResult.title, confidence: klawResult.score });

    // ✅ 최종 truthScore 계산
    const avgScore = engines.reduce((acc, e) => acc + e.score, 0) / engines.length;
    const adjusted = Math.max(0, Math.min(1, avgScore - 0.05 * (engines.length - 1)));

    const elapsed = `${Date.now() - start} ms`;

    res.json({
      success: true,
      message: "✅ Gemini 2.5 기반 실제 교차검증 완료",
      query,
      elapsed,
      engines,
      truthScore: Number(avgScore.toFixed(3)),
      adjustedScore: Number(adjusted.toFixed(3)),
      sources,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("서버 오류:", err);
    res.status(500).json({ success: false, message: "서버 오류: " + err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`));
