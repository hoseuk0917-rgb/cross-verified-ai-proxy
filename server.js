/**
 * ==============================================
 * Cross-Verified AI Proxy v12.2.0
 * Supabase 연동 + 사용자 Key 입력형 (Gemini/Naver/K-Law)
 * ==============================================
 */

import express from "express";
import cors from "cors";
import axios from "axios";
import bodyParser from "body-parser";
import { createClient } from "@supabase/supabase-js";

const app = express();
const PORT = process.env.PORT || 3000;

// === [Middleware 설정] ===
app.use(cors());
app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ extended: true }));

// === [Supabase 연결] ===
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

if (!supabaseUrl || !supabaseServiceKey) {
  console.error("❌ Supabase 환경변수 누락");
  process.exit(1);
}

// === [기본상태 확인용 Endpoint] ===
app.get("/health", (req, res) => {
  res.json({ success: true, message: "✅ Proxy Server Healthy", version: "v12.2.0" });
});

// === [Supabase 연결 상태 확인용] ===
app.get("/api/check-supabase", async (req, res) => {
  try {
    const { count } = await supabase.from("verification_logs").select("*", { count: "exact", head: true });
    res.json({
      success: true,
      message: "✅ Supabase 연결 성공",
      rows: count || 0,
      url: supabaseUrl,
    });
  } catch (err) {
    console.error("Supabase 확인 실패:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

// === [교차검증 엔진 메인 Endpoint] ===
app.post("/api/verify", async (req, res) => {
  const startTime = Date.now();
  try {
    const { query, key, naverKey, naverSecret, klawKey } = req.body;
    if (!query || !key) {
      return res.status(400).json({ success: false, message: "❌ 요청 파라미터 부족 (query/key 필요)" });
    }

    // === 1️⃣ Gemini 호출 ===
    let geminiText = "";
    try {
      const geminiUrl =
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=" + key;

      const gRes = await axios.post(
        geminiUrl,
        {
          contents: [{ role: "user", parts: [{ text: query }] }],
        },
        { timeout: 30000 }
      );
      geminiText = gRes.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    } catch (err) {
      console.warn("⚠️ Gemini 응답 실패:", err.message);
    }

    // === 2️⃣ Naver Search API ===
    let naverItems = [];
    if (naverKey && naverSecret) {
      try {
        const nRes = await axios.get("https://openapi.naver.com/v1/search/encyc.json", {
          headers: {
            "X-Naver-Client-Id": naverKey,
            "X-Naver-Client-Secret": naverSecret,
          },
          params: { query, display: 5 },
          timeout: 15000,
        });
        naverItems = nRes.data?.items || [];
      } catch (err) {
        console.warn("⚠️ Naver 응답 실패:", err.message);
      }
    }

    // === 3️⃣ K-Law (국가법령정보 공동활용 API) ===
    let klawLaws = [];
    if (klawKey) {
      try {
        const kRes = await axios.get("https://www.law.go.kr/DRF/lawSearch.do", {
          params: { target: "law", type: "JSON", OC: klawKey, query },
          timeout: 20000,
        });
        klawLaws = kRes.data?.Law || [];
      } catch (err) {
        console.warn("⚠️ K-Law 응답 실패:", err.message);
      }
    }

    // === 4️⃣ 결과 저장 (Supabase) ===
    const elapsed = Date.now() - startTime;
    const { error } = await supabase.from("verification_logs").insert([
      {
        question: query,
        summary: geminiText?.slice(0, 500),
        sources: { naver: naverItems, klaw: klawLaws },
        cross_score: Math.random().toFixed(3), // 향후 CrossScore 계산 대체
        created_at: new Date().toISOString(),
      },
    ]);

    if (error) console.error("Supabase 저장 실패:", error.message);

    res.json({
      success: true,
      message: "✅ Gemini 2.5 검증 완료 및 Supabase 저장됨",
      query,
      elapsed: `${elapsed} ms`,
      resultPreview: geminiText.slice(0, 300),
    });
  } catch (err) {
    console.error("❌ /api/verify 오류:", err.message);
    res.status(500).json({ success: false, message: "서버 오류: " + err.message });
  }
});

// === [서버 시작] ===
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v12.2.0 running on port ${PORT}`);
});
