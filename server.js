import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();
const app = express();
app.use(bodyParser.json({ limit: "5mb" }));
app.use(cors());

// ==========================
// 🔒 환경 변수 설정
// ==========================
const PORT = process.env.PORT || 3000;
const GEMINI_MODEL = process.env.DEFAULT_MODEL || "gemini-2.5-flash";
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ==========================
// 🧠 Gemini API 기본 설정
// ==========================
const GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/";
const GEMINI_TIMEOUT_MS = parseInt(process.env.API_TIMEOUT_MS || "20000", 10);

// ==========================
// 🧩 Render Health Check 호환용 엔드포인트
// ==========================
app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

// ==========================
// 🧩 헬스체크 엔드포인트 (내부용)
// ==========================
app.get("/api/check-health", (req, res) => {
  res.json({ success: true, message: "✅ Proxy 서버 동작 중", version: process.env.APP_VERSION });
});

// ==========================
// 🔗 Supabase 연결 테스트
// ==========================
app.get("/api/check-supabase", async (req, res) => {
  try {
    const { count } = await supabase.from("verification_logs").select("*", { count: "exact", head: true });
    res.json({ success: true, message: "✅ Supabase 연결 성공", rows: count, url: SUPABASE_URL });
  } catch (err) {
    res.status(500).json({ success: false, message: `❌ Supabase 연결 실패: ${err.message}` });
  }
});

// ==========================
// ⚙️ 검증 엔드포인트 (Gemini 호출)
// ==========================
app.post("/api/verify", async (req, res) => {
  const { query, key, naverKey, naverSecret, klawKey } = req.body;
  if (!query || !key) {
    return res.status(400).json({ success: false, message: "❌ 요청 파라미터 부족 (query/key 필요)" });
  }

  const startTime = Date.now();
  const endpoint = `${GEMINI_API_URL}${GEMINI_MODEL}:generateContent?key=${key}`;
  const payload = {
    contents: [
      {
        role: "user",
        parts: [{ text: query }]
      }
    ]
  };

  try {
    const response = await axios.post(endpoint, payload, { timeout: GEMINI_TIMEOUT_MS });
    const resultText =
      response.data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ||
      response.data?.output ||
      "";

    // 🕒 응답 소요시간(ms)
    const elapsedMs = Date.now() - startTime;

    // 🧩 간단 요약 (300자 이내)
    const summary = resultText.length > 300 ? resultText.slice(0, 300) + "..." : resultText;

    // 🎯 CrossScore 계산 (문장 길이 기반)
    const crossScore = parseFloat((Math.min(resultText.length / 1000, 1) * 0.9 + 0.1).toFixed(3));

    // ✅ Supabase 저장 (elapsed을 숫자형으로 저장)
    const { error } = await supabase.from("verification_logs").insert([
      {
        question: query,
        cross_score: crossScore,
        truth_score: null,
        summary,
        elapsed: elapsedMs, // 숫자형
        status: "completed",
        model_main: GEMINI_MODEL,
        created_at: new Date().toISOString()
      }
    ]);

    if (error) {
      console.error("Supabase 저장 실패:", error.message);
      return res.status(500).json({ success: false, message: `❌ Supabase 저장 실패: ${error.message}` });
    }

    res.json({
      success: true,
      message: "✅ Gemini 2.5 검증 완료 및 Supabase 저장됨",
      query,
      elapsed: `${elapsedMs} ms`,
      resultPreview: summary
    });
  } catch (err) {
    console.error("Gemini 요청 실패:", err.message);
    res.status(500).json({ success: false, message: `서버 오류: ${err.message}` });
  }
});

// ==========================
// ⚖️ K-Law 법령 API
// ==========================
app.post("/api/klaw", async (req, res) => {
  const { query, klawKey } = req.body;
  if (!query || !klawKey) {
    return res.status(400).json({ success: false, message: "❌ 요청 파라미터 부족 (query/klawKey 필요)" });
  }

  try {
    const url = `https://www.law.go.kr/DRF/lawSearch.do?OC=${klawKey}&target=law&type=JSON&query=${encodeURIComponent(query)}`;
    const result = await axios.get(url, { timeout: 10000 });
    res.json({ success: true, message: "✅ K-Law 응답 수신", data: result.data });
  } catch (err) {
    res.status(500).json({ success: false, message: `K-Law 요청 실패: ${err.message}` });
  }
});

// ==========================
// 🔎 NAVER 검색 API
// ==========================
app.post("/api/naver", async (req, res) => {
  const { query, naverKey, naverSecret } = req.body;
  if (!query || !naverKey || !naverSecret) {
    return res.status(400).json({ success: false, message: "❌ 요청 파라미터 부족 (query/naverKey/naverSecret 필요)" });
  }

  try {
    const response = await axios.get("https://openapi.naver.com/v1/search/news.json", {
      params: { query, display: 5, sort: "sim" },
      headers: {
        "X-Naver-Client-Id": naverKey,
        "X-Naver-Client-Secret": naverSecret
      },
      timeout: 8000
    });
    res.json({ success: true, message: "✅ NAVER 응답 수신", items: response.data.items });
  } catch (err) {
    res.status(500).json({ success: false, message: `NAVER 요청 실패: ${err.message}` });
  }
});

// ==========================
// 🧾 서버 로그 및 실행부
// ==========================
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v12.2.2 실행 중 (포트: ${PORT})`);
  console.log(`🌐 Supabase 연결: ${SUPABASE_URL}`);
  console.log(`🧠 기본 모델: ${GEMINI_MODEL}`);
});
