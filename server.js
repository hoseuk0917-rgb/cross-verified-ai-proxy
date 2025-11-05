// =============================================
// Cross-Verified AI Proxy v12.1.1
// + Supabase Connection Check Endpoint 추가
// =============================================

import express from "express";
import axios from "axios";
import cors from "cors";
import crypto from "crypto";
import pkg from "@supabase/supabase-js";
const { createClient } = pkg;

const app = express();
app.use(express.json({ limit: "5mb" }));
app.use(cors());

const PORT = process.env.PORT || 3000;

// === [환경변수 로드 및 검증] ===
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error("❌ Supabase 환경변수 누락됨");
  process.exit(1);
}

// === [Supabase 클라이언트 초기화] ===
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// === [기본 Health 체크] ===
app.get("/health", (req, res) => {
  res.json({ success: true, status: "ok", version: process.env.APP_VERSION });
});

// === [Supabase 연결 확인 엔드포인트] ===
app.get("/api/check-supabase", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("verification_logs")
      .select("id")
      .limit(1);

    if (error) {
      console.error("❌ Supabase Query Error:", error.message);
      return res
        .status(500)
        .json({ success: false, message: "❌ Supabase 쿼리 실패", error: error.message });
    }

    return res.json({
      success: true,
      message: "✅ Supabase 연결 성공",
      rows: data.length,
      url: SUPABASE_URL,
    });
  } catch (err) {
    console.error("❌ Supabase 연결 실패:", err.message);
    return res.status(500).json({
      success: false,
      message: "❌ Supabase 연결 오류 발생",
      error: err.message,
    });
  }
});
// === [예시: Verify API 본체 요약] ===
app.post("/api/verify", async (req, res) => {
  const { query, key } = req.body;
  if (!query || !key) {
    return res.status(400).json({ success: false, message: "❌ query 또는 key 누락" });
  }

  try {
    const startTime = Date.now();

    // 예시: Gemini 호출
    const response = await axios.post(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent",
      {
        contents: [{ parts: [{ text: query }] }],
      },
      { params: { key } }
    );

    const mainText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    const elapsed = `${Date.now() - startTime} ms`;

    // === [결과 Supabase 저장] ===
    await supabase.from("verification_logs").insert([
      {
        user_id: "system", // 실제 앱 로그인 시 auth.uid() 연동
        question: query,
        summary: mainText.slice(0, 200),
        cross_score: Math.random().toFixed(3),
      },
    ]);

    res.json({
      success: true,
      message: "✅ Gemini 2.5 검증 완료 및 로그 저장됨",
      query,
      elapsed,
      resultPreview: mainText.slice(0, 200),
    });
  } catch (err) {
    console.error("❌ Verify 실패:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

// === [Render Sleep 방지 Ping 루프] ===
setInterval(async () => {
  try {
    const res = await axios.get("https://cross-verified-ai-proxy.onrender.com/health");
    console.log(`🔄 Health Ping: ${res.status}`);
  } catch (err) {
    console.warn(`⚠️ Ping 실패: ${err.message}`);
  }
}, 600000);

// === [서버 구동] ===
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v12.1.1 구동 중`);
  console.log(`🌐 포트: ${PORT}`);
  console.log(`📡 Supabase 연결 테스트 엔드포인트: /api/check-supabase`);
});
