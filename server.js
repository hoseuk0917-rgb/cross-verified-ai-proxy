// server.js (토큰 방식 / ping / test-db / admin 포함)
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
// 환경 변수
// ==========================
const PORT = process.env.PORT || 3000;
const GEMINI_MODEL = process.env.DEFAULT_MODEL || "gemini-2.5-flash";
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_SECRET = process.env.ADMIN_SECRET || ""; // 필수: admin 보호용 토큰
const GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/";
const GEMINI_TIMEOUT_MS = parseInt(process.env.API_TIMEOUT_MS || "20000", 10);

// Supabase 초기화
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ==========================
// 헬스체크
// ==========================
app.get("/api/check-health", (req, res) => {
  res.json({ success: true, message: "✅ Proxy 서버 동작 중", version: process.env.APP_VERSION || "v12.x" });
});

// ==========================
// Keep-alive / UptimeRobot용 Ping
// ==========================
app.get("/api/ping", (req, res) => {
  // 단순 200 응답 — UptimeRobot 이나 다른 서비스가 주기적 ping 가능
  res.json({ success: true, message: "pong", ts: new Date().toISOString() });
});

// ==========================
// Supabase 연결 테스트 (DB 읽기 권한으로 간단 확인)
// ==========================
app.get("/api/test-db", async (req, res) => {
  try {
    // verification_logs 존재 유무 & 레코드 수 확인
    const { count, error } = await supabase
      .from("verification_logs")
      .select("*", { count: "exact", head: true });

    if (error) {
      console.error("Test DB - query error:", error);
      return res.status(500).json({ success: false, message: `DB 쿼리 실패: ${error.message}` });
    }

    res.json({ success: true, message: "Supabase 연결 성공", rows: count });
  } catch (err) {
    console.error("Test DB - exception:", err);
    res.status(500).json({ success: false, message: `DB 연결 실패: ${err.message}` });
  }
});

// ==========================
// 간단한 Admin 인증 미들웨어 (Bearer token)
// ==========================
function requireAdmin(req, res, next) {
  const auth = req.headers["authorization"] || "";
  if (!ADMIN_SECRET) {
    console.warn("ADMIN_SECRET 미설정: /admin 접근 불가");
    return res.status(403).send("Admin not configured on server.");
  }
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).send("Unauthorized: Bearer token required");
  }
  const token = auth.split(" ")[1];
  if (token !== ADMIN_SECRET) {
    return res.status(401).send("Unauthorized: invalid token");
  }
  next();
}

// ==========================
// 관리 대시보드 (토큰 필요)
// ==========================
app.get("/admin", requireAdmin, async (req, res) => {
  try {
    // 최근 5개 로그와 전체 카운트 가져오기
    const { data: recent, error: e1 } = await supabase
      .from("verification_logs")
      .select("id, question, model_main, cross_score, elapsed, status, created_at")
      .order("created_at", { ascending: false })
      .limit(5);

    const { count, error: e2 } = await supabase
      .from("verification_logs")
      .select("*", { count: "exact", head: true });

    if (e1 || e2) {
      console.error("Admin Supabase error", e1 || e2);
      return res.status(500).send("DB 조회 중 오류 발생");
    }

    // 간단한 HTML 응답
    const rowsHtml = (recent || []).map(r => `
      <tr>
        <td>${r.id}</td>
        <td>${(r.question || "").replace(/</g,'&lt;').slice(0,80)}</td>
        <td>${r.model_main || ""}</td>
        <td>${r.cross_score ?? ""}</td>
        <td>${r.elapsed ?? ""}</td>
        <td>${r.status ?? ""}</td>
        <td>${r.created_at}</td>
      </tr>`).join("");

    const html = `<!doctype html>
      <html><head><meta charset="utf-8"><title>Admin Dashboard</title>
      <style>body{font-family:Arial,Helvetica,sans-serif;padding:16px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}</style>
      </head><body>
      <h2>Admin Dashboard</h2>
      <p>Total verification_logs rows: <strong>${count ?? 0}</strong></p>
      <h3>Recent 5 logs</h3>
      <table><thead><tr>
      <th>id</th><th>question(앞부분)</th><th>model</th><th>cross_score</th><th>elapsed</th><th>status</th><th>created_at</th>
      </tr></thead><tbody>${rowsHtml}</tbody></table>
      <p>Generated at ${new Date().toISOString()}</p>
      </body></html>`;

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(html);
  } catch (err) {
    console.error("Admin error:", err);
    res.status(500).send("서버 오류");
  }
});

// ==========================
// 검증 엔드포인트 (Gemini 호출 예전 로직 유지)
// ==========================
app.post("/api/verify", async (req, res) => {
  const { query, key } = req.body;
  if (!query || !key) {
    return res.status(400).json({ success: false, message: "❌ 요청 파라미터 부족 (query/key 필요)" });
  }

  const startTime = Date.now();
  const endpoint = `${GEMINI_API_URL}${GEMINI_MODEL}:generateContent?key=${encodeURIComponent(key)}`;
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
      response.data?.output || "";

    const elapsedMs = Date.now() - startTime;

    // 간단 요약
    const summary = resultText.length > 300 ? resultText.slice(0, 300) + "..." : resultText;
    const crossScore = parseFloat((Math.min(resultText.length / 1000, 1) * 0.9 + 0.1).toFixed(3));

    // Supabase에 저장
    const { error } = await supabase.from("verification_logs").insert([
      {
        question: query,
        cross_score: crossScore,
        truth_score: null,
        summary,
        elapsed: elapsedMs, // 숫자형으로 저장 (ms)
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
      message: "✅ Gemini 검증 완료 및 Supabase 저장됨",
      query,
      elapsed: elapsedMs,
      resultPreview: summary
    });
  } catch (err) {
    console.error("Gemini 요청 실패:", err.message || err);
    res.status(500).json({ success: false, message: `서버 오류: ${err.message || err}` });
  }
});

// ==========================
// 서버 시작
// ==========================
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy (token-admin) 실행 중 (포트: ${PORT})`);
  console.log(`🌐 Supabase 연결: ${SUPABASE_URL}`);
  console.log(`🔒 Admin token required for /admin (set ADMIN_SECRET)`);
});
