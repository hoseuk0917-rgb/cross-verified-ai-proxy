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
// 🩺 Render Health Check
// ==========================
app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

// ==========================
// 🧩 내부 헬스체크
// ==========================
app.get("/api/check-health", (req, res) => {
  res.json({
    success: true,
    message: "✅ Proxy 서버 동작 중",
    version: process.env.APP_VERSION || "v12.4.0",
  });
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
// 🧪 DB 연결/쓰기/읽기 테스트
// ==========================
app.get("/api/test-db", async (req, res) => {
  try {
    const testQuestion = "DB 연결 테스트";
    const startTime = Date.now();

    const { error: insertError } = await supabase
      .from("verification_logs")
      .insert([
        {
          question: testQuestion,
          model_main: "test-mode",
          cross_score: 0,
          elapsed: 0,
          status: "test",
          created_at: new Date().toISOString(),
        },
      ]);

    if (insertError) throw new Error(insertError.message);

    const { count, error: selectError } = await supabase
      .from("verification_logs")
      .select("*", { count: "exact", head: true });

    if (selectError) throw new Error(selectError.message);

    const elapsedMs = Date.now() - startTime;
    res.json({
      success: true,
      message: "✅ DB 연결 및 쓰기/읽기 성공",
      rows: count,
      elapsed: `${elapsedMs} ms`,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: `❌ DB 테스트 실패: ${err.message}` });
  }
});
// ==========================
// ⚙️ 검증 엔드포인트 (Gemini 호출)
// ==========================
app.post("/api/verify", async (req, res) => {
  const { query, key } = req.body;
  if (!query || !key) {
    return res.status(400).json({ success: false, message: "❌ 요청 파라미터 부족 (query/key 필요)" });
  }

  const startTime = Date.now();
  const endpoint = `${GEMINI_API_URL}${GEMINI_MODEL}:generateContent?key=${key}`;
  const payload = {
    contents: [{ role: "user", parts: [{ text: query }] }],
  };

  try {
    const response = await axios.post(endpoint, payload, { timeout: GEMINI_TIMEOUT_MS });
    const resultText =
      response.data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ||
      response.data?.output || "";

    const elapsedMs = Date.now() - startTime;
    const summary = resultText.length > 300 ? resultText.slice(0, 300) + "..." : resultText;
    const crossScore = parseFloat((Math.min(resultText.length / 1000, 1) * 0.9 + 0.1).toFixed(3));

    const { error } = await supabase.from("verification_logs").insert([
      {
        question: query,
        cross_score: crossScore,
        truth_score: null,
        summary,
        elapsed: elapsedMs,
        status: "completed",
        model_main: GEMINI_MODEL,
        created_at: new Date().toISOString(),
      },
    ]);

    if (error) throw new Error(error.message);

    res.json({
      success: true,
      message: "✅ Gemini 2.5 검증 완료 및 Supabase 저장됨",
      query,
      elapsed: `${elapsedMs} ms`,
      resultPreview: summary,
    });
  } catch (err) {
    console.error("Gemini 요청 실패:", err.message);
    res.status(500).json({ success: false, message: `서버 오류: ${err.message}` });
  }
});

// ==========================
// 📊 Admin Dashboard (표 + 그래프)
// ==========================
app.get("/admin", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("verification_logs")
      .select("id, question, model_main, cross_score, elapsed, created_at")
      .order("created_at", { ascending: false })
      .limit(20);

    if (error) throw new Error(error.message);

    const rows = data
      .map(
        (r) => `
        <tr>
          <td>${r.id}</td>
          <td>${r.question}</td>
          <td>${r.model_main}</td>
          <td>${r.cross_score}</td>
          <td>${r.elapsed}</td>
          <td>${r.created_at}</td>
        </tr>`
      )
      .join("");

    const labels = data.map((r) => new Date(r.created_at).toLocaleTimeString());
    const values = data.map((r) => r.elapsed || 0);

    res.send(`
      <html>
        <head>
          <title>Cross-Verified AI Dashboard</title>
          <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
          <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #fafafa; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
            th { background: #333; color: #fff; }
            tr:nth-child(even) { background: #f2f2f2; }
            canvas { max-width: 100%; margin-top: 30px; }
          </style>
        </head>
        <body>
          <h1>✅ Cross-Verified AI - Recent Logs</h1>
          <canvas id="elapsedChart" height="100"></canvas>
          <script>
            const ctx = document.getElementById('elapsedChart').getContext('2d');
            new Chart(ctx, {
              type: 'line',
              data: {
                labels: ${JSON.stringify(labels)},
                datasets: [{
                  label: '응답 시간 (ms)',
                  data: ${JSON.stringify(values)},
                  borderColor: '#007bff',
                  backgroundColor: 'rgba(0,123,255,0.2)',
                  fill: true,
                  tension: 0.3
                }]
              },
              options: {
                scales: {
                  y: { beginAtZero: true, title: { display: true, text: 'Milliseconds' } },
                  x: { title: { display: true, text: 'Timestamp' } }
                }
              }
            });
          </script>

          <table>
            <tr>
              <th>ID</th><th>Question</th><th>Model</th><th>Cross Score</th><th>Elapsed</th><th>Created At</th>
            </tr>
            ${rows}
          </table>
        </body>
      </html>
    `);
  } catch (err) {
    res.status(500).send(`<p>❌ Dashboard Error: ${err.message}</p>`);
  }
});

// ==========================
// 🧾 서버 실행부
// ==========================
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v12.4.0 실행 중 (포트: ${PORT})`);
  console.log(`🌐 Supabase 연결: ${SUPABASE_URL}`);
  console.log(`🧠 기본 모델: ${GEMINI_MODEL}`);
});
