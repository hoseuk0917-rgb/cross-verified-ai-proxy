import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import morgan from "morgan";
import { google } from "googleapis";

dotenv.config();
const app = express();
app.use(bodyParser.json({ limit: "5mb" }));
app.use(cors());
app.use(morgan("dev"));

// ================================
// 🔧 환경 변수 설정
// ================================
const PORT = process.env.PORT || 3000;
const GEMINI_MODEL = process.env.DEFAULT_MODEL || "gemini-2.5-flash";
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ================================
// 🧠 Google OAuth 클라이언트 초기화
// ================================
const oauth2Client = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_CALLBACK_URL
);

// ================================
// 🩺 헬스체크
// ================================
app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "✅ Cross-Verified AI Proxy Healthy",
    version: "v12.9.0",
  });
});

// ================================
// 🔗 OAuth 시작 (Google 로그인 요청)
// ================================
app.get("/auth/google", (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/userinfo.email"],
  });
  res.redirect(url);
});

// ================================
// 🔙 OAuth 콜백 (토큰 + 세션 저장)
// ================================
app.get("/auth/google/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("❌ Missing OAuth code");

  try {
    // Google 토큰 교환
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // 사용자 정보 가져오기
    const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
    const { data: user } = await oauth2.userinfo.get();

    // Supabase 세션 저장
    const { error } = await supabase.from("sessions").insert([
      {
        user_email: user.email,
        access_token: tokens.access_token || null,
        refresh_token: tokens.refresh_token || null,
        expires_at: tokens.expiry_date
          ? new Date(tokens.expiry_date).toISOString()
          : null,
      },
    ]);

    if (error) {
      console.error("❌ [Supabase Insert Error]", error.message);
      return res.status(500).send("Supabase insert error");
    }

    console.log(`🟢 [Supabase] Session stored for ${user.email}`);
    return res.redirect(`/admin?email=${encodeURIComponent(user.email)}`);
  } catch (err) {
    console.error("❌ OAuth Callback Error:", err.message);
    return res.status(500).send("Internal Server Error");
  }
});

// ================================
// 🔍 세션 검증 함수
// ================================
async function verifySession(email) {
  const { data, error } = await supabase
    .from("sessions")
    .select("*")
    .eq("user_email", email)
    .order("created_at", { ascending: false })
    .limit(1);

  if (error || !data || data.length === 0) return false;
  const session = data[0];
  if (session.expires_at && new Date(session.expires_at) < new Date()) {
    return false;
  }
  return true;
}

// ================================
// 🧾 Admin Dashboard
// ================================
app.get("/admin", async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("❌ Missing email");
  if (email !== ADMIN_EMAIL)
    return res.status(403).send("❌ Unauthorized admin email");

  const valid = await verifySession(email);
  if (!valid)
    return res.status(401).send("❌ Session invalid or expired. Login again.");

  const { data: logs, error } = await supabase
    .from("verification_logs")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(10);

  if (error) return res.status(500).send("Supabase query failed");

  const html = `
  <html><head><meta charset="utf-8"><title>Admin Dashboard</title>
  <style>
  body{font-family:Arial;padding:16px;background:#fafafa;color:#333}
  table{border-collapse:collapse;width:100%;margin-top:16px}
  th,td{border:1px solid #ccc;padding:8px}
  th{background:#eee}
  </style></head>
  <body>
  <h2>🧭 Cross-Verified AI Admin Dashboard</h2>
  <p>관리자: <b>${email}</b></p>
  <table>
  <tr><th>ID</th><th>질문</th><th>모델</th><th>점수</th><th>시간</th><th>상태</th><th>날짜</th></tr>
  ${logs
    .map(
      (l) => `
    <tr>
      <td>${l.id}</td>
      <td>${l.question?.slice(0, 30) || "-"}</td>
      <td>${l.model_main}</td>
      <td>${l.cross_score}</td>
      <td>${l.elapsed}</td>
      <td>${l.status}</td>
      <td>${new Date(l.created_at).toLocaleString()}</td>
    </tr>`
    )
    .join("")}
  </table></body></html>`;
  res.send(html);
});

// ================================
// 🧠 Gemini 검증 API
// ================================
app.post("/api/verify", async (req, res) => {
  const { query, key } = req.body;
  if (!query || !key)
    return res.status(400).json({ success: false, message: "❌ Missing query/key" });

  try {
    const startTime = Date.now();
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${key}`;
    const result = await axios.post(endpoint, {
      contents: [{ role: "user", parts: [{ text: query }] }],
    });
    const resultText = result.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    const elapsed = Date.now() - startTime;

    const { error } = await supabase.from("verification_logs").insert([
      {
        question: query,
        model_main: GEMINI_MODEL,
        cross_score: 1,
        elapsed,
        status: "completed",
        created_at: new Date().toISOString(),
      },
    ]);

    if (error) throw error;

    res.json({
      success: true,
      message: "✅ Gemini 검증 완료 및 Supabase 저장됨",
      query,
      elapsed,
      resultPreview: resultText.slice(0, 200),
    });
  } catch (err) {
    console.error("Gemini 요청 실패:", err.message);
    res.status(500).json({ success: false, message: `서버 오류: ${err.message}` });
  }
});

// ================================
// 🚀 서버 시작
// ================================
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy (v12.9.0) 실행 중 (포트: ${PORT})`);
  console.log(`🌐 Supabase 연결: ${SUPABASE_URL}`);
  console.log(`🔑 관리자 계정: ${ADMIN_EMAIL}`);
});
