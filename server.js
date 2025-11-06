import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import morgan from "morgan";

dotenv.config();
const app = express();
app.use(bodyParser.json({ limit: "5mb" }));
app.use(cors());
app.use(morgan("dev"));

// ================================
// 🔧 환경 변수
// ================================
const PORT = process.env.PORT || 3000;
const GEMINI_MODEL = process.env.DEFAULT_MODEL || "gemini-2.5-flash";
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL; // 마스터 관리자 이메일
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ================================
// 🧠 Google OAuth 설정
// ================================
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      const email = profile.emails[0].value;
      try {
        // Supabase 세션 저장
        await supabase.from("sessions").insert([
          {
            user_email: email,
            access_token: accessToken,
            refresh_token: refreshToken,
            expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
          },
        ]);
        return done(null, { email });
      } catch (err) {
        console.error("❌ Supabase 세션 저장 실패:", err.message);
        return done(err, null);
      }
    }
  )
);

app.use(passport.initialize());

// ================================
// 🚀 기본 헬스체크
// ================================
app.get("/health", (req, res) => {
  res.json({ success: true, message: "✅ Proxy Server Healthy", version: "v12.8.0" });
});

// ================================
// 🔗 Google OAuth 엔드포인트
// ================================
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/fail" }),
  async (req, res) => {
    res.redirect("/admin");
  }
);

app.get("/auth/fail", (req, res) => {
  res.status(401).send("❌ Google OAuth 인증 실패");
});

// ================================
// ⚙️ Supabase 세션 검증 함수
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
  if (new Date(session.expires_at) < new Date()) return false;
  return true;
}

// ================================
// 🧾 Admin Dashboard
// ================================
app.get("/admin", async (req, res) => {
  const userEmail = req.query.email;
  if (!userEmail) {
    return res.status(400).send("❌ 이메일 정보가 필요합니다 (예: /admin?email=user@gmail.com)");
  }

  if (userEmail !== ADMIN_EMAIL) {
    return res.status(403).send("❌ 관리자 접근 거부 (허용되지 않은 이메일)");
  }

  const isValid = await verifySession(userEmail);
  if (!isValid) {
    return res.status(401).send("❌ 세션 만료 또는 유효하지 않음. 다시 로그인 필요");
  }

  const { data: logs, error } = await supabase
    .from("verification_logs")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(10);

  if (error) {
    return res.status(500).send(`❌ Supabase 쿼리 실패: ${error.message}`);
  }

  const html = `
  <html><head><meta charset="utf-8"><title>Admin Dashboard</title>
  <style>
  body{font-family:Arial;padding:16px;background:#f9f9f9;color:#222}
  table{border-collapse:collapse;width:100%;margin-top:16px}
  th,td{border:1px solid #ccc;padding:8px}
  th{background:#eee}
  </style></head>
  <body>
  <h2>🧭 Cross-Verified AI Admin Dashboard</h2>
  <p>관리자: <b>${userEmail}</b></p>
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
  </table>
  </body></html>`;
  res.send(html);
});

// ================================
// 🧠 Gemini 검증 엔드포인트
// ================================
app.post("/api/verify", async (req, res) => {
  const { query, key } = req.body;
  if (!query || !key) {
    return res.status(400).json({ success: false, message: "❌ 요청 파라미터 부족 (query/key 필요)" });
  }

  try {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${key}`;
    const startTime = Date.now();

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
    console.error("❌ Gemini 요청 실패:", err.message);
    res.status(500).json({ success: false, message: `서버 오류: ${err.message}` });
  }
});

// ================================
// 🚀 서버 시작
// ================================
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy (v12.8.0) 실행 중 (포트: ${PORT})`);
  console.log(`🌐 Supabase 연결: ${SUPABASE_URL}`);
  console.log(`🔑 관리자 계정: ${ADMIN_EMAIL}`);
});
