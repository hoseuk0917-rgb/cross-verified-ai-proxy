// ✅ Cross-Verified AI Test API Endpoints
import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

// ================================
// 기본 /api/ping
// ================================
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    message: "✅ Proxy active and responding",
    version: "10.8.5",
    time: new Date().toISOString(),
  });
});

// ================================
// 🔹 Test Endpoints for Client Checks
// ================================

// 1️⃣ Gemini API Key 테스트 (단순 응답)
app.get("/api/test-gemini", async (req, res) => {
  const { key } = req.query;
  if (!key) return res.status(400).json({ success: false, message: "Key required" });

  // 실제 API 호출 대신 키 유효성 단순 테스트
  if (key.startsWith("AI") || key.startsWith("AIza")) {
    return res.json({ success: true, message: "Gemini key format OK" });
  }
  res.status(401).json({ success: false, message: "Invalid Gemini key format" });
});

// 2️⃣ GitHub Token 테스트
app.get("/api/test-github", async (req, res) => {
  const { key } = req.query;
  if (!key) return res.status(400).json({ success: false, message: "Token required" });

  try {
    const response = await fetch("https://api.github.com/user", {
      headers: { Authorization: `token ${key}` },
    });
    if (response.status === 200) {
      const data = await response.json();
      return res.json({ success: true, message: "GitHub Auth OK", user: data.login });
    } else {
      return res.status(401).json({ success: false, message: "GitHub Token invalid" });
    }
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// 3️⃣ Naver API 테스트
app.get("/api/test-naver", async (req, res) => {
  const { key, secret } = req.query;
  if (!key || !secret) return res.status(400).json({ success: false, message: "ID/Secret required" });

  try {
    const response = await fetch("https://openapi.naver.com/v1/search/news.json?query=test", {
      headers: {
        "X-Naver-Client-Id": key,
        "X-Naver-Client-Secret": secret,
      },
    });
    if (response.status === 200) {
      return res.json({ success: true, message: "Naver API Auth OK" });
    } else {
      return res.status(401).json({ success: false, message: "Naver API Auth Fail" });
    }
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// 4️⃣ K-Law 테스트 (형식 검증용)
app.get("/api/test-klaw", async (req, res) => {
  const { key } = req.query;
  if (!key) return res.status(400).json({ success: false, message: "ID required" });

  // 간단한 형식검증 + 응답
  if (key.includes("@") || key.length < 3) {
    return res.status(400).json({ success: false, message: "Invalid ID format" });
  }
  return res.json({ success: true, message: "K-Law ID format OK" });
});

// ================================
// ✅ Render 서버 실행
// ================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
