/**
 * Cross-Verified AI Proxy Server v10.8.2
 * Render-compatible + Morgan + Direct console.log
 */

import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import morgan from "morgan";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ 미들웨어
app.use(cors());
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true }));

// ✅ Morgan 로그 강제 출력 (stdout으로 바로)
app.use(
  morgan("dev", {
    stream: {
      write: (message) => console.log(message.trim()),
    },
  })
);

// ✅ Ping 엔드포인트
app.get("/api/ping", (req, res) => {
  const time = new Date().toISOString();
  console.log(`[PING] Request from ${req.ip} at ${time}`);
  res.json({
    success: true,
    message: "✅ Proxy active and responding",
    version: "10.8.2",
    time,
  });
});

// ✅ Whitelist 엔드포인트
app.get("/api/check-whitelist", (req, res) => {
  const email = req.query.email || "unknown";
  console.log(`[WHITELIST] Checking access for ${email}`);
  res.json({ email, access: true, lastChecked: new Date().toISOString() });
});

// ✅ Gemini Flash / Pro / Lite
app.post("/proxy/gemini/:model", async (req, res) => {
  const { userEmail, query, klawId } = req.body;
  const model = req.params.model;
  console.log(`[GEMINI] model=${model}, user=${userEmail}, klawId=${klawId}, query="${query?.slice(0, 40)}..."`);
  res.json({
    engine: "Gemini",
    model,
    status: "ok",
    user: userEmail,
    query,
    result: `Simulated Gemini ${model} response.`,
  });
});

// ✅ Fact Verification (FV)
app.post("/proxy/fact", (req, res) => {
  const { userEmail, query } = req.body;
  console.log(`[FACT] user=${userEmail}, query="${query?.slice(0, 40)}..."`);
  res.json({ engine: "Fact Verification", status: "ok", result: "Fact verified." });
});

// ✅ Development Verification (DV)
app.post("/proxy/github/dev", (req, res) => {
  const { repoUrl, userEmail, query } = req.body;
  console.log(`[DEV] user=${userEmail}, repo=${repoUrl}, query="${query?.slice(0, 40)}..."`);
  res.json({ engine: "Development Verification", status: "ok", result: "GitHub analysis simulated." });
});

// ✅ Code Verification (CV)
app.post("/proxy/code", (req, res) => {
  const { userEmail, code } = req.body;
  console.log(`[CODE] user=${userEmail}, code="${code?.slice(0, 40)}..."`);
  res.json({ engine: "Code Verification", status: "ok", result: "Syntax check passed." });
});

// ✅ K-Law Verification (LM)
app.post("/proxy/klaw", (req, res) => {
  const { userEmail, klawId, query } = req.body;
  console.log(`[K-LAW] klawId=${klawId}, user=${userEmail}, query="${query?.slice(0, 40)}..."`);
  res.json({ engine: "K-Law Verification", status: "ok", klawId, result: "K-Law simulated response." });
});

// ✅ 기본 라우트
app.get("/", (req, res) => {
  res.send("✅ Cross-Verified AI Proxy Server is running (v10.8.2)");
});

// ✅ 서버 시작
app.listen(PORT, () => {
  console.log("==========================================");
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
  console.log(`🌐 URL: https://cross-verified-ai-proxy.onrender.com`);
  console.log("==========================================");
});
