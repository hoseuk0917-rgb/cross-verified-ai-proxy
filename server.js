// server.js
import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Flutter Web 빌드 파일 경로
const buildPath = path.join(__dirname, "build", "web");

// ✅ 정적 파일 제공
app.use(express.static(buildPath));

// ✅ 헬스체크 (Render 자동 재시작용)
app.get("/api/ping", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

// ✅ SPA 대응 (404 방지)
app.get("*", (req, res) => {
  res.sendFile(path.resolve(buildPath, "index.html"));
});

app.listen(PORT, () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
