// server.js (Render-compatible full version)
import express from "express";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Flutter Web 빌드 경로 지정
const buildPath = path.join(__dirname, "build", "web");

// ✅ 빌드 폴더 존재 확인
if (!fs.existsSync(buildPath)) {
  console.warn("⚠️  Warning: build/web not found. Serving API only.");
} else {
  console.log("✅ Serving static Flutter web files from:", buildPath);
  app.use(express.static(buildPath));
}

// ✅ 기본 헬스체크 (Render용)
app.get("/api/ping", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

// ✅ SPA 라우팅 (404 방지)
app.get("*", (req, res) => {
  if (fs.existsSync(path.resolve(buildPath, "index.html"))) {
    res.sendFile(path.resolve(buildPath, "index.html"));
  } else {
    res.status(404).send("❌ index.html not found. Please build Flutter web first.");
  }
});

// ✅ Render 호환: 반드시 0.0.0.0으로 청취해야 함
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
