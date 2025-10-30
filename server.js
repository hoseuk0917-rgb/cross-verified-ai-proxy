/**
 * Cross-Verified AI Proxy (Render-safe + Local-safe build)
 * v10.5.3
 */
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Resolve paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// === STEP 1. 기본 미들웨어 설정 ===
app.use(express.json());
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(",") || "*",
    credentials: true,
  })
);

// === STEP 2. 정적 파일 경로 설정 ===
const renderBuildPath = "/opt/render/project/src/build/web";
const localBuildPath = path.join(__dirname, "build", "web");

let activeBuildPath = "";

// Render용 경로 먼저 확인
import fs from "fs";
if (fs.existsSync(renderBuildPath)) {
  activeBuildPath = renderBuildPath;
  console.log(`✅ Using Render build path: ${renderBuildPath}`);
} else if (fs.existsSync(localBuildPath)) {
  activeBuildPath = localBuildPath;
  console.log(`✅ Using Local build path: ${localBuildPath}`);
} else {
  console.warn("⚠️ No build/web directory found. Serving API only.");
}

if (activeBuildPath) {
  app.use(express.static(activeBuildPath));

  app.get("/", (req, res) => {
    res.sendFile(path.join(activeBuildPath, "index.html"));
  });
}

// === STEP 3. 기본 헬스체크 ===
app.get("/api/ping", (req, res) => {
  res.status(200).json({
    message: "✅ Proxy active and responding",
    version: "10.5.3",
    time: new Date().toISOString(),
  });
});

// === STEP 4. 인증 및 API 라우트 예시 ===
app.get("/auth/google/callback", (req, res) => {
  res.status(200).send("✅ Google OAuth callback received");
});

// === STEP 5. fallback 404 ===
app.use((req, res) => {
  res.status(404).send(`
    <html>
      <body style="font-family:sans-serif; text-align:center; padding:60px;">
        <h2>⚠️ Flutter build not found</h2>
        <p>현재 Render에 <code>build/web</code>이 업로드되지 않았습니다.<br/>
        로컬에서 <code>flutter build web</code> 후 다시 커밋하세요.</p>
      </body>
    </html>
  `);
});

// === STEP 6. 서버 시작 ===
app.listen(PORT, () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
