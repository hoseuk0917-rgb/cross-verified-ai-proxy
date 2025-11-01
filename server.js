import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import morgan from "morgan";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use(morgan("dev"));

// ✅ Flutter Web 빌드 결과 서빙
app.use(express.static(path.join(__dirname, "src/build/web")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "src/build/web/index.html"));
});

// ✅ 서버 상태 체크
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    message: "✅ Proxy active and responding",
    version: "10.8.1",
    time: new Date().toISOString(),
  });
});

// ✅ 테스트 엔드포인트 (각 엔진별 키 유효성 확인)
app.post("/api/test/:engine", (req, res) => {
  const { engine } = req.params;
  const { key } = req.body;
  if (!key || key.length < 4) {
    return res.status(400).json({ success: false, message: "❌ Invalid key" });
  }
  res.json({
    success: true,
    message: `✅ ${engine} 연결 성공`,
    keySample: key.slice(0, 4) + "****",
  });
});

// ✅ Gemini 호출 (Stub: 실제 API 연동 전)
app.post("/api/gemini/:model", async (req, res) => {
  const { query, user } = req.body;
  if (!query)
    return res.status(400).json({ success: false, message: "❌ query 없음" });

  res.json({
    success: true,
    model: req.params.model,
    user,
    response: `Gemini-${req.params.model} 시뮬레이션 응답: "${query}"`,
    time: new Date().toISOString(),
  });
});

// ✅ 404 방지
app.use((req, res) =>
  res.status(404).json({ success: false, message: "Endpoint not found" })
);

app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v10.8.1 running on port ${PORT}`);
});
