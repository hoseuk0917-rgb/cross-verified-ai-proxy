// server.js
const express = require("express");
const session = require("express-session");
const passport = require("./utils/passport");
const authRoutes = require("./routes/auth");
const cors = require("cors");
const helmet = require("helmet");

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어
app.use(helmet());
app.use(cors());
app.use(express.json());

// 세션 설정
app.use(
  session({
    secret: process.env.SESSION_SECRET || "cross-verified-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// Passport 초기화
app.use(passport.initialize());
app.use(passport.session());

// 라우트 등록
app.use("/auth", authRoutes);

// 기본 health check
app.get("/health", (req, res) => {
  res.json({
    success: true,
    version: "9.9.1",
    timestamp: new Date(),
    message: "Cross-Verified Proxy Server is healthy and OAuth ready",
  });
});

// 루트 경로
app.get("/", (req, res) => {
  res.send(`<h2>✅ Cross-Verified AI Proxy Server (OAuth Ready)</h2>
  <p><a href="/auth/google">▶ Google 로그인 테스트</a></p>`);
});

app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
