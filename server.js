const express = require("express");
const session = require("express-session");
const passport = require("./utils/passport");
const authRoutes = require("./routes/auth");

const app = express();
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

// 기존 엔드포인트 유지
app.get("/health", (req, res) => {
  res.json({
    success: true,
    version: "9.9.x",
    timestamp: new Date(),
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Cross-Verified Proxy Server running on port ${PORT}`);
});
