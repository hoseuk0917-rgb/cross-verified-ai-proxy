// routes/auth.js
const express = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");

const router = express.Router();

// ✅ Google OAuth 로그인 시작
router.get("/google", passport.authenticate("google", {
  scope: ["profile", "email"]
}));

// ✅ Google OAuth 콜백 처리
router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure" }),
  (req, res) => {
    try {
      const user = req.user;
      const token = jwt.sign(
        {
          email: user.email,
          name: user.displayName,
        },
        process.env.JWT_SECRET || "default-secret",
        { expiresIn: "2h" }
      );

      return res.json({
        success: true,
        user: {
          displayName: user.displayName,
          email: user.email,
        },
        token,
      });
    } catch (err) {
      console.error("OAuth callback error:", err);
      res.status(500).json({ success: false, error: "OAuth processing error" });
    }
  }
);

// ✅ 로그인 실패
router.get("/failure", (req, res) => {
  res.status(401).json({
    success: false,
    error: "Google authentication failed",
  });
});

// ✅ JWT 토큰 검증 엔드포인트
router.get("/verify", (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ success: false, error: "Missing Authorization header" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "default-secret");
    return res.json({ success: true, user: decoded });
  } catch (error) {
    return res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
});

// ✅ 개발용 토큰 발급 (관리자 테스트용)
router.post("/dev-token", express.json(), (req, res) => {
  const { email, name } = req.body;
  if (!email || !name) {
    return res.status(400).json({ success: false, error: "Email and name required" });
  }

  const token = jwt.sign(
    { email, name },
    process.env.JWT_SECRET || "default-secret",
    { expiresIn: "2h" }
  );

  return res.json({ success: true, token });
});

// ✅ 로그아웃 (세션 제거)
router.get("/logout", (req, res) => {
  req.logout(() => {
    res.json({ success: true, message: "Logged out successfully" });
  });
});

module.exports = router;
