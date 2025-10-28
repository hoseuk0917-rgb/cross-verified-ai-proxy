// routes/auth.js
const express = require("express");
const passport = require("passport");
const router = express.Router();

// 구글 로그인 시작
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// 콜백 처리
router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/fail" }),
  (req, res) => {
    res.redirect("/auth/success");
  }
);

// 로그인 성공
router.get("/success", (req, res) => {
  res.json({
    success: true,
    user: req.user,
    message: "Google OAuth login success",
  });
});

// 로그인 실패
router.get("/fail", (req, res) => {
  res.json({ success: false, message: "Google OAuth login failed" });
});

// 로그아웃
router.get("/logout", (req, res) => {
  req.logout(() => res.json({ success: true, message: "Logged out" }));
});

module.exports = router;
