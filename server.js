require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors({ origin: "*", credentials: true }));

// ✅ 세션 설정
app.use(
  session({
    secret: process.env.SESSION_SECRET || "cross-verified-session",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ✅ Google OAuth 설정
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      return done(null, profile);
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ✅ 루트 페이지
app.get("/", (req, res) => {
  res.json({
    message: "🚀 Cross-Verified AI Proxy Server v10.0 (OAuth + JWT Ready)",
  });
});

// ✅ Google 로그인 시작
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// ✅ 로그인 성공 후 JWT 발급
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure" }),
  (req, res) => {
    const user = req.user;
    const token = jwt.sign(
      {
        email: user.emails[0].value,
        name: user.displayName,
      },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      success: true,
      message: "Google login successful ✅",
      user: {
        displayName: user.displayName,
        email: user.emails[0].value,
      },
      token,
    });
  }
);

// ✅ 로그인 실패 시
app.get("/auth/failure", (req, res) => {
  res.status(401).json({ success: false, message: "Google login failed ❌" });
});

// ✅ JWT 검증
app.get("/auth/verify", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing Authorization header" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ success: true, user: decoded });
  } catch (err) {
    res.status(403).json({ success: false, error: "Invalid or expired token" });
  }
});

// ✅ Health check
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    timestamp: new Date().toISOString(),
  });
});

// ✅ 서버 시작
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
