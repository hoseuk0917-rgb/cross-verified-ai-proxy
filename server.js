// server.js — Cross-Verified AI Proxy Server v9.9.1 (Web + App 통합 OAuth 안정버전)
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// ==============================
// 미들웨어 설정
// ==============================
app.use(helmet());
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: "10mb" }));

// 요청 제한
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 200,
  })
);

// ==============================
// 세션 및 Passport 설정
// ==============================
app.use(
  session({
    secret: process.env.SESSION_SECRET || "crossverified_secret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ==============================
// Google OAuth Strategy (웹 로그인용)
// ==============================
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:
        process.env.GOOGLE_CALLBACK_URL ||
        "https://cross-verified-ai-proxy.onrender.com/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      const user = {
        id: profile.id,
        displayName: profile.displayName,
        email: profile.emails[0].value,
      };
      return done(null, user);
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ==============================
// Health Check
// ==============================
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    timestamp: new Date().toISOString(),
    version: "9.9.1",
  });
});

// ==============================
// Google OAuth Routes (웹 로그인용)
// ==============================
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure" }),
  (req, res) => {
    const token = jwt.sign(
      { email: req.user.email, name: req.user.displayName },
      process.env.JWT_SECRET || "jwt_secret",
      { expiresIn: "2h" }
    );
    res.json({
      success: true,
      message: "✅ Google login successful",
      user: req.user,
      token,
    });
  }
);

app.get("/auth/failure", (req, res) => {
  res.status(401).json({ success: false, error: "Google login failed" });
});

// ==============================
// Google OAuth (App / 모바일용)
// ==============================
app.post("/auth/google/app", async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) {
    return res
      .status(400)
      .json({ success: false, error: "idToken is required" });
  }

  try {
    const response = await axios.get(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`
    );
    const data = response.data;

    if (!data.email) throw new Error("Invalid Google token");

    const token = jwt.sign(
      { email: data.email, name: data.name },
      process.env.JWT_SECRET || "jwt_secret",
      { expiresIn: "2h" }
    );

    res.json({
      success: true,
      message: "✅ App login successful",
      user: { email: data.email, name: data.name },
      token,
    });
  } catch (error) {
    console.error("App OAuth error:", error.message);
    res.status(400).json({ success: false, error: error.message });
  }
});

// ==============================
// JWT Verify
// ==============================
app.get("/auth/verify", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ success: false, error: "Missing token" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwt_secret");
    res.json({ success: true, user: decoded });
  } catch {
    res.status(401).json({ success: false, error: "Invalid token" });
  }
});

// ==============================
// Logout (Web 세션)
// ==============================
app.get("/auth/logout", (req, res) => {
  req.logout(() => {
    res.json({ success: true, message: "Logged out successfully" });
  });
});

// ==============================
// 404 핸들러
// ==============================
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// ==============================
// 서버 시작
// ==============================
app.listen(PORT, () => {
  console.log(`
✅ Cross-Verified AI Proxy Server v9.9.1
🚀 Web + App 통합 Google OAuth 활성화
🌐 Running on port ${PORT}
  `);
});
