// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const jwt = require("jsonwebtoken");

const gemini = require("./engine/gemini");
const verification = require("./engine/verification");
const truthscore = require("./engine/truthscore");

const app = express();
const PORT = process.env.PORT || 3000;

// ===== Middleware =====
app.use(cors({ origin: "*", credentials: true }));
app.use(bodyParser.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "crossverified_secret",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ===== Health Check =====
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    version: "10.1.0",
    timestamp: new Date().toISOString(),
  });
});

// ===== Google OAuth =====
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      const user = {
        displayName: profile.displayName,
        email: profile.emails[0].value,
      };
      return done(null, user);
    }
  )
);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure" }),
  (req, res) => {
    const token = jwt.sign(
      {
        email: req.user.email,
        name: req.user.displayName,
      },
      process.env.JWT_SECRET || "crossverified_jwt",
      { expiresIn: "2h" }
    );

    res.json({
      success: true,
      user: req.user,
      token,
    });
  }
);

app.get("/auth/failure", (req, res) => {
  res.status(401).json({ success: false, message: "Authentication failed" });
});

// ===== JWT Verification =====
app.get("/auth/verify", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ success: false, error: "No token provided" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "crossverified_jwt"
    );
    res.json({ success: true, user: decoded });
  } catch (error) {
    res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
});

// ===== Gemini API =====
app.post("/api/gemini/generate", async (req, res) => {
  const { apiKey, model, prompt } = req.body;
  try {
    const result = await gemini.callGemini({ apiKey, model, prompt });
    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/api/gemini/extract-keywords", async (req, res) => {
  try {
    const { text } = req.body;
    const result = await gemini.extractKeywords(text);
    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== Verification Engines =====
app.post("/api/verify/:engine", async (req, res) => {
  try {
    const { engine } = req.params;
    const { query } = req.body;

    // ✅ "all" 분기 로직 (핵심)
    if (engine === "all") {
      const result = await verification.verifyAllEngines(query);
      return res.json(result);
    }

    const result = await verification.verifySingleEngine(engine, query);
    res.json(result);
  } catch (error) {
    console.error("[/api/verify/:engine] Error:", error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== TruthScore Calculation =====
app.post("/api/truthscore/calculate", async (req, res) => {
  try {
    const { scores, weights } = req.body;
    const result = await truthscore.calculate(scores, weights);
    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== Ping Endpoint =====
app.get("/ping", (req, res) => {
  res.json({ success: true, message: "pong" });
});

// ===== 404 Handler =====
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// ===== Start Server =====
app.listen(PORT, () => {
  console.log("✅ Server running on port " + PORT);
});
