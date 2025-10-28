/**
 * Cross-Verified AI Proxy Server v9.8.8 (Run on Render)
 */
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

// ────────────────────────────────
// Engine modules
// ────────────────────────────────
const geminiEngine = require("./engine/gemini");
const verificationEngine = require("./engine/verification");
const truthScoreEngine = require("./engine/truthscore");
const cryptoUtils = require("./utils/crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// ────────────────────────────────
// Middleware
// ────────────────────────────────
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "10mb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later.",
});
app.use(limiter);

// ────────────────────────────────
// Health / Ping
// ────────────────────────────────
app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    status: "healthy",
    version: "9.8.8",
    timestamp: new Date().toISOString(),
  });
});

app.get("/ping", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    version: "9.8.8",
    uptime: process.uptime(),
  });
});

// ────────────────────────────────
// Gemini API
// ────────────────────────────────
app.post("/api/gemini/generate", async (req, res) => {
  try {
    const { apiKey, model, prompt, temperature, maxTokens } = req.body;
    if (!apiKey || !prompt) {
      return res.status(400).json({ error: "API key and prompt required" });
    }
    const result = await geminiEngine.callGemini({
      apiKey,
      model: model || "gemini-2.5-flash",
      prompt,
      temperature: temperature || 0.7,
      maxTokens: maxTokens || 2048,
    });
    res.json(result);
  } catch (err) {
    console.error("Gemini error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/gemini/extract-keywords", async (req, res) => {
  try {
    const { apiKey, text } = req.body;
    if (!apiKey || !text) return res.status(400).json({ error: "Missing fields" });
    const result = await geminiEngine.extractKeywords(text, apiKey);
    res.json(result);
  } catch (err) {
    console.error("Keyword error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ────────────────────────────────
// Verification Engines
// ────────────────────────────────

// ✅ Must be above :engine route
app.post("/api/verify/all", async (req, res) => {
  try {
    const { query, apiKeys } = req.body;
    if (!query) return res.status(400).json({ error: "Query is required" });
    const result = await verificationEngine.verifyAll(query, apiKeys || {});
    res.json(result);
  } catch (err) {
    console.error("verify/all error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/verify/:engine", async (req, res) => {
  try {
    const { engine } = req.params;
    const { query, apiKey } = req.body;
    if (!query) return res.status(400).json({ error: "Query is required" });

    let result;
    switch (engine) {
      case "crossref":
        result = await verificationEngine.verifyCrossRef(query); break;
      case "openalex":
        result = await verificationEngine.verifyOpenAlex(query); break;
      case "gdelt":
        result = await verificationEngine.verifyGDELT(query); break;
      case "wikidata":
        result = await verificationEngine.verifyWikidata(query); break;
      case "github":
        result = await verificationEngine.verifyGitHub(query, apiKey); break;
      case "klaw":
        result = await verificationEngine.verifyKLaw(query, apiKey); break;
      default:
        return res.status(400).json({ error: "Invalid engine name" });
    }
    res.json(result);
  } catch (err) {
    console.error("verify/:engine error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ────────────────────────────────
// TruthScore Engine
// ────────────────────────────────
app.post("/api/truthscore/calculate", async (req, res) => {
  try {
    const { engines } = req.body;
    if (!Array.isArray(engines))
      return res.status(400).json({ error: "Engines array required" });
    const result = truthScoreEngine.calculateTruthScore(engines);
    res.json(result);
  } catch (err) {
    console.error("TruthScore error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ────────────────────────────────
// Encryption / Decryption
// ────────────────────────────────
app.post("/api/keys/encrypt", (req, res) => {
  try {
    const { plaintext, masterPassword } = req.body;
    if (!plaintext || !masterPassword)
      return res.status(400).json({ error: "Missing fields" });
    const encrypted = cryptoUtils.encryptKey(plaintext, masterPassword);
    res.json({ success: true, encrypted });
  } catch (err) {
    console.error("encrypt error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/keys/decrypt", (req, res) => {
  try {
    const { encryptedData, masterPassword } = req.body;
    if (!encryptedData || !masterPassword)
      return res.status(400).json({ error: "Missing fields" });
    const decrypted = cryptoUtils.decryptKey(encryptedData, masterPassword);
    res.json({ success: true, decrypted });
  } catch (err) {
    console.error("decrypt error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/keys/validate", async (req, res) => {
  try {
    const { apiKey } = req.body;
    if (!apiKey) return res.status(400).json({ error: "API key required" });
    const result = await geminiEngine.validateApiKey(apiKey);
    res.json(result);
  } catch (err) {
    console.error("validate error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ────────────────────────────────
// Fallback & Error Handlers
// ────────────────────────────────
app.use((req, res) => res.status(404).json({ error: "Endpoint not found" }));
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// ────────────────────────────────
// Start Server
// ────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║  Cross-Verified AI Proxy Server v9.8.8 (Render Ready)     ║
║  Server running on http://localhost:${PORT}               ║
╚══════════════════════════════════════════════════════════╝
`);
  console.log("Available endpoints:");
  console.log("  GET  /health");
  console.log("  GET  /ping");
  console.log("  POST /api/gemini/generate");
  console.log("  POST /api/gemini/extract-keywords");
  console.log("  POST /api/verify/all");
  console.log("  POST /api/verify/:engine");
  console.log("  POST /api/truthscore/calculate");
  console.log("  POST /api/keys/encrypt");
  console.log("  POST /api/keys/decrypt");
  console.log("  POST /api/keys/validate");
});
