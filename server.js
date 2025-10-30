/**
 * Cross-Verified AI Proxy Server v10.4.0
 * Integrated Proxy + TruthScore + OAuth + Health Routes
 */

import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

import { callGemini } from "./engine/gemini.js";
import { verifyEngines, verifySingleEngine } from "./engine/verification.js";
import { calculateTruthScore } from "./engine/truthscore.js";

dotenv.config();
const app = express();

app.use(cors());
app.use(bodyParser.json());

// ✅ Basic Rate Limiter
app.use(rateLimit({
  windowMs: process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX_REQUESTS || 100
}));

// ✅ Health Check
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    version: "10.4.0",
    timestamp: new Date().toISOString()
  });
});

// ✅ JWT Auth Verification
app.get("/auth/verify", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, error: "No token" });
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ success: true, user });
  } catch (err) {
    res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
});

// ✅ Developer Token
app.post("/auth/dev-token", (req, res) => {
  const { email, name } = req.body;
  if (!email || !name) return res.status(400).json({ success: false, error: "Missing credentials" });
  const token = jwt.sign({ email, name }, process.env.JWT_SECRET, { expiresIn: "2h" });
  res.json({ success: true, token });
});

// ----------------------------------------------------------------------
// ✅ Proxy Routes
// ----------------------------------------------------------------------

// Gemini Proxy
app.post("/proxy/gemini/:model", async (req, res) => {
  const { model } = req.params;
  const { apiKey, prompt } = req.body;
  const result = await callGemini({ apiKey, model, prompt });
  res.json(result);
});

// Unified Multi-Engine Verification
app.get("/proxy/external", async (req, res) => {
  const { query } = req.query;
  const results = await verifyEngines(query);
  res.json(results);
});

// Single Engine Verification
app.get("/proxy/:engine", async (req, res) => {
  const { engine } = req.params;
  const { query } = req.query;
  const result = await verifySingleEngine(engine, query);
  res.json(result);
});

// ----------------------------------------------------------------------
// ✅ TruthScore Calculation
// ----------------------------------------------------------------------
app.post("/truthscore/calculate", async (req, res) => {
  const { query, weights } = req.body;
  if (!query) return res.status(400).json({ error: "Query missing" });
  const score = await calculateTruthScore(query, weights);
  res.json(score);
});

// ----------------------------------------------------------------------
// ✅ 404 fallback
// ----------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// ----------------------------------------------------------------------
// ✅ Start Server
// ----------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
