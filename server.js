/**
 * Cross-Verified AI Proxy Server v9.7.7
 * Render-compatible full version
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// ✅ 엔진 모듈 경로 수정 (Render 호환)
const geminiEngine = require('./proxy-server/src/engine/gemini');
const verificationEngine = require('./proxy-server/src/engine/verification');
const truthScoreEngine = require('./proxy-server/src/engine/truthscore');
const cryptoUtils = require('./utils/crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// 보안 및 미들웨어
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// 요청 제한 (Rate Limit)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// ✅ Render Health Check 엔드포인트 (가장 먼저 선언)
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'healthy',
    version: '9.7.7',
    timestamp: new Date().toISOString()
  });
});

/**
 * 간단한 Ping (서버 상태 확인용)
 */
app.get('/ping', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: '9.7.7',
    uptime: process.uptime()
  });
});

/**
 * Gemini API 프록시
 */
app.post('/api/gemini/generate', async (req, res) => {
  try {
    const { apiKey, model, prompt, temperature, maxTokens, systemInstruction } = req.body;

    if (!apiKey) return res.status(400).json({ error: 'API key is required' });
    if (!prompt) return res.status(400).json({ error: 'Prompt is required' });

    const result = await geminiEngine.callGemini({
      apiKey,
      model: model || 'flash',
      prompt,
      temperature: temperature || 0.7,
      maxTokens: maxTokens || 2048,
      systemInstruction
    });

    res.json(result);
  } catch (error) {
    console.error('Gemini API error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 키워드 추출
 */
app.post('/api/gemini/extract-keywords', async (req, res) => {
  try {
    const { apiKey, text } = req.body;
    if (!apiKey || !text)
      return res.status(400).json({ error: 'API key and text are required' });

    const result = await geminiEngine.extractKeywords(text, apiKey);
    res.json(result);
  } catch (error) {
    console.error('Keyword extraction error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 검증 엔진 - 개별 엔진 테스트
 */
app.post('/api/verify/:engine', async (req, res) => {
  try {
    const { engine } = req.params;
    const { query, apiKey } = req.body;

    if (!query) return res.status(400).json({ error: 'Query is required' });

    let result;
    switch (engine) {
      case 'crossref': result = await verificationEngine.verifyCrossRef(query); break;
      case 'openalex': result = await verificationEngine.verifyOpenAlex(query); break;
      case 'gdelt': result = await verificationEngine.verifyGDELT(query); break;
      case 'wikidata': result = await verificationEngine.verifyWikidata(query); break;
      case 'github': result = await verificationEngine.verifyGitHub(query, apiKey); break;
      case 'klaw': result = await verificationEngine.verifyKLaw(query, apiKey); break;
      default: return res.status(400).json({ error: 'Invalid engine name' });
    }

    res.json(result);
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 검증 엔진 - 전체 검증
 */
app.post('/api/verify/all', async (req, res) => {
  try {
    const { query, apiKeys } = req.body;
    if (!query) return res.status(400).json({ error: 'Query is required' });

    const result = await verificationEngine.verifyAll(query, apiKeys || {});
    res.json(result);
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * TruthScore 계산
 */
app.post('/api/truthscore/calculate', async (req, res) => {
  try {
    const { engines } = req.body;
    if (!engines || !Array.isArray(engines))
      return res.status(400).json({ error: 'Engines array is required' });

    const result = truthScoreEngine.calculateTruthScore(engines);
    res.json(result);
  } catch (error) {
    console.error('TruthScore calculation error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * API Key 암복호화
 */
app.post('/api/keys/encrypt', async (req, res) => {
  try {
    const { plaintext, masterPassword } = req.body;
    if (!plaintext || !masterPassword)
      return res.status(400).json({ error: 'Plaintext and master password are required' });

    const encrypted = cryptoUtils.encryptKey(plaintext, masterPassword);
    res.json({ success: true, encrypted });
  } catch (error) {
    console.error('Encryption error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/keys/decrypt', async (req, res) => {
  try {
    const { encryptedData, masterPassword } = req.body;
    if (!encryptedData || !masterPassword)
      return res.status(400).json({ error: 'Encrypted data and master password are required' });

    const decrypted = cryptoUtils.decryptKey(encryptedData, masterPassword);
    res.json({ success: true, decrypted });
  } catch (error) {
    console.error('Decryption error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Gemini API Key 검증
 */
app.post('/api/keys/validate', async (req, res) => {
  try {
    const { apiKey } = req.body;
    if (!apiKey) return res.status(400).json({ error: 'API key is required' });

    const result = await geminiEngine.validateApiKey(apiKey);
    res.json(result);
  } catch (error) {
    console.error('Validation error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 404 핸들러 (맨 마지막)
 */
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

/**
 * 에러 핸들러
 */
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

/**
 * 서버 시작
 */
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║   Cross-Verified AI Proxy Server v9.7.7 (Render Ready)   ║
║   Server running on http://localhost:${PORT}               ║
╚══════════════════════════════════════════════════════════╝
  `);
  console.log('Available endpoints:');
  console.log('  GET  /health');
  console.log('  GET  /ping');
  console.log('  POST /api/gemini/generate');
  console.log('  POST /api/gemini/extract-keywords');
  console.log('  POST /api/verify/:engine');
  console.log('  POST /api/verify/all');
  console.log('  POST /api/truthscore/calculate');
  console.log('  POST /api/keys/encrypt');
  console.log('  POST /api/keys/decrypt');
  console.log('  POST /api/keys/validate');
  console.log('');
});

module.exports = app;
