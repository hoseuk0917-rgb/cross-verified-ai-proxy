// Cross-Verified AI Proxy Server v8.8.5 - Adaptive Reset Full Edition
// Author: Claude + User
// Date: 2025-10-30
// Platform: Render.com Serverless

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for Render.com
app.set('trust proxy', 1);

// ========================
// 환경 변수
// ========================
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-key';
const HMAC_SECRET = process.env.HMAC_SECRET || 'your-hmac-secret-key';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || '*';

// ========================
// 미들웨어
// ========================
app.use(helmet());
app.use(cors({
  origin: ALLOWED_ORIGINS === '*' ? '*' : ALLOWED_ORIGINS.split(','),
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100, // 100 요청
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// ========================
// 유틸리티 함수
// ========================

// JWT 생성
function generateJWT(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 15 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

// JWT 검증
function verifyJWT(token) {
  try {
    const [header, payload, signature] = token.split('.');
    const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
    if (signature !== expectedSig) return null;
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (decoded.exp < Date.now()) return null;
    return decoded;
  } catch {
    return null;
  }
}

// HMAC 검증
function verifyHMAC(body, timestamp, signature) {
  const expectedSig = crypto.createHmac('sha256', HMAC_SECRET)
    .update(JSON.stringify(body) + timestamp)
    .digest('hex');
  return signature === expectedSig;
}

// 재시도 로직 (Exponential Backoff)
async function retryRequest(fn, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, Math.pow(2, i) * 1000));
    }
  }
}

// ========================
// 미들웨어 - 보안 검증
// ========================
function securityMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  const signature = req.headers['x-app-signature'];
  const timestamp = req.headers['x-timestamp'];

  // JWT 검증
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid JWT token' });
  }
  const token = authHeader.split(' ')[1];
  const decoded = verifyJWT(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid or expired JWT token' });
  }

  // HMAC 검증
  if (!signature || !timestamp) {
    return res.status(401).json({ error: 'Missing HMAC signature or timestamp' });
  }
  if (!verifyHMAC(req.body, timestamp, signature)) {
    return res.status(401).json({ error: 'Invalid HMAC signature' });
  }

  req.user = decoded;
  next();
}

// ========================
// Health Check (Pre-Wake Ping)
// ========================
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: '8.8.5',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/healthz', (req, res) => {
  res.json({
    status: 'healthy',
    version: '8.8.5',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// ========================
// JWT 토큰 발급
// ========================
app.post('/auth/token', (req, res) => {
  const { appId } = req.body;
  if (!appId || appId !== 'cross-verified-ai') {
    return res.status(400).json({ error: 'Invalid appId' });
  }
  const token = generateJWT({ appId, iat: Date.now() });
  res.json({ token, expiresIn: '15m' });
});

// ========================
// Gemini API - 답변 생성
// ========================
app.post('/api/gemini', securityMiddleware, async (req, res) => {
  const { prompt, apiKey } = req.body;

  if (!prompt || !apiKey) {
    return res.status(400).json({ error: 'Missing prompt or apiKey' });
  }

  try {
    const response = await retryRequest(() => 
      axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=${apiKey}`,
        {
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.7,
            maxOutputTokens: 2048
          }
        },
        { timeout: 30000 }
      )
    );

    const text = response.data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    res.json({ 
      success: true, 
      text,
      model: 'gemini-flash-latest'
    });
  } catch (error) {
    const status = error.response?.status || 500;
    const message = error.response?.data?.error?.message || error.message;
    
    res.status(status).json({
      success: false,
      error: message,
      code: status === 429 ? 'RATE_LIMIT' : status === 403 ? 'FORBIDDEN' : 'ERROR'
    });
  }
});

// ========================
// Gemini API - 일치도 평가
// ========================
app.post('/api/gemini/evaluate', securityMiddleware, async (req, res) => {
  const { answer, verificationSources, apiKey } = req.body;

  if (!answer || !verificationSources || !apiKey) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const prompt = `다음 답변과 검증 소스의 일치도를 0~1로 평가하세요:

답변: "${answer}"

검증 소스:
- GDELT: ${JSON.stringify(verificationSources.gdelt)}
- CrossRef: ${JSON.stringify(verificationSources.crossref)}
- OpenAlex: ${JSON.stringify(verificationSources.openalex)}
- Wikidata: ${JSON.stringify(verificationSources.wikidata)}

각 소스별 일치도를 JSON으로만 반환하세요 (다른 설명 없이):
{"gdelt": 0.9, "crossref": 0.8, "openalex": 0.85, "wikidata": 0.7}`;

  try {
    const response = await retryRequest(() =>
      axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=${apiKey}`,
        {
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.3,
            maxOutputTokens: 256
          }
        },
        { timeout: 20000 }
      )
    );

    const text = response.data.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    const matchScores = jsonMatch ? JSON.parse(jsonMatch[0]) : {};

    res.json({
      success: true,
      matchScores,
      raw: text
    });
  } catch (error) {
    const status = error.response?.status || 500;
    res.status(status).json({
      success: false,
      error: error.response?.data?.error?.message || error.message,
      code: status === 429 ? 'RATE_LIMIT' : 'ERROR'
    });
  }
});

// ========================
// Mistral API - Failover
// ========================
app.post('/api/mistral', securityMiddleware, async (req, res) => {
  const { prompt } = req.body;

  if (!prompt) {
    return res.status(400).json({ error: 'Missing prompt' });
  }

  try {
    const response = await retryRequest(() =>
      axios.post(
        'https://api.llama-api.com/chat/completions',
        {
          model: 'mistral-7b-instruct',
          messages: [{ role: 'user', content: prompt }],
          max_tokens: 2048
        },
        { timeout: 30000 }
      )
    );

    const text = response.data.choices?.[0]?.message?.content || '';
    res.json({
      success: true,
      text,
      model: 'mistral-7b-instruct',
      fallback: true
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ========================
// GDELT 검증
// ========================
app.post('/api/verify/gdelt', securityMiddleware, async (req, res) => {
  const { query } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Missing query' });
  }

  try {
    const response = await retryRequest(() =>
      axios.get('https://api.gdeltproject.org/api/v2/doc/doc', {
        params: {
          query,
          mode: 'artlist',
          maxrecords: 10,
          format: 'json'
        },
        timeout: 15000
      })
    );

    const articles = response.data.articles || [];
    const score = Math.min(articles.length / 10, 1);

    res.json({
      success: true,
      engine: 'gdelt',
      score,
      count: articles.length,
      sources: articles.slice(0, 3).map(a => ({
        title: a.title,
        url: a.url,
        date: a.seendate
      }))
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      engine: 'gdelt',
      error: error.message
    });
  }
});

// ========================
// CrossRef 검증
// ========================
app.post('/api/verify/crossref', securityMiddleware, async (req, res) => {
  const { query } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Missing query' });
  }

  try {
    const response = await retryRequest(() =>
      axios.get('https://api.crossref.org/works', {
        params: {
          query,
          rows: 10
        },
        timeout: 15000
      })
    );

    const items = response.data.message.items || [];
    const score = Math.min(items.length / 10, 1);

    res.json({
      success: true,
      engine: 'crossref',
      score,
      count: items.length,
      sources: items.slice(0, 3).map(i => ({
        title: i.title?.[0] || 'N/A',
        doi: i.DOI,
        publisher: i.publisher
      }))
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      engine: 'crossref',
      error: error.message
    });
  }
});

// ========================
// OpenAlex 검증
// ========================
app.post('/api/verify/openalex', securityMiddleware, async (req, res) => {
  const { query } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Missing query' });
  }

  try {
    const response = await retryRequest(() =>
      axios.get('https://api.openalex.org/works', {
        params: {
          search: query,
          per_page: 10
        },
        timeout: 15000
      })
    );

    const results = response.data.results || [];
    const score = Math.min(results.length / 10, 1);

    res.json({
      success: true,
      engine: 'openalex',
      score,
      count: results.length,
      sources: results.slice(0, 3).map(r => ({
        title: r.title,
        doi: r.doi,
        citations: r.cited_by_count
      }))
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      engine: 'openalex',
      error: error.message
    });
  }
});

// ========================
// Wikidata 검증
// ========================
app.post('/api/verify/wikidata', securityMiddleware, async (req, res) => {
  const { query } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Missing query' });
  }

  try {
    const response = await retryRequest(() =>
      axios.get('https://www.wikidata.org/w/api.php', {
        params: {
          action: 'wbsearchentities',
          search: query,
          language: 'en',
          limit: 10,
          format: 'json'
        },
        timeout: 15000
      })
    );

    const results = response.data.search || [];
    const score = Math.min(results.length / 10, 1);

    res.json({
      success: true,
      engine: 'wikidata',
      score,
      count: results.length,
      sources: results.slice(0, 3).map(r => ({
        label: r.label,
        description: r.description,
        id: r.id
      }))
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      engine: 'wikidata',
      error: error.message
    });
  }
});

// ========================
// TruthScore 계산 (ECC 보정 포함)
// ========================
app.post('/api/verify/truthscore', securityMiddleware, async (req, res) => {
  const { results, matchScores } = req.body;

  if (!results) {
    return res.status(400).json({ error: 'Missing results' });
  }

  // 초기 가중치
  const weights = {
    gdelt: 0.9,
    crossref: 1.0,
    openalex: 1.0,
    wikidata: 0.8
  };

  // 활성 엔진 필터링
  const activeEngines = Object.keys(results).filter(key => results[key]?.success);
  
  if (activeEngines.length === 0) {
    return res.json({
      truthScore: 0.0,
      activeEngines: [],
      backupUsed: true,
      status: 'no_verification',
      ecc: 0
    });
  }

  // 가중치 정규화
  const totalWeight = activeEngines.reduce((sum, key) => sum + weights[key], 0);
  const normalizedWeights = {};
  activeEngines.forEach(key => {
    normalizedWeights[key] = weights[key] / totalWeight;
  });

  // TruthScore 계산
  const lambda = 0.03;
  const alpha = 0.5;
  let rawScore = 0;

  activeEngines.forEach(key => {
    const R_i = matchScores?.[key] || 0.5; // 일치도 (기본값 0.5)
    const Q_i = results[key].score || 0.5; // 검증 엔진 점수
    const t = 0; // 시간 감쇠 (현재는 0)
    
    const score_i = R_i * Q_i * Math.exp(-lambda * t);
    rawScore += normalizedWeights[key] * score_i;
  });

  // ECC 보정
  const eccRatio = activeEngines.length / 4; // 전체 엔진 4개
  const C_ecc = Math.pow(eccRatio, alpha);
  const truthScore = Math.min(rawScore * C_ecc, 1.0);

  res.json({
    truthScore: parseFloat(truthScore.toFixed(3)),
    rawScore: parseFloat(rawScore.toFixed(3)),
    ecc: parseFloat(C_ecc.toFixed(3)),
    activeEngines,
    normalizedWeights,
    backupUsed: activeEngines.length < 4,
    status: activeEngines.length === 4 ? 'full_verification' : 'partial_verification'
  });
});

// ========================
// 서버 시작
// ========================
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy v8.8.5 running on port ${PORT}`);
  console.log(`📘 Health Check: http://localhost:${PORT}/health`);
  console.log(`🔒 Security: JWT + HMAC-SHA256 enabled`);
});