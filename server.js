const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// 모듈 import
const geminiEngine = require('./proxy-server/src/engine/gemini');
const verificationEngine = require('./proxy-server/src/engine/verification');
const truthScoreEngine = require('./proxy-server/src/engine/truthscore');
const cryptoUtils = require('./utils/crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어 설정
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100, // 최대 100 요청
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// 엔진 상태 저장 (실제로는 데이터베이스 사용)
const engineStates = new Map();

/**
 * 서버 상태 확인 (Ping)
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

    if (!apiKey) {
      return res.status(400).json({ error: 'API key is required' });
    }

    if (!prompt) {
      return res.status(400).json({ error: 'Prompt is required' });
    }

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

    if (!apiKey || !text) {
      return res.status(400).json({ error: 'API key and text are required' });
    }

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

    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }

    let result;
    switch (engine) {
      case 'crossref':
        result = await verificationEngine.verifyCrossRef(query);
        break;
      case 'openalex':
        result = await verificationEngine.verifyOpenAlex(query);
        break;
      case 'gdelt':
        result = await verificationEngine.verifyGDELT(query);
        break;
      case 'wikidata':
        result = await verificationEngine.verifyWikidata(query);
        break;
      case 'github':
        result = await verificationEngine.verifyGitHub(query, apiKey);
        break;
      case 'klaw':
        result = await verificationEngine.verifyKLaw(query, apiKey);
        break;
      default:
        return res.status(400).json({ error: 'Invalid engine name' });
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

    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }

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

    if (!engines || !Array.isArray(engines)) {
      return res.status(400).json({ error: 'Engines array is required' });
    }

    const result = truthScoreEngine.calculateTruthScore(engines);
    res.json(result);
  } catch (error) {
    console.error('TruthScore calculation error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 통합 검증 및 신뢰도 계산
 */
app.post('/api/cross-verify', async (req, res) => {
  try {
    const { 
      query, 
      geminiApiKey, 
      geminiModel = 'flash',
      apiKeys = {},
      generateAnswer = true 
    } = req.body;

    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }

    if (!geminiApiKey) {
      return res.status(400).json({ error: 'Gemini API key is required' });
    }

    const startTime = Date.now();
    let answer = null;
    let keywords = [];

    // 1. Gemini로 답변 생성 (선택)
    if (generateAnswer) {
      const geminiResponse = await geminiEngine.callGemini({
        apiKey: geminiApiKey,
        model: geminiModel,
        prompt: query,
        temperature: 0.7,
        maxTokens: 2048
      });

      if (geminiResponse.success) {
        answer = geminiResponse.text;
        
        // 2. 키워드 추출
        const keywordResult = await geminiEngine.extractKeywords(answer, geminiApiKey);
        if (keywordResult.success) {
          keywords = keywordResult.keywords;
        }
      } else {
        return res.status(500).json({
          error: 'Failed to generate answer',
          details: geminiResponse.error
        });
      }
    } else {
      // 답변 생성 없이 쿼리로 직접 검증
      const keywordResult = await geminiEngine.extractKeywords(query, geminiApiKey);
      if (keywordResult.success) {
        keywords = keywordResult.keywords;
      }
    }

    // 3. 검증 엔진 실행 (키워드 기반)
    const verificationQuery = keywords.slice(0, 5).join(' ') || query;
    const verificationResults = await verificationEngine.verifyAll(verificationQuery, apiKeys);

    if (!verificationResults.success) {
      return res.status(500).json({
        error: 'Verification failed',
        details: verificationResults.error
      });
    }

    // 4. 각 엔진별 검증가능성 계산
    const engines = [];
    for (const [engineName, engineResult] of Object.entries(verificationResults.results)) {
      if (engineResult.success && engineResult.sourceDetected) {
        // 키워드 매칭 점수 계산 (간단한 버전)
        const keywordMatch = calculateKeywordMatch(keywords, engineResult.sources);
        
        engines.push({
          name: engineName,
          isActive: true,
          sourceDetected: true,
          quality: engineResult.quality,
          keywordMatch: keywordMatch,
          sources: engineResult.sources,
          count: engineResult.count,
          weight: truthScoreEngine.INITIAL_WEIGHTS[engineName] || 1.0,
          deltaW: truthScoreEngine.DELTA_W_INITIAL,
          timeDelta: 0
        });
      } else {
        engines.push({
          name: engineName,
          isActive: false,
          sourceDetected: false,
          quality: engineResult.quality,
          keywordMatch: 0,
          sources: [],
          count: 0,
          weight: truthScoreEngine.INITIAL_WEIGHTS[engineName] || 1.0,
          deltaW: truthScoreEngine.DELTA_W_INITIAL,
          timeDelta: 0
        });
      }
    }

    // 5. TruthScore 계산
    const truthScoreResult = truthScoreEngine.calculateTruthScore(engines);

    const endTime = Date.now();
    const totalDuration = endTime - startTime;

    res.json({
      success: true,
      query: query,
      answer: answer,
      keywords: keywords,
      verification: verificationResults,
      truthScore: truthScoreResult,
      engines: engines,
      metadata: {
        duration: `${totalDuration}ms`,
        timestamp: new Date().toISOString(),
        model: geminiModel
      }
    });

  } catch (error) {
    console.error('Cross-verification error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 키워드 매칭 점수 계산 (간단한 버전)
 */
function calculateKeywordMatch(keywords, sources) {
  if (!keywords || keywords.length === 0 || !sources || sources.length === 0) {
    return 0.5;
  }

  const sourceText = sources.map(s => 
    `${s.title || ''} ${s.description || ''} ${s.label || ''}`
  ).join(' ').toLowerCase();

  let matchCount = 0;
  keywords.forEach(keyword => {
    if (sourceText.includes(keyword.toLowerCase())) {
      matchCount++;
    }
  });

  const matchScore = matchCount / keywords.length;
  return Math.min(1.0, Math.max(0.3, matchScore)); // 0.3 ~ 1.0 범위
}

/**
 * API Key 암호화
 */
app.post('/api/keys/encrypt', async (req, res) => {
  try {
    const { plaintext, masterPassword } = req.body;

    if (!plaintext || !masterPassword) {
      return res.status(400).json({ error: 'Plaintext and master password are required' });
    }

    const encrypted = cryptoUtils.encryptKey(plaintext, masterPassword);
    res.json({ success: true, encrypted });
  } catch (error) {
    console.error('Encryption error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * API Key 복호화
 */
app.post('/api/keys/decrypt', async (req, res) => {
  try {
    const { encryptedData, masterPassword } = req.body;

    if (!encryptedData || !masterPassword) {
      return res.status(400).json({ error: 'Encrypted data and master password are required' });
    }

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

    if (!apiKey) {
      return res.status(400).json({ error: 'API key is required' });
    }

    const result = await geminiEngine.validateApiKey(apiKey);
    res.json(result);
  } catch (error) {
    console.error('Validation error:', error);
    res.status(500).json({ error: error.message });
  }
});
// ✅ Render Health Check
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});
/**
 * 404 핸들러
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


// 서버 시작
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║   Cross-Verified AI Proxy Server v9.7.7                  ║
║   Server running on http://localhost:${PORT}               ║
╚══════════════════════════════════════════════════════════╝
  `);
  console.log('Available endpoints:');
  console.log('  GET  /ping');
  console.log('  POST /api/gemini/generate');
  console.log('  POST /api/gemini/extract-keywords');
  console.log('  POST /api/verify/:engine');
  console.log('  POST /api/verify/all');
  console.log('  POST /api/truthscore/calculate');
  console.log('  POST /api/cross-verify');
  console.log('  POST /api/keys/encrypt');
  console.log('  POST /api/keys/decrypt');
  console.log('  POST /api/keys/validate');
  console.log('');
});

module.exports = app;
