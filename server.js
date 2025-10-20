/**
 * Cross-Verified AI Server v8.8.8
 * 단일 파일 버전 - 테스트 및 배포용
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import axios from 'axios';
import dotenv from 'dotenv';
import pg from 'pg';

dotenv.config();

const { Pool } = pg;
const app = express();
const PORT = process.env.PORT || 3000;

// ==================== 환경변수 검증 ====================
if (!process.env.JWT_SECRET) {
  console.error('❌ ERROR: JWT_SECRET environment variable is required!');
  process.exit(1);
}

if (!process.env.HMAC_SECRET) {
  console.error('❌ ERROR: HMAC_SECRET environment variable is required!');
  process.exit(1);
}

if (!process.env.ENCRYPTION_KEY) {
  console.error('❌ ERROR: ENCRYPTION_KEY environment variable is required!');
  console.error('   Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

// ==================== 설정 ====================
const config = {
  jwtSecret: process.env.JWT_SECRET,
  hmacSecret: process.env.HMAC_SECRET,
  encryptionKey: Buffer.from(process.env.ENCRYPTION_KEY, 'hex'),
  databaseUrl: process.env.DATABASE_URL,
  geminiKeys: [
    process.env.GEMINI_KEY_1,
    process.env.GEMINI_KEY_2,
    process.env.GEMINI_KEY_3
  ].filter(Boolean),
  geminiModel: 'gemini-1.5-flash-latest',
  dailyLimit: 1500
};

// ==================== PostgreSQL 연결 ====================
let pool = null;

if (config.databaseUrl) {
  pool = new Pool({
    connectionString: config.databaseUrl,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
  
  console.log('✅ PostgreSQL connection configured');
} else {
  console.warn('⚠️  DATABASE_URL not set. Keys will be stored in memory only.');
}

// ==================== 암호화/복호화 ====================
function encryptData(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', config.encryptionKey, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted,
    authTag: authTag.toString('hex')
  };
}

function decryptData(encrypted) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    config.encryptionKey,
    Buffer.from(encrypted.iv, 'hex')
  );
  
  decipher.setAuthTag(Buffer.from(encrypted.authTag, 'hex'));
  
  let decrypted = decipher.update(encrypted.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// ==================== DB 초기화 ====================
async function initializeDatabase() {
  if (!pool) return;
  
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_keys (
        id SERIAL PRIMARY KEY,
        client_id VARCHAR(255) UNIQUE NOT NULL,
        encrypted_keys TEXT NOT NULL,
        iv VARCHAR(64) NOT NULL,
        auth_tag VARCHAR(64) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('✅ Database table initialized');
  } catch (error) {
    console.error('❌ Database initialization error:', error.message);
  }
}

// 서버 시작 시 DB 초기화
if (pool) {
  initializeDatabase().catch(console.error);
}

// ==================== Gemini 키 관리자 ====================
class KeyManager {
  constructor() {
    this.keys = config.geminiKeys.map((key, index) => ({
      id: index,
      key: key,
      requestCount: 0,
      status: 'active', // active, limited, exhausted, waiting
      lastResetTime: new Date().setUTCHours(0, 0, 0, 0),
      nextRetryTime: null,
      failCount: 0
    }));
    
    this.currentIndex = 0;
  }
  
  getCurrentKey() {
    const key = this.keys[this.currentIndex];
    
    if (!key || key.status === 'exhausted' || key.status === 'waiting') {
      this.rotateToNextKey();
      return this.getCurrentKey();
    }
    
    return key;
  }
  
  rotateToNextKey() {
    const startIndex = this.currentIndex;
    
    do {
      this.currentIndex = (this.currentIndex + 1) % this.keys.length;
      const key = this.keys[this.currentIndex];
      
      if (key.status === 'active') {
        console.log(`🔁 Key ${this.currentIndex} 로 전환`);
        return key;
      }
      
      if (this.currentIndex === startIndex) {
        console.warn('🚫 모든 Gemini 키 소진');
        return null;
      }
    } while (true);
  }
  
  recordSuccess(keyId) {
    const key = this.keys[keyId];
    if (key) {
      key.requestCount++;
      key.failCount = 0;
      
      const usage = key.requestCount / config.dailyLimit;
      if (usage >= 0.9) key.status = 'limited';
      if (usage >= 1.0) key.status = 'exhausted';
    }
  }
  
  recordFailure(keyId, errorType) {
    const key = this.keys[keyId];
    if (!key) return;
    
    key.failCount++;
    
    if (errorType === 429 || errorType === 403) {
      key.status = 'exhausted';
      console.warn(`⚠️ Key ${keyId} 제한 (${errorType})`);
      this.rotateToNextKey();
    }
  }
  
  getAllKeysStatus() {
    return this.keys.map(key => ({
      id: key.id,
      status: key.status,
      requestCount: key.requestCount,
      usage: (key.requestCount / config.dailyLimit * 100).toFixed(1) + '%',
      remaining: Math.max(0, config.dailyLimit - key.requestCount),
      failCount: key.failCount
    }));
  }
  
  isVerifyOnlyMode() {
    return this.keys.every(key => 
      key.status === 'exhausted' || key.status === 'waiting'
    );
  }
}

const keyManager = new KeyManager();

// ==================== 사용자별 키 관리 ====================
// 메모리 캐시 (빠른 접근)
const userKeysCache = new Map();

// DB에 사용자 키 저장 (암호화)
async function saveUserKeysToDb(clientId, keys) {
  if (!pool) {
    // DB 없으면 메모리만 사용
    return;
  }
  
  try {
    const keysJson = JSON.stringify(keys);
    const encrypted = encryptData(keysJson);
    
    await pool.query(`
      INSERT INTO user_keys (client_id, encrypted_keys, iv, auth_tag, updated_at)
      VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
      ON CONFLICT (client_id)
      DO UPDATE SET
        encrypted_keys = $2,
        iv = $3,
        auth_tag = $4,
        updated_at = CURRENT_TIMESTAMP
    `, [clientId, encrypted.encryptedData, encrypted.iv, encrypted.authTag]);
    
    console.log(`✅ Keys saved to DB for client: ${clientId}`);
  } catch (error) {
    console.error('❌ Error saving keys to DB:', error.message);
    throw error;
  }
}

// DB에서 사용자 키 불러오기 (복호화)
async function loadUserKeysFromDb(clientId) {
  if (!pool) {
    return null;
  }
  
  try {
    const result = await pool.query(
      'SELECT encrypted_keys, iv, auth_tag FROM user_keys WHERE client_id = $1',
      [clientId]
    );
    
    if (result.rows.length === 0) {
      return null;
    }
    
    const row = result.rows[0];
    const decrypted = decryptData({
      encryptedData: row.encrypted_keys,
      iv: row.iv,
      authTag: row.auth_tag
    });
    
    const keys = JSON.parse(decrypted);
    console.log(`✅ Keys loaded from DB for client: ${clientId}`);
    return keys;
  } catch (error) {
    console.error('❌ Error loading keys from DB:', error.message);
    return null;
  }
}

// 사용자 키 설정
async function setUserKeys(clientId, keys) {
  const validKeys = keys.filter(k => k && k.trim().length > 0);
  
  if (validKeys.length === 0) {
    throw new Error('At least one valid key is required');
  }
  
  const keyData = {
    keys: validKeys,
    currentIndex: 0,
    requestCounts: validKeys.map(() => 0),
    createdAt: Date.now()
  };
  
  // 메모리 캐시에 저장
  userKeysCache.set(clientId, keyData);
  
  // DB에 암호화해서 저장
  try {
    await saveUserKeysToDb(clientId, validKeys);
  } catch (error) {
    console.warn('⚠️  Failed to save to DB, using memory only');
  }
  
  return validKeys.length;
}

// 사용자 키 가져오기
async function getUserKeys(clientId) {
  // 먼저 메모리 캐시 확인
  let keyData = userKeysCache.get(clientId);
  
  if (keyData) {
    return keyData;
  }
  
  // 캐시에 없으면 DB에서 불러오기
  const keysFromDb = await loadUserKeysFromDb(clientId);
  
  if (keysFromDb) {
    keyData = {
      keys: keysFromDb,
      currentIndex: 0,
      requestCounts: keysFromDb.map(() => 0),
      createdAt: Date.now()
    };
    
    // 캐시에 저장
    userKeysCache.set(clientId, keyData);
    return keyData;
  }
  
  return null;
}

// 사용자 키로 Gemini 호출
async function callGeminiWithUserKey(clientId, prompt) {
  const userKeyData = await getUserKeys(clientId);
  
  if (!userKeyData) {
    throw new Error('No keys configured. Please set your Gemini API keys first.');
  }
  
  const { keys, currentIndex, requestCounts } = userKeyData;
  const apiKey = keys[currentIndex];
  
  try {
    const answer = await callGeminiAPI(apiKey, prompt);
    
    // 성공 시 카운트 증가
    requestCounts[currentIndex]++;
    userKeysCache.set(clientId, { ...userKeyData, requestCounts });
    
    return {
      success: true,
      answer,
      keyIndex: currentIndex
    };
  } catch (error) {
    // 실패 시 다음 키로 로테이션
    if (error.response && (error.response.status === 429 || error.response.status === 403)) {
      console.warn(`⚠️ User ${clientId} Key ${currentIndex} failed with ${error.response.status}`);
      
      // 다음 키로 전환
      const nextIndex = (currentIndex + 1) % keys.length;
      userKeysCache.set(clientId, { ...userKeyData, currentIndex: nextIndex });
      
      // 한 번 더 시도
      if (nextIndex !== currentIndex) {
        return callGeminiWithUserKey(clientId, prompt);
      }
    }
    
    throw error;
  }
}

// ==================== TruthScore 계산기 ====================
class TruthScoreCalculator {
  constructor() {
    this.weights = {
      gdelt: 0.9,
      crossref: 1.0,
      openalex: 1.0,
      wikidata: 0.8,
      mistral: 0.1
    };
    this.lambda = 0.03;
    
    // 가중치 정규화
    const engines = ['gdelt', 'crossref', 'openalex', 'wikidata'];
    const sum = engines.reduce((acc, e) => acc + this.weights[e], 0);
    this.normalizedWeights = {};
    engines.forEach(e => {
      this.normalizedWeights[e] = this.weights[e] / sum;
    });
  }
  
  calculate(results, hasGeminiResponse = true, mistralExist = false) {
    let totalScore = 0;
    const activeEngines = [];
    
    for (const [engine, result] of Object.entries(results)) {
      if (!result.ok || !this.normalizedWeights[engine]) continue;
      
      const w = this.normalizedWeights[engine];
      const Q = result.score || 0;
      const R = result.reliability || 1.0;
      const t = result.recency || 0;
      
      const timeDecay = Math.exp(-this.lambda * t);
      
      let contribution;
      if (hasGeminiResponse) {
        contribution = w * Q * R * timeDecay;
      } else {
        contribution = w * Q * timeDecay;
      }
      
      totalScore += contribution;
      activeEngines.push(engine);
    }
    
    // Mistral Exist 보정
    if (!hasGeminiResponse && mistralExist) {
      totalScore += this.weights.mistral;
    }
    
    // Clamping: 1.0 이하로 제한
    const truthScore = Math.min(1.0, totalScore);
    
    return {
      truthScore: parseFloat(truthScore.toFixed(3)),
      truthScore_raw: parseFloat(totalScore.toFixed(3)),
      truthScore_final: parseFloat(truthScore.toFixed(3)),
      activeEngines,
      mistralBoost: (!hasGeminiResponse && mistralExist) ? this.weights.mistral : 0,
      mode: hasGeminiResponse ? 'normal' : 'verify_only'
    };
  }
}

const truthScoreCalculator = new TruthScoreCalculator();

// ==================== 미들웨어 ====================
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100,
  message: { success: false, error: 'Rate limit exceeded' }
});

app.use('/api', limiter);

// 요청 로깅
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ==================== JWT 유틸리티 ====================
function generateToken(payload = {}) {
  return jwt.sign(
    {
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      version: '8.8.8'
    },
    config.jwtSecret,
    { expiresIn: '15m' }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, config.jwtSecret);
  } catch (error) {
    return null;
  }
}

// JWT 인증 미들웨어
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Missing or invalid Authorization header'
    });
  }
  
  const token = authHeader.substring(7);
  const decoded = verifyToken(token);
  
  if (!decoded) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired token'
    });
  }
  
  req.user = decoded;
  next();
}

// ==================== Gemini API ====================
async function callGeminiAPI(apiKey, prompt) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${config.geminiModel}:generateContent?key=${apiKey}`;
  
  const response = await axios.post(
    url,
    {
      contents: [{
        parts: [{ text: prompt }]
      }]
    },
    { timeout: 30000 }
  );
  
  const text = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
  
  if (!text) {
    throw new Error('Invalid Gemini API response');
  }
  
  return text;
}

async function generateAnswer(question, maxRetries = 1) {
  let lastError = null;
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const key = keyManager.getCurrentKey();
      
      if (!key) {
        return {
          success: false,
          error: 'All Gemini keys exhausted',
          mode: 'verify_only'
        };
      }
      
      const answer = await callGeminiAPI(key.key, question);
      
      keyManager.recordSuccess(key.id);
      
      return {
        success: true,
        answer,
        keyId: key.id,
        model: config.geminiModel
      };
      
    } catch (error) {
      lastError = error;
      const key = keyManager.getCurrentKey();
      
      if (error.response) {
        const status = error.response.status;
        
        if (status === 429 || status === 403) {
          console.warn(`⚠️ Key ${key?.id} 에러 ${status}`);
          keyManager.recordFailure(key?.id, status);
          
          if (attempt < maxRetries) continue;
        }
      }
      
      if (attempt < maxRetries) {
        keyManager.rotateToNextKey();
        continue;
      }
    }
  }
  
  return {
    success: false,
    error: lastError?.message || 'Gemini API call failed',
    statusCode: lastError?.response?.status
  };
}

// ==================== 검증 엔진 ====================
async function verifyWithGDELT(query) {
  try {
    const response = await axios.get('https://api.gdeltproject.org/api/v2/doc/doc', {
      params: {
        query: query,
        mode: 'artlist',
        maxrecords: 10,
        format: 'json'
      },
      timeout: 10000
    });
    
    const articles = response.data?.articles || [];
    
    if (articles.length === 0) {
      return { ok: false, score: 0, sources: [] };
    }
    
    const score = Math.min(1.0, articles.length / 10) * 0.9;
    
    return {
      ok: true,
      score: parseFloat(score.toFixed(3)),
      sources: articles.slice(0, 3).map(a => ({
        title: a.title,
        url: a.url
      })),
      count: articles.length
    };
  } catch (error) {
    console.error('❌ GDELT 에러:', error.message);
    return { ok: false, score: 0, error: error.message };
  }
}

async function verifyWithCrossRef(query) {
  try {
    const response = await axios.get('https://api.crossref.org/works', {
      params: {
        query: query,
        rows: 10
      },
      timeout: 10000
    });
    
    const items = response.data?.message?.items || [];
    
    if (items.length === 0) {
      return { ok: false, score: 0, sources: [] };
    }
    
    const score = Math.min(1.0, items.length / 10) * 1.0;
    
    return {
      ok: true,
      score: parseFloat(score.toFixed(3)),
      sources: items.slice(0, 3).map(i => ({
        doi: i.DOI,
        title: i.title?.[0] || 'Untitled'
      })),
      count: items.length
    };
  } catch (error) {
    console.error('❌ CrossRef 에러:', error.message);
    return { ok: false, score: 0, error: error.message };
  }
}

async function verifyWithOpenAlex(query) {
  try {
    const response = await axios.get('https://api.openalex.org/works', {
      params: {
        search: query,
        per_page: 10
      },
      timeout: 10000
    });
    
    const results = response.data?.results || [];
    
    if (results.length === 0) {
      return { ok: false, score: 0, sources: [] };
    }
    
    const score = Math.min(1.0, results.length / 10) * 1.0;
    
    return {
      ok: true,
      score: parseFloat(score.toFixed(3)),
      sources: results.slice(0, 3).map(w => ({
        id: w.id,
        title: w.title || 'Untitled'
      })),
      count: results.length
    };
  } catch (error) {
    console.error('❌ OpenAlex 에러:', error.message);
    return { ok: false, score: 0, error: error.message };
  }
}

async function verifyWithWikidata(query) {
  try {
    const response = await axios.get('https://www.wikidata.org/w/api.php', {
      params: {
        action: 'wbsearchentities',
        search: query,
        language: 'en',
        limit: 10,
        format: 'json',
        origin: '*'
      },
      timeout: 10000
    });
    
    const entities = response.data?.search || [];
    
    if (entities.length === 0) {
      return { ok: false, score: 0, sources: [] };
    }
    
    const score = Math.min(1.0, entities.length / 10) * 0.8;
    
    return {
      ok: true,
      score: parseFloat(score.toFixed(3)),
      sources: entities.slice(0, 3).map(e => ({
        id: e.id,
        label: e.label || 'Unlabeled'
      })),
      count: entities.length
    };
  } catch (error) {
    console.error('❌ Wikidata 에러:', error.message);
    return { ok: false, score: 0, error: error.message };
  }
}

// ==================== 라우트 ====================

// Health Check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    version: '8.8.8',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/healthz', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    version: '8.8.8'
  });
});

// 상태 정보
app.get('/status', (req, res) => {
  const keysStatus = keyManager.getAllKeysStatus();
  const verifyOnlyMode = keyManager.isVerifyOnlyMode();
  
  res.json({
    success: true,
    version: '8.8.8',
    server: {
      uptime: process.uptime(),
      memory: process.memoryUsage()
    },
    gemini: {
      keys: keysStatus,
      verifyOnlyMode
    }
  });
});

// JWT 토큰 발급
app.post('/api/auth/token', (req, res) => {
  try {
    const { clientId } = req.body;
    
    const token = generateToken({
      clientId: clientId || 'anonymous'
    });
    
    res.json({
      success: true,
      token,
      expiresIn: '15m'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// 사용자 Gemini 키 설정
app.post('/api/config/keys', authenticateJWT, async (req, res) => {
  try {
    const { keys } = req.body;
    const clientId = req.user.clientId;
    
    if (!keys || !Array.isArray(keys)) {
      return res.status(400).json({
        success: false,
        error: 'Keys must be an array'
      });
    }
    
    const keyCount = await setUserKeys(clientId, keys);
    
    res.json({
      success: true,
      message: `${keyCount} key(s) configured and encrypted successfully`,
      keyCount,
      encrypted: true,
      storage: pool ? 'database' : 'memory'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// 사용자 키 상태 조회
app.get('/api/config/keys', authenticateJWT, async (req, res) => {
  try {
    const clientId = req.user.clientId;
    const userKeyData = await getUserKeys(clientId);
    
    if (!userKeyData) {
      return res.json({
        success: true,
        configured: false,
        message: 'No keys configured'
      });
    }
    
    res.json({
      success: true,
      configured: true,
      keyCount: userKeyData.keys.length,
      currentIndex: userKeyData.currentIndex,
      requestCounts: userKeyData.requestCounts,
      totalRequests: userKeyData.requestCounts.reduce((a, b) => a + b, 0),
      encrypted: true,
      storage: pool ? 'database' : 'memory'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Gemini 키 상태
app.get('/api/gemini/keys', (req, res) => {
  const keysStatus = keyManager.getAllKeysStatus();
  const verifyOnlyMode = keyManager.isVerifyOnlyMode();
  
  res.json({
    success: true,
    keys: keysStatus,
    verifyOnlyMode,
    currentIndex: keyManager.currentIndex
  });
});

// Gemini 답변 생성
app.post('/api/gemini/generate', authenticateJWT, async (req, res) => {
  try {
    const { question } = req.body;
    const clientId = req.user.clientId;
    
    if (!question) {
      return res.status(400).json({
        success: false,
        error: 'Missing question'
      });
    }
    
    // 사용자 키 확인
    const userKeyData = await getUserKeys(clientId);
    
    if (!userKeyData) {
      return res.status(400).json({
        success: false,
        error: 'No Gemini API keys configured. Please set your keys first.',
        needsConfig: true
      });
    }
    
    const result = await callGeminiWithUserKey(clientId, question);
    
    res.json({
      ...result,
      model: config.geminiModel
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// 검증 엔진 실행
app.post('/api/verify/engines', async (req, res) => {
  try {
    const { query } = req.body;
    
    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Missing query'
      });
    }
    
    const [gdeltResult, crossrefResult, openalexResult, wikidataResult] = await Promise.all([
      verifyWithGDELT(query),
      verifyWithCrossRef(query),
      verifyWithOpenAlex(query),
      verifyWithWikidata(query)
    ]);
    
    res.json({
      success: true,
      results: {
        gdelt: gdeltResult,
        crossref: crossrefResult,
        openalex: openalexResult,
        wikidata: wikidataResult
      }
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// TruthScore 계산
app.post('/api/verify/truthscore', async (req, res) => {
  try {
    const { results, mistralExist } = req.body;
    
    if (!results) {
      return res.status(400).json({
        success: false,
        error: 'Missing results'
      });
    }
    
    const truthScoreResult = truthScoreCalculator.calculate(
      results,
      true,
      mistralExist || false
    );
    
    res.json({
      success: true,
      ...truthScoreResult
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// 전체 검증 프로세스
app.post('/api/verify/question', authenticateJWT, async (req, res) => {
  try {
    const { question } = req.body;
    const clientId = req.user.clientId;
    
    if (!question) {
      return res.status(400).json({
        success: false,
        error: 'Missing question'
      });
    }
    
    console.log(`\n🔍 새 질문 (User: ${clientId}): "${question}"`);
    
    // 1. Gemini 답변 생성 (사용자 키 사용)
    console.log('📝 Gemini 답변 생성 중...');
    let answerResult = { success: false };
    
    const userKeyData = await getUserKeys(clientId);
    
    if (userKeyData) {
      try {
        answerResult = await callGeminiWithUserKey(clientId, question);
      } catch (error) {
        console.warn('⚠️ Gemini 호출 실패:', error.message);
        answerResult = {
          success: false,
          error: error.message
        };
      }
    } else {
      answerResult = {
        success: false,
        error: 'No Gemini API keys configured',
        needsConfig: true
      };
    }
    
    // 2. 병렬 검증
    console.log('🔎 검증 엔진 실행 중...');
    const [gdeltResult, crossrefResult, openalexResult, wikidataResult] = await Promise.all([
      verifyWithGDELT(question),
      verifyWithCrossRef(question),
      verifyWithOpenAlex(question),
      verifyWithWikidata(question)
    ]);
    
    const verificationResults = {
      gdelt: gdeltResult,
      crossref: crossrefResult,
      openalex: openalexResult,
      wikidata: wikidataResult
    };
    
    // 3. TruthScore 계산
    console.log('📊 TruthScore 계산 중...');
    const truthScoreResult = truthScoreCalculator.calculate(
      verificationResults,
      answerResult.success,
      false
    );
    
    // 4. 응답 생성
    const response = {
      success: true,
      question,
      answer: answerResult.success ? answerResult.answer : null,
      gemini: {
        success: answerResult.success,
        keyIndex: answerResult.keyIndex,
        model: config.geminiModel,
        error: answerResult.error,
        needsConfig: answerResult.needsConfig
      },
      verification: {
        gdelt: {
          ok: gdeltResult.ok,
          score: gdeltResult.score,
          count: gdeltResult.count,
          sources: gdeltResult.sources?.slice(0, 3)
        },
        crossref: {
          ok: crossrefResult.ok,
          score: crossrefResult.score,
          count: crossrefResult.count,
          sources: crossrefResult.sources?.slice(0, 3)
        },
        openalex: {
          ok: openalexResult.ok,
          score: openalexResult.score,
          count: openalexResult.count,
          sources: openalexResult.sources?.slice(0, 3)
        },
        wikidata: {
          ok: wikidataResult.ok,
          score: wikidataResult.score,
          count: wikidataResult.count,
          sources: wikidataResult.sources?.slice(0, 3)
        }
      },
      truthScore: truthScoreResult.truthScore_final,
      truthScoreDetails: truthScoreResult,
      timestamp: new Date().toISOString()
    };
    
    console.log(`✅ 완료! TruthScore: ${truthScoreResult.truthScore_final}`);
    
    res.json(response);
    
  } catch (error) {
    console.error('❌ Verify 에러:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// 404 핸들러
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not Found'
  });
});

// 에러 핸들러
app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error'
  });
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   🚀 Cross-Verified AI Server v8.8.9                 ║
║                                                       ║
║   🌐 Server running on port ${PORT}                     ║
║   🔑 Gemini Keys: ${config.geminiKeys.length} loaded (server keys)         ║
║   🔐 Encryption: AES-256-GCM Enabled                  ║
║   💾 Database: ${pool ? 'PostgreSQL Connected' : 'Memory Only'}              ║
║   🛡️  Security: JWT + HMAC + Rate Limiter            ║
║                                                       ║
║   Endpoints:                                          ║
║   • GET  /health                                      ║
║   • GET  /healthz                                     ║
║   • GET  /status                                      ║
║   • POST /api/auth/token                              ║
║   • POST /api/config/keys (User Keys - Encrypted)    ║
║   • GET  /api/config/keys                             ║
║   • POST /api/verify/question                         ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
  `);
});

export default app;
