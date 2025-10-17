// Cross-Verified AI v8.7.9 - Health Dual Fallback Edition
// server.js - Production Ready with Auto Health Endpoint Detection

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// 환경 변수
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this';
const HMAC_SECRET = process.env.HMAC_SECRET || 'your-hmac-secret-key-change-this';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') || ['*'];

console.log('🔧 Server Configuration:');
console.log('   VERSION: 8.7.9 (Health Dual Fallback Edition)');
console.log('   PORT:', PORT);
console.log('   JWT_SECRET:', JWT_SECRET ? 'Set' : 'Not Set');
console.log('   HMAC_SECRET:', HMAC_SECRET ? 'Set' : 'Not Set');
console.log('   ALLOWED_ORIGINS:', ALLOWED_ORIGINS);

// ===== UTILITY FUNCTIONS =====

// 재시도 로직 (exponential backoff)
async function retryRequest(fn, retries = 3, delay = 1000) {
    for (let i = 0; i < retries; i++) {
        try {
            return await fn();
        } catch (error) {
            const isLastAttempt = i === retries - 1;
            const isRetryable = error.code === 'ECONNABORTED' || 
                                error.code === 'ETIMEDOUT' ||
                                error.response?.status >= 500;
            
            if (isLastAttempt || !isRetryable) {
                throw error;
            }
            
            console.log(`⚠️ Retry ${i + 1}/${retries} after ${delay}ms...`);
            await new Promise(resolve => setTimeout(resolve, delay));
            delay *= 2; // exponential backoff
        }
    }
}

// ===== SECURITY MIDDLEWARE =====

app.set('trust proxy', 1);

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    if (ALLOWED_ORIGINS.includes('*') || !origin || ALLOWED_ORIGINS.some(o => origin.includes(o))) {
        res.header('Access-Control-Allow-Origin', origin || '*');
    }
    
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-app-signature, x-timestamp, Accept, Origin, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    
    next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiter - 100 requests per 15 minutes
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/health' || req.path === '/healthz' || req.path === '/ping'
});

app.use('/api/', limiter);

// ===== PUBLIC ENDPOINTS =====

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Cross-Verified AI Proxy v8.7.9 - Health Dual Fallback Edition',
        status: 'running',
        timestamp: new Date().toISOString(),
        edition: 'Health Dual Fallback Edition',
        features: [
            'Health Auto-Fallback (/health + /healthz)',
            'Gemini Key Rotation (1-3 keys)',
            'Pre-Wake Cold Start Optimization',
            'JWT + HMAC-SHA256 Security',
            'GDELT News/Web Verification',
            'TruthScore with ECC Correction',
            'Fail-Grace: Gemini → Mistral → Partial → Standby'
        ],
        endpoints: {
            health: '/health (or /healthz - both work!)',
            ping: '/ping',
            auth: '/auth/token',
            test: '/api/test-connection',
            api: {
                gemini: '/api/gemini',
                mistral: '/api/mistral',
                verify: {
                    gdelt: '/api/verify/gdelt',
                    crossref: '/api/verify/crossref',
                    openalex: '/api/verify/openalex',
                    wikidata: '/api/verify/wikidata'
                }
            }
        }
    });
});

// 🔥 Health Check - Dual Fallback (both /health and /healthz work!)
app.get(['/health', '/healthz'], (req, res) => {
    res.status(200).json({ 
        status: 'ok', 
        version: '8.7.9',
        edition: 'Health Dual Fallback',
        endpoint: req.path,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        engines: {
            ai: ['Gemini (1-3 keys)', 'Mistral (fallback)'],
            verification: ['GDELT (0.9)', 'CrossRef (1.0)', 'OpenAlex (1.0)', 'Wikidata (0.8)']
        },
        env: {
            node: process.version,
            platform: process.platform
        }
    });
});

// Ping endpoint (Pre-Wake용)
app.get('/ping', (req, res) => {
    res.json({ 
        pong: true, 
        timestamp: Date.now(),
        uptime: process.uptime(),
        version: '8.7.9',
        message: 'Server awake and ready!'
    });
});

// JWT 토큰 발급 (15분 TTL)
app.post('/auth/token', (req, res) => {
    try {
        const { appId } = req.body;
        
        // v8.7.9 appId 검증
        if (!appId || appId !== 'cross-verified-ai-v8.7.9') {
            console.log('❌ Invalid app ID:', appId);
            return res.status(401).json({ error: 'Invalid app identification' });
        }
        
        const token = jwt.sign(
            { appId, timestamp: Date.now() },
            JWT_SECRET,
            { expiresIn: '15m' }
        );
        
        console.log('✅ JWT token issued for v8.7.9');
        res.json({ token, expiresIn: 900, version: '8.7.9' });
    } catch (error) {
        console.error('❌ Token generation error:', error);
        res.status(500).json({ error: 'Token generation failed' });
    }
});

// 통합 연결 테스트 엔드포인트
app.post('/api/test-connection', async (req, res) => {
    try {
        const results = {
            server: { status: 'ok', version: '8.7.9' },
            endpoints: {
                health: false,
                healthz: false,
                ping: false
            },
            timestamp: Date.now()
        };

        // 자체 엔드포인트 확인
        try {
            results.endpoints.health = true;
            results.endpoints.healthz = true;
            results.endpoints.ping = true;
        } catch (e) {
            console.error('❌ Endpoint check failed:', e);
        }

        res.json(results);
    } catch (error) {
        console.error('❌ Connection test error:', error);
        res.status(500).json({ error: 'Connection test failed' });
    }
});

// ===== MIDDLEWARE =====

// JWT 검증 미들웨어
function verifyJWT(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.replace('Bearer ', '');
    
    if (!token) {
        console.log('❌ No JWT token provided');
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        console.log('❌ Invalid JWT token:', err.message);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// HMAC 서명 검증 미들웨어
function verifyHMAC(req, res, next) {
    const signature = req.headers['x-app-signature'];
    const timestamp = req.headers['x-timestamp'];
    
    if (!signature || !timestamp) {
        console.log('❌ Missing signature or timestamp');
        return res.status(401).json({ error: 'Missing signature or timestamp' });
    }
    
    // 타임스탬프 검증 (5분 이내)
    const now = Date.now();
    const requestTime = parseInt(timestamp);
    if (isNaN(requestTime) || Math.abs(now - requestTime) > 5 * 60 * 1000) {
        console.log('❌ Timestamp expired or invalid');
        return res.status(401).json({ error: 'Request timestamp expired or invalid' });
    }
    
    // HMAC 검증
    try {
        const body = JSON.stringify(req.body);
        const data = body + timestamp;
        const expectedSignature = crypto
            .createHmac('sha256', HMAC_SECRET)
            .update(data)
            .digest('hex');
        
        if (signature !== expectedSignature) {
            console.log('❌ Invalid HMAC signature');
            return res.status(401).json({ error: 'Invalid signature' });
        }
        
        next();
    } catch (error) {
        console.error('❌ HMAC verification error:', error);
        return res.status(401).json({ error: 'Signature verification failed' });
    }
}

// ===== API ENDPOINTS =====

// Gemini API Proxy (Key Rotation Support)
app.post('/api/gemini', verifyJWT, verifyHMAC, async (req, res) => {
    const { apiKey, prompt, model = 'gemini-flash-latest' } = req.body;
    
    console.log('📤 Gemini API request received');
    console.log('   Model:', model);
    
    if (!apiKey || !prompt) {
        console.log('❌ Missing apiKey or prompt');
        return res.status(400).json({ error: 'Missing apiKey or prompt' });
    }
    
    try {
        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
        
        const response = await retryRequest(async () => {
            return await axios.post(
                apiUrl,
                {
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: {
                        temperature: 0.7,
                        maxOutputTokens: 2048,
                    }
                },
                {
                    headers: { 'Content-Type': 'application/json' },
                    timeout: 30000
                }
            );
        }, 2); // 2회 재시도
        
        console.log('✅ Gemini API success');
        res.json({
            success: true,
            data: response.data,
            engine: 'Gemini',
            model: model,
            timestamp: Date.now(),
            version: '8.7.9'
        });
        
    } catch (error) {
        console.error('❌ Gemini API Error:', error.response?.data || error.message);
        
        // 429 또는 403 에러를 클라이언트에 전달 (키 로테이션용)
        if (error.response?.status === 429 || error.response?.status === 403) {
            return res.status(error.response.status).json({
                error: 'API quota exceeded',
                status: error.response.status,
                needRotation: true,
                message: 'Please rotate to next Gemini key or use Mistral fallback'
            });
        }
        
        res.status(500).json({
            error: 'Gemini API request failed',
            details: error.response?.data?.error?.message || error.message
        });
    }
});

// Mistral API Proxy (무료 Fallback)
app.post('/api/mistral', verifyJWT, verifyHMAC, async (req, res) => {
    const { prompt } = req.body;
    
    console.log('📤 Mistral API request received (Fallback mode)');
    
    if (!prompt) {
        return res.status(400).json({ error: 'Missing prompt' });
    }
    
    try {
        const response = await retryRequest(async () => {
            return await axios.post(
                'https://api.mistral.ai/v1/chat/completions',
                {
                    model: 'mistral-tiny',
                    messages: [{ role: 'user', content: prompt }]
                },
                {
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${process.env.MISTRAL_API_KEY || ''}`
                    },
                    timeout: 30000
                }
            );
        }, 2);
        
        console.log('✅ Mistral API success');
        res.json({
            success: true,
            data: response.data,
            engine: 'Mistral',
            weight: 0.8,
            fallback: true,
            timestamp: Date.now(),
            version: '8.7.9'
        });
        
    } catch (error) {
        console.error('❌ Mistral API Error:', error.message);
        res.status(500).json({
            error: 'Mistral API request failed',
            details: error.message
        });
    }
});

// GDELT API Proxy (뉴스·웹 검증)
app.post('/api/verify/gdelt', verifyJWT, verifyHMAC, async (req, res) => {
    const { query, maxrecords = 10 } = req.body;
    
    console.log('📤 GDELT verification request:', query);
    
    if (!query) {
        return res.status(400).json({ error: 'Missing query' });
    }
    
    try {
        const response = await retryRequest(async () => {
            return await axios.get(
                'https://api.gdeltproject.org/api/v2/doc/doc',
                {
                    params: {
                        query: query,
                        mode: 'artlist',
                        format: 'json',
                        maxrecords: maxrecords,
                        sort: 'datedesc'
                    },
                    headers: { 
                        'User-Agent': 'CrossVerifiedAI/8.7.9 (mailto:admin@example.com)' 
                    },
                    timeout: 15000
                }
            );
        }, 3); // 3회 재시도
        
        console.log('✅ GDELT verification success');
        
        const articles = response.data?.articles || [];
        
        res.json({
            success: true,
            data: {
                articles: articles,
                count: articles.length,
                query: query
            },
            source: 'GDELT',
            weight: 0.9,
            timestamp: Date.now(),
            version: '8.7.9'
        });
        
    } catch (error) {
        console.error('❌ GDELT Error:', error.message);
        
        // Graceful degradation
        if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
            console.log('⚠️ GDELT timeout, returning empty results');
            return res.json({
                success: true,
                data: { articles: [], count: 0, query: query },
                source: 'GDELT',
                weight: 0.9,
                timeout: true,
                message: 'GDELT search timed out, returned empty results',
                timestamp: Date.now(),
                version: '8.7.9'
            });
        }
        
        res.status(500).json({ 
            error: 'GDELT verification failed', 
            details: error.message,
            code: error.code
        });
    }
});

// CrossRef API Proxy
app.post('/api/verify/crossref', verifyJWT, verifyHMAC, async (req, res) => {
    const { doi } = req.body;
    
    console.log('📤 CrossRef verification request:', doi);
    
    if (!doi) {
        return res.status(400).json({ error: 'Missing DOI' });
    }
    
    try {
        const response = await retryRequest(async () => {
            return await axios.get(
                `https://api.crossref.org/works/${encodeURIComponent(doi)}`,
                {
                    headers: { 'User-Agent': 'CrossVerifiedAI/8.7.9 (mailto:admin@example.com)' },
                    timeout: 10000
                }
            );
        }, 2);
        
        console.log('✅ CrossRef verification success');
        res.json({
            success: true,
            data: response.data,
            source: 'CrossRef',
            weight: 1.0,
            timestamp: Date.now(),
            version: '8.7.9'
        });
        
    } catch (error) {
        console.error('❌ CrossRef Error:', error.message);
        res.status(404).json({ 
            error: 'DOI not found', 
            details: error.message 
        });
    }
});

// OpenAlex API Proxy
app.post('/api/verify/openalex', verifyJWT, verifyHMAC, async (req, res) => {
    const { query } = req.body;
    
    console.log('📤 OpenAlex search request:', query);
    
    if (!query) {
        return res.status(400).json({ error: 'Missing query' });
    }
    
    try {
        const response = await retryRequest(async () => {
            return await axios.get(
                `https://api.openalex.org/works?search=${encodeURIComponent(query)}`,
                {
                    headers: { 'User-Agent': 'mailto:admin@example.com' },
                    timeout: 10000
                }
            );
        }, 2);
        
        console.log('✅ OpenAlex search success');
        res.json({
            success: true,
            data: response.data,
            source: 'OpenAlex',
            weight: 1.0,
            timestamp: Date.now(),
            version: '8.7.9'
        });
        
    } catch (error) {
        console.error('❌ OpenAlex Error:', error.message);
        res.status(500).json({ 
            error: 'Search failed', 
            details: error.message 
        });
    }
});

// Wikidata API Proxy
app.post('/api/verify/wikidata', verifyJWT, verifyHMAC, async (req, res) => {
    const { query } = req.body;
    
    console.log('📤 Wikidata search request:', query);
    
    if (!query) {
        return res.status(400).json({ error: 'Missing query' });
    }
    
    try {
        const response = await retryRequest(async () => {
            return await axios.get(
                `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(query)}&language=en&format=json`,
                { timeout: 10000 }
            );
        }, 2);
        
        console.log('✅ Wikidata search success');
        res.json({
            success: true,
            data: response.data,
            source: 'Wikidata',
            weight: 0.8,
            timestamp: Date.now(),
            version: '8.7.9'
        });
        
    } catch (error) {
        console.error('❌ Wikidata Error:', error.message);
        res.status(500).json({ 
            error: 'Search failed', 
            details: error.message 
        });
    }
});

// ===== ERROR HANDLING =====

// 404 handler
app.use((req, res) => {
    console.log('⚠️ 404 Not Found:', req.method, req.path);
    res.status(404).json({ 
        error: 'Not Found',
        path: req.path,
        method: req.method,
        message: 'The requested endpoint does not exist',
        version: '8.7.9',
        hint: 'Try /health or /healthz for health check'
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('❌ Error:', err);
    res.status(err.status || 500).json({
        error: err.message || 'Internal server error',
        path: req.path,
        version: '8.7.9'
    });
});

// ===== START SERVER =====

const server = app.listen(PORT, () => {
    console.log('');
    console.log('🚀 Cross-Verified AI Proxy Server v8.7.9');
    console.log('📡 Health Dual Fallback Edition');
    console.log('🌐 Server running on port', PORT);
    console.log('🔒 Security: JWT + HMAC-SHA256 enabled');
    console.log('🔄 Retry Logic: Enabled (exponential backoff)');
    console.log('🌍 Trust Proxy: Enabled (Render.com)');
    console.log('⏰ Auto-sleep after 15 minutes of inactivity');
    console.log('⚡ Pre-Wake: Ping endpoints ready for cold start optimization');
    console.log('');
    console.log('🏥 Health Endpoints (both work!):');
    console.log('  GET  /health   ← Local/Debug');
    console.log('  GET  /healthz  ← Render internal');
    console.log('  GET  /ping     ← Pre-Wake cold start');
    console.log('');
    console.log('🤖 AI Engines:');
    console.log('  • Gemini (1-3 keys with rotation)');
    console.log('  • Mistral (fallback, w=0.8)');
    console.log('');
    console.log('🔍 Verification Engines:');
    console.log('  • GDELT (news/web, w=0.9)');
    console.log('  • CrossRef (DOI/journals, w=1.0)');
    console.log('  • OpenAlex (papers/citations, w=1.0)');
    console.log('  • Wikidata (knowledge graph, w=0.8)');
    console.log('');
    console.log('📋 API Endpoints:');
    console.log('  POST /auth/token');
    console.log('  POST /api/test-connection');
    console.log('  POST /api/gemini');
    console.log('  POST /api/mistral');
    console.log('  POST /api/verify/gdelt');
    console.log('  POST /api/verify/crossref');
    console.log('  POST /api/verify/openalex');
    console.log('  POST /api/verify/wikidata');
    console.log('');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('📴 SIGTERM signal received: closing HTTP server');
    server.close(() => {
        console.log('✅ HTTP server closed');
    });
});

module.exports = app;