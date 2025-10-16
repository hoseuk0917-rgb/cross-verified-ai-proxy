// Cross-Verified AI v8.6.5 - Render Serverless Proxy
// server.js

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
console.log('   PORT:', PORT);
console.log('   JWT_SECRET:', JWT_SECRET ? 'Set' : 'Not Set');
console.log('   HMAC_SECRET:', HMAC_SECRET ? 'Set' : 'Not Set');
console.log('   ALLOWED_ORIGINS:', ALLOWED_ORIGINS);

// ===== SECURITY MIDDLEWARE =====

// Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// CORS - Handle preflight and actual requests
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    // Allow all origins if * is set, or check whitelist
    if (ALLOWED_ORIGINS.includes('*') || !origin || ALLOWED_ORIGINS.some(o => origin.includes(o))) {
        res.header('Access-Control-Allow-Origin', origin || '*');
    }
    
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-app-signature, x-timestamp, Accept, Origin, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400'); // 24 hours
    
    // Handle preflight
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
        message: 'Cross-Verified AI Proxy v8.6.5',
        status: 'running',
        timestamp: new Date().toISOString(),
        endpoints: {
            health: '/health',
            healthz: '/healthz',
            ping: '/ping',
            auth: '/auth/token',
            api: {
                gemini: '/api/gemini',
                mistral: '/api/mistral',
                search: '/api/search/duckduckgo',
                verify: {
                    crossref: '/api/verify/crossref',
                    openalex: '/api/verify/openalex',
                    wikidata: '/api/verify/wikidata'
                }
            }
        }
    });
});

// Health check endpoints
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        version: '8.6.5',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

app.get('/healthz', (req, res) => {
    res.json({ 
        status: 'ok',
        version: '8.6.5',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Ping endpoint
app.get('/ping', (req, res) => {
    res.json({ 
        pong: true, 
        timestamp: Date.now(),
        uptime: process.uptime()
    });
});

// JWT 토큰 발급 (15분 TTL)
app.post('/auth/token', (req, res) => {
    try {
        const { appId } = req.body;
        
        if (!appId || appId !== 'cross-verified-ai-v8.6.5') {
            console.log('❌ Invalid app ID:', appId);
            return res.status(401).json({ error: 'Invalid app identification' });
        }
        
        const token = jwt.sign(
            { appId, timestamp: Date.now() },
            JWT_SECRET,
            { expiresIn: '15m' }
        );
        
        console.log('✅ JWT token issued');
        res.json({ token, expiresIn: 900 });
    } catch (error) {
        console.error('❌ Token generation error:', error);
        res.status(500).json({ error: 'Token generation failed' });
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

// Gemini API Proxy
// Gemini API Proxy
app.post('/api/gemini', verifyJWT, verifyHMAC, async (req, res) => {
    const { apiKey, prompt, model = 'gemini-1.5-flash' } = req.body; // ← 기본값 변경!
    
    console.log('📤 Gemini API request received');
    
    if (!apiKey || !prompt) {
        console.log('❌ Missing apiKey or prompt');
        return res.status(400).json({ error: 'Missing apiKey or prompt' });
    }
    
    try {
        // v1beta 대신 v1 사용 가능
        const apiUrl = `https://generativelanguage.googleapis.com/v1/models/${model}:generateContent?key=${apiKey}`;
        
        const response = await axios.post(
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
        
        console.log('✅ Gemini API success');
        res.json({
            success: true,
            data: response.data,
            engine: 'Gemini',
            model: model,
            timestamp: Date.now()
        });
        
    } catch (error) {
        console.error('❌ Gemini API Error:', error.response?.data || error.message);
        
        // 429 또는 403 에러를 클라이언트에 전달 (키 로테이션용)
        if (error.response?.status === 429 || error.response?.status === 403) {
            return res.status(error.response.status).json({
                error: 'API quota exceeded',
                status: error.response.status,
                needRotation: true
            });
        }
        
        res.status(500).json({
            error: 'Gemini API request failed',
            details: error.response?.data?.error?.message || error.message
        });
    }
});

// DuckDuckGo Search Proxy - 타임아웃 증가
app.post('/api/search/duckduckgo', verifyJWT, verifyHMAC, async (req, res) => {
    const { query } = req.body;
    
    console.log('📤 DuckDuckGo search request:', query);
    
    if (!query) {
        return res.status(400).json({ error: 'Missing query' });
    }
    
    try {
        const response = await axios.get(
            `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1`,
            { timeout: 20000 } // ← 10초 → 20초로 증가
        );
        
        console.log('✅ DuckDuckGo search success');
        res.json({
            success: true,
            data: response.data,
            source: 'DuckDuckGo',
            timestamp: Date.now()
        });
        
    } catch (error) {
        console.error('❌ DuckDuckGo Error:', error.message);
        
        // 타임아웃이면 빈 결과 반환 (실패로 처리하지 않음)
        if (error.code === 'ECONNABORTED') {
            console.log('⚠️ DuckDuckGo timeout, returning empty results');
            return res.json({
                success: true,
                data: { RelatedTopics: [] },
                source: 'DuckDuckGo',
                timeout: true,
                timestamp: Date.now()
            });
        }
        
        res.status(500).json({ error: 'Search failed', details: error.message });
    }
});
// Mistral API Proxy (무료)
app.post('/api/mistral', verifyJWT, verifyHMAC, async (req, res) => {
    const { prompt } = req.body;
    
    console.log('📤 Mistral API request received');
    
    if (!prompt) {
        return res.status(400).json({ error: 'Missing prompt' });
    }
    
    try {
        const response = await axios.post(
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
        
        console.log('✅ Mistral API success');
        res.json({
            success: true,
            data: response.data,
            engine: 'Mistral',
            timestamp: Date.now()
        });
        
    } catch (error) {
        console.error('❌ Mistral API Error:', error.message);
        res.status(500).json({
            error: 'Mistral API request failed',
            details: error.message
        });
    }
});

// DuckDuckGo Search Proxy
app.post('/api/search/duckduckgo', verifyJWT, verifyHMAC, async (req, res) => {
    const { query } = req.body;
    
    console.log('📤 DuckDuckGo search request:', query);
    
    if (!query) {
        return res.status(400).json({ error: 'Missing query' });
    }
    
    try {
        const response = await axios.get(
            `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1`,
            { timeout: 10000 }
        );
        
        console.log('✅ DuckDuckGo search success');
        res.json({
            success: true,
            data: response.data,
            source: 'DuckDuckGo',
            timestamp: Date.now()
        });
        
    } catch (error) {
        console.error('❌ DuckDuckGo Error:', error.message);
        res.status(500).json({ error: 'Search failed', details: error.message });
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
        const response = await axios.get(
            `https://api.crossref.org/works/${encodeURIComponent(doi)}`,
            {
                headers: { 'User-Agent': 'CrossVerifiedAI/8.6.5 (mailto:admin@example.com)' },
                timeout: 10000
            }
        );
        
        console.log('✅ CrossRef verification success');
        res.json({
            success: true,
            data: response.data,
            source: 'CrossRef',
            timestamp: Date.now()
        });
        
    } catch (error) {
        console.error('❌ CrossRef Error:', error.message);
        res.status(404).json({ error: 'DOI not found', details: error.message });
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
        const response = await axios.get(
            `https://api.openalex.org/works?search=${encodeURIComponent(query)}`,
            {
                headers: { 'User-Agent': 'mailto:admin@example.com' },
                timeout: 10000
            }
        );
        
        console.log('✅ OpenAlex search success');
        res.json({
            success: true,
            data: response.data,
            source: 'OpenAlex',
            timestamp: Date.now()
        });
        
    } catch (error) {
        console.error('❌ OpenAlex Error:', error.message);
        res.status(500).json({ error: 'Search failed', details: error.message });
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
        const response = await axios.get(
            `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(query)}&language=en&format=json`,
            { timeout: 10000 }
        );
        
        console.log('✅ Wikidata search success');
        res.json({
            success: true,
            data: response.data,
            source: 'Wikidata',
            timestamp: Date.now()
        });
        
    } catch (error) {
        console.error('❌ Wikidata Error:', error.message);
        res.status(500).json({ error: 'Search failed', details: error.message });
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
        message: 'The requested endpoint does not exist'
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('❌ Error:', err);
    res.status(err.status || 500).json({
        error: err.message || 'Internal server error',
        path: req.path
    });
});

// ===== START SERVER =====

const server = app.listen(PORT, () => {
    console.log('');
    console.log('🚀 Cross-Verified AI Proxy Server v8.6.5');
    console.log('📡 Server running on port', PORT);
    console.log('🔒 Security: JWT + HMAC-SHA256 enabled');
    console.log('⏰ Auto-sleep after 15 minutes of inactivity (Render free tier)');
    console.log('');
    console.log('Available endpoints:');
    console.log('  GET  /health');
    console.log('  GET  /healthz');
    console.log('  GET  /ping');
    console.log('  POST /auth/token');
    console.log('  POST /api/gemini');
    console.log('  POST /api/search/duckduckgo');
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