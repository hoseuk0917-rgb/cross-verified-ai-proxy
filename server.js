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
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret';
const HMAC_SECRET = process.env.HMAC_SECRET || 'your-hmac-secret';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') || ['*'];

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));

// Rate limiter
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests' }
});
app.use('/api/', limiter);

// ===== 중요: Health Check 엔드포인트 =====
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        version: '8.6.5',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

app.get('/ping', (req, res) => {
    res.json({ pong: true, timestamp: Date.now() });
});

// JWT 토큰 발급
app.post('/auth/token', (req, res) => {
    const { appId } = req.body;
    if (!appId || appId !== 'cross-verified-ai-v8.6.5') {
        return res.status(401).json({ error: 'Invalid app ID' });
    }
    const token = jwt.sign({ appId, timestamp: Date.now() }, JWT_SECRET, { expiresIn: '15m' });
    res.json({ token, expiresIn: 900 });
});

// JWT 검증 미들웨어
function verifyJWT(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// HMAC 검증 미들웨어
function verifyHMAC(req, res, next) {
    const signature = req.headers['x-app-signature'];
    const timestamp = req.headers['x-timestamp'];
    if (!signature || !timestamp) {
        return res.status(401).json({ error: 'Missing signature' });
    }
    const now = Date.now();
    const requestTime = parseInt(timestamp);
    if (Math.abs(now - requestTime) > 5 * 60 * 1000) {
        return res.status(401).json({ error: 'Timestamp expired' });
    }
    const body = JSON.stringify(req.body);
    const data = body + timestamp;
    const expectedSignature = crypto.createHmac('sha256', HMAC_SECRET).update(data).digest('hex');
    if (signature !== expectedSignature) {
        return res.status(401).json({ error: 'Invalid signature' });
    }
    next();
}

// Gemini API
app.post('/api/gemini', verifyJWT, verifyHMAC, async (req, res) => {
    const { apiKey, prompt, model = 'gemini-pro' } = req.body;
    if (!apiKey || !prompt) {
        return res.status(400).json({ error: 'Missing apiKey or prompt' });
    }
    try {
        const response = await axios.post(
            `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
            {
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { temperature: 0.7, maxOutputTokens: 2048 }
            },
            { headers: { 'Content-Type': 'application/json' }, timeout: 30000 }
        );
        res.json({ success: true, data: response.data, engine: 'Gemini', timestamp: Date.now() });
    } catch (error) {
        if (error.response?.status === 429 || error.response?.status === 403) {
            return res.status(error.response.status).json({
                error: 'API quota exceeded',
                status: error.response.status,
                needRotation: true
            });
        }
        res.status(500).json({ error: 'Gemini API failed', details: error.message });
    }
});

// DuckDuckGo Search
app.post('/api/search/duckduckgo', verifyJWT, verifyHMAC, async (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: 'Missing query' });
    try {
        const response = await axios.get(
            `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1`,
            { timeout: 10000 }
        );
        res.json({ success: true, data: response.data, source: 'DuckDuckGo', timestamp: Date.now() });
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// CrossRef
app.post('/api/verify/crossref', verifyJWT, verifyHMAC, async (req, res) => {
    const { doi } = req.body;
    if (!doi) return res.status(400).json({ error: 'Missing DOI' });
    try {
        const response = await axios.get(
            `https://api.crossref.org/works/${encodeURIComponent(doi)}`,
            { headers: { 'User-Agent': 'CrossVerifiedAI/8.6.5' }, timeout: 10000 }
        );
        res.json({ success: true, data: response.data, source: 'CrossRef', timestamp: Date.now() });
    } catch (error) {
        res.status(404).json({ error: 'DOI not found' });
    }
});

// OpenAlex
app.post('/api/verify/openalex', verifyJWT, verifyHMAC, async (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: 'Missing query' });
    try {
        const response = await axios.get(
            `https://api.openalex.org/works?search=${encodeURIComponent(query)}`,
            { headers: { 'User-Agent': 'mailto:admin@example.com' }, timeout: 10000 }
        );
        res.json({ success: true, data: response.data, source: 'OpenAlex', timestamp: Date.now() });
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// Wikidata
app.post('/api/verify/wikidata', verifyJWT, verifyHMAC, async (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: 'Missing query' });
    try {
        const response = await axios.get(
            `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(query)}&language=en&format=json`,
            { timeout: 10000 }
        );
        res.json({ success: true, data: response.data, source: 'Wikidata', timestamp: Date.now() });
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Cross-Verified AI Proxy v8.6.5',
        endpoints: {
            health: '/health',
            ping: '/ping',
            auth: '/auth/token',
            api: '/api/*'
        }
    });
});

// Error handling
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Cross-Verified AI Proxy Server v8.6.5`);
    console.log(`📡 Server running on port ${PORT}`);
    console.log(`🔒 Security: JWT + HMAC-SHA256 enabled`);
});

module.exports = app;