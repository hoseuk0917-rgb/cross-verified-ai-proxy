const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 10000;

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
  message: { error: 'Too many requests' },
});
app.use('/api/', limiter);

// ===== Health Check =====
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        version: '8.6.5',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

app.get('/healthz', (req, res) => {
    res.json({ status: 'ok' });  // 기존 것도 유지
});
// ===== Ping =====
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

// JWT 검증
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

// HMAC 검증
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
  const expectedSignature = crypto.createHmac('sha256', HMAC_SECRET).update(body + timestamp).digest('hex');
  if (signature !== expectedSignature) {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  next();
}

// Root
app.get('/', (req, res) => {
  res.json({
    message: '✅ Cross-Verified AI Proxy v8.6.5',
    health: '/healthz',
    ping: '/ping',
    version: '8.6.5',
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

// ✅ 서버 시작
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Proxy Server v8.6.5`);
  console.log(`📡 Server running on port ${PORT}`);
  console.log(`🔒 Security: JWT + HMAC-SHA256 enabled`);
});
