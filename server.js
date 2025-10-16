const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();

// ✅ Render가 자동으로 지정하는 포트 (중요)
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
  message: { error: 'Too many requests' }
});
app.use('/api/', limiter);

// ===== Render 헬스체크용 엔드포인트 =====
app.get('/healthz', (req, res) => {
  r
