// src/server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const session = require('express-session');
const passport = require('passport');
const rateLimit = require('express-rate-limit');

// 유틸리티 및 미들웨어
const { corsMiddleware, corsErrorHandler } = require('./middleware/cors');
const { refreshAccessToken } = require('./middleware/auth');
const { initializeDatabase, cleanupOldLogs } = require('./utils/db');
const { logger, getSystemHealth } = require('./utils/logger');

// 라우터
const authRouter = require('./routes/auth');
const geminiRouter = require('./routes/gemini');
const klawRouter = require('./routes/klaw');
const externalRouter = require('./routes/external');
const githubRouter = require('./routes/github');

// Express 앱 생성
const app = express();
const PORT = process.env.PORT || 3000;

// Rate Limiting 설정
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 1000, // 최대 1000 요청
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// 미들웨어 설정
app.use(helmet()); // 보안 헤더
app.use(compression()); // Gzip 압축
app.use(express.json({ limit: '10mb' })); // JSON 파싱
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(corsMiddleware); // CORS
app.use(morgan('combined')); // HTTP 로깅
app.use(limiter); // Rate limiting

// Session 설정
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS에서만
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24시간
  }
}));

// Passport 초기화
app.use(passport.initialize());
app.use(passport.session());

// 요청 ID 미들웨어 (추적용)
app.use((req, res, next) => {
  req.id = require('crypto').randomBytes(16).toString('hex');
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Health Check 엔드포인트
app.get('/health', async (req, res) => {
  try {
    const health = await getSystemHealth();
    const overallStatus = Object.values(health).every(s => s.status === 'healthy') ? 'healthy' : 'degraded';

    res.json({
      success: true,
      status: overallStatus,
      timestamp: new Date().toISOString(),
      services: health,
      uptime: process.uptime(),
      memory: process.memoryUsage()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      status: 'unhealthy',
      error: error.message
    });
  }
});

// Root 엔드포인트
app.get('/', (req, res) => {
  res.json({
    name: 'Cross-Verified Proxy Server',
    version: '9.8.4',
    description: 'Multi-Engine Verification Gateway',
    endpoints: {
      auth: '/auth',
      gemini: '/proxy/gemini',
      klaw: '/proxy/klaw',
      external: '/proxy/external',
      github: '/proxy/github'
    },
    documentation: 'https://github.com/cross-verified-ai/proxy-server',
    status: 'operational'
  });
});

// API 라우터 등록
app.use('/auth', authRouter);
app.use('/proxy/gemini', geminiRouter);
app.use('/proxy/klaw', klawRouter);
app.use('/proxy/external', externalRouter);
app.use('/proxy/github', githubRouter);

// Token Refresh 엔드포인트
app.post('/auth/refresh', refreshAccessToken);

// 404 에러 핸들러
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.path,
    method: req.method
  });
});

// CORS 에러 핸들러
app.use(corsErrorHandler);

// 전역 에러 핸들러
app.use((err, req, res, next) => {
  console.error('❌ Global error:', err);

  // 스택 트레이스는 개발 환경에서만 노출
  const errorResponse = {
    success: false,
    error: err.message || 'Internal server error',
    requestId: req.id
  };

  if (process.env.NODE_ENV === 'development') {
    errorResponse.stack = err.stack;
  }

  res.status(err.status || 500).json(errorResponse);
});

// 서버 시작
async function startServer() {
  try {
    // 데이터베이스 초기화
    logger.info('Initializing database...');
    await initializeDatabase();

    // 서버 시작
    app.listen(PORT, '0.0.0.0', () => {
      logger.success(`🚀 Cross-Verified Proxy Server v9.8.4 running on port ${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`CORS Origins: ${process.env.ALLOWED_ORIGINS || 'http://localhost:5173'}`);
      logger.info(`Health Check: http://localhost:${PORT}/health`);
    });

    // 로그 정리 스케줄러 (매일 자정)
    const schedule = () => {
      const now = new Date();
      const night = new Date(
        now.getFullYear(),
        now.getMonth(),
        now.getDate() + 1,
        0, 0, 0
      );
      const msToMidnight = night.getTime() - now.getTime();

      setTimeout(() => {
        cleanupOldLogs();
        setInterval(cleanupOldLogs, 24 * 60 * 60 * 1000); // 매일
      }, msToMidnight);
    };

    schedule();

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful Shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully...');
  process.exit(0);
});

// Unhandled Promise Rejection
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Uncaught Exception
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// 서버 시작
startServer();

module.exports = app;
