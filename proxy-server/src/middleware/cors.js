// src/middleware/cors.js
const cors = require('cors');

// 환경변수에서 허용된 Origin 가져오기
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173')
  .split(',')
  .map(origin => origin.trim());

/**
 * CORS 옵션 설정
 */
const corsOptions = {
  origin: function (origin, callback) {
    // Origin이 없는 경우 (예: 모바일 앱, Postman 등) 허용
    if (!origin) {
      return callback(null, true);
    }

    // 허용된 Origin 목록에 있는지 확인
    if (ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*')) {
      callback(null, true);
    } else {
      console.warn(`⚠️  Blocked by CORS: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // 쿠키 포함 허용
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-API-Key',
    'X-Request-ID'
  ],
  exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
  maxAge: 86400 // Preflight 요청 캐시 시간 (24시간)
};

/**
 * CORS 미들웨어
 */
const corsMiddleware = cors(corsOptions);

/**
 * 커스텀 CORS 에러 핸들러
 */
function corsErrorHandler(err, req, res, next) {
  if (err.message === 'Not allowed by CORS') {
    res.status(403).json({
      success: false,
      error: 'CORS policy violation',
      message: 'Your origin is not allowed to access this resource'
    });
  } else {
    next(err);
  }
}

module.exports = {
  corsMiddleware,
  corsErrorHandler,
  ALLOWED_ORIGINS
};
