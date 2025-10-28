// src/middleware/auth.js
const jwt = require('jsonwebtoken');
const { query } = require('../utils/db');
const { logAudit } = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';
const JWT_EXPIRES_IN = '24h'; // Access Token 유효기간
const REFRESH_TOKEN_EXPIRES_IN = '30d'; // Refresh Token 유효기간

/**
 * JWT 토큰 생성
 * @param {object} payload - 토큰 페이로드
 * @param {string} expiresIn - 만료 시간
 * @returns {string} - JWT 토큰
 */
function generateToken(payload, expiresIn = JWT_EXPIRES_IN) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

/**
 * JWT 토큰 검증
 * @param {string} token - JWT 토큰
 * @returns {object|null} - 디코딩된 페이로드 또는 null
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

/**
 * Refresh Token 생성 및 저장
 * @param {number} userId - 사용자 ID
 * @returns {Promise<string>} - Refresh Token
 */
async function generateRefreshToken(userId) {
  const refreshToken = generateToken({ userId }, REFRESH_TOKEN_EXPIRES_IN);
  
  // DB에 Refresh Token 저장
  await query(`
    UPDATE users
    SET refresh_token = $1
    WHERE id = $2
  `, [refreshToken, userId]);

  return refreshToken;
}

/**
 * JWT 인증 미들웨어
 */
async function authenticate(req, res, next) {
  try {
    // Authorization 헤더에서 토큰 추출
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'No token provided'
      });
    }

    const token = authHeader.substring(7); // "Bearer " 제거

    // 토큰 검증
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }

    // 사용자 정보 조회
    const result = await query(`
      SELECT id, google_id, email, name, is_active
      FROM users
      WHERE id = $1
    `, [decoded.userId]);

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'User not found'
      });
    }

    const user = result.rows[0];

    // 비활성 사용자 체크
    if (!user.is_active) {
      return res.status(403).json({
        success: false,
        error: 'Account is inactive'
      });
    }

    // 요청 객체에 사용자 정보 추가
    req.user = user;
    req.userId = user.id;

    next();
  } catch (error) {
    console.error('❌ Authentication error:', error);
    
    // 감사 로그 기록
    await logAudit({
      action: 'auth_failed',
      details: { error: error.message },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: false
    });

    return res.status(500).json({
      success: false,
      error: 'Authentication failed'
    });
  }
}

/**
 * 선택적 인증 미들웨어 (토큰이 있으면 검증, 없으면 통과)
 */
async function optionalAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decoded = verifyToken(token);
      
      if (decoded) {
        const result = await query(`
          SELECT id, google_id, email, name, is_active
          FROM users
          WHERE id = $1 AND is_active = true
        `, [decoded.userId]);

        if (result.rows.length > 0) {
          req.user = result.rows[0];
          req.userId = result.rows[0].id;
        }
      }
    }

    next();
  } catch (error) {
    // 에러가 발생해도 통과
    next();
  }
}

/**
 * Refresh Token으로 Access Token 갱신
 */
async function refreshAccessToken(req, res) {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        error: 'Refresh token is required'
      });
    }

    // Refresh Token 검증
    const decoded = verifyToken(refreshToken);
    if (!decoded) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired refresh token'
      });
    }

    // DB에서 Refresh Token 확인
    const result = await query(`
      SELECT id, email, name, refresh_token
      FROM users
      WHERE id = $1 AND is_active = true
    `, [decoded.userId]);

    if (result.rows.length === 0 || result.rows[0].refresh_token !== refreshToken) {
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token'
      });
    }

    const user = result.rows[0];

    // 새로운 Access Token 발급
    const newAccessToken = generateToken({
      userId: user.id,
      email: user.email
    });

    // 감사 로그 기록
    await logAudit({
      userId: user.id,
      action: 'token_refreshed',
      details: { email: user.email },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      success: true,
      accessToken: newAccessToken
    });
  } catch (error) {
    console.error('❌ Token refresh error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to refresh token'
    });
  }
}

module.exports = {
  generateToken,
  verifyToken,
  generateRefreshToken,
  authenticate,
  optionalAuth,
  refreshAccessToken,
  JWT_SECRET,
  JWT_EXPIRES_IN,
  REFRESH_TOKEN_EXPIRES_IN
};
