// src/routes/auth.js
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { query } = require('../utils/db');
const { generateToken, generateRefreshToken } = require('../middleware/auth');
const { logAudit } = require('../utils/logger');

const router = express.Router();

// Google OAuth 설정
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_REDIRECT_URI || '/auth/google/callback',
  passReqToCallback: true
},
async function(req, accessToken, refreshToken, profile, done) {
  try {
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const name = profile.displayName;
    const profilePicture = profile.photos[0]?.value || null;

    // 사용자 조회 또는 생성
    let result = await query(`
      SELECT id, google_id, email, name, is_active
      FROM users
      WHERE google_id = $1
    `, [googleId]);

    let user;

    if (result.rows.length > 0) {
      // 기존 사용자 - 로그인 시간 업데이트
      user = result.rows[0];
      await query(`
        UPDATE users
        SET last_login = NOW(), profile_picture = $1
        WHERE id = $2
      `, [profilePicture, user.id]);
    } else {
      // 신규 사용자 - 계정 생성
      result = await query(`
        INSERT INTO users (google_id, email, name, profile_picture)
        VALUES ($1, $2, $3, $4)
        RETURNING id, google_id, email, name, is_active
      `, [googleId, email, name, profilePicture]);
      user = result.rows[0];
    }

    // 감사 로그 기록
    await logAudit({
      userId: user.id,
      action: result.rows.length > 0 ? 'user_login' : 'user_created',
      details: { email, googleId },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    return done(null, user);
  } catch (error) {
    console.error('❌ Google OAuth error:', error);
    return done(error, null);
  }
}));

// Passport Serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await query(`
      SELECT id, google_id, email, name, is_active
      FROM users
      WHERE id = $1
    `, [id]);

    if (result.rows.length > 0) {
      done(null, result.rows[0]);
    } else {
      done(new Error('User not found'), null);
    }
  } catch (error) {
    done(error, null);
  }
});

/**
 * @route   GET /auth/google
 * @desc    Google OAuth 로그인 시작
 * @access  Public
 */
router.get('/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    accessType: 'offline',
    prompt: 'consent'
  })
);

/**
 * @route   GET /auth/google/callback
 * @desc    Google OAuth 콜백
 * @access  Public
 */
router.get('/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/auth/failure',
    session: false
  }),
  async (req, res) => {
    try {
      const user = req.user;

      // JWT 토큰 생성
      const accessToken = generateToken({
        userId: user.id,
        email: user.email
      });

      // Refresh Token 생성
      const refreshToken = await generateRefreshToken(user.id);

      // 프론트엔드로 리다이렉트 (토큰 포함)
      const redirectUrl = process.env.GOOGLE_ORIGIN || 'http://localhost:5173';
      res.redirect(`${redirectUrl}/auth/callback?accessToken=${accessToken}&refreshToken=${refreshToken}`);
    } catch (error) {
      console.error('❌ Callback error:', error);
      res.redirect('/auth/failure');
    }
  }
);

/**
 * @route   GET /auth/failure
 * @desc    OAuth 실패 페이지
 * @access  Public
 */
router.get('/failure', (req, res) => {
  res.status(401).json({
    success: false,
    error: 'Authentication failed'
  });
});

/**
 * @route   POST /auth/logout
 * @desc    로그아웃
 * @access  Private
 */
router.post('/logout', async (req, res) => {
  try {
    const { userId } = req.body;

    if (userId) {
      // Refresh Token 제거
      await query(`
        UPDATE users
        SET refresh_token = NULL
        WHERE id = $1
      `, [userId]);

      // 감사 로그 기록
      await logAudit({
        userId,
        action: 'user_logout',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: true
      });
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('❌ Logout error:', error);
    res.status(500).json({
      success: false,
      error: 'Logout failed'
    });
  }
});

/**
 * @route   GET /auth/me
 * @desc    현재 사용자 정보 조회
 * @access  Private (JWT 필요)
 */
router.get('/me', async (req, res) => {
  try {
    // JWT에서 userId 추출
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({
        success: false,
        error: 'No token provided'
      });
    }

    const { verifyToken } = require('../middleware/auth');
    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        success: false,
        error: 'Invalid token'
      });
    }

    // 사용자 정보 조회
    const result = await query(`
      SELECT id, google_id, email, name, profile_picture, created_at, last_login
      FROM users
      WHERE id = $1 AND is_active = true
    `, [decoded.userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    res.json({
      success: true,
      user: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Get user error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get user info'
    });
  }
});

module.exports = router;
