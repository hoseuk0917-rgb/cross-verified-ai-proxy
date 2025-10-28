// src/routes/gemini.js
const express = require('express');
const { authenticate } = require('../middleware/auth');
const { query } = require('../utils/db');
const { decrypt } = require('../utils/encrypt');
const { callGemini } = require('../utils/fetcher');
const { logRequest, logAudit } = require('../utils/logger');

const router = express.Router();

/**
 * @route   POST /proxy/gemini/:model
 * @desc    Gemini API Proxy
 * @access  Private
 */
router.post('/:model', authenticate, async (req, res) => {
  const startTime = Date.now();
  const { model } = req.params;
  const { keyIndex = 1, ...payload } = req.body;
  const userId = req.userId;

  try {
    // 유효한 모델명 체크
    const validModels = [
      'gemini-2.0-flash-exp',
      'gemini-1.5-flash',
      'gemini-1.5-flash-8b',
      'gemini-1.5-pro',
      'gemini-pro'
    ];

    if (!validModels.includes(model)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid model name'
      });
    }

    // API Key 조회 (복호화)
    const keyResult = await query(`
      SELECT encrypted_key, iv, auth_tag, is_active, expires_at
      FROM api_keys
      WHERE user_id = $1
        AND service = 'gemini'
        AND key_index = $2
        AND is_active = true
    `, [userId, keyIndex]);

    if (keyResult.rows.length === 0) {
      await logAudit({
        userId,
        action: 'gemini_api_key_not_found',
        resource: `gemini/${model}`,
        details: { keyIndex },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        success: false
      });

      return res.status(404).json({
        success: false,
        error: 'API key not found. Please register your Gemini API key first.'
      });
    }

    const keyData = keyResult.rows[0];

    // 만료 체크
    if (keyData.expires_at && new Date(keyData.expires_at) < new Date()) {
      return res.status(401).json({
        success: false,
        error: 'API key has expired'
      });
    }

    // API Key 복호화
    let apiKey;
    try {
      apiKey = decrypt(keyData.encrypted_key, keyData.iv, keyData.auth_tag);
    } catch (error) {
      console.error('❌ Decryption failed:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to decrypt API key'
      });
    }

    // Gemini API 호출
    const result = await callGemini(apiKey, model, payload);

    const latency = Date.now() - startTime;

    // 요청 로그 기록
    await logRequest({
      userId,
      service: 'gemini',
      endpoint: `/proxy/gemini/${model}`,
      method: 'POST',
      statusCode: result.status,
      latency,
      requestSize: JSON.stringify(payload).length,
      responseSize: result.data ? JSON.stringify(result.data).length : 0,
      success: result.success,
      errorMessage: result.error?.message
    });

    // 실패한 경우
    if (!result.success) {
      return res.status(result.status || 500).json({
        success: false,
        error: result.error?.message || 'API request failed',
        details: result.error
      });
    }

    // 성공 응답
    res.json({
      success: true,
      data: result.data,
      latency,
      model
    });

  } catch (error) {
    console.error('❌ Gemini proxy error:', error);

    const latency = Date.now() - startTime;

    await logRequest({
      userId,
      service: 'gemini',
      endpoint: `/proxy/gemini/${model}`,
      method: 'POST',
      statusCode: 500,
      latency,
      success: false,
      errorMessage: error.message
    });

    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

/**
 * @route   GET /proxy/gemini/keys
 * @desc    사용자의 Gemini API Key 목록 조회
 * @access  Private
 */
router.get('/keys', authenticate, async (req, res) => {
  try {
    const userId = req.userId;

    const result = await query(`
      SELECT key_index, is_active, expires_at, created_at, updated_at
      FROM api_keys
      WHERE user_id = $1 AND service = 'gemini'
      ORDER BY key_index
    `, [userId]);

    res.json({
      success: true,
      keys: result.rows
    });
  } catch (error) {
    console.error('❌ Get keys error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve API keys'
    });
  }
});

/**
 * @route   POST /proxy/gemini/keys
 * @desc    Gemini API Key 등록/업데이트
 * @access  Private
 */
router.post('/keys', authenticate, async (req, res) => {
  try {
    const userId = req.userId;
    const { apiKey, keyIndex = 1, expiresAt = null } = req.body;

    if (!apiKey) {
      return res.status(400).json({
        success: false,
        error: 'API key is required'
      });
    }

    // keyIndex 유효성 체크 (1-5)
    if (keyIndex < 1 || keyIndex > 5) {
      return res.status(400).json({
        success: false,
        error: 'Key index must be between 1 and 5'
      });
    }

    // API Key 암호화
    const { encrypt } = require('../utils/encrypt');
    const { encryptedData, iv, authTag } = encrypt(apiKey);

    // DB에 저장 (UPSERT)
    await query(`
      INSERT INTO api_keys (user_id, service, encrypted_key, iv, auth_tag, key_index, expires_at)
      VALUES ($1, 'gemini', $2, $3, $4, $5, $6)
      ON CONFLICT (user_id, service, key_index)
      DO UPDATE SET
        encrypted_key = EXCLUDED.encrypted_key,
        iv = EXCLUDED.iv,
        auth_tag = EXCLUDED.auth_tag,
        expires_at = EXCLUDED.expires_at,
        updated_at = NOW(),
        is_active = true
    `, [userId, encryptedData, iv, authTag, keyIndex, expiresAt]);

    // 감사 로그 기록
    await logAudit({
      userId,
      action: 'gemini_api_key_registered',
      resource: `gemini/key/${keyIndex}`,
      details: { keyIndex },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      success: true,
      message: 'API key registered successfully',
      keyIndex
    });
  } catch (error) {
    console.error('❌ Register key error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to register API key'
    });
  }
});

/**
 * @route   DELETE /proxy/gemini/keys/:keyIndex
 * @desc    Gemini API Key 삭제
 * @access  Private
 */
router.delete('/keys/:keyIndex', authenticate, async (req, res) => {
  try {
    const userId = req.userId;
    const { keyIndex } = req.params;

    await query(`
      DELETE FROM api_keys
      WHERE user_id = $1 AND service = 'gemini' AND key_index = $2
    `, [userId, keyIndex]);

    await logAudit({
      userId,
      action: 'gemini_api_key_deleted',
      resource: `gemini/key/${keyIndex}`,
      details: { keyIndex },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      success: true,
      message: 'API key deleted successfully'
    });
  } catch (error) {
    console.error('❌ Delete key error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete API key'
    });
  }
});

module.exports = router;
