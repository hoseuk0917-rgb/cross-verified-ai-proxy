// src/routes/github.js
const express = require('express');
const { authenticate } = require('../middleware/auth');
const { query: dbQuery } = require('../utils/db');
const { decrypt } = require('../utils/encrypt');
const { callGitHub } = require('../utils/fetcher');
const { logRequest } = require('../utils/logger');

const router = express.Router();

/**
 * @route   GET /proxy/github/*
 * @desc    GitHub API Proxy (개발 검증용)
 * @access  Private
 */
router.get('/*', authenticate, async (req, res) => {
  const startTime = Date.now();
  const userId = req.userId;
  const endpoint = '/' + req.params[0]; // '/repos/:owner/:repo' 등

  try {
    // GitHub Token 조회 (복호화)
    const keyResult = await dbQuery(`
      SELECT encrypted_key, iv, auth_tag
      FROM api_keys
      WHERE user_id = $1
        AND service = 'github'
        AND is_active = true
      LIMIT 1
    `, [userId]);

    if (keyResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'GitHub token not found. Please register your GitHub Personal Access Token first.'
      });
    }

    const keyData = keyResult.rows[0];
    const token = decrypt(keyData.encrypted_key, keyData.iv, keyData.auth_tag);

    // GitHub API 호출
    const result = await callGitHub(token, endpoint, req.query);
    const latency = Date.now() - startTime;

    await logRequest({
      userId,
      service: 'github',
      endpoint: `/proxy/github${endpoint}`,
      method: 'GET',
      statusCode: result.status,
      latency,
      success: result.success,
      errorMessage: result.error?.message
    });

    if (!result.success) {
      return res.status(result.status || 500).json({
        success: false,
        error: result.error?.message || 'API request failed',
        details: result.error
      });
    }

    res.json({
      success: true,
      data: result.data,
      latency
    });
  } catch (error) {
    console.error('❌ GitHub proxy error:', error);

    const latency = Date.now() - startTime;

    await logRequest({
      userId,
      service: 'github',
      endpoint: `/proxy/github${endpoint}`,
      method: 'GET',
      statusCode: 500,
      latency,
      success: false,
      errorMessage: error.message
    });

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * @route   POST /proxy/github/keys
 * @desc    GitHub Personal Access Token 등록
 * @access  Private
 */
router.post('/keys', authenticate, async (req, res) => {
  try {
    const userId = req.userId;
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        error: 'GitHub token is required'
      });
    }

    // 암호화
    const { encrypt } = require('../utils/encrypt');
    const { encryptedData, iv, authTag } = encrypt(token);

    // DB에 저장
    await dbQuery(`
      INSERT INTO api_keys (user_id, service, encrypted_key, iv, auth_tag, key_index)
      VALUES ($1, 'github', $2, $3, $4, 1)
      ON CONFLICT (user_id, service, key_index)
      DO UPDATE SET
        encrypted_key = EXCLUDED.encrypted_key,
        iv = EXCLUDED.iv,
        auth_tag = EXCLUDED.auth_tag,
        updated_at = NOW(),
        is_active = true
    `, [userId, encryptedData, iv, authTag]);

    res.json({
      success: true,
      message: 'GitHub token registered successfully'
    });
  } catch (error) {
    console.error('❌ Register GitHub token error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to register GitHub token'
    });
  }
});

/**
 * @route   DELETE /proxy/github/keys
 * @desc    GitHub Token 삭제
 * @access  Private
 */
router.delete('/keys', authenticate, async (req, res) => {
  try {
    const userId = req.userId;

    await dbQuery(`
      DELETE FROM api_keys
      WHERE user_id = $1 AND service = 'github'
    `, [userId]);

    res.json({
      success: true,
      message: 'GitHub token deleted successfully'
    });
  } catch (error) {
    console.error('❌ Delete GitHub token error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete GitHub token'
    });
  }
});

/**
 * @route   GET /proxy/github/search/repositories
 * @desc    GitHub 레포지토리 검색 (특화된 엔드포인트)
 * @access  Private
 */
router.post('/search/repositories', authenticate, async (req, res) => {
  const startTime = Date.now();
  const userId = req.userId;

  try {
    const { query, sort = 'stars', order = 'desc', per_page = 10 } = req.body;

    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter is required'
      });
    }

    // GitHub Token 조회
    const keyResult = await dbQuery(`
      SELECT encrypted_key, iv, auth_tag
      FROM api_keys
      WHERE user_id = $1 AND service = 'github' AND is_active = true
      LIMIT 1
    `, [userId]);

    if (keyResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'GitHub token not found'
      });
    }

    const keyData = keyResult.rows[0];
    const token = decrypt(keyData.encrypted_key, keyData.iv, keyData.auth_tag);

    // GitHub Search API 호출
    const result = await callGitHub(token, '/search/repositories', {
      q: query,
      sort,
      order,
      per_page
    });

    const latency = Date.now() - startTime;

    if (!result.success) {
      return res.status(result.status || 500).json({
        success: false,
        error: result.error?.message || 'Search failed'
      });
    }

    res.json({
      success: true,
      data: result.data,
      latency
    });
  } catch (error) {
    console.error('❌ GitHub search error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
