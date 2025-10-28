// src/routes/external.js
const express = require('express');
const { authenticate, optionalAuth } = require('../middleware/auth');
const { query: dbQuery } = require('../utils/db');
const { decrypt } = require('../utils/encrypt');
const {
  callCrossRef,
  callOpenAlex,
  callGDELT,
  callWikidata,
  callNaver,
  fetchParallel
} = require('../utils/fetcher');
const { logRequest, logNaverLatency } = require('../utils/logger');

const router = express.Router();

/**
 * @route   GET /proxy/external/crossref
 * @desc    CrossRef API Proxy (학술 논문 검색)
 * @access  Public
 */
router.get('/crossref', optionalAuth, async (req, res) => {
  const startTime = Date.now();
  const userId = req.userId || null;

  try {
    const { query, email } = req.query;

    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter is required'
      });
    }

    // 사용자 이메일 (Polite Pool 용)
    let userEmail = email;
    if (userId && !userEmail) {
      const userResult = await dbQuery(`SELECT email FROM users WHERE id = $1`, [userId]);
      userEmail = userResult.rows[0]?.email;
    }

    const result = await callCrossRef(query, userEmail);
    const latency = Date.now() - startTime;

    await logRequest({
      userId,
      service: 'crossref',
      endpoint: '/proxy/external/crossref',
      method: 'GET',
      statusCode: result.status,
      latency,
      success: result.success,
      errorMessage: result.error?.message
    });

    if (!result.success) {
      return res.status(result.status || 500).json({
        success: false,
        error: result.error?.message || 'API request failed'
      });
    }

    res.json({
      success: true,
      data: result.data,
      latency
    });
  } catch (error) {
    console.error('❌ CrossRef proxy error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * @route   GET /proxy/external/openalex
 * @desc    OpenAlex API Proxy (학술 데이터 검색)
 * @access  Public
 */
router.get('/openalex', optionalAuth, async (req, res) => {
  const startTime = Date.now();
  const userId = req.userId || null;

  try {
    const { query } = req.query;

    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter is required'
      });
    }

    const result = await callOpenAlex(query);
    const latency = Date.now() - startTime;

    await logRequest({
      userId,
      service: 'openalex',
      endpoint: '/proxy/external/openalex',
      method: 'GET',
      statusCode: result.status,
      latency,
      success: result.success,
      errorMessage: result.error?.message
    });

    if (!result.success) {
      return res.status(result.status || 500).json({
        success: false,
        error: result.error?.message || 'API request failed'
      });
    }

    res.json({
      success: true,
      data: result.data,
      latency
    });
  } catch (error) {
    console.error('❌ OpenAlex proxy error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * @route   GET /proxy/external/gdelt
 * @desc    GDELT API Proxy (뉴스 이벤트 데이터)
 * @access  Public
 */
router.get('/gdelt', optionalAuth, async (req, res) => {
  const startTime = Date.now();
  const userId = req.userId || null;

  try {
    const { query } = req.query;

    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter is required'
      });
    }

    const result = await callGDELT(query);
    const latency = Date.now() - startTime;

    await logRequest({
      userId,
      service: 'gdelt',
      endpoint: '/proxy/external/gdelt',
      method: 'GET',
      statusCode: result.status,
      latency,
      success: result.success,
      errorMessage: result.error?.message
    });

    if (!result.success) {
      return res.status(result.status || 500).json({
        success: false,
        error: result.error?.message || 'API request failed'
      });
    }

    res.json({
      success: true,
      data: result.data,
      latency
    });
  } catch (error) {
    console.error('❌ GDELT proxy error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * @route   GET /proxy/external/wikidata
 * @desc    Wikidata SPARQL Proxy (지식 그래프 검색)
 * @access  Public
 */
router.get('/wikidata', optionalAuth, async (req, res) => {
  const startTime = Date.now();
  const userId = req.userId || null;

  try {
    const { query } = req.query;

    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter is required'
      });
    }

    const result = await callWikidata(query);
    const latency = Date.now() - startTime;

    await logRequest({
      userId,
      service: 'wikidata',
      endpoint: '/proxy/external/wikidata',
      method: 'GET',
      statusCode: result.status,
      latency,
      success: result.success,
      errorMessage: result.error?.message
    });

    if (!result.success) {
      return res.status(result.status || 500).json({
        success: false,
        error: result.error?.message || 'API request failed'
      });
    }

    res.json({
      success: true,
      data: result.data,
      latency
    });
  } catch (error) {
    console.error('❌ Wikidata proxy error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * @route   GET /proxy/external/naver
 * @desc    Naver Search API Proxy (뉴스 검색 - Whitelist 필터링)
 * @access  Private
 */
router.get('/naver', authenticate, async (req, res) => {
  const startTime = Date.now();
  const userId = req.userId;

  try {
    const { query, display = 10 } = req.query;

    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter is required'
      });
    }

    // Naver API Key 조회 (복호화)
    const keyResult = await dbQuery(`
      SELECT encrypted_key, iv, auth_tag
      FROM api_keys
      WHERE user_id = $1
        AND service = 'naver'
        AND is_active = true
      LIMIT 1
    `, [userId]);

    if (keyResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Naver API key not found. Please register your Naver API credentials first.'
      });
    }

    const keyData = keyResult.rows[0];
    const credentials = JSON.parse(decrypt(keyData.encrypted_key, keyData.iv, keyData.auth_tag));

    // Naver API 호출
    const result = await callNaver(credentials.clientId, credentials.clientSecret, query, display);
    const latency = Date.now() - startTime;

    // Latency 로깅
    await logNaverLatency(latency, { query, display });

    await logRequest({
      userId,
      service: 'naver',
      endpoint: '/proxy/external/naver',
      method: 'GET',
      statusCode: result.status,
      latency,
      success: result.success,
      errorMessage: result.error?.message
    });

    if (!result.success) {
      return res.status(result.status || 500).json({
        success: false,
        error: result.error?.message || 'API request failed'
      });
    }

    // Whitelist 필터링
    const filteredData = await filterNaverByWhitelist(result.data);

    res.json({
      success: true,
      data: filteredData,
      latency,
      filtered: result.data.items?.length !== filteredData.items?.length
    });
  } catch (error) {
    console.error('❌ Naver proxy error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Naver 검색 결과를 Whitelist로 필터링
 * @param {object} data - Naver API 응답 데이터
 * @returns {Promise<object>} - 필터링된 데이터
 */
async function filterNaverByWhitelist(data) {
  try {
    if (!data.items || data.items.length === 0) {
      return data;
    }

    // Whitelist 조회
    const whitelistResult = await dbQuery(`
      SELECT domain, q_score
      FROM nav_whitelist
      WHERE active = true
    `);

    const whitelist = new Set(whitelistResult.rows.map(row => row.domain));
    const qScores = {};
    whitelistResult.rows.forEach(row => {
      qScores[row.domain] = row.q_score;
    });

    // 필터링 및 Q 스코어 추가
    const filteredItems = data.items
      .filter(item => {
        try {
          const url = new URL(item.link);
          const domain = url.hostname.replace('www.', '');
          return whitelist.has(domain);
        } catch {
          return false;
        }
      })
      .map(item => {
        try {
          const url = new URL(item.link);
          const domain = url.hostname.replace('www.', '');
          return {
            ...item,
            domain,
            qScore: qScores[domain] || 0.5
          };
        } catch {
          return { ...item, qScore: 0.5 };
        }
      });

    return {
      ...data,
      total: filteredItems.length,
      items: filteredItems,
      originalTotal: data.total
    };
  } catch (error) {
    console.error('❌ Whitelist filtering error:', error);
    return data;
  }
}

/**
 * @route   POST /proxy/external/batch
 * @desc    병렬 배치 검증 (Core Logic Engine)
 * @access  Private
 */
router.post('/batch', authenticate, async (req, res) => {
  const startTime = Date.now();
  const userId = req.userId;

  try {
    const { query, engines = [] } = req.body;

    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter is required'
      });
    }

    // 요청할 엔진 설정
    const requests = [];

    if (engines.includes('crossref')) {
      requests.push({
        engine: 'crossref',
        call: () => callCrossRef(query)
      });
    }

    if (engines.includes('openalex')) {
      requests.push({
        engine: 'openalex',
        call: () => callOpenAlex(query)
      });
    }

    if (engines.includes('gdelt')) {
      requests.push({
        engine: 'gdelt',
        call: () => callGDELT(query)
      });
    }

    if (engines.includes('wikidata')) {
      requests.push({
        engine: 'wikidata',
        call: () => callWikidata(query)
      });
    }

    // 병렬 실행
    const results = await Promise.allSettled(
      requests.map(req => req.call())
    );

    // 결과 정리
    const batchResults = {};
    requests.forEach((req, index) => {
      const result = results[index];
      batchResults[req.engine] = {
        success: result.status === 'fulfilled' && result.value.success,
        data: result.status === 'fulfilled' ? result.value.data : null,
        error: result.status === 'rejected' ? result.reason : result.value?.error
      };
    });

    const latency = Date.now() - startTime;

    res.json({
      success: true,
      results: batchResults,
      latency,
      query
    });
  } catch (error) {
    console.error('❌ Batch proxy error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * @route   POST /proxy/external/naver/keys
 * @desc    Naver API Key 등록
 * @access  Private
 */
router.post('/naver/keys', authenticate, async (req, res) => {
  try {
    const userId = req.userId;
    const { clientId, clientSecret } = req.body;

    if (!clientId || !clientSecret) {
      return res.status(400).json({
        success: false,
        error: 'Both clientId and clientSecret are required'
      });
    }

    // 암호화
    const { encrypt } = require('../utils/encrypt');
    const credentials = JSON.stringify({ clientId, clientSecret });
    const { encryptedData, iv, authTag } = encrypt(credentials);

    // DB에 저장
    await dbQuery(`
      INSERT INTO api_keys (user_id, service, encrypted_key, iv, auth_tag, key_index)
      VALUES ($1, 'naver', $2, $3, $4, 1)
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
      message: 'Naver API credentials registered successfully'
    });
  } catch (error) {
    console.error('❌ Register Naver key error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to register API credentials'
    });
  }
});

module.exports = router;
