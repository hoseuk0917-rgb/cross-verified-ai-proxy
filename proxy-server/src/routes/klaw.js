// src/routes/klaw.js
const express = require('express');
const { authenticate, optionalAuth } = require('../middleware/auth');
const { callKLaw } = require('../utils/fetcher');
const { logRequest } = require('../utils/logger');

const router = express.Router();

/**
 * @route   GET /proxy/klaw/:target
 * @desc    K-Law API Proxy
 * @access  Public (선택적 인증)
 * 
 * 지원되는 target:
 * - law: 법령 검색
 * - statute: 법률 조문 검색
 * - precedent: 판례 검색
 * - adminRul: 행정규칙 검색
 */
router.get('/:target', optionalAuth, async (req, res) => {
  const startTime = Date.now();
  const { target } = req.params;
  const userId = req.userId || null;

  try {
    // 유효한 target 체크
    const validTargets = ['law', 'statute', 'precedent', 'adminRul'];
    if (!validTargets.includes(target)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid target. Must be one of: law, statute, precedent, adminRul'
      });
    }

    // 쿼리 파라미터 추출
    const {
      query: searchQuery,
      display = 10,
      page = 1,
      sort = 'lnsCd',
      ...otherParams
    } = req.query;

    if (!searchQuery) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter is required'
      });
    }

    // K-Law API 호출
    const result = await callKLaw(target, {
      query: searchQuery,
      display,
      page,
      sort,
      ...otherParams
    });

    const latency = Date.now() - startTime;

    // 요청 로그 기록
    await logRequest({
      userId,
      service: 'klaw',
      endpoint: `/proxy/klaw/${target}`,
      method: 'GET',
      statusCode: result.status,
      latency,
      requestSize: JSON.stringify(req.query).length,
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

    // 응답 데이터 정규화
    const normalizedData = normalizeKLawResponse(result.data, target);

    res.json({
      success: true,
      data: normalizedData,
      latency,
      target,
      query: searchQuery
    });

  } catch (error) {
    console.error('❌ K-Law proxy error:', error);

    const latency = Date.now() - startTime;

    await logRequest({
      userId,
      service: 'klaw',
      endpoint: `/proxy/klaw/${target}`,
      method: 'GET',
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
 * K-Law API 응답 정규화
 * @param {object} data - 원본 응답 데이터
 * @param {string} target - API 타겟
 * @returns {object} - 정규화된 데이터
 */
function normalizeKLawResponse(data, target) {
  try {
    // K-Law API는 XML을 JSON으로 변환한 형태로 반환됨
    // 응답 구조를 정규화하여 일관된 형태로 변환

    if (!data) {
      return {
        total: 0,
        items: []
      };
    }

    let items = [];
    let total = 0;

    switch (target) {
      case 'law':
        // 법령 검색 결과
        if (data.LawSearch) {
          total = parseInt(data.LawSearch.totalCnt) || 0;
          const laws = data.LawSearch.law;
          
          if (laws) {
            items = Array.isArray(laws) ? laws : [laws];
            items = items.map(law => ({
              lawId: law.법령ID,
              lawName: law.법령명한글,
              lawNameEng: law.법령명영문,
              lawType: law.법령구분명,
              promulgationDate: law.공포일자,
              enforcementDate: law.시행일자,
              lawContent: law.법령내용 || null
            }));
          }
        }
        break;

      case 'statute':
        // 법률 조문 검색 결과
        if (data.StatuteSearch) {
          total = parseInt(data.StatuteSearch.totalCnt) || 0;
          const statutes = data.StatuteSearch.statute;
          
          if (statutes) {
            items = Array.isArray(statutes) ? statutes : [statutes];
            items = items.map(statute => ({
              lawId: statute.법령ID,
              lawName: statute.법령명한글,
              articleNo: statute.조문번호,
              articleTitle: statute.조문제목,
              articleContent: statute.조문내용
            }));
          }
        }
        break;

      case 'precedent':
        // 판례 검색 결과
        if (data.PrecedentSearch) {
          total = parseInt(data.PrecedentSearch.totalCnt) || 0;
          const precedents = data.PrecedentSearch.precedent;
          
          if (precedents) {
            items = Array.isArray(precedents) ? precedents : [precedents];
            items = items.map(prec => ({
              caseId: prec.판례일련번호,
              caseName: prec.사건명,
              caseNumber: prec.사건번호,
              judgmentDate: prec.선고일자,
              courtName: prec.법원명,
              caseType: prec.사건종류명,
              judgmentSummary: prec.판시사항 || null
            }));
          }
        }
        break;

      case 'adminRul':
        // 행정규칙 검색 결과
        if (data.AdminRulSearch) {
          total = parseInt(data.AdminRulSearch.totalCnt) || 0;
          const rules = data.AdminRulSearch.adminRul;
          
          if (rules) {
            items = Array.isArray(rules) ? rules : [rules];
            items = items.map(rule => ({
              ruleId: rule.행정규칙ID,
              ruleName: rule.행정규칙명,
              ruleType: rule.행정규칙구분명,
              issueAgency: rule.발령기관명,
              issueDate: rule.발령일자,
              enforcementDate: rule.시행일자
            }));
          }
        }
        break;
    }

    return {
      total,
      items,
      count: items.length
    };

  } catch (error) {
    console.error('❌ K-Law response normalization error:', error);
    return {
      total: 0,
      items: [],
      error: 'Failed to parse response'
    };
  }
}

/**
 * @route   GET /proxy/klaw/health
 * @desc    K-Law API 상태 확인
 * @access  Public
 */
router.get('/health/check', async (req, res) => {
  try {
    const result = await callKLaw('law', {
      query: '헌법',
      display: 1
    });

    res.json({
      success: result.success,
      status: result.success ? 'healthy' : 'unhealthy',
      latency: result.latency
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      status: 'unhealthy',
      error: error.message
    });
  }
});

module.exports = router;
