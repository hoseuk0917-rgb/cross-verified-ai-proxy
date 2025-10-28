// src/utils/logger.js
const { query } = require('./db');

/**
 * Request 로그 기록
 * @param {object} logData - 로그 데이터
 */
async function logRequest(logData) {
  try {
    const {
      userId = null,
      service,
      endpoint,
      method = 'GET',
      statusCode = 0,
      latency = 0,
      requestSize = 0,
      responseSize = 0,
      success = false,
      errorMessage = null
    } = logData;

    await query(`
      INSERT INTO request_logs (
        user_id, service, endpoint, method, status_code,
        latency_ms, request_size, response_size, success, error_message
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [
      userId, service, endpoint, method, statusCode,
      Math.round(latency), requestSize, responseSize, success, errorMessage
    ]);
  } catch (error) {
    console.error('❌ Failed to log request:', error);
  }
}

/**
 * Audit 로그 기록 (보안 감사용)
 * @param {object} auditData - 감사 로그 데이터
 */
async function logAudit(auditData) {
  try {
    const {
      userId = null,
      action,
      resource = null,
      details = {},
      ipAddress = null,
      userAgent = null,
      success = true
    } = auditData;

    await query(`
      INSERT INTO audit_logs (
        user_id, action, resource, details, ip_address, user_agent, success
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [
      userId, action, resource, JSON.stringify(details), ipAddress, userAgent, success
    ]);
  } catch (error) {
    console.error('❌ Failed to log audit:', error);
  }
}

/**
 * Monitoring 로그 기록 (성능 메트릭용)
 * @param {object} metricData - 메트릭 데이터
 */
async function logMetric(metricData) {
  try {
    const {
      service,
      metricName,
      metricValue,
      unit = 'ms',
      metadata = {}
    } = metricData;

    await query(`
      INSERT INTO monitoring_logs (
        service, metric_name, metric_value, unit, metadata
      )
      VALUES ($1, $2, $3, $4, $5)
    `, [
      service, metricName, metricValue, unit, JSON.stringify(metadata)
    ]);
  } catch (error) {
    console.error('❌ Failed to log metric:', error);
  }
}

/**
 * Naver API Latency 로깅
 * @param {number} latency - 응답 시간 (ms)
 * @param {object} metadata - 추가 메타데이터
 */
async function logNaverLatency(latency, metadata = {}) {
  await logMetric({
    service: 'naver',
    metricName: 'nav_api_latency',
    metricValue: latency,
    unit: 'ms',
    metadata
  });
}

/**
 * API 호출 성공률 계산
 * @param {string} service - 서비스명
 * @param {number} hours - 기간 (시간)
 * @returns {Promise<object>} - { successRate, totalCalls, successfulCalls }
 */
async function getSuccessRate(service, hours = 24) {
  try {
    const result = await query(`
      SELECT 
        COUNT(*) as total_calls,
        SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful_calls,
        ROUND(
          100.0 * SUM(CASE WHEN success THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0),
          2
        ) as success_rate
      FROM request_logs
      WHERE service = $1
        AND created_at > NOW() - INTERVAL '${hours} hours'
    `, [service]);

    return result.rows[0] || { total_calls: 0, successful_calls: 0, success_rate: 0 };
  } catch (error) {
    console.error('❌ Failed to get success rate:', error);
    return { total_calls: 0, successful_calls: 0, success_rate: 0 };
  }
}

/**
 * 평균 응답 시간 계산
 * @param {string} service - 서비스명
 * @param {number} hours - 기간 (시간)
 * @returns {Promise<number>} - 평균 응답 시간 (ms)
 */
async function getAverageLatency(service, hours = 24) {
  try {
    const result = await query(`
      SELECT ROUND(AVG(latency_ms), 2) as avg_latency
      FROM request_logs
      WHERE service = $1
        AND success = true
        AND created_at > NOW() - INTERVAL '${hours} hours'
    `, [service]);

    return result.rows[0]?.avg_latency || 0;
  } catch (error) {
    console.error('❌ Failed to get average latency:', error);
    return 0;
  }
}

/**
 * Naver Whitelist 통계
 * @returns {Promise<object>} - Whitelist 통계
 */
async function getWhitelistStats() {
  try {
    const result = await query(`
      SELECT 
        tier,
        COUNT(*) as count,
        AVG(q_score) as avg_q_score,
        SUM(CASE WHEN active THEN 1 ELSE 0 END) as active_count
      FROM nav_whitelist
      GROUP BY tier
      ORDER BY tier
    `);

    return result.rows;
  } catch (error) {
    console.error('❌ Failed to get whitelist stats:', error);
    return [];
  }
}

/**
 * 서비스 상태 체크
 * @returns {Promise<object>} - 전체 서비스 상태
 */
async function getSystemHealth() {
  try {
    const services = ['gemini', 'klaw', 'crossref', 'openalex', 'gdelt', 'wikidata', 'naver', 'github'];
    const health = {};

    for (const service of services) {
      const stats = await getSuccessRate(service, 1); // 최근 1시간
      const avgLatency = await getAverageLatency(service, 1);

      health[service] = {
        successRate: stats.success_rate,
        totalCalls: stats.total_calls,
        avgLatency,
        status: stats.success_rate >= 90 ? 'healthy' : stats.success_rate >= 70 ? 'degraded' : 'unhealthy'
      };
    }

    return health;
  } catch (error) {
    console.error('❌ Failed to get system health:', error);
    return {};
  }
}

/**
 * 콘솔 로거 (색상 포함)
 */
const logger = {
  info: (message, data = null) => {
    console.log(`ℹ️  ${message}`, data || '');
  },
  success: (message, data = null) => {
    console.log(`✅ ${message}`, data || '');
  },
  warning: (message, data = null) => {
    console.warn(`⚠️  ${message}`, data || '');
  },
  error: (message, error = null) => {
    console.error(`❌ ${message}`, error || '');
  },
  debug: (message, data = null) => {
    if (process.env.NODE_ENV === 'development') {
      console.log(`🐛 ${message}`, data || '');
    }
  }
};

module.exports = {
  logRequest,
  logAudit,
  logMetric,
  logNaverLatency,
  getSuccessRate,
  getAverageLatency,
  getWhitelistStats,
  getSystemHealth,
  logger
};
