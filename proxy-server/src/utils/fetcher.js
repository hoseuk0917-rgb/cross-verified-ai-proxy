// src/utils/fetcher.js
const axios = require('axios');
const axiosRetry = require('axios-retry').default;
const xml2js = require('xml2js');

// Axios 기본 설정
const axiosInstance = axios.create({
  timeout: 30000, // 30초 타임아웃
  headers: {
    'User-Agent': 'Cross-Verified-AI/9.8.4',
    'Accept': 'application/json, text/xml'
  }
});

// 재시도 로직 설정
axiosRetry(axiosInstance, {
  retries: 3,
  retryDelay: axiosRetry.exponentialDelay,
  retryCondition: (error) => {
    // 네트워크 에러 또는 5xx 에러인 경우 재시도
    return axiosRetry.isNetworkOrIdempotentRequestError(error) ||
           (error.response && error.response.status >= 500);
  },
  onRetry: (retryCount, error, requestConfig) => {
    console.log(`🔄 Retry attempt ${retryCount} for ${requestConfig.url}`);
  }
});

/**
 * API 요청 수행 (재시도 로직 포함)
 * @param {object} config - Axios 설정 객체
 * @returns {Promise<object>} - { success, data, error, latency }
 */
async function fetchWithRetry(config) {
  const startTime = Date.now();
  
  try {
    const response = await axiosInstance(config);
    const latency = Date.now() - startTime;
    
    return {
      success: true,
      data: response.data,
      status: response.status,
      headers: response.headers,
      latency,
      error: null
    };
  } catch (error) {
    const latency = Date.now() - startTime;
    
    return {
      success: false,
      data: null,
      status: error.response?.status || 0,
      error: {
        message: error.message,
        code: error.code,
        response: error.response?.data
      },
      latency
    };
  }
}

/**
 * JSON 또는 XML 응답 파싱
 * @param {string|object} data - 응답 데이터
 * @param {string} contentType - Content-Type 헤더
 * @returns {Promise<object>} - 파싱된 JSON 객체
 */
async function parseResponse(data, contentType = '') {
  // 이미 객체인 경우
  if (typeof data === 'object' && data !== null) {
    return data;
  }

  // XML 응답 처리
  if (contentType.includes('xml') || (typeof data === 'string' && data.trim().startsWith('<'))) {
    try {
      const parser = new xml2js.Parser({
        explicitArray: false,
        ignoreAttrs: false,
        mergeAttrs: true
      });
      return await parser.parseStringPromise(data);
    } catch (error) {
      console.error('❌ XML parsing error:', error);
      throw new Error('Failed to parse XML response');
    }
  }

  // JSON 응답 처리
  if (typeof data === 'string') {
    try {
      return JSON.parse(data);
    } catch (error) {
      console.error('❌ JSON parsing error:', error);
      throw new Error('Failed to parse JSON response');
    }
  }

  return data;
}

/**
 * 병렬 API 호출 (Promise.all)
 * @param {Array<object>} requests - 요청 설정 배열
 * @returns {Promise<Array<object>>} - 결과 배열
 */
async function fetchParallel(requests) {
  const promises = requests.map(config => fetchWithRetry(config));
  return await Promise.all(promises);
}

/**
 * 순차 API 호출 (하나씩 실행)
 * @param {Array<object>} requests - 요청 설정 배열
 * @returns {Promise<Array<object>>} - 결과 배열
 */
async function fetchSequential(requests) {
  const results = [];
  for (const config of requests) {
    const result = await fetchWithRetry(config);
    results.push(result);
  }
  return results;
}

/**
 * Gemini API 호출
 * @param {string} apiKey - Gemini API 키
 * @param {string} model - 모델명 (gemini-2.0-flash-exp, gemini-pro 등)
 * @param {object} payload - 요청 페이로드
 * @returns {Promise<object>} - 응답 결과
 */
async function callGemini(apiKey, model, payload) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  
  return await fetchWithRetry({
    method: 'POST',
    url,
    data: payload,
    headers: {
      'Content-Type': 'application/json'
    }
  });
}

/**
 * K-Law API 호출
 * @param {string} target - 대상 API (law, statute, precedent 등)
 * @param {object} params - 쿼리 파라미터
 * @returns {Promise<object>} - 응답 결과
 */
async function callKLaw(target, params) {
  const baseUrl = 'https://www.law.go.kr/DRF/lawService.do';
  
  return await fetchWithRetry({
    method: 'GET',
    url: baseUrl,
    params: {
      target,
      type: 'JSON',
      ...params
    }
  });
}

/**
 * CrossRef API 호출
 * @param {string} query - 검색 쿼리
 * @param {string} email - 사용자 이메일 (Polite Pool 용)
 * @returns {Promise<object>} - 응답 결과
 */
async function callCrossRef(query, email = '') {
  const url = 'https://api.crossref.org/works';
  
  return await fetchWithRetry({
    method: 'GET',
    url,
    params: {
      query,
      rows: 10,
      mailto: email || undefined
    }
  });
}

/**
 * OpenAlex API 호출
 * @param {string} query - 검색 쿼리
 * @returns {Promise<object>} - 응답 결과
 */
async function callOpenAlex(query) {
  const url = 'https://api.openalex.org/works';
  
  return await fetchWithRetry({
    method: 'GET',
    url,
    params: {
      search: query,
      per_page: 10
    }
  });
}

/**
 * GDELT API 호출
 * @param {string} query - 검색 쿼리
 * @returns {Promise<object>} - 응답 결과
 */
async function callGDELT(query) {
  const url = 'https://api.gdeltproject.org/api/v2/doc/doc';
  
  return await fetchWithRetry({
    method: 'GET',
    url,
    params: {
      query,
      mode: 'artlist',
      maxrecords: 10,
      format: 'json'
    }
  });
}

/**
 * Wikidata SPARQL 호출
 * @param {string} query - SPARQL 쿼리
 * @returns {Promise<object>} - 응답 결과
 */
async function callWikidata(query) {
  const url = 'https://query.wikidata.org/sparql';
  
  return await fetchWithRetry({
    method: 'GET',
    url,
    params: {
      query,
      format: 'json'
    },
    headers: {
      'Accept': 'application/sparql-results+json'
    }
  });
}

/**
 * Naver Search API 호출
 * @param {string} clientId - Naver API Client ID
 * @param {string} clientSecret - Naver API Client Secret
 * @param {string} query - 검색 쿼리
 * @param {number} display - 검색 결과 개수 (기본 10)
 * @returns {Promise<object>} - 응답 결과
 */
async function callNaver(clientId, clientSecret, query, display = 10) {
  const url = 'https://openapi.naver.com/v1/search/news.json';
  
  return await fetchWithRetry({
    method: 'GET',
    url,
    params: {
      query,
      display,
      sort: 'sim' // 정확도순
    },
    headers: {
      'X-Naver-Client-Id': clientId,
      'X-Naver-Client-Secret': clientSecret
    }
  });
}

/**
 * GitHub API 호출
 * @param {string} token - GitHub Personal Access Token
 * @param {string} endpoint - API 엔드포인트
 * @param {object} params - 쿼리 파라미터
 * @returns {Promise<object>} - 응답 결과
 */
async function callGitHub(token, endpoint, params = {}) {
  const url = `https://api.github.com${endpoint}`;
  
  return await fetchWithRetry({
    method: 'GET',
    url,
    params,
    headers: {
      'Authorization': `token ${token}`,
      'Accept': 'application/vnd.github.v3+json'
    }
  });
}

module.exports = {
  fetchWithRetry,
  parseResponse,
  fetchParallel,
  fetchSequential,
  callGemini,
  callKLaw,
  callCrossRef,
  callOpenAlex,
  callGDELT,
  callWikidata,
  callNaver,
  callGitHub
};
