const axios = require('axios');

/**
 * 검증 엔진 통합 모듈
 * CrossRef, OpenAlex, GDELT, Wikidata, GitHub, K-Law
 */

// 출처 공신력(Quality) 기본값
const DEFAULT_QUALITY = {
  crossref: 0.95,      // 학술 데이터베이스 - 매우 높음
  openalex: 0.90,      // 오픈 학술 그래프
  gdelt: 0.85,         // 글로벌 이벤트 데이터
  wikidata: 0.80,      // 위키데이터
  github: 0.75,        // 코드 검증
  klaw: 0.95          // 법령 정보 - 매우 높음
};

/**
 * CrossRef API 검증
 * @param {string} query - 검색 쿼리
 * @returns {Object} 검증 결과
 */
async function verifyCrossRef(query) {
  try {
    const response = await axios.get('https://api.crossref.org/works', {
      params: {
        query: query,
        rows: 5
      },
      timeout: 5000
    });

    if (response.data && response.data.message && response.data.message.items) {
      const items = response.data.message.items;
      return {
        success: true,
        sourceDetected: items.length > 0,
        count: items.length,
        sources: items.slice(0, 3).map(item => ({
          title: item.title?.[0] || 'N/A',
          doi: item.DOI,
          year: item.published?.['date-parts']?.[0]?.[0] || 'N/A',
          relevance: item.score || 0
        })),
        quality: DEFAULT_QUALITY.crossref
      };
    }

    return { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.crossref };
  } catch (error) {
    console.error('CrossRef verification error:', error.message);
    return { success: false, sourceDetected: false, error: error.message, quality: DEFAULT_QUALITY.crossref };
  }
}

/**
 * OpenAlex API 검증
 * @param {string} query - 검색 쿼리
 * @returns {Object} 검증 결과
 */
async function verifyOpenAlex(query) {
  try {
    const response = await axios.get('https://api.openalex.org/works', {
      params: {
        search: query,
        per_page: 5
      },
      timeout: 5000
    });

    if (response.data && response.data.results) {
      const results = response.data.results;
      return {
        success: true,
        sourceDetected: results.length > 0,
        count: results.length,
        sources: results.slice(0, 3).map(item => ({
          title: item.title || 'N/A',
          id: item.id,
          year: item.publication_year || 'N/A',
          citationCount: item.cited_by_count || 0
        })),
        quality: DEFAULT_QUALITY.openalex
      };
    }

    return { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.openalex };
  } catch (error) {
    console.error('OpenAlex verification error:', error.message);
    return { success: false, sourceDetected: false, error: error.message, quality: DEFAULT_QUALITY.openalex };
  }
}

/**
 * GDELT API 검증
 * @param {string} query - 검색 쿼리
 * @returns {Object} 검증 결과
 */
async function verifyGDELT(query) {
  try {
    // GDELT Doc 2.0 API
    const response = await axios.get('https://api.gdeltproject.org/api/v2/doc/doc', {
      params: {
        query: query,
        mode: 'artlist',
        maxrecords: 5,
        format: 'json'
      },
      timeout: 5000
    });

    if (response.data && response.data.articles) {
      const articles = response.data.articles;
      return {
        success: true,
        sourceDetected: articles.length > 0,
        count: articles.length,
        sources: articles.slice(0, 3).map(item => ({
          title: item.title || 'N/A',
          url: item.url,
          date: item.seendate || 'N/A',
          domain: item.domain || 'N/A'
        })),
        quality: DEFAULT_QUALITY.gdelt
      };
    }

    return { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.gdelt };
  } catch (error) {
    console.error('GDELT verification error:', error.message);
    return { success: false, sourceDetected: false, error: error.message, quality: DEFAULT_QUALITY.gdelt };
  }
}

/**
 * Wikidata API 검증
 * @param {string} query - 검색 쿼리
 * @returns {Object} 검증 결과
 */
async function verifyWikidata(query) {
  try {
    const response = await axios.get('https://www.wikidata.org/w/api.php', {
      params: {
        action: 'wbsearchentities',
        search: query,
        language: 'en',
        format: 'json',
        limit: 5
      },
      timeout: 5000
    });

    if (response.data && response.data.search) {
      const results = response.data.search;
      return {
        success: true,
        sourceDetected: results.length > 0,
        count: results.length,
        sources: results.slice(0, 3).map(item => ({
          label: item.label || 'N/A',
          id: item.id,
          description: item.description || 'N/A'
        })),
        quality: DEFAULT_QUALITY.wikidata
      };
    }

    return { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.wikidata };
  } catch (error) {
    console.error('Wikidata verification error:', error.message);
    return { success: false, sourceDetected: false, error: error.message, quality: DEFAULT_QUALITY.wikidata };
  }
}

/**
 * GitHub API 검증
 * @param {string} query - 검색 쿼리
 * @param {string} apiToken - GitHub API Token (선택)
 * @returns {Object} 검증 결과
 */
async function verifyGitHub(query, apiToken = null) {
  try {
    const headers = apiToken 
      ? { 'Authorization': `token ${apiToken}` }
      : {};

    const response = await axios.get('https://api.github.com/search/repositories', {
      params: {
        q: query,
        per_page: 5,
        sort: 'stars'
      },
      headers,
      timeout: 5000
    });

    if (response.data && response.data.items) {
      const items = response.data.items;
      return {
        success: true,
        sourceDetected: items.length > 0,
        count: items.length,
        sources: items.slice(0, 3).map(item => ({
          name: item.name || 'N/A',
          fullName: item.full_name,
          url: item.html_url,
          stars: item.stargazers_count || 0,
          description: item.description || 'N/A'
        })),
        quality: DEFAULT_QUALITY.github
      };
    }

    return { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.github };
  } catch (error) {
    console.error('GitHub verification error:', error.message);
    return { success: false, sourceDetected: false, error: error.message, quality: DEFAULT_QUALITY.github };
  }
}

/**
 * K-Law API 검증 (Mock - 실제 API는 인증 필요)
 * @param {string} query - 검색 쿼리
 * @param {string} apiKey - K-Law API Key (선택)
 * @returns {Object} 검증 결과
 */
async function verifyKLaw(query, apiKey = null) {
  try {
    // 실제 K-Law API 엔드포인트는 인증 및 정확한 URL 필요
    // 여기서는 Mock 데이터 반환
    
    // 실제 구현 시:
    // const response = await axios.get('https://www.law.go.kr/DRF/lawSearch.do', {
    //   params: {
    //     OC: apiKey,
    //     target: 'law',
    //     query: query,
    //     type: 'JSON'
    //   },
    //   timeout: 5000
    // });

    // Mock response
    if (query && query.trim().length > 0) {
      return {
        success: true,
        sourceDetected: true,
        count: 1,
        sources: [{
          title: `관련 법령: ${query}`,
          lawId: 'mock-law-id',
          type: 'law',
          relevance: 0.85
        }],
        quality: DEFAULT_QUALITY.klaw,
        note: 'Mock data - 실제 API Key 필요'
      };
    }

    return { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.klaw };
  } catch (error) {
    console.error('K-Law verification error:', error.message);
    return { success: false, sourceDetected: false, error: error.message, quality: DEFAULT_QUALITY.klaw };
  }
}

/**
 * 모든 엔진 병렬 검증
 * @param {string} query - 검색 쿼리
 * @param {Object} apiKeys - API Keys 객체
 * @returns {Object} 통합 검증 결과
 */
async function verifyAll(query, apiKeys = {}) {
  const startTime = Date.now();

  try {
    const [crossref, openalex, gdelt, wikidata, github, klaw] = await Promise.allSettled([
      verifyCrossRef(query),
      verifyOpenAlex(query),
      verifyGDELT(query),
      verifyWikidata(query),
      verifyGitHub(query, apiKeys.github),
      verifyKLaw(query, apiKeys.klaw)
    ]);

    const results = {
      crossref: crossref.status === 'fulfilled' ? crossref.value : { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.crossref },
      openalex: openalex.status === 'fulfilled' ? openalex.value : { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.openalex },
      gdelt: gdelt.status === 'fulfilled' ? gdelt.value : { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.gdelt },
      wikidata: wikidata.status === 'fulfilled' ? wikidata.value : { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.wikidata },
      github: github.status === 'fulfilled' ? github.value : { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.github },
      klaw: klaw.status === 'fulfilled' ? klaw.value : { success: false, sourceDetected: false, quality: DEFAULT_QUALITY.klaw }
    };

    const endTime = Date.now();
    const duration = endTime - startTime;

    return {
      success: true,
      results,
      metadata: {
        duration: `${duration}ms`,
        timestamp: new Date().toISOString(),
        activeEngines: Object.values(results).filter(r => r.sourceDetected).length
      }
    };
  } catch (error) {
    console.error('Verification error:', error);
    return {
      success: false,
      error: error.message,
      metadata: {
        timestamp: new Date().toISOString()
      }
    };
  }
}

module.exports = {
  verifyCrossRef,
  verifyOpenAlex,
  verifyGDELT,
  verifyWikidata,
  verifyGitHub,
  verifyKLaw,
  verifyAll,
  DEFAULT_QUALITY
};
