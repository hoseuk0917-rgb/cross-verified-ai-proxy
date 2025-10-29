/**
 * verification.js
 * Cross-Verified AI Proxy - Multi-engine Verification Module
 * v10.2 stable (Naver whitelist, async-safe)
 */

const axios = require("axios");

// 안전 실행 래퍼 (각 엔진이 실패해도 서버 전체 영향 X)
async function safeFetch(fetchFn, engineName) {
  try {
    const result = await fetchFn();
    return { engine: engineName, success: true, hits: result?.hits || 0, data: result?.data || [] };
  } catch (err) {
    console.error(`[${engineName}] Error:`, err.message);
    return { engine: engineName, success: false, error: err.message };
  }
}

/* ============================
   외부 검증 엔진별 개별 함수
   ============================ */

async function crossrefSearch(query) {
  const url = `https://api.crossref.org/works?query=${encodeURIComponent(query)}&rows=3`;
  const res = await axios.get(url);
  return { hits: res.data.message.items.length, data: res.data.message.items };
}

async function openalexSearch(query) {
  const url = `https://api.openalex.org/works?search=${encodeURIComponent(query)}`;
  const res = await axios.get(url);
  return { hits: res.data.results.length, data: res.data.results };
}

async function gdeltSearch(query) {
  const url = `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(query)}&maxrecords=3&format=json`;
  const res = await axios.get(url);
  return { hits: res.data.articles?.length || 0, data: res.data.articles || [] };
}

async function wikidataSearch(query) {
  const url = `https://www.wikidata.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(query)}&format=json`;
  const res = await axios.get(url);
  return { hits: res.data.query.search.length, data: res.data.query.search };
}

// ✅ GitHub API (사용자 입력 토큰 기반)
async function githubSearch(query, token) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}+in:name,description&per_page=3`;
  const res = await axios.get(url, { headers });
  return { hits: res.data.items.length, data: res.data.items };
}

// ✅ Naver API (뉴스 + 화이트리스트 필터)
async function naverSearch(query, clientId, clientSecret) {
  const url = `https://openapi.naver.com/v1/search/news.json?query=${encodeURIComponent(query)}&display=10`;
  const headers = { "X-Naver-Client-Id": clientId, "X-Naver-Client-Secret": clientSecret };
  const res = await axios.get(url, { headers });

  // ✅ 화이트리스트 (월별 갱신, DB 연동됨)
  const whitelist = [
    "연합뉴스", "KBS", "MBC", "SBS", "JTBC", "YTN", "한국경제", "매일경제", "서울경제",
    "조선일보", "중앙일보", "동아일보", "한겨레", "경향신문", "머니투데이", "뉴스1",
  ];

  const filtered = res.data.items.filter(item =>
    whitelist.some(name => item?.originallink?.includes(name) || item?.description?.includes(name))
  );

  return { hits: filtered.length, data: filtered };
}

// ✅ K-Law API (사용자 입력 아이디 기반)
async function klawSearch(query, userId) {
  const url = `https://www.k-law.kr/openapi/${userId}/lawSearch.do?q=${encodeURIComponent(query)}`;
  const res = await axios.get(url);
  return { hits: res.data?.results?.length || 0, data: res.data?.results || [] };
}

/* ============================
   병렬 통합 검증 (verifyAll)
   ============================ */
async function verifyAllEngines({
  query,
  githubToken,
  naverClientId,
  naverClientSecret,
  klawUserId
}) {
  console.log(`[verifyAll] Running multi-engine verification for query="${query}"`);

  const engines = [
    safeFetch(() => crossrefSearch(query), "CrossRef"),
    safeFetch(() => openalexSearch(query), "OpenAlex"),
    safeFetch(() => gdeltSearch(query), "GDELT"),
    safeFetch(() => wikidataSearch(query), "Wikidata"),
    safeFetch(() => githubSearch(query, githubToken), "GitHub"),
    safeFetch(() => naverSearch(query, naverClientId, naverClientSecret), "Naver"),
    safeFetch(() => klawSearch(query, klawUserId), "K-Law"),
  ];

  const results = await Promise.all(engines);
  const successful = results.filter(r => r.success);
  const totalHits = successful.reduce((sum, r) => sum + (r.hits || 0), 0);

  return { success: true, query, totalHits, results };
}

/* ============================
   모듈 내보내기
   ============================ */
module.exports = {
  verifyAllEngines,
};
