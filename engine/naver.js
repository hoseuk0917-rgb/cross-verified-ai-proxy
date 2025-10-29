
  Naver Verification Engine (뉴스 + 화이트리스트 기반)
  v9.8.4 Annex A 3.3.2 기준 구현
 

const axios = require(axios);
const fs = require(fs);
const path = require(path);

const WHITELIST_PATH = path.join(__dirname, ..datanaver_whitelist.json);

module.exports = {
  async verifyNaver({ clientId, clientSecret, query }) {
    try {
       ① 화이트리스트 로드
      const whitelist = JSON.parse(fs.readFileSync(WHITELIST_PATH, utf-8));
      const whitelistDomains = whitelist.domains  [];

       ② 뉴스 전용 검색 API
      const url = `httpsopenapi.naver.comv1searchnews.jsonquery=${encodeURIComponent(query)}&display=20`;

      const response = await axios.get(url, {
        headers {
          X-Naver-Client-Id clientId,
          X-Naver-Client-Secret clientSecret,
        },
      });

      const items = response.data.items  [];

       ③ 필터링 화이트리스트 매체만
      const validItems = items.filter(item =
        whitelistDomains.some(domain = item.link.includes(domain))
      );

       ④ 지표 계산
      const Rf = validItems.length  (items.length  1);
      const Mk = Math.min(
        (validItems.filter(i = i.title.includes(query)).length  (validItems.length  1)),
        1
      );
      const Sw = Math.min(
        (validItems.filter(i = i.description.includes(query)).length  (validItems.length  1)),
        1
      );

       ⑤ 신뢰도 산출 (명세서 식 적용)
      const trust = 0.4  Rf + 0.4  Mk + 0.2  Sw;

      return {
        success true,
        engine naver,
        verifiedCount validItems.length,
        totalCount items.length,
        trustScore parseFloat(trust.toFixed(3)),
        whitelistRatio Rf,
        keywordMatch Mk,
        snippetMatch Sw,
        whitelistLastUpdate whitelist.lastUpdate  unknown,
      };
    } catch (err) {
      console.error([Naver Engine] Error, err.message);
      return { success false, engine naver, error err.message };
    }
  }
};
