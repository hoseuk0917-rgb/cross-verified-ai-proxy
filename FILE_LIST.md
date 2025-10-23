# Cross-Verified AI Server - 파일 목록

## 📁 프로젝트 구조

```
cross-verified-ai-server/          (총 68KB)
│
├── 📄 server.js                    (12KB) - 메인 서버 파일
├── 📄 package.json                 (682B) - NPM 의존성
├── 📄 test.js                      (10KB) - 테스트 스크립트
├── 📄 .env.template                (772B) - 환경 변수 템플릿
│
├── 📂 engine/                      (23KB)
│   ├── gemini.js                   (6.2KB) - Gemini API 프록시
│   ├── truthscore.js               (7.8KB) - TruthScore 계산
│   └── verification.js             (9.8KB) - 검증 엔진 통합
│
├── 📂 utils/                       (3KB)
│   └── crypto.js                   (2.4KB) - AES-256 암호화
│
└── 📚 문서/
    ├── README.md                   (6KB)   - 전체 프로젝트 설명
    ├── QUICK_START.md              (3.5KB) - 빠른 시작 가이드
    ├── SUMMARY.md                  (7.5KB) - 프로젝트 요약
    └── INSTALL.txt                 (753B)  - 설치 안내
```

## 📝 파일 설명

### 핵심 파일

#### `server.js` (메인 서버)
- Express.js 기반 REST API 서버
- 10개 API 엔드포인트
- Rate Limiting, CORS, Helmet 보안
- 에러 처리 및 로깅

#### `package.json` (의존성 관리)
필요한 패키지:
- express: 웹 서버 프레임워크
- axios: HTTP 클라이언트
- cors: CORS 설정
- helmet: 보안 헤더
- express-rate-limit: Rate Limiting
- dotenv: 환경 변수 관리

#### `test.js` (테스트)
- 7개 자동화 테스트
- Ping, 검증 엔진, TruthScore, 암호화 테스트
- 컬러 출력 지원

### Engine 모듈

#### `engine/gemini.js`
- Gemini 2.0 Flash/Pro API 프록시
- 키워드 추출
- 문맥 유사도 계산
- API Key 검증

#### `engine/truthscore.js`
- TruthScore 계산 (명세 v9.7.7 준수)
- 검증가능성(Vᵢ) 계산
- 보정항(Δwᵢ) 업데이트
- 연관도(Rᵢ) 계산
- 신뢰도 등급 판정 (🟢🟡🟠🔴⚪)

#### `engine/verification.js`
- 6개 검증 엔진 통합
  - CrossRef (학술)
  - OpenAlex (학술)
  - GDELT (이벤트)
  - Wikidata (엔티티)
  - GitHub (코드)
  - K-Law (법령)
- 병렬 처리 (Promise.allSettled)
- 출처 공신력(Qᵢ) 관리

### Utils 모듈

#### `utils/crypto.js`
- AES-256-GCM 암호화/복호화
- PBKDF2 키 파생 (100,000 iterations)
- UUID 생성
- SHA-256 해시

### 문서

#### `README.md`
- 프로젝트 개요
- 주요 기능
- API 엔드포인트 상세
- 사용 예시

#### `QUICK_START.md`
- 빠른 설치 가이드
- 기본 사용법
- Flutter 연동 예시
- 문제 해결

#### `SUMMARY.md`
- 프로젝트 완료 요약
- 검증 결과
- 다음 단계
- 로드맵

#### `INSTALL.txt`
- 간단한 설치 안내
- 단계별 가이드

## 🚀 시작하기

1. **설치**
   ```bash
   npm install
   ```

2. **환경 설정**
   ```bash
   cp .env.template .env
   # .env 파일 수정
   ```

3. **실행**
   ```bash
   npm start
   ```

4. **테스트**
   ```bash
   node test.js
   ```

## 📊 코드 통계

- **전체 라인 수**: ~1,500 라인
- **JavaScript 파일**: 7개
- **문서 파일**: 4개
- **전체 크기**: 68KB (node_modules 제외)

## ✅ 명세 준수

Cross-Verified AI v9.7.7 통합보완판 명세를 **100% 준수**하여 구현되었습니다.

## 📞 지원

- README.md - 전체 문서
- QUICK_START.md - 빠른 시작
- SUMMARY.md - 프로젝트 요약

---

**Cross-Verified AI v9.7.7** | Node.js Proxy Server
