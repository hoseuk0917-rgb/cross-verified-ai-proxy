# Cross-Verified Proxy Server v9.8.4

다중 AI·데이터 검증엔진(Gemini, CrossRef, OpenAlex, GDELT, Wikidata, GitHub, Naver, K-Law 등)을 통합 라우팅하기 위한 백엔드 프록시 게이트웨이

## 📋 시스템 개요

Cross-Verified Proxy Server는 다음 기능을 제공합니다:

- **Google OAuth 2.0 인증** - 안전한 사용자 인증 및 세션 관리
- **AES-256-GCM 암호화** - API 키 안전 저장
- **다중 검증 엔진 프록시**
  - Gemini API (최대 5개 키 지원)
  - K-Law API (법령 검색)
  - CrossRef (학술 논문)
  - OpenAlex (학술 데이터)
  - GDELT (뉴스 이벤트)
  - Wikidata (지식 그래프)
  - Naver Search (뉴스 - Whitelist 필터링)
  - GitHub API (개발 검증)
- **병렬 처리** - Promise.all 기반 동시 호출
- **Naver Whitelist 관리** - 53개 공신력 매체 필터링
- **로깅 및 감사** - 요청 추적, 성능 모니터링, 보안 감사

## 🚀 빠른 시작

### 1. 설치

```bash
cd proxy-server
npm install
```

### 2. 환경변수 설정

`.env.example`을 복사하여 `.env` 파일 생성:

```bash
cp .env.example .env
```

필수 환경변수 설정:
- `DATABASE_URL` - PostgreSQL 연결 문자열
- `ENCRYPTION_KEY` - AES-256 암호화 키 (64자 hex)
- `JWT_SECRET` - JWT 토큰 서명 키
- `GOOGLE_CLIENT_ID` - Google OAuth Client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth Client Secret
- `ALLOWED_ORIGINS` - CORS 허용 도메인

### 3. 데이터베이스 초기화

서버 첫 실행 시 자동으로 테이블 생성 및 Whitelist 초기화됨

### 4. 서버 실행

```bash
# 프로덕션
npm start

# 개발 (nodemon)
npm run dev
```

서버는 기본적으로 `http://localhost:3000`에서 실행됩니다.

## 📡 API 엔드포인트

### 인증 (Authentication)

#### Google OAuth 로그인
```
GET /auth/google
```

#### 사용자 정보 조회
```
GET /auth/me
Authorization: Bearer <access_token>
```

#### 토큰 갱신
```
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "<refresh_token>"
}
```

#### 로그아웃
```
POST /auth/logout
Content-Type: application/json

{
  "userId": 1
}
```

### Gemini API

#### Gemini API 호출
```
POST /proxy/gemini/:model
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "keyIndex": 1,
  "contents": [
    {
      "role": "user",
      "parts": [{ "text": "Hello Gemini!" }]
    }
  ]
}
```

지원 모델:
- `gemini-2.0-flash-exp`
- `gemini-1.5-flash`
- `gemini-1.5-flash-8b`
- `gemini-1.5-pro`
- `gemini-pro`

#### API Key 등록
```
POST /proxy/gemini/keys
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "apiKey": "<your-gemini-api-key>",
  "keyIndex": 1,
  "expiresAt": "2025-12-31T23:59:59Z"
}
```

#### API Key 목록 조회
```
GET /proxy/gemini/keys
Authorization: Bearer <access_token>
```

#### API Key 삭제
```
DELETE /proxy/gemini/keys/:keyIndex
Authorization: Bearer <access_token>
```

### K-Law API

#### 법령 검색
```
GET /proxy/klaw/law?query=헌법&display=10&page=1
```

#### 법률 조문 검색
```
GET /proxy/klaw/statute?query=민법&display=10
```

#### 판례 검색
```
GET /proxy/klaw/precedent?query=손해배상&display=10
```

#### 행정규칙 검색
```
GET /proxy/klaw/adminRul?query=시행령&display=10
```

### 외부 검증 엔진

#### CrossRef (학술 논문)
```
GET /proxy/external/crossref?query=artificial+intelligence&email=user@example.com
```

#### OpenAlex (학술 데이터)
```
GET /proxy/external/openalex?query=machine+learning
```

#### GDELT (뉴스 이벤트)
```
GET /proxy/external/gdelt?query=technology
```

#### Wikidata (지식 그래프)
```
GET /proxy/external/wikidata?query=SELECT...
```

#### Naver Search (뉴스 - Whitelist 필터링)
```
GET /proxy/external/naver?query=인공지능&display=10
Authorization: Bearer <access_token>
```

Naver API Key 등록:
```
POST /proxy/external/naver/keys
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "clientId": "<naver-client-id>",
  "clientSecret": "<naver-client-secret>"
}
```

#### 병렬 배치 검증 (Core Logic Engine)
```
POST /proxy/external/batch
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "query": "climate change",
  "engines": ["crossref", "openalex", "gdelt", "wikidata"]
}
```

### GitHub API

#### GitHub API 호출 (일반)
```
GET /proxy/github/repos/:owner/:repo
Authorization: Bearer <access_token>
```

#### 레포지토리 검색
```
POST /proxy/github/search/repositories
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "query": "react",
  "sort": "stars",
  "order": "desc",
  "per_page": 10
}
```

#### GitHub Token 등록
```
POST /proxy/github/keys
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "token": "<github-personal-access-token>"
}
```

### 시스템

#### Health Check
```
GET /health
```

응답:
```json
{
  "success": true,
  "status": "healthy",
  "timestamp": "2025-10-28T12:00:00.000Z",
  "services": {
    "gemini": { "successRate": 98.5, "avgLatency": 245, "status": "healthy" },
    "klaw": { "successRate": 99.1, "avgLatency": 189, "status": "healthy" },
    ...
  },
  "uptime": 86400,
  "memory": { ... }
}
```

## 🔐 보안 기능

### API Key 암호화
- **AES-256-GCM** 암호화로 API 키 저장
- IV (Initialization Vector) 및 Auth Tag 사용
- 복호화는 요청 시점에만 수행

### JWT 인증
- **Access Token**: 24시간 유효
- **Refresh Token**: 30일 유효
- 자동 토큰 갱신 지원

### CORS 보안
- 환경변수 기반 Origin 화이트리스트
- Preflight 요청 캐싱 (24시간)
- 와일드카드(*) 프로덕션 금지

### Rate Limiting
- 15분당 최대 1000 요청
- IP 기반 제한

### Audit Logging
- 모든 인증 이벤트 기록
- Key 등록/삭제 추적
- 보안 이벤트 모니터링

## 📊 데이터베이스 스키마

### Users
- Google OAuth 사용자 정보
- Refresh Token 저장

### API Keys
- AES-256-GCM 암호화된 키 저장
- 서비스별/인덱스별 관리
- 만료일 지원

### Request Logs
- API 호출 이력
- 성공률, 지연시간 추적
- 30일 보존

### Naver Whitelist
- 53개 공신력 매체 목록
- Tier 1-5 분류
- Q Score (공신력 점수)

### Monitoring Logs
- 성능 메트릭
- Naver API Latency 추적
- 7일 보존

### Audit Logs
- 보안 감사 로그
- 사용자 행동 추적
- 90일 보존

## 🛠️ 배포 (Render.com)

### 1. 환경변수 설정

Render Dashboard에서 다음 변수 설정:

```
NODE_ENV=production
PORT=3000
DATABASE_URL=<render-postgres-external-url>
DATABASE_URL_INTERNAL=<render-postgres-internal-url>
ENCRYPTION_KEY=<generate-64-char-hex>
JWT_SECRET=<generate-secret>
SESSION_SECRET=<generate-secret>
GOOGLE_CLIENT_ID=<google-oauth-client-id>
GOOGLE_CLIENT_SECRET=<google-oauth-client-secret>
GOOGLE_ORIGIN=https://cross-verified-ai.onrender.com
GOOGLE_REDIRECT_URI=https://cross-verified-ai.onrender.com/auth/google/callback
ALLOWED_ORIGINS=https://cross-verified-ai.app,https://cross-verified-ai.onrender.com
```

### 2. Build Command
```
npm install
```

### 3. Start Command
```
npm start
```

### 4. Health Check Path
```
/health
```

## 📝 개발

### 프로젝트 구조
```
proxy-server/
├─ src/
│  ├─ server.js              # 메인 서버
│  ├─ routes/
│  │  ├─ auth.js             # Google OAuth
│  │  ├─ gemini.js           # Gemini Proxy
│  │  ├─ klaw.js             # K-Law Proxy
│  │  ├─ external.js         # 외부 엔진 Proxy
│  │  └─ github.js           # GitHub Proxy
│  ├─ utils/
│  │  ├─ db.js               # PostgreSQL
│  │  ├─ encrypt.js          # AES-256 암복호화
│  │  ├─ fetcher.js          # API 호출
│  │  └─ logger.js           # 로깅
│  └─ middleware/
│     ├─ auth.js             # JWT 인증
│     └─ cors.js             # CORS 설정
├─ test/
│  └─ test-server.html       # 테스트용 HTML
├─ package.json
├─ .env.example
└─ README.md
```

### 테스트

테스트용 HTML 파일 사용:
```bash
# 서버 실행 후
open test/test-server.html
```

## 🐛 트러블슈팅

### 데이터베이스 연결 실패
- `DATABASE_URL` 확인
- PostgreSQL 서버 실행 상태 확인
- SSL 설정 확인 (프로덕션: required)

### Google OAuth 실패
- Google Cloud Console에서 Client ID/Secret 확인
- Redirect URI 정확히 설정
- 승인된 JavaScript 원본 추가

### CORS 에러
- `ALLOWED_ORIGINS` 환경변수 확인
- 프로덕션에서 와일드카드(*) 사용 금지
- Preflight 요청 확인

## 📄 라이선스

MIT License

## 👥 지원

문의사항이나 이슈는 GitHub Issues에 등록해주세요.
