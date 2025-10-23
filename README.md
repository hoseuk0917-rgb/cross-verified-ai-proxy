# Cross-Verified AI Proxy Server v9.7.7

## 개요

Cross-Verified AI 시스템의 백엔드 프록시 서버입니다. Gemini 2.5 Flash/Pro API를 프록시하고, 다중 검증 엔진을 통합하여 AI 응답의 신뢰도(TruthScore)를 계산합니다.

## 주요 기능

### 1. Gemini API 프록시
- Gemini 2.5 Flash 및 Pro 모델 지원
- 키워드 추출
- 문맥 유사도 계산
- API Key 검증

### 2. 다중 검증 엔진
- **CrossRef**: 학술 논문 데이터베이스
- **OpenAlex**: 오픈 학술 그래프
- **GDELT**: 글로벌 이벤트 데이터
- **Wikidata**: 위키데이터 엔티티
- **GitHub**: 코드 저장소 검색
- **K-Law**: 한국 법령 정보

### 3. TruthScore 계산 엔진
- 검증가능성(Verifiability) 계산
- 보정항(Δwᵢ) 업데이트
- 연관도(Relevance) 계산
- 신뢰도 등급 판정 (🟢🟡🟠🔴⚪)

### 4. 보안
- AES-256-GCM 암호화
- PBKDF2 키 파생
- API Key 안전한 저장

## 설치

```bash
cd proxy-server
npm install
```

## 환경 설정

`.env.template` 파일을 복사하여 `.env` 파일을 생성하고 필요한 값을 설정합니다:

```bash
cp .env.template .env
```

## 실행

### 개발 모드
```bash
npm run dev
```

### 프로덕션 모드
```bash
npm start
```

서버는 기본적으로 `http://localhost:3000`에서 실행됩니다.

## API 엔드포인트

### 서버 상태

#### GET /ping
서버 상태 확인

**응답 예시:**
```json
{
  "status": "ok",
  "timestamp": "2025-10-24T10:00:00.000Z",
  "version": "9.7.7",
  "uptime": 123.45
}
```

### Gemini API

#### POST /api/gemini/generate
Gemini로 텍스트 생성

**요청 본문:**
```json
{
  "apiKey": "your-gemini-api-key",
  "model": "flash",
  "prompt": "Explain quantum computing",
  "temperature": 0.7,
  "maxTokens": 2048
}
```

#### POST /api/gemini/extract-keywords
텍스트에서 키워드 추출

**요청 본문:**
```json
{
  "apiKey": "your-gemini-api-key",
  "text": "Your text here..."
}
```

### 검증 엔진

#### POST /api/verify/:engine
개별 엔진으로 검증 (crossref, openalex, gdelt, wikidata, github, klaw)

**요청 본문:**
```json
{
  "query": "artificial intelligence",
  "apiKey": "optional-for-github-and-klaw"
}
```

#### POST /api/verify/all
모든 엔진으로 동시 검증

**요청 본문:**
```json
{
  "query": "quantum computing",
  "apiKeys": {
    "github": "optional-github-token",
    "klaw": "optional-klaw-key"
  }
}
```

### TruthScore

#### POST /api/truthscore/calculate
TruthScore 계산

**요청 본문:**
```json
{
  "engines": [
    {
      "name": "crossref",
      "isActive": true,
      "sourceDetected": true,
      "quality": 0.95,
      "keywordMatch": 0.85,
      "weight": 1.0,
      "deltaW": 1.0,
      "timeDelta": 0
    }
  ]
}
```

### 통합 검증

#### POST /api/cross-verify
통합 검증 및 신뢰도 계산

**요청 본문:**
```json
{
  "query": "What is machine learning?",
  "geminiApiKey": "your-gemini-api-key",
  "geminiModel": "flash",
  "apiKeys": {
    "github": "optional-github-token",
    "klaw": "optional-klaw-key"
  },
  "generateAnswer": true
}
```

**응답 예시:**
```json
{
  "success": true,
  "query": "What is machine learning?",
  "answer": "Machine learning is...",
  "keywords": ["machine learning", "artificial intelligence", ...],
  "verification": {
    "results": {...}
  },
  "truthScore": {
    "truthScore": 85.5,
    "confidence": "high",
    "icon": "🟢",
    "details": {...},
    "activeEnginesCount": 4
  },
  "metadata": {
    "duration": "2345ms",
    "timestamp": "2025-10-24T10:00:00.000Z",
    "model": "flash"
  }
}
```

### 암호화

#### POST /api/keys/encrypt
API Key 암호화

**요청 본문:**
```json
{
  "plaintext": "your-api-key",
  "masterPassword": "your-master-password"
}
```

#### POST /api/keys/decrypt
API Key 복호화

**요청 본문:**
```json
{
  "encryptedData": {
    "encrypted": "...",
    "iv": "...",
    "salt": "...",
    "tag": "..."
  },
  "masterPassword": "your-master-password"
}
```

#### POST /api/keys/validate
Gemini API Key 검증

**요청 본문:**
```json
{
  "apiKey": "your-gemini-api-key"
}
```

## 테스트

서버를 실행한 후 별도 터미널에서:

```bash
node test.js
```

테스트는 다음을 확인합니다:
1. 서버 Ping
2. CrossRef 검증
3. OpenAlex 검증
4. Wikidata 검증
5. 전체 검증 엔진
6. TruthScore 계산
7. 암호화/복호화

## 프로젝트 구조

```
proxy-server/
├── server.js              # 메인 서버 파일
├── package.json           # 의존성 및 스크립트
├── .env.template          # 환경 변수 템플릿
├── test.js               # 테스트 스크립트
├── engine/
│   ├── gemini.js         # Gemini API 프록시
│   ├── verification.js   # 검증 엔진 통합
│   └── truthscore.js     # TruthScore 계산
└── utils/
    └── crypto.js         # 암호화 유틸리티
```

## 시스템 요구사항

- Node.js 16.x 이상
- npm 7.x 이상

## 명세 준수

본 프록시 서버는 다음 명세를 따릅니다:
- Cross-Verified AI v9.7.7 통합보완판
- 검증가능성(Vᵢ) 계산
- 보정항(Δwᵢ) 업데이트 로직
- TruthScore 연산 구조
- Fail-Grace 및 복구 정책

## 주의사항

1. **Gemini API Key 필수**: 대부분의 기능은 유효한 Gemini API Key가 필요합니다.
2. **Rate Limiting**: 15분당 100 요청으로 제한됩니다.
3. **K-Law API**: 현재 Mock 데이터를 반환하며, 실제 API Key 연동이 필요합니다.
4. **GitHub API**: Token 없이도 사용 가능하지만, Rate Limit이 낮습니다.

## 향후 개발 계획

- [ ] PostgreSQL 데이터베이스 연동
- [ ] JWT 기반 인증 시스템
- [ ] Ping 스케줄러 (15분마다)
- [ ] Key 로테이션 자동화
- [ ] Audit Trail 로깅
- [ ] WebSocket 지원 (실시간 검증)

## 라이선스

MIT

## 문의

프로젝트 관련 문의는 이슈를 등록해 주세요.
