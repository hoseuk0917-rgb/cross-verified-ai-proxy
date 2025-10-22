# Cross-Verified AI v9.7.4 Rev D

> 다중 출처 검증 AI 플랫폼 - 명세서 기반 완전 구현

## 📋 개요

Cross-Verified AI는 Gemini 엔진의 답변을 6개의 외부 검증 엔진(CrossRef, OpenAlex, GDELT, Wikidata, GitHub, K-Law)을 통해 교차 검증하고, **TruthScore**로 신뢰도를 정량화하는 시스템입니다.

### 주요 기능
- ✅ **5가지 모드**: QV(질문검증), FV(사실검증), DV(개발검증), CV(코드검증), LM(법령정보)
- ✅ **TruthScore 계산**: Σ (Rᵢ × Qᵢ × e^(-λt) × wᵢ)
- ✅ **Δwᵢ 보정**: 검증 결과 기반 가중치 자동 조정 (FIFO 10회 로그)
- ✅ **신뢰도 아이콘**: 🟢(높음), 🟡?(출처부족), 🟡△(일치도낮음), 🔴✕(낮음)
- ✅ **API Key 관리**: 암호화 저장 및 Fail-Grace 전환
- ✅ **실시간 검증**: 6개 엔진 병렬 처리

## 🏗️ 시스템 아키텍처

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   Frontend  │────▶│  Node.js Server  │────▶│ Verification Engines│
│  (테스트 UI) │     │   (Express)      │     │  (CrossRef, GDELT,  │
└─────────────┘     └──────────────────┘     │   GitHub, K-Law 등) │
                             │                └─────────────────────┘
                             ▼
                    ┌──────────────────┐
                    │   Gemini API     │
                    │  (답변 생성)      │
                    └──────────────────┘
```

## 🚀 빠른 시작

### 1. 설치

```bash
# 의존성 설치
npm install

# 또는
yarn install
```

### 2. API Key 준비

필수:
- **Gemini API Key**: https://makersuite.google.com/app/apikey

선택 (GitHub 검증용):
- **GitHub API Key**: https://github.com/settings/tokens

### 3. 서버 실행

```bash
# 개발 모드
npm run dev

# 프로덕션 모드
npm start
```

서버가 `http://localhost:10000`에서 실행됩니다.

### 4. 테스트 페이지 접속

브라우저에서 `http://localhost:10000` 접속

1. **API Key 설정**
   - Gemini API Key 입력
   - GitHub API Key 입력 (선택)
   - "저장" 클릭
   - "연결 테스트"로 확인

2. **질문 및 검증**
   - 모드 선택 (QV/FV/DV/CV/LM)
   - 질문 입력
   - "검증 시작" 클릭
   - TruthScore 및 상세 결과 확인

## 📡 API 엔드포인트

### 1. API Key 관리

#### POST `/api/config/keys`
API Key 저장

```json
{
  "gemini": "AIzaSy...",
  "github": "ghp_..."
}
```

#### GET `/api/config/keys`
저장된 API Key 조회 (마스킹)

#### POST `/api/config/test`
API Key 연결 테스트

### 2. 답변 생성

#### POST `/api/generate`
Gemini를 통한 답변 생성

```json
{
  "question": "양자컴퓨터의 원리는?",
  "mode": "QV"
}
```

### 3. 통합 검증

#### POST `/api/verify/complete`
답변 생성 + 검증 + TruthScore 계산

```json
{
  "question": "양자컴퓨터의 원리는?",
  "mode": "QV",
  "includeGeneration": true
}
```

**응답 예시:**
```json
{
  "success": true,
  "mode": "QV",
  "question": "양자컴퓨터의 원리는?",
  "answer": "양자컴퓨터는...",
  "verification": {
    "truthScore": "75.42",
    "confidence": {
      "icon": "🟢",
      "color": "green",
      "label": "높은 신뢰도"
    },
    "engines": [
      {
        "engine": "CrossRef",
        "Ri": "0.80",
        "Qi": "1.00",
        "timeDecay": "0.951",
        "wi": "0.250",
        "score": "0.190",
        "sources": 3
      }
    ],
    "totalSources": 8,
    "avgConsistency": "0.72"
  },
  "deltaWeights": {
    "CrossRef": 0.03,
    "OpenAlex": 0.025
  },
  "performance": {
    "generationTime": "1234ms",
    "verificationTime": "567ms",
    "totalTime": "1801ms"
  }
}
```

### 4. 상태 확인

#### GET `/api/status`
서버 상태 및 설정 확인

#### GET `/api/delta-logs`
Δwᵢ 보정 로그 조회 (최대 10개)

## 🔧 명세서 핵심 구현

### TruthScore 계산 (§ 5.1.1)

```javascript
TruthScore = Σ (Rᵢ × Qᵢ × e^(-λt) × wᵢ)

where:
  Rᵢ = 검증 엔진별 신뢰도 (0~1)
  Qᵢ = 출처 품질 지표 (0~1) - Rev D 개선
  e^(-λt) = 시간 감쇠 (λ = 0.1)
  wᵢ = 엔진 가중치 (정규화)
```

### 신뢰도 아이콘 매핑 (§ 5.2)

| TruthScore | 조건 | 아이콘 | 설명 |
|-----------|------|--------|------|
| ≥ 70% | - | 🟢 | 높은 신뢰도 |
| 40-69% | 출처 < 2 | 🟡? | 출처 부족 |
| 40-69% | 일치도 < 0.6 | 🟡△ | 일치도 낮음 |
| < 40% | - | 🔴✕ | 낮은 신뢰도 |

### Δwᵢ 보정 공식 (§ 3.2)

```javascript
wᵢ' = 0.8 × wᵢ(prev) + 0.2 × Δwᵢ(new)

// FIFO 10회 로그 보존
// 11회째 생성 시 가장 오래된 로그 자동 삭제
```

### 모드별 활성 엔진 (§ 4.1)

| 모드 | 활성 엔진 | 설명 |
|------|-----------|------|
| QV | CrossRef, OpenAlex, GDELT, Wikidata | 질문 검증 |
| FV | CrossRef, OpenAlex, GDELT, Wikidata | 사실 검증 |
| DV | GitHub, GDELT | 개발 검증 |
| CV | GitHub, GDELT | 코드 검증 (Pro) |
| LM | K-Law | 법령 정보 |

### 엔진별 가중치 (§ 3.3)

| 엔진 | 초기 가중치 (wᵢ,₀) | 품질 지표 (Qᵢ) |
|------|-------------------|----------------|
| CrossRef | 0.25 | 1.0 |
| OpenAlex | 0.25 | 0.9 |
| GDELT | 0.25 | 0.8 |
| Wikidata | 0.25 | 0.75 |
| GitHub | 0.50 | 0.85 |
| K-Law | 1.00 | 1.0 |

## 🔒 보안 (§ 8.1)

- **AES-256 암호화**: API Key 로컬 저장 시
- **PBKDF2**: UUID 파생 키 생성
- **TLS 1.3**: 서버-클라이언트 통신
- **환경 변수**: 민감 정보 분리

## 📦 배포

### Render.com 배포

1. GitHub Repository 연결
2. Build Command: `npm install`
3. Start Command: `npm start`
4. Environment Variables:
   - `NODE_ENV=production`

### 환경 변수 설정

```bash
# .env 파일 생성 (선택)
PORT=10000
NODE_ENV=production
```

## 🧪 테스트

### 수동 테스트

```bash
# 서버 상태 확인
curl http://localhost:10000/api/status

# API Key 저장
curl -X POST http://localhost:10000/api/config/keys \
  -H "Content-Type: application/json" \
  -d '{"gemini":"YOUR_KEY"}'

# 전체 검증
curl -X POST http://localhost:10000/api/verify/complete \
  -H "Content-Type: application/json" \
  -d '{"question":"양자컴퓨터란?","mode":"QV"}'
```

## 📊 성능

- **답변 생성**: ~1-2초 (Gemini)
- **검증 처리**: ~0.5-1초 (병렬 처리)
- **총 처리 시간**: ~1.5-3초

## 🐛 문제 해결

### API Key 오류
```
오류: Gemini API Key가 설정되지 않았습니다
→ /api/config/keys로 Key 저장 필요
```

### 검증 엔진 오류
```
오류: CrossRef API 오류: 429
→ API Rate Limit 초과, 잠시 후 재시도
```

### GitHub 인증 오류
```
오류: GitHub API 오류: 401
→ GitHub Personal Access Token 확인
```

## 📝 명세서

본 구현은 다음 명세서를 기반으로 합니다:
- **Cross-Verified AI v9.7.4 Rev D**
- 2025-10 버전
- 보완사항: Qᵢ 재정의, AES-256 전면 적용, Fail-Grace 최적화

## 🔗 관련 링크

- **Gemini API**: https://ai.google.dev/
- **CrossRef API**: https://www.crossref.org/services/metadata-delivery/rest-api/
- **GitHub API**: https://docs.github.com/en/rest
- **GDELT**: https://www.gdeltproject.org/
- **K-Law**: https://www.law.go.kr/

## 📜 라이선스

MIT License

## 👥 기여

이슈 및 PR 환영합니다!

---

**Cross-Verified AI v9.7.4 Rev D** - 명세서 기반 완전 구현 ✅
