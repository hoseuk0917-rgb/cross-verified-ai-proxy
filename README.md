# Cross-Verified AI v9.7.3 Rev C

## 🎯 프로젝트 개요

Cross-Verified AI는 **다중 출처 검증 (Multi-Source Verification)**을 통해 AI 응답의 사실 신뢰도를 정량화하고, 코드 · 법령 · 학술 검증까지 통합 관리하는 검증형 AI 플랫폼입니다.

## ✨ 핵심 기능

### 1. 5가지 검증 모드
- **QV (질문검증)**: 사용자 질문 + 사실 검증
- **FV (사실검증)**: 기존 문장 사실 검증 / 신뢰도 피드백
- **DV (개발검증)**: 코드 / 기술 정합성 검증
- **CV (코드검증)**: 사용자 입력 코드 검증 (Pro 전용)
- **LM (법령정보)**: 법령 검색 / 조항 조회

### 2. TruthScore 계산
```
TruthScore = Σ (Rᵢ × Qᵢ × e^(-λt) × wᵢ)
```
- **Rᵢ**: 검증 엔진별 신뢰도 (0~1)
- **Qᵢ**: 출처 공신력 값
- **λ**: 시간 감쇠 상수
- **wᵢ**: 엔진별 가중치

### 3. 신뢰도 아이콘 매핑 (명세서 5.2)

| 신뢰도 범위 | 아이콘 | 표시 기준 | 신뢰도 하락 사유 |
|------------|--------|----------|-----------------|
| ≥ 0.7 | 🟢 | 정상 | – |
| 0.4~0.69 (출처 부족) | 🟡 ? | 출처 없음 또는 부족 | 출처 부족 |
| 0.4~0.69 (기타 사유) | 🟡 △ | 일치도 낮음 / 최신성 부족 | 일치도 낮음 |
| < 0.4 | 🔴 ✕ | 검증 실패 / 불일치 | 불일치 |

### 4. 검증 엔진
- **CrossRef**: 학술 논문 DOI / 서지 정보
- **OpenAlex**: 연구자 · 논문 메타데이터
- **GDELT**: 뉴스 및 웹 콘텐츠
- **Wikidata**: 지식 그래프
- **GitHub**: 소스코드 / API Repository
- **K-Law**: 법령 / 행정규칙 API

## 🚀 설치 및 실행

### 필수 요구사항
- Node.js 16.x 이상
- npm 또는 yarn

### 설치
```bash
npm install
```

### 개발 서버 실행
```bash
npm start
```

서버가 실행되면 브라우저에서 `http://localhost:3000`으로 접속하세요.

### 개발 모드 (자동 재시작)
```bash
npm run dev
```

## 📁 프로젝트 구조

```
cross-verified-ai/
│
├── server.js              # 백엔드 서버 및 검증 로직
├── index.html             # 프론트엔드 UI
├── package.json           # 프로젝트 의존성
├── README.md              # 프로젝트 문서
│
├── assets/                # 신뢰도 아이콘
│   ├── icon_confidence_green.png       # 🟢 정상
│   ├── icon_confidence_question_png.png # 🟡 ? 출처 부족
│   ├── icon_confidence_triangle.png    # 🟡 △ 일치도 낮음
│   └── icon_confidence_x.png           # 🔴 ✕ 검증 실패
│
└── test.js                # 테스트 스크립트
```

## 🔍 API 엔드포인트

### POST /api/verify
검증 요청을 처리합니다.

**요청 본문:**
```json
{
  "query": "검증할 질문 또는 문장",
  "mode": "QV"
}
```

**응답:**
```json
{
  "mode": "QV",
  "query": "...",
  "truthScore": 0.75,
  "percentage": 75,
  "dropReason": "lack_of_sources",
  "icon": {
    "icon": "question",
    "label": "출처 부족",
    "color": "#eab308"
  },
  "verificationResults": [...],
  "weights": {...},
  "deltaWeights": [...]
}
```

### GET /api/modes
사용 가능한 모드 정보를 반환합니다.

### GET /api/health
서버 상태를 확인합니다.

## 🧪 테스트

```bash
npm test
```

## 📊 명세서 준수 사항

이 프로토타입은 **Cross-Verified AI v9.7.3 Rev C** 명세서의 다음 항목을 구현합니다:

- ✅ **3.3**: 초기 가중치 정의
- ✅ **4.1**: 모드별 활성 엔진 규칙
- ✅ **5.1.1**: TruthScore 공식
- ✅ **5.2**: 신뢰도 아이콘 매핑 (핵심!)
- ✅ **5.3**: Δwᵢ 보정 공식
- ✅ **5.4**: 신뢰도 산출 절차

## 🔐 보안

실제 배포 시 다음 보안 기능을 추가해야 합니다:
- AES-256 암호화 (Δwᵢ 로그)
- PBKDF2 키 파생
- TLS 1.3 전송 보호
- API Key 관리
- Fail-Grace 모드

## 📝 라이선스

MIT License

## 👥 기여자

Cross-Verified AI Development Team

## 📞 문의

프로젝트에 대한 질문이나 제안은 이슈를 통해 남겨주세요.

---

**버전**: v9.7.3 Rev C  
**마지막 업데이트**: 2025-10-22
