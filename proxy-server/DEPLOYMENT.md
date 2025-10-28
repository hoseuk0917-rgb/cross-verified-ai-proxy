# Render.com 배포 체크리스트

## ✅ 배포 전 준비사항

### 1. GitHub 저장소 준비
- [ ] Git 저장소 초기화 완료
- [ ] `.gitignore` 파일 확인 (node_modules, .env 제외)
- [ ] GitHub에 Push 완료
- [ ] 저장소가 Public 또는 Render 연동 가능한 상태

### 2. PostgreSQL 데이터베이스
- [ ] Render에서 PostgreSQL 데이터베이스 생성
- [ ] Internal Database URL 복사
- [ ] External Database URL 복사
- [ ] Database 이름 기록: `cross-verified-db`

### 3. Google OAuth 2.0 설정
- [ ] Google Cloud Console 프로젝트 생성
- [ ] OAuth 2.0 클라이언트 ID 생성
- [ ] **프로덕션용** Client ID 및 Secret 생성
- [ ] 승인된 JavaScript 원본 추가:
  - `https://your-service-name.onrender.com`
- [ ] 승인된 리디렉션 URI 추가:
  - `https://your-service-name.onrender.com/auth/google/callback`

### 4. 보안 키 생성
- [ ] ENCRYPTION_KEY (64자 hex)
- [ ] JWT_SECRET (hex)
- [ ] SESSION_SECRET (hex)
- [ ] HMAC_SECRET (hex) - 선택사항

**생성 방법**:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 📋 Render.com 환경변수 설정

### 필수 환경변수

```env
# 서버 설정
NODE_ENV = production
PORT = 3000

# CORS 설정 (실제 도메인으로 변경!)
ALLOWED_ORIGINS = https://your-frontend-domain.com,https://your-service-name.onrender.com

# 데이터베이스 (Render PostgreSQL에서 복사)
DATABASE_URL = <External Database URL>
DATABASE_URL_INTERNAL = <Internal Database URL>
DATABASE_URL_EXTERNAL = <External Database URL>

# 보안 키 (Render의 'Generate' 버튼 사용)
ENCRYPTION_KEY = <Generate - 64자 hex>
JWT_SECRET = <Generate>
SESSION_SECRET = <Generate>
HMAC_SECRET = <Generate>

# Google OAuth (프로덕션용)
GOOGLE_CLIENT_ID = <프로덕션-client-id.apps.googleusercontent.com>
GOOGLE_CLIENT_SECRET = <프로덕션-client-secret>
GOOGLE_ORIGIN = https://your-service-name.onrender.com
GOOGLE_REDIRECT_URI = https://your-service-name.onrender.com/auth/google/callback
```

### ⚠️ 주의사항

1. **ALLOWED_ORIGINS**
   - ❌ 절대 `*` (와일드카드) 사용 금지
   - ✅ 실제 도메인만 명시
   - ✅ 여러 도메인은 쉼표로 구분
   - ✅ `http://localhost:5173` 제거 (프로덕션)

2. **DATABASE_URL**
   - ✅ `DATABASE_URL_INTERNAL`은 Render 내부 연결용
   - ✅ `DATABASE_URL_EXTERNAL`은 외부 테스트용
   - ✅ 둘 다 설정 필요

3. **ENCRYPTION_KEY**
   - ⚠️ 반드시 64자 hex 문자열
   - ⚠️ 한 번 설정하면 변경 시 기존 암호화된 데이터 복호화 불가

4. **Google OAuth**
   - ✅ 프로덕션용 Client ID/Secret 사용
   - ✅ 개발용과 프로덕션용 구분
   - ✅ Redirect URI가 정확히 일치해야 함

## 🚀 Render.com 서비스 설정

### Web Service 생성

1. **Name**: `cross-verified-proxy`
2. **Environment**: `Node`
3. **Region**: `Oregon (US West)` 또는 가장 가까운 지역
4. **Branch**: `main`
5. **Build Command**: `npm install`
6. **Start Command**: `npm start`
7. **Plan**: `Starter` ($7/month) 권장 (Free는 Cold Start 있음)

### Health Check 설정

- **Health Check Path**: `/health`
- **Health Check Grace Period**: `300` seconds

### Auto-Deploy 설정

- [ ] GitHub 저장소 연동
- [ ] Auto-Deploy 활성화
- [ ] `main` 브랜치에 Push 시 자동 배포

## ✅ 배포 후 검증

### 1. Health Check 확인

```bash
curl https://your-service-name.onrender.com/health
```

**예상 응답**:
```json
{
  "success": true,
  "status": "healthy",
  "timestamp": "2025-10-28T...",
  "services": {
    "gemini": { "status": "healthy", "successRate": 0, ... },
    "klaw": { "status": "healthy", "successRate": 0, ... },
    ...
  }
}
```

### 2. Google OAuth 테스트

브라우저에서:
```
https://your-service-name.onrender.com/auth/google
```

- [ ] Google 로그인 화면이 나타나는가?
- [ ] 로그인 후 리디렉션이 정상 작동하는가?
- [ ] Access Token과 Refresh Token을 받는가?

### 3. K-Law API 테스트 (인증 불필요)

```bash
curl "https://your-service-name.onrender.com/proxy/klaw/law?query=헌법&display=3"
```

- [ ] 정상 응답을 받는가?
- [ ] 법령 데이터가 반환되는가?

### 4. 데이터베이스 확인

Render PostgreSQL Dashboard에서:
- [ ] `users` 테이블 생성됨
- [ ] `api_keys` 테이블 생성됨
- [ ] `nav_whitelist` 테이블에 53개 매체 존재
- [ ] `request_logs` 테이블 생성됨

### 5. 로그 확인

Render Dashboard의 Logs 탭:
```
✅ PostgreSQL connected successfully
✅ Database schema initialized successfully
✅ Naver Whitelist initialized with 53 media outlets
🚀 Cross-Verified Proxy Server v9.8.4 running on port 3000
```

## 🔧 트러블슈팅

### 배포 실패 시

#### 빌드 에러
```
Error: Cannot find module 'xyz'
```
**해결**: `package.json`의 `dependencies` 확인

#### 데이터베이스 연결 실패
```
Error: connect ECONNREFUSED
```
**해결**:
1. `DATABASE_URL_INTERNAL` 사용 확인
2. PostgreSQL이 같은 Region에 있는지 확인
3. PostgreSQL이 실행 중인지 확인

#### Google OAuth 에러
```
Error: redirect_uri_mismatch
```
**해결**:
1. Google Cloud Console의 Redirect URI 확인
2. `GOOGLE_REDIRECT_URI` 환경변수 확인
3. URI가 정확히 일치하는지 확인 (대소문자, `/` 포함)

#### CORS 에러
```
Access to fetch ... has been blocked by CORS policy
```
**해결**:
1. `ALLOWED_ORIGINS`에 프론트엔드 도메인 추가
2. 와일드카드(`*`) 제거
3. 프로토콜(`https://`) 포함 확인

### Cold Start (Free Plan)

Free Plan 사용 시 15분 이상 요청이 없으면 서버가 Sleep 모드로 전환되어 첫 요청 시 30초 이상 걸림.

**해결책**:
1. Starter Plan ($7/month) 사용
2. 또는 외부 Uptime Monitor 서비스 사용 (예: UptimeRobot)

## 📊 성능 모니터링

### Render Dashboard

1. **Metrics 탭**: CPU, 메모리, 네트워크 사용량
2. **Logs 탭**: 실시간 로그 확인
3. **Events 탭**: 배포 이력

### 자체 Health Check

주기적으로 Health Check 엔드포인트 호출:
```bash
curl https://your-service-name.onrender.com/health
```

### 데이터베이스 모니터링

PostgreSQL Dashboard:
- **Connections**: 현재 연결 수
- **Storage**: 사용 중인 용량
- **Metrics**: CPU, 메모리 사용량

## 🔄 업데이트 배포

1. 코드 수정
2. Git Commit & Push
3. Render가 자동으로 재배포 (Auto-Deploy 활성화 시)

수동 배포:
- Render Dashboard → "Manual Deploy" → "Deploy latest commit"

## 🔐 보안 체크리스트

- [ ] 모든 환경변수가 설정되어 있음
- [ ] ENCRYPTION_KEY가 64자 hex
- [ ] JWT_SECRET이 충분히 길고 랜덤
- [ ] ALLOWED_ORIGINS에 와일드카드 없음
- [ ] Google OAuth가 프로덕션용 설정
- [ ] 데이터베이스 비밀번호가 강력함
- [ ] HTTPS 사용 (Render 기본 제공)

## 📝 배포 완료 체크리스트

- [ ] Health Check 정상 응답
- [ ] Google OAuth 로그인 작동
- [ ] K-Law API 호출 성공
- [ ] 데이터베이스 테이블 생성 확인
- [ ] Naver Whitelist 53개 매체 확인
- [ ] 로그에 에러 없음
- [ ] 프론트엔드에서 API 호출 성공
- [ ] CORS 설정 정상 작동

## 🎉 배포 완료!

모든 체크리스트를 통과했다면 배포가 성공적으로 완료되었습니다!

### 다음 단계

1. 프론트엔드 앱에서 API 연동
2. Gemini API Key 등록
3. Naver API Key 등록 (선택)
4. GitHub Token 등록 (선택)
5. 실제 검증 기능 테스트

### 유용한 링크

- Render Dashboard: https://dashboard.render.com/
- Google Cloud Console: https://console.cloud.google.com/
- 서버 Health Check: `https://your-service-name.onrender.com/health`
- API 문서: `README.md`
- 구현 검증: `VERIFICATION.md`

## 💡 프로덕션 팁

1. **데이터베이스 백업**: Render PostgreSQL은 자동 백업 제공
2. **로그 보존**: 중요 로그는 외부 로깅 서비스 사용 고려
3. **모니터링**: Uptime monitoring 설정 권장
4. **보안 업데이트**: 정기적으로 npm 패키지 업데이트
5. **환경변수 백업**: 환경변수를 안전한 곳에 백업

---

문제가 발생하면 Render Logs를 먼저 확인하고, GitHub Issues에 문의하세요.
