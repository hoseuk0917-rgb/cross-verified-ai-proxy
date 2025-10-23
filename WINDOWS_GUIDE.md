# Windows에서 서버 실행하기 🪟

## 사전 요구사항

### Node.js 설치 확인
cmd 창을 열고 다음 명령어 실행:
```cmd
node --version
npm --version
```

만약 "명령을 찾을 수 없습니다" 오류가 나면:
1. https://nodejs.org 에서 LTS 버전 다운로드
2. 설치 후 cmd 재시작
3. 다시 확인

## 단계별 실행 방법

### 1단계: 프로젝트 폴더로 이동
```cmd
cd C:\projects\cross-verified-ai-proxy
```

### 2단계: 의존성 설치 (처음 한 번만)
```cmd
npm install
```

설치 중 다음과 같은 메시지가 나타납니다:
```
added 143 packages, and audited 144 packages in 6s
```

### 3단계: 서버 실행
```cmd
npm start
```

**중요**: 이 cmd 창은 닫지 마세요! 서버가 계속 실행되어야 합니다.

성공하면 다음이 표시됩니다:
```
╔══════════════════════════════════════════════════════════╗
║   Cross-Verified AI Proxy Server v9.7.7                  ║
║   Server running on http://localhost:3000               ║
╚══════════════════════════════════════════════════════════╝

Available endpoints:
  GET  /ping
  POST /api/gemini/generate
  ...
```

### 4단계: 테스트 (새 cmd 창)
**새로운 cmd 창을 열어서** (Ctrl+T 또는 새 창):

```cmd
cd C:\projects\cross-verified-ai-proxy
curl http://localhost:3000/ping
```

또는:
```cmd
node test.js
```

## 🔧 문제 해결

### 문제 1: "npm start" 후 아무것도 안 나타남
**확인사항**:
- package.json 파일이 있는지 확인
- 오류 메시지가 있는지 확인

**해결**: package.json의 scripts 섹션 확인:
```json
{
  "scripts": {
    "start": "node server.js"
  }
}
```

없다면 직접 실행:
```cmd
node server.js
```

### 문제 2: 포트 3000이 이미 사용 중
**오류 메시지**:
```
Error: listen EADDRINUSE: address already in use :::3000
```

**해결 방법 1**: 다른 포트 사용
`.env` 파일 수정:
```
PORT=3001
```

**해결 방법 2**: 기존 프로세스 종료
```cmd
# 포트 사용 프로세스 찾기
netstat -ano | findstr :3000

# 나온 PID 번호로 종료 (예: PID가 1234인 경우)
taskkill /PID 1234 /F
```

### 문제 3: 모듈을 찾을 수 없음
**오류 메시지**:
```
Error: Cannot find module 'express'
```

**해결**:
```cmd
# node_modules 삭제 후 재설치
rmdir /s /q node_modules
del package-lock.json
npm install
```

### 문제 4: EPERM 또는 권한 오류
**해결**: 관리자 권한으로 cmd 실행
1. cmd 검색
2. 우클릭 → "관리자 권한으로 실행"
3. 다시 시도

## 📝 정상 실행 예시

### 터미널 1 (서버 실행)
```cmd
C:\projects\cross-verified-ai-proxy>npm start

> cross-verified-ai-proxy@1.0.0 start
> node server.js

╔══════════════════════════════════════════════════════════╗
║   Cross-Verified AI Proxy Server v9.7.7                  ║
║   Server running on http://localhost:3000               ║
╚══════════════════════════════════════════════════════════╝

Available endpoints:
  GET  /ping
  POST /api/gemini/generate
  POST /api/verify/all
  POST /api/truthscore/calculate
  ...
```

### 터미널 2 (테스트)
```cmd
C:\projects\cross-verified-ai-proxy>curl http://localhost:3000/ping
{"status":"ok","timestamp":"2025-10-24T...","version":"9.7.7","uptime":5.123}
```

## 🌐 브라우저에서 테스트

cmd 대신 브라우저를 사용할 수도 있습니다:

1. 서버 실행 (npm start)
2. 브라우저 열기
3. 주소창에 입력: `http://localhost:3000/ping`
4. JSON 응답 확인

## 🎯 빠른 체크리스트

실행이 안 된다면 순서대로 확인:
- [ ] Node.js 설치됨 (node --version 확인)
- [ ] 올바른 폴더에 있음 (server.js 파일이 있는 폴더)
- [ ] npm install 실행함
- [ ] .env 파일 있음
- [ ] npm start 실행함
- [ ] 서버가 종료되지 않고 실행 중
- [ ] 새 터미널에서 curl 실행

## 💡 팁

### PowerShell 사용
cmd 대신 PowerShell을 사용할 수도 있습니다:
```powershell
# curl 대신 Invoke-WebRequest 사용
Invoke-WebRequest -Uri http://localhost:3000/ping
```

### nodemon으로 자동 재시작
개발 중 코드 수정 시 자동 재시작:
```cmd
npm install -g nodemon
nodemon server.js
```

---

**도움이 더 필요하면 오류 메시지를 정확히 알려주세요!**
