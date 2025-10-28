@echo off
REM Cross-Verified Proxy Server 빠른 시작 스크립트 (Windows)
REM Usage: quick-start.bat

echo ============================================
echo Cross-Verified Proxy Server v9.8.4
echo 빠른 시작
echo ============================================
echo.

REM Node.js 버전 확인
echo 1. Node.js 버전 확인...
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js가 설치되지 않았습니다.
    echo         https://nodejs.org/ 에서 Node.js v18 이상을 설치해주세요.
    pause
    exit /b 1
)

for /f "tokens=1 delims=v" %%i in ('node -v') do set NODE_VERSION=%%i
echo [OK] Node.js 확인 완료
echo.

REM 프로젝트 디렉터리 이동
echo 2. 프로젝트 디렉터리 확인...
cd proxy-server 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] proxy-server 디렉터리를 찾을 수 없습니다.
    pause
    exit /b 1
)
echo [OK] 프로젝트 디렉터리 확인 완료
echo.

REM 의존성 설치
echo 3. 의존성 설치...
if not exist "node_modules" (
    call npm install
    if %errorlevel% neq 0 (
        echo [ERROR] 의존성 설치 실패
        pause
        exit /b 1
    )
    echo [OK] 의존성 설치 완료
) else (
    echo [INFO] node_modules가 이미 존재합니다. 건너뜁니다.
)
echo.

REM .env 파일 확인
echo 4. 환경변수 파일 확인...
if not exist ".env" (
    echo [WARN] .env 파일이 없습니다.
    set /p CREATE_ENV=.env.example을 복사하여 .env를 생성하시겠습니까? (Y/N): 
    if /i "%CREATE_ENV%"=="Y" (
        copy .env.example .env >nul
        echo [OK] .env 파일 생성 완료
        echo.
        echo [WARN] 중요: .env 파일을 편집하여 다음 값들을 설정해주세요:
        echo        - DATABASE_URL (PostgreSQL 연결 문자열)
        echo        - ENCRYPTION_KEY (64자 hex)
        echo        - JWT_SECRET
        echo        - GOOGLE_CLIENT_ID
        echo        - GOOGLE_CLIENT_SECRET
        echo.
        echo 보안 키 생성:
        echo    node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
        echo.
        pause
    ) else (
        echo [ERROR] 환경변수 설정이 필요합니다.
        pause
        exit /b 1
    )
) else (
    echo [OK] .env 파일이 존재합니다.
)
echo.

REM 데이터베이스 초기화
echo 5. 데이터베이스 초기화...
set /p INIT_DB=데이터베이스를 초기화하시겠습니까? (Y/N): 
if /i "%INIT_DB%"=="Y" (
    call npm run init-db
    if %errorlevel% neq 0 (
        echo [ERROR] 데이터베이스 초기화 실패
        echo         DATABASE_URL이 올바르게 설정되어 있는지 확인하세요.
        pause
        exit /b 1
    )
    echo [OK] 데이터베이스 초기화 완료
) else (
    echo [INFO] 데이터베이스 초기화를 건너뜁니다.
)
echo.

REM 서버 시작
echo 6. 서버 시작...
set /p START_SERVER=서버를 시작하시겠습니까? (Y/N): 
if /i "%START_SERVER%"=="Y" (
    echo.
    echo ============================================
    echo 서버 시작!
    echo ============================================
    echo.
    echo 서버 URL: http://localhost:3000
    echo Health Check: http://localhost:3000/health
    echo 테스트 UI: test\test-server.html
    echo.
    echo 서버를 중지하려면 Ctrl+C를 누르세요.
    echo.
    call npm start
) else (
    echo.
    echo [OK] 설치가 완료되었습니다!
    echo.
    echo 서버를 시작하려면 다음 명령어를 실행하세요:
    echo    cd proxy-server
    echo    npm start
    echo.
    echo 또는 개발 모드 (nodemon):
    echo    npm run dev
    echo.
    pause
)
