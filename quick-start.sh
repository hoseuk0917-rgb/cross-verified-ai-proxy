#!/bin/bash

# Cross-Verified Proxy Server 빠른 시작 스크립트
# Usage: ./quick-start.sh

set -e

echo "🚀 Cross-Verified Proxy Server v9.8.4 빠른 시작"
echo "================================================"
echo ""

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 함수: 성공 메시지
success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# 함수: 경고 메시지
warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# 함수: 에러 메시지
error() {
    echo -e "${RED}❌ $1${NC}"
}

# Node.js 버전 확인
echo "1. Node.js 버전 확인..."
if ! command -v node &> /dev/null; then
    error "Node.js가 설치되지 않았습니다."
    echo "   https://nodejs.org/ 에서 Node.js v18 이상을 설치해주세요."
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    error "Node.js v18 이상이 필요합니다. 현재 버전: $(node -v)"
    exit 1
fi
success "Node.js $(node -v) 확인 완료"

# PostgreSQL 확인
echo ""
echo "2. PostgreSQL 확인..."
if ! command -v psql &> /dev/null; then
    warning "PostgreSQL이 설치되지 않았습니다."
    echo "   https://www.postgresql.org/download/ 에서 PostgreSQL 17을 설치해주세요."
    echo "   또는 Docker Compose를 사용할 수 있습니다: docker-compose up -d"
else
    success "PostgreSQL 확인 완료"
fi

# 프로젝트 디렉터리 확인
cd proxy-server 2>/dev/null || {
    error "proxy-server 디렉터리를 찾을 수 없습니다."
    echo "   현재 디렉터리: $(pwd)"
    exit 1
}
success "프로젝트 디렉터리 확인 완료"

# 의존성 설치
echo ""
echo "3. 의존성 설치..."
if [ ! -d "node_modules" ]; then
    npm install
    success "의존성 설치 완료"
else
    warning "node_modules가 이미 존재합니다. 건너뜁니다."
fi

# .env 파일 확인
echo ""
echo "4. 환경변수 파일 확인..."
if [ ! -f ".env" ]; then
    warning ".env 파일이 없습니다."
    read -p "   .env.example을 복사하여 .env를 생성하시겠습니까? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp .env.example .env
        success ".env 파일 생성 완료"
        echo ""
        warning "⚠️  중요: .env 파일을 편집하여 다음 값들을 설정해주세요:"
        echo "   - DATABASE_URL (PostgreSQL 연결 문자열)"
        echo "   - ENCRYPTION_KEY (64자 hex)"
        echo "   - JWT_SECRET"
        echo "   - GOOGLE_CLIENT_ID"
        echo "   - GOOGLE_CLIENT_SECRET"
        echo ""
        echo "보안 키 생성:"
        echo "   node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\""
        echo ""
        read -p "설정을 완료한 후 Enter를 눌러 계속하세요..."
    else
        error "환경변수 설정이 필요합니다."
        exit 1
    fi
else
    success ".env 파일이 존재합니다."
fi

# 데이터베이스 초기화
echo ""
echo "5. 데이터베이스 초기화..."
read -p "   데이터베이스를 초기화하시겠습니까? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    npm run init-db
    if [ $? -eq 0 ]; then
        success "데이터베이스 초기화 완료"
    else
        error "데이터베이스 초기화 실패"
        echo "   DATABASE_URL이 올바르게 설정되어 있는지 확인하세요."
        exit 1
    fi
else
    warning "데이터베이스 초기화를 건너뜁니다."
fi

# 서버 시작 여부 확인
echo ""
echo "6. 서버 시작..."
read -p "   서버를 시작하시겠습니까? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    success "서버를 시작합니다..."
    echo ""
    echo "================================================"
    echo "🎉 서버 시작!"
    echo "================================================"
    echo ""
    echo "서버 URL: http://localhost:3000"
    echo "Health Check: http://localhost:3000/health"
    echo "테스트 UI: test/test-server.html"
    echo ""
    echo "서버를 중지하려면 Ctrl+C를 누르세요."
    echo ""
    npm start
else
    echo ""
    success "설치가 완료되었습니다!"
    echo ""
    echo "서버를 시작하려면 다음 명령어를 실행하세요:"
    echo "   cd proxy-server"
    echo "   npm start"
    echo ""
    echo "또는 개발 모드 (nodemon):"
    echo "   npm run dev"
fi
