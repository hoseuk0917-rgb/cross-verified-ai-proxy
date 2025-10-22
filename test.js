const http = require('http');

// 테스트 설정
const HOST = 'localhost';
const PORT = 3000;
const BASE_URL = `http://${HOST}:${PORT}`;

console.log('='.repeat(80));
console.log('Cross-Verified AI v9.7.3 Rev C - 테스트 시작');
console.log('='.repeat(80));
console.log('');

// 서버가 실행 중인지 확인
function checkServer() {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: HOST,
      port: PORT,
      path: '/api/health',
      method: 'GET'
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        console.log('✅ 서버 상태 확인:', data);
        resolve(JSON.parse(data));
      });
    });

    req.on('error', (err) => {
      console.error('❌ 서버 연결 실패:', err.message);
      console.log('');
      console.log('서버를 먼저 실행해주세요:');
      console.log('  npm start');
      reject(err);
    });

    req.end();
  });
}

// 검증 테스트
function testVerification(mode, query) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ mode, query });

    const options = {
      hostname: HOST,
      port: PORT,
      path: '/api/verify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    console.log('');
    console.log('-'.repeat(80));
    console.log(`📝 테스트: ${mode} 모드`);
    console.log(`   질문: ${query}`);
    console.log('-'.repeat(80));

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const result = JSON.parse(data);
          
          console.log('');
          console.log(`🎯 TruthScore: ${result.percentage}%`);
          console.log(`📊 아이콘: ${result.icon.icon} (${result.icon.label})`);
          console.log(`📋 하락 사유: ${result.dropReason || 'N/A'}`);
          
          if (result.verificationResults) {
            console.log('');
            console.log('검증 엔진 결과:');
            result.verificationResults.forEach(engine => {
              console.log(`  - ${engine.engine}: 신뢰도 ${(engine.reliability * 100).toFixed(0)}%, 출처 ${engine.sources}개`);
            });
          }
          
          console.log('');
          console.log('✅ 테스트 통과');
          
          resolve(result);
        } catch (err) {
          console.error('❌ 응답 파싱 실패:', err.message);
          reject(err);
        }
      });
    });

    req.on('error', (err) => {
      console.error('❌ 요청 실패:', err.message);
      reject(err);
    });

    req.write(postData);
    req.end();
  });
}

// 모드 정보 테스트
function testModes() {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: HOST,
      port: PORT,
      path: '/api/modes',
      method: 'GET'
    };

    console.log('');
    console.log('-'.repeat(80));
    console.log('📚 모드 정보 조회');
    console.log('-'.repeat(80));

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const result = JSON.parse(data);
          console.log('');
          Object.entries(result.modes).forEach(([mode, info]) => {
            console.log(`${mode}: ${info.name}`);
            console.log(`  설명: ${info.description}`);
            console.log(`  엔진: ${info.engines.join(', ')}`);
            console.log('');
          });
          console.log('✅ 모드 정보 조회 성공');
          resolve(result);
        } catch (err) {
          console.error('❌ 응답 파싱 실패:', err.message);
          reject(err);
        }
      });
    });

    req.on('error', (err) => {
      console.error('❌ 요청 실패:', err.message);
      reject(err);
    });

    req.end();
  });
}

// 메인 테스트 실행
async function runTests() {
  try {
    // 1. 서버 상태 확인
    await checkServer();
    
    // 2. 모드 정보 조회
    await testModes();
    
    // 3. 각 모드별 검증 테스트
    const testCases = [
      { mode: 'QV', query: '기후 변화가 북극곰 개체수에 미치는 영향은?' },
      { mode: 'FV', query: '2024년 노벨 물리학상은 AI 관련 연구로 수여되었다.' },
      { mode: 'DV', query: 'React 18의 새로운 concurrent rendering 기능에 대해 설명해주세요.' },
      { mode: 'CV', query: 'const fibonacci = (n) => n <= 1 ? n : fibonacci(n-1) + fibonacci(n-2);' },
      { mode: 'LM', query: '개인정보보호법 제15조의 내용은?' }
    ];
    
    for (const testCase of testCases) {
      await testVerification(testCase.mode, testCase.query);
      // 테스트 간 대기
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    console.log('');
    console.log('='.repeat(80));
    console.log('🎉 모든 테스트 완료!');
    console.log('='.repeat(80));
    console.log('');
    console.log('웹 UI 접속: http://localhost:3000');
    console.log('');
    
  } catch (error) {
    console.error('');
    console.error('테스트 실패:', error.message);
    process.exit(1);
  }
}

// 테스트 실행
runTests();
