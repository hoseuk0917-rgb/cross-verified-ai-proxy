const axios = require('axios');

const BASE_URL = 'http://localhost:3000';

// 색상 출력을 위한 ANSI 코드
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logSuccess(message) {
  log(`✅ ${message}`, 'green');
}

function logError(message) {
  log(`❌ ${message}`, 'red');
}

function logInfo(message) {
  log(`ℹ️  ${message}`, 'cyan');
}

function logWarning(message) {
  log(`⚠️  ${message}`, 'yellow');
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * 테스트 1: Ping 테스트
 */
async function testPing() {
  log('\n=== Test 1: Ping Server ===', 'blue');
  try {
    const response = await axios.get(`${BASE_URL}/ping`);
    if (response.data.status === 'ok') {
      logSuccess('Server is responding');
      logInfo(`Version: ${response.data.version}`);
      logInfo(`Uptime: ${Math.floor(response.data.uptime)}s`);
      return true;
    }
  } catch (error) {
    logError(`Ping failed: ${error.message}`);
    return false;
  }
}

/**
 * 테스트 2: 검증 엔진 테스트 (CrossRef)
 */
async function testCrossRef() {
  log('\n=== Test 2: CrossRef Verification ===', 'blue');
  try {
    const response = await axios.post(`${BASE_URL}/api/verify/crossref`, {
      query: 'artificial intelligence machine learning'
    });
    
    if (response.data.success && response.data.sourceDetected) {
      logSuccess('CrossRef verification successful');
      logInfo(`Found ${response.data.count} sources`);
      if (response.data.sources && response.data.sources.length > 0) {
        logInfo(`First source: ${response.data.sources[0].title}`);
      }
      return true;
    } else {
      logWarning('CrossRef verification returned no sources');
      return false;
    }
  } catch (error) {
    logError(`CrossRef test failed: ${error.message}`);
    return false;
  }
}

/**
 * 테스트 3: OpenAlex 검증 테스트
 */
async function testOpenAlex() {
  log('\n=== Test 3: OpenAlex Verification ===', 'blue');
  try {
    const response = await axios.post(`${BASE_URL}/api/verify/openalex`, {
      query: 'quantum computing'
    });
    
    if (response.data.success && response.data.sourceDetected) {
      logSuccess('OpenAlex verification successful');
      logInfo(`Found ${response.data.count} sources`);
      return true;
    } else {
      logWarning('OpenAlex verification returned no sources');
      return false;
    }
  } catch (error) {
    logError(`OpenAlex test failed: ${error.message}`);
    return false;
  }
}

/**
 * 테스트 4: Wikidata 검증 테스트
 */
async function testWikidata() {
  log('\n=== Test 4: Wikidata Verification ===', 'blue');
  try {
    const response = await axios.post(`${BASE_URL}/api/verify/wikidata`, {
      query: 'Albert Einstein'
    });
    
    if (response.data.success && response.data.sourceDetected) {
      logSuccess('Wikidata verification successful');
      logInfo(`Found ${response.data.count} entities`);
      if (response.data.sources && response.data.sources.length > 0) {
        logInfo(`First entity: ${response.data.sources[0].label}`);
      }
      return true;
    } else {
      logWarning('Wikidata verification returned no sources');
      return false;
    }
  } catch (error) {
    logError(`Wikidata test failed: ${error.message}`);
    return false;
  }
}

/**
 * 테스트 5: 전체 검증 엔진 테스트
 */
async function testVerifyAll() {
  log('\n=== Test 5: All Verification Engines ===', 'blue');
  try {
    const response = await axios.post(`${BASE_URL}/api/verify/all`, {
      query: 'climate change research'
    });
    
    if (response.data.success) {
      logSuccess('All engines verification completed');
      logInfo(`Duration: ${response.data.metadata.duration}`);
      logInfo(`Active engines: ${response.data.metadata.activeEngines}`);
      
      // 각 엔진 결과 요약
      const results = response.data.results;
      Object.keys(results).forEach(engine => {
        const result = results[engine];
        if (result.sourceDetected) {
          log(`  ✓ ${engine}: ${result.count} sources`, 'green');
        } else {
          log(`  ✗ ${engine}: No sources`, 'yellow');
        }
      });
      
      return true;
    }
  } catch (error) {
    logError(`Verify all test failed: ${error.message}`);
    return false;
  }
}

/**
 * 테스트 6: TruthScore 계산 테스트
 */
async function testTruthScore() {
  log('\n=== Test 6: TruthScore Calculation ===', 'blue');
  try {
    // Mock 엔진 데이터
    const engines = [
      {
        name: 'crossref',
        isActive: true,
        sourceDetected: true,
        quality: 0.95,
        keywordMatch: 0.85,
        weight: 1.0,
        deltaW: 1.0,
        timeDelta: 0
      },
      {
        name: 'openalex',
        isActive: true,
        sourceDetected: true,
        quality: 0.90,
        keywordMatch: 0.78,
        weight: 1.0,
        deltaW: 1.0,
        timeDelta: 0
      },
      {
        name: 'wikidata',
        isActive: true,
        sourceDetected: true,
        quality: 0.80,
        keywordMatch: 0.92,
        weight: 1.0,
        deltaW: 1.0,
        timeDelta: 0
      }
    ];

    const response = await axios.post(`${BASE_URL}/api/truthscore/calculate`, {
      engines
    });
    
    if (response.data.truthScore !== undefined) {
      logSuccess('TruthScore calculation successful');
      logInfo(`TruthScore: ${response.data.truthScore}%`);
      logInfo(`Confidence: ${response.data.confidence} ${response.data.icon}`);
      logInfo(`Active engines: ${response.data.activeEnginesCount}`);
      
      // 엔진별 세부 정보
      log('\n  Engine Details:', 'cyan');
      Object.keys(response.data.details).forEach(engine => {
        const detail = response.data.details[engine];
        log(`  - ${engine}: V=${detail.verifiability}, R=${detail.relevance}, ΔW=${detail.deltaW}`, 'cyan');
      });
      
      return true;
    }
  } catch (error) {
    logError(`TruthScore test failed: ${error.message}`);
    return false;
  }
}

/**
 * 테스트 7: 암호화/복호화 테스트
 */
async function testEncryption() {
  log('\n=== Test 7: Encryption/Decryption ===', 'blue');
  try {
    const plaintext = 'test-api-key-12345';
    const masterPassword = 'test-master-password';

    // 암호화
    const encryptResponse = await axios.post(`${BASE_URL}/api/keys/encrypt`, {
      plaintext,
      masterPassword
    });

    if (!encryptResponse.data.success) {
      logError('Encryption failed');
      return false;
    }

    logSuccess('Encryption successful');
    const encryptedData = encryptResponse.data.encrypted;

    // 복호화
    const decryptResponse = await axios.post(`${BASE_URL}/api/keys/decrypt`, {
      encryptedData,
      masterPassword
    });

    if (decryptResponse.data.success && decryptResponse.data.decrypted === plaintext) {
      logSuccess('Decryption successful');
      logInfo(`Original: ${plaintext}`);
      logInfo(`Decrypted: ${decryptResponse.data.decrypted}`);
      return true;
    } else {
      logError('Decryption failed or data mismatch');
      return false;
    }
  } catch (error) {
    logError(`Encryption test failed: ${error.message}`);
    return false;
  }
}

/**
 * 메인 테스트 실행
 */
async function runTests() {
  log('\n╔══════════════════════════════════════════════════════════╗', 'blue');
  log('║   Cross-Verified AI Proxy Server - Test Suite           ║', 'blue');
  log('╚══════════════════════════════════════════════════════════╝', 'blue');

  const results = {
    passed: 0,
    failed: 0,
    total: 0
  };

  // 서버 응답 대기
  logInfo('Waiting for server to be ready...');
  await sleep(1000);

  // 테스트 실행
  const tests = [
    { name: 'Ping', fn: testPing },
    { name: 'CrossRef', fn: testCrossRef },
    { name: 'OpenAlex', fn: testOpenAlex },
    { name: 'Wikidata', fn: testWikidata },
    { name: 'Verify All', fn: testVerifyAll },
    { name: 'TruthScore', fn: testTruthScore },
    { name: 'Encryption', fn: testEncryption }
  ];

  for (const test of tests) {
    results.total++;
    try {
      const passed = await test.fn();
      if (passed) {
        results.passed++;
      } else {
        results.failed++;
      }
    } catch (error) {
      logError(`Test ${test.name} threw an error: ${error.message}`);
      results.failed++;
    }
    await sleep(500);
  }

  // 결과 요약
  log('\n╔══════════════════════════════════════════════════════════╗', 'blue');
  log('║   Test Results Summary                                    ║', 'blue');
  log('╚══════════════════════════════════════════════════════════╝', 'blue');
  log(`\nTotal Tests: ${results.total}`);
  logSuccess(`Passed: ${results.passed}`);
  if (results.failed > 0) {
    logError(`Failed: ${results.failed}`);
  } else {
    log(`Failed: ${results.failed}`, 'green');
  }
  
  const successRate = ((results.passed / results.total) * 100).toFixed(1);
  log(`\nSuccess Rate: ${successRate}%`, successRate >= 70 ? 'green' : 'red');
  
  log('\n');
}

// 테스트 시작
runTests().catch(error => {
  logError(`Test suite failed: ${error.message}`);
  process.exit(1);
});
