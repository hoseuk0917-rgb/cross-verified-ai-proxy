const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));
app.use('/assets', express.static(path.join(__dirname, 'assets')));

// ============================================================================
// 검증 엔진 가중치 (명세서 3.3)
// ============================================================================
const ENGINE_WEIGHTS = {
  // 기본 엔진 (QV/FV 모드)
  CrossRef: 0.25,
  OpenAlex: 0.25,
  GDELT: 0.25,
  Wikidata: 0.25,
  
  // 특화 엔진 (DV/CV/LM 모드)
  GitHub: 0.50,    // DV/CV 모드 전용
  'K-Law': 1.00    // LM 모드 전용
};

// 출처 품질 지표 Qᵢ (명세서 5.1.1)
const SOURCE_QUALITY = {
  CrossRef: 1.0,
  OpenAlex: 0.9,
  GDELT: 0.8,
  Wikidata: 0.75,
  GitHub: 0.85,
  'K-Law': 1.0
};

// 시간 감쇠 상수
const LAMBDA = 0.1;

// ============================================================================
// 모드별 활성 엔진 (명세서 4.1)
// ============================================================================
const MODE_ENGINES = {
  QV: ['CrossRef', 'OpenAlex', 'GDELT', 'Wikidata'],
  FV: ['CrossRef', 'OpenAlex', 'GDELT', 'Wikidata'],
  DV: ['GitHub', 'GDELT'],
  CV: ['GitHub', 'GDELT'],
  LM: ['K-Law']
};

// ============================================================================
// 검증 엔진 시뮬레이션
// ============================================================================
function simulateVerificationEngine(engine, query) {
  // 실제로는 외부 API를 호출하지만, 여기서는 시뮬레이션
  const reliability = 0.6 + Math.random() * 0.3; // Rᵢ: 0.6~0.9
  const consistency = 0.5 + Math.random() * 0.4; // 0.5~0.9
  const recency = 0.7 + Math.random() * 0.3;     // 0.7~1.0
  const sources = Math.floor(Math.random() * 6) + 1; // 1~6개
  
  // 시간 차이 (일 단위, 0~365일)
  const daysSinceUpdate = Math.floor(Math.random() * 365);
  
  return {
    engine,
    reliability,
    consistency,
    recency,
    sources,
    daysSinceUpdate,
    quality: SOURCE_QUALITY[engine] || 0.8
  };
}

// ============================================================================
// TruthScore 계산 (명세서 5.1.1)
// ============================================================================
function calculateTruthScore(verificationResults, weights) {
  let totalScore = 0;
  let totalWeight = 0;
  
  verificationResults.forEach(result => {
    const { engine, reliability, quality, daysSinceUpdate } = result;
    const weight = weights[engine] || 0;
    
    // 시간 감쇠: e^(-λt)
    const timeDecay = Math.exp(-LAMBDA * (daysSinceUpdate / 365));
    
    // TruthScore = Σ (Rᵢ × Qᵢ × e^(-λt) × wᵢ)
    const engineScore = reliability * quality * timeDecay * weight;
    
    totalScore += engineScore;
    totalWeight += weight;
  });
  
  // 정규화
  return totalWeight > 0 ? totalScore / totalWeight : 0;
}

// ============================================================================
// Δwᵢ 보정 계산 (명세서 5.3)
// ============================================================================
function calculateDeltaWeight(result, previousTrend = 0) {
  const { consistency, reliability } = result;
  
  // 추세 계산 (간단한 예시)
  const trend = consistency > 0.7 ? 0.1 : -0.1;
  
  // Δwᵢ = α × (consistency - 0.5) + β × (Rᵢ - 0.7) + γ × trendᵢ
  const alpha = 0.3;
  const beta = 0.5;
  const gamma = 0.2;
  
  const deltaWeight = 
    alpha * (consistency - 0.5) + 
    beta * (reliability - 0.7) + 
    gamma * trend;
  
  return {
    deltaWeight: Math.max(-0.2, Math.min(0.2, deltaWeight)), // 제한: -0.2 ~ 0.2
    trend
  };
}

// ============================================================================
// 신뢰도 아이콘 매핑 (명세서 5.2) - 핵심 로직!
// ============================================================================
function getIconForScore(score, dropReason = null) {
  if (score >= 0.7) {
    return {
      icon: 'green',
      label: '정상',
      color: '#22c55e'
    };
  } else if (score >= 0.4 && score < 0.7) {
    // 0.4~0.69 범위에서 하락 사유에 따라 다른 아이콘!
    if (dropReason === 'lack_of_sources') {
      return {
        icon: 'question',
        label: '출처 부족',
        color: '#eab308'
      };
    } else {
      // 일치도 낮음 또는 최신성 부족
      return {
        icon: 'triangle',
        label: '일치도 낮음 / 최신성 부족',
        color: '#eab308'
      };
    }
  } else {
    return {
      icon: 'x',
      label: '검증 실패 / 불일치',
      color: '#ef4444'
    };
  }
}

// 신뢰도 하락 사유 판단
function determineDropReason(verificationResults) {
  const totalSources = verificationResults.reduce((sum, r) => sum + r.sources, 0);
  const avgConsistency = verificationResults.reduce((sum, r) => sum + r.consistency, 0) / verificationResults.length;
  const avgRecency = verificationResults.reduce((sum, r) => sum + r.recency, 0) / verificationResults.length;
  
  if (totalSources < 3) {
    return 'lack_of_sources';
  } else if (avgConsistency < 0.6) {
    return 'low_consistency';
  } else if (avgRecency < 0.5) {
    return 'low_recency';
  }
  
  return 'other';
}

// LM 모드 아이콘 (명세서 5.2)
function getLMIcon(status) {
  const icons = {
    success: { icon: 'green', label: 'API 통신 정상', color: '#22c55e' },
    delayed: { icon: 'triangle', label: 'API 지연', color: '#eab308' },
    error: { icon: 'x', label: 'API 오류', color: '#ef4444' }
  };
  return icons[status] || icons.error;
}

// ============================================================================
// API 엔드포인트
// ============================================================================

// 검증 요청
app.post('/api/verify', (req, res) => {
  try {
    const { query, mode = 'QV', sentenceFilter = 'all' } = req.body;
    
    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }
    
    // 모드별 활성 엔진
    const activeEngines = MODE_ENGINES[mode] || MODE_ENGINES.QV;
    
    // LM 모드는 특별 처리
    if (mode === 'LM') {
      const apiStatus = Math.random() > 0.1 ? 'success' : (Math.random() > 0.5 ? 'delayed' : 'error');
      const iconInfo = getLMIcon(apiStatus);
      
      return res.json({
        mode,
        query,
        isLMMode: true,
        apiStatus,
        icon: iconInfo,
        results: [{
          engine: 'K-Law',
          status: apiStatus,
          message: '법령 검색 ' + (apiStatus === 'success' ? '성공' : apiStatus === 'delayed' ? '지연 중' : '실패')
        }]
      });
    }
    
    // 검증 엔진 실행
    const verificationResults = activeEngines.map(engine => 
      simulateVerificationEngine(engine, query)
    );
    
    // 가중치 정규화
    let weights = {};
    let totalWeight = 0;
    activeEngines.forEach(engine => {
      weights[engine] = ENGINE_WEIGHTS[engine] || 0.25;
      totalWeight += weights[engine];
    });
    
    // 정규화하여 총합 = 1.0
    if (totalWeight > 0) {
      Object.keys(weights).forEach(engine => {
        weights[engine] /= totalWeight;
      });
    }
    
    // TruthScore 계산
    const truthScore = calculateTruthScore(verificationResults, weights);
    
    // Δwᵢ 보정
    const deltaWeights = verificationResults.map(result => {
      const { deltaWeight, trend } = calculateDeltaWeight(result);
      return {
        engine: result.engine,
        deltaWeight,
        trend,
        newWeight: weights[result.engine] + deltaWeight
      };
    });
    
    // 신뢰도 하락 사유 판단
    const dropReason = determineDropReason(verificationResults);
    
    // 아이콘 결정
    const iconInfo = getIconForScore(truthScore, dropReason);
    
    // 응답 생성
    res.json({
      mode,
      query,
      truthScore: Math.round(truthScore * 100) / 100,
      percentage: Math.round(truthScore * 100),
      dropReason,
      icon: iconInfo,
      verificationResults: verificationResults.map(r => ({
        engine: r.engine,
        reliability: Math.round(r.reliability * 100) / 100,
        consistency: Math.round(r.consistency * 100) / 100,
        recency: Math.round(r.recency * 100) / 100,
        sources: r.sources,
        daysSinceUpdate: r.daysSinceUpdate
      })),
      weights,
      deltaWeights,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 모드 정보
app.get('/api/modes', (req, res) => {
  res.json({
    modes: {
      QV: {
        name: '질문검증',
        description: '사용자 질문 + 사실 검증',
        engines: MODE_ENGINES.QV
      },
      FV: {
        name: '사실검증',
        description: '기존 문장 사실 검증 / 신뢰도 피드백',
        engines: MODE_ENGINES.FV
      },
      DV: {
        name: '개발검증',
        description: '코드 / 기술 정합성 검증',
        engines: MODE_ENGINES.DV
      },
      CV: {
        name: '코드검증',
        description: '사용자 입력 코드 검증 (Pro 전용)',
        engines: MODE_ENGINES.CV
      },
      LM: {
        name: '법령정보',
        description: '법령 검색 / 조항 조회',
        engines: MODE_ENGINES.LM
      }
    }
  });
});

// 헬스 체크
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: '9.7.3',
    timestamp: new Date().toISOString()
  });
});

// 루트 경로
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`🚀 Cross-Verified AI Server running on port ${PORT}`);
  console.log(`📍 http://localhost:${PORT}`);
});

module.exports = app;
