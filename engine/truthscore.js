/**
 * TruthScore 계산 엔진
 * Cross-Verified AI v9.7.7 명세 기반
 */

// 초기값 및 상수
const INITIAL_WEIGHTS = {
  crossref: 1.00,
  openalex: 1.00,
  gdelt: 1.00,
  wikidata: 1.00,
  github: 1.00,
  klaw: 1.00
};

const DELTA_W_INITIAL = 1.00;
const DELTA_W_MIN = 0.60;
const DELTA_W_MAX = 1.40;
const DELTA_W_STABLE_MIN = 0.80;
const DELTA_W_STABLE_MAX = 1.20;

const LEARNING_RATE = 0.08; // η
const DECAY_COEFFICIENT = 0.05; // λ
const STABILITY_BIAS = 0.02; // γ
const INACTIVE_DECAY = 0.8; // α

// 연관도 가중치
const ALPHA = 0.7; // Verifiability 가중치
const BETA = 0.3; // Quality 가중치

/**
 * 검증가능성(Verifiability) 계산
 * @param {number} keywordMatch - Gemini 키워드 매칭 점수 (0-1)
 * @param {number} quality - 출처 공신력 (Qi)
 * @param {number} timeDelta - 시간 경과 (초)
 * @returns {number} 검증가능성 점수
 */
function calculateVerifiability(keywordMatch, quality, timeDelta = 0) {
  const timeDecay = Math.exp(-DECAY_COEFFICIENT * timeDelta / 3600); // 시간을 시간 단위로 변환
  const vi = keywordMatch * quality * timeDecay;
  return Math.max(0, Math.min(1, vi)); // 0-1 범위로 정규화
}

/**
 * 보정항(Δwi) 계산
 * @param {Object} params - 계산 파라미터
 * @returns {number} 새로운 보정항 값
 */
function calculateDeltaWeight(params) {
  const {
    previousDeltaW,
    verifiability,
    normalizedV,
    activeEngineMean,
    isActive,
    timeDelta = 0
  } = params;

  if (!isActive) {
    // 비활성 엔진: 점진적 감쇠
    return Math.max(DELTA_W_MIN, previousDeltaW * INACTIVE_DECAY);
  }

  // 활성 엔진: 검증가능성 기반 업데이트
  const timeDecay = Math.exp(-DECAY_COEFFICIENT * timeDelta / 3600);
  const verifiabilityDiff = (normalizedV - activeEngineMean) + STABILITY_BIAS;
  const newComponent = verifiabilityDiff * timeDecay;
  
  const deltaW = (1 - LEARNING_RATE) * previousDeltaW + 
                 LEARNING_RATE * newComponent;

  // 임계치 적용
  return Math.max(DELTA_W_MIN, Math.min(DELTA_W_MAX, deltaW));
}

/**
 * Δwi 상태 확인
 * @param {number} deltaW - 보정항 값
 * @returns {Object} 상태 정보
 */
function checkDeltaWStatus(deltaW) {
  if (deltaW >= DELTA_W_STABLE_MIN && deltaW <= DELTA_W_STABLE_MAX) {
    return { status: 'stable', warning: false };
  } else if (deltaW < DELTA_W_STABLE_MIN || deltaW > DELTA_W_STABLE_MAX) {
    return { status: 'warning', warning: true, message: '⚠️ 가중치 편차 감지' };
  }
  return { status: 'unknown', warning: false };
}

/**
 * 연관도(Ri) 계산
 * @param {number} verifiability - 검증가능성 (Vi)
 * @param {number} quality - 출처 공신력 (Qi)
 * @returns {number} 연관도
 */
function calculateRelevance(verifiability, quality) {
  return ALPHA * verifiability + BETA * quality;
}

/**
 * TruthScore 계산
 * @param {Array} engines - 검증 엔진 배열
 * @returns {Object} TruthScore 및 상세 정보
 */
function calculateTruthScore(engines) {
  let numerator = 0;
  let denominator = 0;
  const activeEngines = [];
  const details = {};

  // 1단계: 활성 엔진 필터링 및 검증가능성 계산
  engines.forEach(engine => {
    if (engine.isActive && engine.sourceDetected) {
      const vi = calculateVerifiability(
        engine.keywordMatch || 0.5,
        engine.quality,
        engine.timeDelta || 0
      );
      
      activeEngines.push({
        ...engine,
        verifiability: vi
      });
    }
  });

  // 2단계: 검증가능성 정규화
  const totalV = activeEngines.reduce((sum, e) => sum + e.verifiability, 0);
  
  if (totalV === 0) {
    return {
      truthScore: 0,
      confidence: 'none',
      details: {},
      warning: '출처 미검출'
    };
  }

  activeEngines.forEach(engine => {
    engine.normalizedV = engine.verifiability / totalV;
  });

  // 3단계: 평균 정규화 검증가능성 계산
  const meanNormalizedV = activeEngines.reduce((sum, e) => sum + e.normalizedV, 0) / activeEngines.length;

  // 4단계: TruthScore 계산
  activeEngines.forEach(engine => {
    const weight = engine.weight || INITIAL_WEIGHTS[engine.name];
    const relevance = calculateRelevance(engine.verifiability, engine.quality);
    const timeDecay = Math.exp(-DECAY_COEFFICIENT * (engine.timeDelta || 0) / 3600);
    
    const contribution = weight * relevance * engine.quality * timeDecay;
    numerator += contribution;
    denominator += weight;

    // 보정항 업데이트
    const newDeltaW = calculateDeltaWeight({
      previousDeltaW: engine.deltaW || DELTA_W_INITIAL,
      verifiability: engine.verifiability,
      normalizedV: engine.normalizedV,
      activeEngineMean: meanNormalizedV,
      isActive: true,
      timeDelta: engine.timeDelta || 0
    });

    const deltaWStatus = checkDeltaWStatus(newDeltaW);

    details[engine.name] = {
      verifiability: engine.verifiability.toFixed(3),
      normalizedV: engine.normalizedV.toFixed(3),
      relevance: relevance.toFixed(3),
      quality: engine.quality.toFixed(2),
      weight: weight.toFixed(2),
      deltaW: newDeltaW.toFixed(3),
      deltaWStatus: deltaWStatus,
      contribution: (contribution / denominator * 100).toFixed(1) + '%'
    };
  });

  const truthScore = denominator > 0 ? (numerator / denominator) * 100 : 0;

  // 신뢰도 등급 결정
  let confidence = 'unknown';
  let icon = '⚪';
  
  if (truthScore >= 90) {
    confidence = 'high';
    icon = '🟢';
  } else if (truthScore >= 70) {
    confidence = 'medium-high';
    icon = '🟡';
  } else if (truthScore >= 50) {
    confidence = 'medium';
    icon = '🟠';
  } else if (truthScore > 0) {
    confidence = 'low';
    icon = '🔴';
  }

  return {
    truthScore: Math.round(truthScore * 10) / 10,
    confidence,
    icon,
    details,
    activeEnginesCount: activeEngines.length,
    meanNormalizedV: meanNormalizedV.toFixed(3)
  };
}

/**
 * Fail-Grace 모드 처리
 * @param {Object} engineState - 엔진 상태
 * @returns {Object} 업데이트된 상태
 */
function handleFailGrace(engineState) {
  // Fail-Grace 중에는 Δwi를 동결
  return {
    ...engineState,
    deltaW: engineState.deltaW || DELTA_W_INITIAL,
    failGraceActive: true,
    skipNextUpdate: true
  };
}

module.exports = {
  calculateVerifiability,
  calculateDeltaWeight,
  calculateRelevance,
  calculateTruthScore,
  checkDeltaWStatus,
  handleFailGrace,
  INITIAL_WEIGHTS,
  DELTA_W_INITIAL,
  DELTA_W_MIN,
  DELTA_W_MAX
};
