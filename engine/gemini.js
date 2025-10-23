const axios = require('axios');

/**
 * Gemini API 프록시 모듈
 * Gemini 2.5 Flash 및 Pro 모델 지원
 */

const GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta';

// 모델 엔드포인트
const MODELS = {
  flash: 'gemini-2.0-flash-exp',
  pro: 'gemini-2.0-exp'
};

/**
 * Gemini API 호출
 * @param {Object} params - 호출 파라미터
 * @returns {Object} Gemini 응답
 */
async function callGemini(params) {
  const {
    apiKey,
    model = 'flash',
    prompt,
    temperature = 0.7,
    maxTokens = 2048,
    systemInstruction = null
  } = params;

  if (!apiKey) {
    throw new Error('Gemini API key is required');
  }

  const modelName = MODELS[model] || MODELS.flash;
  const url = `${GEMINI_BASE_URL}/models/${modelName}:generateContent`;

  try {
    const requestBody = {
      contents: [{
        parts: [{
          text: prompt
        }]
      }],
      generationConfig: {
        temperature: temperature,
        maxOutputTokens: maxTokens,
        topP: 0.95,
        topK: 40
      }
    };

    // System instruction 추가 (선택)
    if (systemInstruction) {
      requestBody.systemInstruction = {
        parts: [{ text: systemInstruction }]
      };
    }

    const response = await axios.post(url, requestBody, {
      params: { key: apiKey },
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 30000 // 30초
    });

    if (response.data && response.data.candidates && response.data.candidates.length > 0) {
      const candidate = response.data.candidates[0];
      const text = candidate.content?.parts?.[0]?.text || '';
      
      return {
        success: true,
        text: text,
        model: modelName,
        finishReason: candidate.finishReason,
        safetyRatings: candidate.safetyRatings,
        usage: response.data.usageMetadata
      };
    }

    return {
      success: false,
      error: 'No valid response from Gemini',
      response: response.data
    };
  } catch (error) {
    console.error('Gemini API error:', error.message);
    
    if (error.response) {
      return {
        success: false,
        error: error.response.data?.error?.message || 'Gemini API error',
        status: error.response.status,
        details: error.response.data
      };
    }

    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * 키워드 추출 (Gemini 기반)
 * @param {string} text - 분석할 텍스트
 * @param {string} apiKey - Gemini API Key
 * @returns {Object} 추출된 키워드
 */
async function extractKeywords(text, apiKey) {
  const prompt = `Extract the most important keywords and key phrases from the following text. 
Return them as a JSON array of strings, with the most relevant terms first.
Limit to 10 keywords maximum.

Text: """
${text}
"""

Format your response as a valid JSON array only, like: ["keyword1", "keyword2", ...]`;

  try {
    const response = await callGemini({
      apiKey,
      model: 'flash',
      prompt,
      temperature: 0.3,
      maxTokens: 500
    });

    if (response.success) {
      try {
        // JSON 파싱 시도
        const cleanedText = response.text.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
        const keywords = JSON.parse(cleanedText);
        return {
          success: true,
          keywords: Array.isArray(keywords) ? keywords : [],
          raw: response.text
        };
      } catch (parseError) {
        // JSON 파싱 실패 시 간단한 키워드 추출
        const words = response.text.split(/[,\n]/).map(w => w.trim()).filter(w => w.length > 0);
        return {
          success: true,
          keywords: words.slice(0, 10),
          raw: response.text,
          warning: 'Fallback keyword extraction used'
        };
      }
    }

    return {
      success: false,
      error: response.error
    };
  } catch (error) {
    console.error('Keyword extraction error:', error.message);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * 문맥 유사도 계산 (Gemini 기반 임베딩)
 * @param {string} generatedAnswer - AI 생성 답변
 * @param {Object} sourceData - 검증 출처 데이터
 * @param {string} apiKey - Gemini API Key
 * @returns {number} 유사도 점수 (0-1)
 */
async function calculateSemanticSimilarity(generatedAnswer, sourceData, apiKey) {
  // 출처 텍스트 구성
  const sourceText = sourceData.sources?.map(s => 
    `${s.title || ''} ${s.description || ''}`
  ).join(' ') || '';

  if (!sourceText || sourceText.trim().length === 0) {
    return 0.5; // 기본값
  }

  const prompt = `Compare the semantic similarity between the following generated answer and source information.
Rate the similarity on a scale from 0.0 to 1.0, where:
- 1.0 = Identical or nearly identical meaning
- 0.7-0.9 = High similarity, same core concepts
- 0.5-0.6 = Moderate similarity, related topics
- 0.3-0.4 = Low similarity, loosely related
- 0.0-0.2 = No similarity or contradictory

Generated Answer: """
${generatedAnswer}
"""

Source Information: """
${sourceText}
"""

Respond with only a single number between 0.0 and 1.0, nothing else.`;

  try {
    const response = await callGemini({
      apiKey,
      model: 'flash',
      prompt,
      temperature: 0.1,
      maxTokens: 10
    });

    if (response.success) {
      const score = parseFloat(response.text.trim());
      if (!isNaN(score) && score >= 0 && score <= 1) {
        return score;
      }
    }

    return 0.5; // 기본값
  } catch (error) {
    console.error('Semantic similarity error:', error.message);
    return 0.5; // 기본값
  }
}

/**
 * API Key 유효성 검증
 * @param {string} apiKey - Gemini API Key
 * @returns {Object} 검증 결과
 */
async function validateApiKey(apiKey) {
  try {
    const response = await callGemini({
      apiKey,
      model: 'flash',
      prompt: 'Hello, test connection.',
      temperature: 0.1,
      maxTokens: 10
    });

    return {
      valid: response.success,
      message: response.success ? 'API Key is valid' : response.error
    };
  } catch (error) {
    return {
      valid: false,
      message: error.message
    };
  }
}

module.exports = {
  callGemini,
  extractKeywords,
  calculateSemanticSimilarity,
  validateApiKey,
  MODELS
};
