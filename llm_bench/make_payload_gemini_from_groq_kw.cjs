// make_payload_gemini_from_groq_kw.cjs
// usage: node make_payload_gemini_from_groq_kw.cjs out_groq_kw_1.json payload_gemini_kwpost.json
const fs = require("fs");

const inPath = process.argv[2];
const outPath = process.argv[3] || "payload_gemini_kwpost.json";
if (!inPath) {
  console.error("Usage: node make_payload_gemini_from_groq_kw.cjs <out_groq_kw_#.json> [out_payload.json]");
  process.exit(1);
}

const outer = JSON.parse(fs.readFileSync(inPath, "utf8"));
let c = String(outer?.choices?.[0]?.message?.content ?? "").trim();

// strip code fences if present
c = c.replace(/^\s*```(?:json)?\s*/i, "").replace(/\s*```\s*$/i, "").trim();

// parse inner JSON (fallback: first {...} block)
let kw;
try {
  kw = JSON.parse(c);
} catch (e) {
  const m = c.match(/\{[\s\S]*\}/);
  if (!m) throw e;
  kw = JSON.parse(m[0]);
}

const question = "2025년 한국 인구는?";

// Gemini에게는 “긴 원문” 대신 이 압축 요약만 준다.
const prompt = `
당신은 “검증 판정 모델”이다.
아래 [질문]과 [Groq가 원문에서 추출한 요약/키워드/숫자/인용문]만 보고 판단하라.
- 원문에 없는 숫자/표현을 만들지 마라.
- 출력은 JSON 한 덩어리만 (코드펜스 금지).

[질문]
${question}

[Groq 추출(JSON)]
${JSON.stringify(kw, null, 2)}

[요구 출력 JSON 스키마]
{
  "verdict": "SUPPORTED" | "CONTRADICTED" | "INSUFFICIENT",
  "confidence_01": 0.0 ~ 1.0,
  "final_answer_ko": "한국어로 1~2문장. 숫자 있으면 포함(원문 기반).",
  "reason_brief": "1~2문장.",
  "key_numbers": ["원문 기반 핵심 수치 문자열 0~5개"],
  "used_quotes": ["사용한 인용문(있으면) 0~2개"]
}
`.trim();

const payload = {
  contents: [{ role: "user", parts: [{ text: prompt }] }],
  generationConfig: { temperature: 0.1, maxOutputTokens: 512 }
};

fs.writeFileSync(outPath, JSON.stringify(payload, null, 2), "utf8");
console.log(`OK: ${outPath} created`);
