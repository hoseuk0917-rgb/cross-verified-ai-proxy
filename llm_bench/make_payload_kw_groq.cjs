const fs = require("fs");
const path = require("path");

const dir = __dirname;
const inTxt = path.join(dir, "kw_caseA.txt");
const outJson = path.join(dir, "payload_kw_groq.json");

if (!fs.existsSync(inTxt)) throw new Error("Missing kw_caseA.txt");

const raw = fs.readFileSync(inTxt, "utf8");

const prompt = [
  "당신은 '핵심 정보 추출기'다.",
  "",
  "아래 [QUESTION]과 [EVIDENCE] 원문을 보고, 원문에 있는 내용만으로 JSON을 출력하라.",
  "",
  "규칙:",
  "1) 절대 추측/상상 금지. 원문에 없는 숫자/고유명사/단정 생성 금지.",
  "2) numbers/dates/entities/terms/quotes는 반드시 원문에서 그대로 복사한 문자열이어야 한다.",
  "3) quotes는 원문에서 '그대로' 따온 짧은 인용(10~40자)만 3~8개.",
  "4) claims_ko는 1~3문장, 단 원문에 있는 정보만 압축.",
  "5) 원문에 정확한 '2025 인구 수치'가 없으면 missing에 '정확한 수치 없음'을 명시.",
  "",
  "출력 형식: 반드시 JSON 한 덩어리(코드펜스 금지).",
  "",
  "스키마:",
  "{",
  '  "numbers": ["원문에서 그대로 복사한 숫자/단위"],',
  '  "dates": ["YYYY", "YYYY-MM-DD" 등"],',
  '  "entities": ["기관/지명/지표명(원문 그대로)"],',
  '  "terms": ["핵심 키워드(원문 그대로)"],',
  '  "quotes": ["원문 그대로 짧은 인용 3~8개"],',
  '  "claims_ko": "한국어 1~3문장(원문 기반 압축)",',
  '  "missing": ["부족한 정보가 있으면 나열"]',
  "}",
  "",
  raw
].join("\n");

const payload = {
  model: "llama-3.3-70b-versatile",
  temperature: 0.1,
  messages: [{ role: "user", content: prompt }]
};

fs.writeFileSync(outJson, JSON.stringify(payload, null, 2));
console.log("OK:", path.basename(outJson), "created");
