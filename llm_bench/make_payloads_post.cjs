// make_payloads_post.cjs
// 목적: post_prompt_case2.txt의 EVIDENCE PACK(E1:, E2:...)을 읽어서
//      payload_groq_post.json / payload_gemini_post.json / payload_cf_post.json 생성

const fs = require("fs");
const path = require("path");

const dir = __dirname;

const PROMPT_TXT = path.join(dir, "post_prompt_case2.txt");
const OUT_GROQ = path.join(dir, "payload_groq_post.json");
const OUT_GEM  = path.join(dir, "payload_gemini_post.json");
const OUT_CF   = path.join(dir, "payload_cf_post.json");

function mustRead(p) {
  if (!fs.existsSync(p)) throw new Error(`Missing file: ${p}`);
  return fs.readFileSync(p, "utf8");
}

// post_prompt_case2.txt에서 E1: ... snippet="..." 라인을 파싱
function parseEvidencePack(txt) {
  const lines = txt.split(/\r?\n/);
  const items = [];

  // 예: E1: [engine=kosis] [date=2025-01-01] [title=KOSIS (발췌)] snippet="...text..."
  const re = /^E(\d+):\s*\[engine=([^\]]+)\]\s*\[date=([^\]]+)\]\s*\[title=([^\]]+)\]\s*snippet="([\s\S]*)"\s*$/;

  for (const line of lines) {
    const m = line.match(re);
    if (!m) continue;

    const id = `E${m[1]}`;
    const engine = (m[2] || "").trim();
    const date = (m[3] || "").trim();
    const title = (m[4] || "").trim();
    const snippet = (m[5] || "").trim();

    items.push({
      id,
      engine,
      title,
      url: "",          // post_prompt에는 url이 없으니 빈값(필요하면 엔진별로 채워도 됨)
      snippet,
      date
    });
  }

  // 정렬: E1, E2, ...
  items.sort((a, b) => {
    const ai = Number(String(a.id).slice(1)) || 0;
    const bi = Number(String(b.id).slice(1)) || 0;
    return ai - bi;
  });

  return items;
}

// 간단 sanity check: placeholder면 경고
function warnIfPlaceholders(evs) {
  const bad = evs.filter(e => /<paste>|\.{3}/i.test(e.snippet));
  if (bad.length) {
    console.warn("[WARN] Evidence snippet still looks like placeholder for:", bad.map(x => x.id).join(", "));
    console.warn("       post_prompt_case2.txt에서 snippet=\"...\" 부분을 실제 숫자 포함 텍스트로 교체하세요.");
  }
}

function buildSharedUserContent({ userQuery, evidenceItems }) {
  // Groq/CF 공통: “user content” 하나로 넣기 (현재 너의 구조 유지)
    return [
    "당신은 “검증 판정 모델”이다.",
    "",
    "아래 질문과 근거(evidence items)를 보고 판단한다.",
    "",
    "[판정 규칙]",
    '- 근거가 질문/주장에 대해 "지지(SUPPORTED)" / "반박(CONTRADICTED)" / "판단불가(INSUFFICIENT)" 인지 결정한다.',
    "- 근거에는 노이즈(무관/불명확/신뢰 어려움)가 섞일 수 있다.",
    "- 추측으로 단정하지 말고, 반드시 근거의 snippet 내용에 기반하라.",
    "- 근거 snippet에 유효한 수치(숫자/단위/연도/정의)가 있으면, 그 수치를 최우선으로 활용하라.",
    "- 근거가 '확인할 수 있음/제공함'처럼 수치를 직접 제시하지 않으면, 해당 근거만으로는 수치 확정이 불가능하므로 INSUFFICIENT로 판단하라.",
    "- 질문이 특정 수치(예: 2025년 인구)를 요구하는데, 근거에 그 수치가 없으면 절대 만들어내지 마라.",
    "- 출력은 반드시 JSON 한 덩어리만. 절대 코드펜스(```), 백틱, 추가 텍스트를 붙이지 마라.",
    "",
    "[질문]",
    userQuery,
    "",
    "[요구 출력 JSON 스키마]",
    "{",
    '  "verdict": "SUPPORTED" | "CONTRADICTED" | "INSUFFICIENT",',
    '  "confidence_01": 0.0 ~ 1.0,',
    '  "evidence_used": ["E1","E2"],',
    '  "final_answer_ko": "한국어 1~3문장. 근거 기반. 근거에 수치가 있으면 반드시 숫자+단위를 포함(예: 51,234,567명 / 51.6 million). 수치가 없으면 수치가 없다고 명시.",',
    '  "reason_brief": "한국어 1~3문장. 왜 이 verdict인지(수치 존재/부재를 포함).",',
    '  "next_queries": ["추가로 확인하면 좋은 검색어 0~3개"]',
    "}",
    "",
    "[근거 목록]",
    "아래 JSON 배열의 각 항목에는 id가 있다. 근거를 고를 때 id로만 선택해야 한다.",
    "(주의: 근거 목록에 있는 내용 외에는 가정하지 마라.)",
    "",
    JSON.stringify(
      evidenceItems.map(e => ({
        id: e.id,
        title: e.title || "",
        url: e.url || "",
        snippet: e.snippet || "",
        date: e.date || ""
      })),
      null,
      2
    )
    ].join("\n");
}

function writeJson(p, obj) {
  fs.writeFileSync(p, JSON.stringify(obj, null, 2), "utf8");
}

function main() {
  const txt = mustRead(PROMPT_TXT);
  const evidenceItems = parseEvidencePack(txt);

  if (!evidenceItems.length) {
    throw new Error("No evidence items found. post_prompt_case2.txt에 'E1:' 같은 라인이 있는지 확인하세요.");
  }

  warnIfPlaceholders(evidenceItems);

  const userQuery = "2025년 한국 인구는?"; // 케이스2 고정 (원하면 파일에서 읽도록 바꿀 수 있음)
  const userContent = buildSharedUserContent({ userQuery, evidenceItems });

  // 1) GROQ payload (OpenAI-compatible chat)
  const groqPayload = {
    model: "llama-3.3-70b-versatile",
    temperature: 0.1,
    messages: [{ role: "user", content: userContent }]
  };

  // 2) GEMINI payload (generateContent)
  const geminiPayload = {
    contents: [
      {
        role: "user",
        parts: [{ text: userContent }]
      }
    ]
  };

  // 3) CF Workers AI (messages 기반)
  const cfPayload = {
    messages: [{ role: "user", content: userContent }],
    temperature: 0.1
  };

  writeJson(OUT_GROQ, groqPayload);
  writeJson(OUT_GEM, geminiPayload);
  writeJson(OUT_CF, cfPayload);

  console.log("OK: payload_*_post.json created from post_prompt_case2.txt EVIDENCE PACK");
}

main();
