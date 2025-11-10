// utils/xmlParser.js
// Cross-Verified AI Proxy v14.4.1 — XML Parser 단일화 유지
// (fast-xml-parser 기반, xml2js 완전 제거)
// ───────────────────────────────────────────────
import { XMLParser } from "fast-xml-parser";

/**
 * XML → JSON 변환 함수
 * @param {string} xmlString - 원본 XML 문자열
 * @returns {object} 변환된 JSON 객체
 */
export function parseXMLtoJSON(xmlString) {
  try {
    const parser = new XMLParser({
      ignoreAttributes: false,      // XML 속성 보존
      attributeNamePrefix: "@_",    // 속성 prefix
      parseTagValue: true,          // 태그값 변환
      parseAttributeValue: true,    // 속성값 변환
      trimValues: true,             // 공백 제거
      allowBooleanAttributes: true  // 단일 속성 허용
    });
    return parser.parse(xmlString);
  } catch (err) {
    console.error("❌ XML 파싱 실패:", err.message);
    return { error: true, message: err.message };
  }
}

/**
 * XML 응답에서 특정 키 추출 (선택적 유틸)
 * @param {string} xmlString
 * @param {string[]} keys
 * @returns {object}
 */
export function extractFields(xmlString, keys = []) {
  const data = parseXMLtoJSON(xmlString);
  if (data.error) return data;
  const jsonText = JSON.stringify(data);
  const found = {};
  for (const k of keys) {
    const regex = new RegExp(`"${k}"\\s*:\\s*"([^"]+)"`);
    const match = regex.exec(jsonText);
    if (match && match[1]) found[k] = match[1];
  }
  return found;
}
