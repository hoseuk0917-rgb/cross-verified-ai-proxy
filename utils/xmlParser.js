// utils/xmlParser.js
import { XMLParser } from "fast-xml-parser";

export async function parseXmlToJson(xml) {
  try {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: "",
      parseAttributeValue: true,
      trimValues: true,
    });
    return parser.parse(xml);
  } catch (err) {
    console.error("XML Parse Error:", err.message);
    return { error: err.message };
  }
}
