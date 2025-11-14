import fs from "fs";
import path from "path";

const TERMS_PATH = path.resolve("./config/klaw_terms.json");
const LOG_PATH = path.resolve("./usage.log");

function rebuildTerms() {
  const terms = JSON.parse(fs.readFileSync(TERMS_PATH, "utf-8"));
  if (!fs.existsSync(LOG_PATH)) {
    console.log("usage.log not found, skipping rebuild.");
    return;
  }

  const text = fs.readFileSync(LOG_PATH, "utf-8");
  const lines = text.split("\n").filter(l => l.length > 2);

  const freq = {};
  for (const line of lines) {
    const words = line.match(/[가-힣A-Za-z0-9]+/g);
    if (!words) continue;
    for (const w of words) {
      freq[w] = (freq[w] || 0) + 1;
    }
  }

  // 상위 50개 신규 후보만 반영
  const newWords = Object.entries(freq)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 50)
    .map(([w]) => w)
    .filter(w => !terms[w]);

  for (const w of newWords) {
    terms[w] = [];
  }

  fs.writeFileSync(TERMS_PATH, JSON.stringify(terms, null, 2));
  console.log(`✅ Updated klaw_terms.json with ${newWords.length} new entries`);
}

rebuildTerms();
