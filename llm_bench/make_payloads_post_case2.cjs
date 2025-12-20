// make_payloads_post_case2.cjs
const fs = require("fs");
const path = require("path");

const dir = __dirname;
const postPromptPath = path.join(dir, "post_prompt_case2.txt");
if (!fs.existsSync(postPromptPath)) throw new Error("Missing: post_prompt_case2.txt");

const post = fs.readFileSync(postPromptPath, "utf8");

const payloadGroq = {
  model: "llama-3.3-70b-versatile",
  temperature: 0.1,
  messages: [{ role: "user", content: post }]
};
fs.writeFileSync(path.join(dir, "payload_groq_post_case2.json"), JSON.stringify(payloadGroq, null, 2), "utf8");

const payloadGemini = {
  contents: [{ role: "user", parts: [{ text: post }] }],
  generationConfig: { temperature: 0.1 }
};
fs.writeFileSync(path.join(dir, "payload_gemini_post_case2.json"), JSON.stringify(payloadGemini, null, 2), "utf8");

const payloadCF = {
  messages: [{ role: "user", content: post }]
};
fs.writeFileSync(path.join(dir, "payload_cf_post_case2.json"), JSON.stringify(payloadCF, null, 2), "utf8");

console.log("OK: payload_*_post_case2.json created");
