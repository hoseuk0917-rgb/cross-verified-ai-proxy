const fs = require("fs");
const path = require("path");

const root = __dirname;
const prePath = path.join(root, "pre_prompt_case1.txt");
if (!fs.existsSync(prePath)) throw new Error("Missing pre_prompt_case1.txt");

const pre = fs.readFileSync(prePath, "utf8");
if (!pre.trim()) throw new Error("pre_prompt_case1.txt is empty");

const payloadGroq = {
  model: "llama-3.3-70b-versatile",
  temperature: 0.1,
  messages: [{ role: "user", content: pre }],
};

const payloadGemini = {
  contents: [{ role: "user", parts: [{ text: pre }] }],
  generationConfig: { temperature: 0.1 },
};

const payloadCF = {
  messages: [{ role: "user", content: pre }],
};

fs.writeFileSync(path.join(root, "payload_groq_pre.json"), JSON.stringify(payloadGroq, null, 2), "utf8");
fs.writeFileSync(path.join(root, "payload_gemini_pre.json"), JSON.stringify(payloadGemini, null, 2), "utf8");
fs.writeFileSync(path.join(root, "payload_cf_pre.json"), JSON.stringify(payloadCF, null, 2), "utf8");

console.log("OK created:");
for (const f of ["payload_groq_pre.json", "payload_gemini_pre.json", "payload_cf_pre.json"]) {
  const st = fs.statSync(path.join(root, f));
  console.log(f, st.size, "bytes");
}
