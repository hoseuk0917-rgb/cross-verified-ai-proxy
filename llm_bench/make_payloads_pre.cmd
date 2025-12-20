import fs from "fs";

const pre = fs.readFileSync("pre_prompt_case1.txt", "utf8");

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
  model: "@cf/meta/llama-3.1-8b-instruct",
  temperature: 0.1,
  messages: [{ role: "user", content: pre }],
};

fs.writeFileSync("payload_groq_pre.json", JSON.stringify(payloadGroq, null, 2), "utf8");
fs.writeFileSync("payload_gemini_pre.json", JSON.stringify(payloadGemini, null, 2), "utf8");
fs.writeFileSync("payload_cf_pre.json", JSON.stringify(payloadCF, null, 2), "utf8");

console.log("OK: payload_*_pre.json created");
