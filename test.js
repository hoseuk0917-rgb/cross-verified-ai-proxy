import axios from "axios";
const key = process.env.GEMINI_API_KEY;
const url = `https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=${key}`;
const data = { contents: [{ parts: [{ text: "테스트 문장입니다." }] }] };
axios.post(url, data)
  .then(r => console.log("✅ Gemini OK:", r.data.candidates?.[0]?.content?.parts?.[0]?.text))
  .catch(e => console.error("❌ Gemini 실패:", e.response?.status, e.response?.data));
