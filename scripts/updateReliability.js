// scripts/updateReliability.js
import dotenv from "dotenv";
import fs from "fs";
import axios from "axios";
import { sendAdminNotice } from "../utils/mailer.js";
dotenv.config();

(async () => {
  try {
    const geminiKey = process.env.GEMINI_ADMIN_KEY;
    const prompt = `
      최신 언론중재위·팩트체크넷·KPF 공개자료를 기반으로
      언론사별 bias, factcheck, arbitration 수치를 JSON으로 재구성하라.
      형식: {"chosun.com": {"bias":0.42,"factcheck":12,"arbitration":5}, ...}
    `;
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=${geminiKey}`;
    const r = await axios.post(url, { contents: [{ parts: [{ text: prompt }] }] });
    const result = r.data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();

    if (!result) throw new Error("Empty Gemini response");
    fs.writeFileSync("data/media_reliability_pending.json", result);
    console.log("✅ media_reliability_pending.json 생성 완료");

    await sendAdminNotice(
      "📥 Cross-Verified AI – 신뢰도 데이터 갱신 승인 요청",
      `<p>새로운 신뢰도 데이터가 생성되었습니다.</p>
       <p>관리자 대시보드에서 <b>승인</b>하여 적용하세요.</p>
       <a href="https://${process.env.APP_DOMAIN}/admin/dashboard">관리자 페이지 이동</a>`
    );
  } catch (err) {
    console.error("❌ updateReliability failed:", err.message);
  }
})();
