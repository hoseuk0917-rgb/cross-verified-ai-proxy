/**
 * Cross-Verified AI: Render SMTP Relay 테스트 스크립트
 * 작성자: Ho Seok Goh
 * 기능: .env 기반 SMTP 설정을 불러와 테스트 메일을 전송함
 */

import dotenv from "dotenv";
import nodemailer from "nodemailer";

dotenv.config();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendTestEmail() {
  try {
    const info = await transporter.sendMail({
      from: `"Cross-Verified AI 자동알림" <${process.env.MAIL_FROM}>`,
      to: process.env.MAIL_TO,
      subject: "📢 Render SMTP 메일 테스트 성공 알림",
      html: `
        <div style="font-family:Segoe UI,Roboto,sans-serif;line-height:1.5;">
          <h2>✅ Render SMTP 연결 성공</h2>
          <p>이 메일은 Cross-Verified AI 서버에서 자동 전송된 테스트 메일입니다.</p>
          <p><strong>발신자:</strong> ${process.env.MAIL_FROM}</p>
          <p><strong>수신자:</strong> ${process.env.MAIL_TO}</p>
          <p style="color:gray;">(서버 시간: ${new Date().toLocaleString()})</p>
        </div>
      `,
    });

    console.log("✅ 메일 발송 성공!");
    console.log(`📩 Message ID: ${info.messageId}`);
  } catch (err) {
    console.error("❌ 메일 발송 실패:", err.message);
  }
}

sendTestEmail();
