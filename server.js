// server.js
import express from "express";
import fs from "fs";
import path from "path";
import cors from "cors";
import nodemailer from "nodemailer";

const app = express();
app.use(cors());
app.use(express.json());

/* ==========================================
   1️⃣ Whitelist Check API
   ========================================== */
app.get("/api/check-whitelist", async (req, res) => {
  try {
    const filePath = path.resolve("./whitelist.json");

    // Load existing whitelist
    let oldList = [];
    if (fs.existsSync(filePath)) {
      oldList = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    }

    // Example new whitelist data (you can replace this with live data fetching)
    const newList = ["NAVER", "GOOGLE", "K-LAW", "GITHUB", "RENDER"];

    // Compare difference
    const diff = newList.filter(x => !oldList.includes(x));
    let updated = false;

    if (diff.length > 0) {
      fs.writeFileSync(filePath, JSON.stringify(newList, null, 2));
      updated = true;

      // Send email alert if updated
      await sendUpdateAlert(diff);
      console.log("✅ Whitelist updated:", diff);
    }

    res.json({
      status: "ok",
      updated,
      diff,
      lastChecked: new Date().toISOString(),
      message: updated
        ? "Whitelist updated and alert sent"
        : "No change detected",
    });
  } catch (err) {
    console.error("❌ Whitelist check failed:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ==========================================
   2️⃣ Gmail Notification Function
   ========================================== */
async function sendUpdateAlert(diff) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      type: "OAuth2",
      user: process.env.MAIL_FROM,
      clientId: process.env.GMAIL_CLIENT_ID,
      clientSecret: process.env.GMAIL_CLIENT_SECRET,
      refreshToken: process.env.GMAIL_REFRESH_TOKEN,
    },
  });

  const mailOptions = {
    from: process.env.MAIL_FROM,
    to: process.env.MAIL_TO,
    subject: "🔔 Cross-Verified AI Whitelist Update Alert",
    text: `The following whitelist entries have changed:\n\n${diff.join("\n")}`,
  };

  await transporter.sendMail(mailOptions);
  console.log("📨 Alert email sent successfully!");
}

/* ==========================================
   3️⃣ Flutter Web Static Serving
   ========================================== */
const webPath = path.resolve("build/web");
app.use(express.static(webPath));

// Static routing must be declared last
app.get("*", (_, res) => {
  res.sendFile(path.join(webPath, "index.html"));
});

/* ==========================================
   4️⃣ Server Start
   ========================================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Cross-Verified AI Proxy running on port ${PORT}`);
});
