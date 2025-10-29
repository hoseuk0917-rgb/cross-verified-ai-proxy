// ============================================================
// Cross-Verified AI Proxy Server
// Google OAuth2 + JWT + Login Logs + Auto Cleanup + Admin Dashboard
// ============================================================

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const cron = require("node-cron");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// ============================================================
// 1️⃣ Database Connection
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ============================================================
// 2️⃣ Session Config
// ============================================================
app.use(
  session({
    secret: process.env.SESSION_SECRET || "cross-verified-jwt-key-2025",
    resave: false,
    saveUninitialized: true,
  })
);

// ============================================================
// 3️⃣ Google OAuth Setup
// ============================================================
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      done(null, profile);
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use(passport.initialize());
app.use(passport.session());

// ============================================================
// 4️⃣ OAuth Routes
// ============================================================
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/callback",
  passport.authenticate("google", { failureRedirect: "/auth/fail" }),
  async (req, res) => {
    try {
      const profile = req.user;
      const token = jwt.sign(
        {
          email: profile.emails[0].value,
          name: profile.displayName,
        },
        process.env.JWT_SECRET || "cross-verified-jwt-key-2025",
        { expiresIn: "2h" }
      );

      await pool.query(
        "INSERT INTO login_logs (email, name, ip_address) VALUES ($1, $2, $3)",
        [profile.emails[0].value, profile.displayName, req.ip]
      );

      res.json({
        success: true,
        user: {
          displayName: profile.displayName,
          email: profile.emails[0].value,
        },
        token,
      });
    } catch (err) {
      console.error("❌ OAuth callback error:", err.message);
      res.status(500).json({ success: false, error: err.message });
    }
  }
);

app.get("/auth/fail", (_, res) =>
  res.status(401).json({ success: false, error: "OAuth failed" })
);

app.get("/auth/verify", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res.status(401).json({ success: false, error: "Missing token" });

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "cross-verified-jwt-key-2025"
    );
    res.json({ success: true, user: decoded });
  } catch (err) {
    res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
});

// ============================================================
// 5️⃣ DB Setup
// ============================================================
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS login_logs (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        name VARCHAR(100),
        login_time TIMESTAMP DEFAULT NOW(),
        ip_address VARCHAR(50)
      );
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_login_logs_email ON login_logs(email);
    `);
    console.log("✅ login_logs table ready");
  } catch (err) {
    console.error("❌ DB setup error:", err.message);
  }
})();

// ============================================================
// 6️⃣ Auto Cleanup (every midnight)
// ============================================================
cron.schedule("0 0 * * *", async () => {
  try {
    const result = await pool.query(
      "DELETE FROM login_logs WHERE login_time < NOW() - INTERVAL '7 days';"
    );
    console.log(`🧹 ${result.rowCount} old logs deleted (older than 7 days)`);
  } catch (err) {
    console.error("❌ Log cleanup failed:", err.message);
  }
});

// ============================================================
// 7️⃣ Admin API (JSON)
// ============================================================
app.get("/admin/logs", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res.status(401).json({ success: false, error: "Missing token" });

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "cross-verified-jwt-key-2025"
    );

    const result = await pool.query(`
      SELECT email, name, ip_address, login_time 
      FROM login_logs
      ORDER BY login_time DESC
      LIMIT 10;
    `);

    res.json({
      success: true,
      user: decoded.email,
      logs: result.rows,
    });
  } catch (err) {
    console.error("❌ /admin/logs error:", err.message);
    res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
});

// ============================================================
// 8️⃣ Admin Dashboard (HTML Table View)
// ============================================================
app.get("/admin/logs/view", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res
        .status(401)
        .send("<h3 style='color:red'>Unauthorized: Missing token</h3>");

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "cross-verified-jwt-key-2025"
    );

    const result = await pool.query(`
      SELECT email, name, ip_address, login_time 
      FROM login_logs
      ORDER BY login_time DESC
      LIMIT 10;
    `);

    const tableRows = result.rows
      .map(
        (r) => `
        <tr>
          <td>${r.email}</td>
          <td>${r.name || "-"}</td>
          <td>${r.ip_address || "-"}</td>
          <td>${new Date(r.login_time).toLocaleString()}</td>
        </tr>`
      )
      .join("");

    const html = `
      <html>
        <head>
          <title>Admin Login Logs</title>
          <style>
            body { font-family: Arial; background-color: #f7f7f7; padding: 20px; }
            h1 { color: #333; }
            table { border-collapse: collapse; width: 100%; background: white; }
            th, td { border: 1px solid #ccc; padding: 10px; text-align: left; }
            th { background-color: #eee; }
          </style>
        </head>
        <body>
          <h1>Recent Login Logs (Admin View)</h1>
          <p><b>User:</b> ${decoded.email}</p>
          <table>
            <tr><th>Email</th><th>Name</th><th>IP Address</th><th>Login Time</th></tr>
            ${tableRows}
          </table>
        </body>
      </html>
    `;

    res.send(html);
  } catch (err) {
    console.error("❌ /admin/logs/view error:", err.message);
    res.status(401).send("<h3 style='color:red'>Invalid or expired token</h3>");
  }
});

// ============================================================
// 9️⃣ Health Check
// ============================================================
app.get("/health", (_, res) =>
  res.json({
    status: "ok",
    version: "10.3.0",
    timestamp: new Date().toISOString(),
  })
);

// ============================================================
// 🔟 Start Server
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
