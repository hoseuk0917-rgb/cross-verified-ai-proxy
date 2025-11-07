// =======================================================
// Cross-Verified AI Proxy — v13.9.0 (Admin Dashboard)
// =======================================================

import express from "express";
import session from "express-session";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import dotenv from "dotenv";
import cors from "cors";
import morgan from "morgan";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { createClient } from "@supabase/supabase-js";
import axios from "axios";
import path from "path";
import { fileURLToPath } from "url";
import { parseXMLtoJSON } from "./utils/xmlParser.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// EJS + Static 세팅
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// ─────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(morgan("dev"));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const PgStore = connectPgSimple(session);
const pgPool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
app.use(session({
  store: new PgStore({ pool: pgPool, tableName: "session_store" }),
  secret: process.env.SESSION_SECRET || "dev-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 86400000 },
}));
// ─────────────────────────────
// ✅ OAuth (Google Admin)
// ─────────────────────────────
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_ADMIN_CLIENT_ID,
  clientSecret: process.env.GOOGLE_ADMIN_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_ADMIN_CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    const whitelist = process.env.ADMIN_WHITELIST?.split(",") || [];
    if (!whitelist.includes(email)) return done(new Error("Unauthorized admin user"));
    await supabase.from("users").upsert([{ email, name: profile.displayName }], { onConflict: "email" });
    return done(null, { email, name: profile.displayName });
  } catch (err) { return done(err); }
}));
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));
app.use(passport.initialize());
app.use(passport.session());

// ─────────────────────────────
// ✅ Admin Dashboard Route
// ─────────────────────────────
function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.redirect("/auth/admin");
}

app.get("/auth/admin", passport.authenticate("google", { scope: ["email", "profile"] }));
app.get("/auth/admin/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => res.redirect("/admin/dashboard"));
app.get("/auth/failure", (req, res) => res.status(401).send("❌ OAuth Failed"));

app.get("/admin/dashboard", ensureAuth, async (req, res) => {
  const { data: logs } = await supabase
    .from("api_logs")
    .select("created_at, engine, truthscore, response_time")
    .order("created_at", { ascending: false })
    .limit(20);

  const avgTruth = logs?.reduce((a, b) => a + (b.truthscore || 0), 0) / (logs?.length || 1);
  const avgResponse = logs?.reduce((a, b) => a + (b.response_time || 0), 0) / (logs?.length || 1);
  res.render("dashboard", {
    user: req.user,
    stats: { avgTruth: avgTruth.toFixed(2), avgResponse: avgResponse.toFixed(0), count: logs?.length || 0 },
    logs: logs || [],
  });
});
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Cross-Verified Admin Dashboard</title>
  <link rel="stylesheet" href="/css/dashboard.css">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <header><h2>🧭 Cross-Verified AI Admin Dashboard</h2></header>
  <section>
    <h3>Welcome, <%= user.name %> (<%= user.email %>)</h3>
    <div class="stats">
      <div>🧠 평균 TruthScore: <b><%= stats.avgTruth %></b></div>
      <div>⚡ 평균 응답속도: <b><%= stats.avgResponse %> ms</b></div>
      <div>📈 로그 수: <b><%= stats.count %></b></div>
    </div>
    <canvas id="truthChart" width="400" height="150"></canvas>
  </section>
  <footer><p>© 2025 Cross-Verified AI</p></footer>

  <script>
  const ctx = document.getElementById('truthChart');
  const data = <%- JSON.stringify(logs.map(l => l.truthscore || 0)) %>;
  new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.map((_,i)=>i+1),
      datasets: [{ label: 'TruthScore', data, borderColor:'#3b82f6', fill:false }]
    },
    options:{ scales:{ y:{min:0,max:1} } }
  });
  </script>
</body>
</html>
body {
  font-family: "Inter", sans-serif;
  background: #f8fafc;
  color: #1e293b;
  margin: 0;
  padding: 0;
}
header {
  background: #1e293b;
  color: #fff;
  padding: 12px 20px;
}
section {
  padding: 20px;
}
.stats {
  display: flex;
  gap: 20px;
  margin-bottom: 20px;
}
.stats div {
  background: #fff;
  padding: 10px 15px;
  border-radius: 10px;
  box-shadow: 0 2px 6px rgba(0,0,0,0.1);
}
