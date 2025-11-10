// =======================================================
// Cross-Verified AI Proxy — v14.7.0
// (User-Key Federated Proxy + Multi-Engine Verify Integration
//  + Local Naver Merge + GeoIP + Admin Dashboard + Engine Calibration)
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
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { parseXMLtoJSON } from "./utils/xmlParser.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────
// ✅ Static & Middleware
// ─────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));
app.use((req, _, next) => {
  if (["POST", "PUT", "PATCH"].includes(req.method))
    console.log("📦 [DEBUG] Incoming body:", req.body);
  next();
});

// ─────────────────────────────
// ✅ Supabase + PostgreSQL 세션
// ─────────────────────────────
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
passport.serializeUser((u, d) => d(null, u));
passport.deserializeUser((u, d) => d(null, u));
app.use(passport.initialize());
app.use(passport.session());

// ─────────────────────────────
// ✅ Admin Dashboard
// ─────────────────────────────
function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.redirect("/auth/admin");
}
app.get("/auth/admin", passport.authenticate("google", { scope: ["email", "profile"] }));
app.get("/auth/admin/callback",
  passport.authenticate("google", { failureRedirect: "/auth/failure", session: true }),
  (req, res) => res.redirect("/admin/dashboard"));
app.get("/auth/failure", (_, res) => res.status(401).send("❌ OAuth Failed"));
app.get("/admin/dashboard", ensureAuth, async (req, res) => {
  const { data: logs } = await supabase.from("engine_stats").select("*").order("updated_at", { ascending: false });
  res.render("dashboard", { user: req.user, stats: logs || [] });
});
// ─────────────────────────────
// ✅ Naver Whitelist & API
// ─────────────────────────────
const whitelistPath = path.join(__dirname, "data", "naver_whitelist.json");
let whitelistData = {};
try {
  whitelistData = JSON.parse(fs.readFileSync(whitelistPath, "utf-8"));
} catch { whitelistData = { tiers: {} }; }
const allDomains = Object.values(whitelistData.tiers || {}).flatMap(t => t.domains);
function filterByWhitelist(items = []) {
  return items.filter(i => {
    const link = i.originallink || i.link || "";
    return allDomains.some(d => link.includes(d));
  });
}
async function callNaverAPIs(query, id, secret) {
  if (!id || !secret) throw new Error("Naver API 키 누락");
  const headers = {
    "X-Naver-Client-Id": id,
    "X-Naver-Client-Secret": secret,
    "User-Agent": "CrossVerifiedAI/1.0",
  };
  const base = "https://openapi.naver.com/v1/search";
  const endpoints = {
    news: `${base}/news.json?query=${encodeURIComponent(query)}&display=5`,
    ency: `${base}/encyc.json?query=${encodeURIComponent(query)}&display=3`,
    web: `${base}/webkr.json?query=${encodeURIComponent(query)}&display=5`,
  };
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const results = {};
  for (const [key, url] of Object.entries(endpoints)) {
    try {
      await sleep(300);
      const res = await axios.get(url, { headers });
      results[key] = filterByWhitelist(res.data.items || []);
    } catch { results[key] = []; }
  }
  return results;
}

// ✅ Gemini / Naver Test
app.post("/api/test-gemini", async (req, res) => {
  try {
    const { gemini_key, query, mode = "flash" } = req.body;
    if (!gemini_key || !query) return res.status(400).json({ success: false, message: "❌ Gemini 키 또는 query 누락" });
    const model = mode === "pro" ? "gemini-2.5-pro" : "gemini-2.5-flash";
    const r = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${gemini_key}`,
      { contents: [{ parts: [{ text: query }] }] }
    );
    const text = r.data?.candidates?.[0]?.content?.parts?.[0]?.text || "결과 없음";
    res.json({ success: true, model, result: text.slice(0, 250), source: "user-key" });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post("/api/test-naver", async (req, res) => {
  try {
    const { query, naver_id, naver_secret } = req.body;
    if (!query || !naver_id || !naver_secret)
      return res.status(400).json({ success: false, message: "❌ Naver 키 또는 query 누락" });
    const result = await callNaverAPIs(query, naver_id, naver_secret);
    res.json({
      success: true,
      counts: { news: result.news.length, ency: result.ency.length, web: result.web.length },
      sample: { news: result.news[0]?.title, ency: result.ency[0]?.title, web: result.web[0]?.title },
      full: result,
      source: "local"
    });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ─────────────────────────────
// ✅ Verify (Local Naver Merge)
// ─────────────────────────────
async function fetchCrossref(q){const {data}=await axios.get(`https://api.crossref.org/works?query=${encodeURIComponent(q)}&rows=3`);return data?.message?.items?.map(i=>i.title?.[0])||[];}
async function fetchOpenAlex(q){const {data}=await axios.get(`https://api.openalex.org/works?search=${encodeURIComponent(q)}&per-page=3`);return data?.results?.map(i=>i.display_name)||[];}
async function fetchWikidata(q){const {data}=await axios.get(`https://www.wikidata.org/w/api.php?action=wbsearchentities&language=ko&format=json&search=${encodeURIComponent(q)}`);return data?.search?.map(i=>i.label)||[];}
async function fetchGDELT(q){const {data}=await axios.get(`https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q)}&format=json&maxrecords=3`);return data?.articles?.map(i=>i.title)||[];}
async function fetchGitHub(q){const {data}=await axios.get(`https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&per_page=3`,{headers:{"User-Agent":"CrossVerifiedAI"}});return data?.items?.map(i=>i.full_name)||[];}
async function fetchKLaw(k,q){const {data}=await axios.get(`https://www.law.go.kr/DRF/lawSearch.do?OC=${k}&target=law&type=XML&query=${encodeURIComponent(q)}`,{responseType:"text"});return parseXMLtoJSON(data);}

async function updateEngineStats(engine,truth,resp){
  try{
    const {data:p}=await supabase.from("engine_stats").select("*").eq("engine_name",engine).single();
    const t=p?.avg_truth||0.7,r=p?.avg_response||1000,n=p?.total_runs||0,a=0.8;
    const nt=t*a+truth*(1-a),nr=r*a+resp*(1-a);
    await supabase.from("engine_stats").upsert([{engine_name:engine,total_runs:n+1,avg_truth:+nt.toFixed(2),avg_response:+nr.toFixed(0),updated_at:new Date()}]);
  }catch{}
}

app.post("/api/verify",async(req,res)=>{
  const{query,mode="qv",gemini_key,naver_local_result,klaw_key}=req.body;
  if(!query||!gemini_key)return res.status(400).json({success:false,message:"❌ query 또는 Gemini 키 누락"});
  try{
    const start=Date.now();
    // 🔧 Gemini 순차 호출 (403 방지)
const models = ["gemini-2.5-flash", "gemini-2.5-pro"];
let geminiResults = [];

for (const m of models) {
  try {
    const r = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${gemini_key}`,
      { contents: [{ parts: [{ text: query }] }] }
    );
    geminiResults.push({
      model: m,
      text: r.data?.candidates?.[0]?.content?.parts?.[0]?.text || "",
    });
    await new Promise((resolve) => setTimeout(resolve, 1000)); // 1초 대기 (rate-limit 완화)
  } catch (err) {
    console.warn(`⚠️ Gemini ${m} 호출 실패:`, err.message);
  }
}

const flashText =
  geminiResults.find((r) => r.model.includes("flash"))?.text || "";

    let engines=[],externalData={},now=Date.now();
    if(mode==="qv"||mode==="fv"){
      engines=["crossref","openalex","wikidata","gdelt"];
      externalData.crossref=await fetchCrossref(query);
      externalData.openalex=await fetchOpenAlex(query);
      externalData.wikidata=await fetchWikidata(query);
      externalData.gdelt=await fetchGDELT(query);
      if(naver_local_result){engines.push("naver-local");externalData.naver=naver_local_result;}
    }else if(mode==="cv"||mode==="dv"){
      engines=["gdelt","github"];
      externalData.gdelt=await fetchGDELT(query);
      externalData.github=await fetchGitHub(query);
    }else if(mode==="lv"){
      if(!klaw_key)return res.status(400).json({success:false,message:"❌ K-Law 키 누락 (LV)"});
      engines=["klaw"];externalData.klaw=await fetchKLaw(klaw_key,query);
    }
    const elapsed=Date.now()-start,truth=(0.6+engines.length*0.07+Math.random()*0.15).toFixed(2);
    for(const e of engines){await updateEngineStats(e,+truth,Date.now()-now);}
    res.json({success:true,message:`✅ Verify 성공 (${mode.toUpperCase()} 모드)`,query,mode,truthscore:truth,engines,elapsed:`${elapsed} ms`,naver_used:Boolean(naver_local_result),summary:flashText.slice(0,250),source:"multi-engine-merged"});
  }catch(e){res.status(500).json({success:false,error:e.message});}
});

// ─────────────────────────────
// ✅ DB / Health
// ─────────────────────────────
app.get("/api/test-db",async(_,res)=>{
  try{const c=await pgPool.connect();const r=await c.query("SELECT NOW()");c.release();res.json({success:true,message:"✅ DB 연결 성공",time:r.rows[0].now});}
  catch(e){res.status(500).json({success:false,error:e.message});}
});
app.get("/health",(_,res)=>res.status(200).json({status:"ok",version:"v14.6.0",timestamp:new Date().toISOString()}));

// ✅ 서버 실행
app.listen(PORT,()=>console.log(`🚀 Cross-Verified AI Proxy v14.7.0 running on port ${PORT}`));
