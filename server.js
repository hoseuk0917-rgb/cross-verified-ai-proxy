import express from "express";
import cors from "cors";
import helmet from "helmet";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());

const JWT_SECRET = process.env.JWT_SECRET || "dev-jwt";
const HMAC_SECRET = process.env.HMAC_SECRET || "dev-hmac";

const limiter = rateLimit({ windowMs: 60 * 1000, max: 30 });
app.use(limiter);

app.get("/ping", (req, res) => res.json({ ok: true, time: Date.now() }));

app.post("/auth", (req, res) => {
  const token = jwt.sign({ user: "tester" }, JWT_SECRET, { expiresIn: "15m" });
  res.json({ token });
});

app.post("/proxy", (req, res) => {
  const sig = crypto
    .createHmac("sha256", HMAC_SECRET)
    .update(JSON.stringify(req.body))
    .digest("hex");
  res.json({ status: "ok", signature: sig });
});

app.listen(3000, () => console.log("✅ Proxy running on port 3000"));
