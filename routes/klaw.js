// routes/klaw.js
import express from "express";
import axios from "axios";
import { parseXmlToJson } from "../utils/xmlParser.js";

const router = express.Router();
const BASE_URL = "http://www.law.go.kr/DRF/lawSearch.do";

// 🔍 모바일용 법령 API 프록시
router.get("/search", async (req, res) => {
  try {
    const {
      target = "law",
      query = "",
      type = "JSON",
      OC = process.env.KLAW_EMAIL_ID || "test",
      mobileYn = "Y",
      ...rest
    } = req.query;

    const params = new URLSearchParams({
      OC,
      target,
      query,
      type,
      mobileYn,
      ...rest,
    });

    const url = `${BASE_URL}?${params.toString()}`;
    const response = await axios.get(url);

    if (type.toUpperCase() === "XML") {
      const json = await parseXmlToJson(response.data);
      return res.json({ success: true, source: "klaw", target, data: json });
    }

    res.json({ success: true, source: "klaw", target, data: response.data });
  } catch (err) {
    console.error("❌ K-Law Proxy Error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
