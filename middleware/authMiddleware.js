// middleware/authMiddleware.js
const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // "Bearer <token>"

  if (!token) {
    return res.status(401).json({ success: false, error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwt_secret");
    req.user = decoded; // req.user.email, req.user.name 사용 가능
    next();
  } catch (error) {
    return res.status(403).json({ success: false, error: "Invalid or expired token" });
  }
};
