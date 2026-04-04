// middleware/refreshToken.js
// NOTE: The primary refresh logic lives in authController.refreshAccessToken
// (exposed as POST /auth/refresh-token).  This standalone helper is kept
// for backward-compatibility but now includes proper error handling.
import jwt from "jsonwebtoken";
import Session from "../models/sessionModel.js";
import { generateAccessToken, generateRefreshToken } from "../utils/token.js";

export const refreshAccessToken = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ success: false, message: "No refresh token provided" });
    }

    // Safely verify the refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    } catch (err) {
      return res.status(401).json({ success: false, message: "Invalid or expired refresh token" });
    }

    // Look up session by sessionId embedded in the token
    const session = await Session.findById(decoded.sessionId);

    if (!session || !session.isActive) {
      return res.status(401).json({ success: false, message: "Session expired or not found" });
    }

    // Token rotation guard — reject if stored token doesn't match
    if (session.refreshToken !== refreshToken) {
      return res.status(401).json({ success: false, message: "Token mismatch" });
    }

    // Issue new tokens
    const newAccessToken  = generateAccessToken(decoded.userId, session._id);
    const newRefreshToken = generateRefreshToken(decoded.userId, session._id);

    // Persist the new refresh token (rotation)
    session.refreshToken = newRefreshToken;
    await session.save();

    // Set cookies
    const cookieBase = { httpOnly: true, secure: false, sameSite: "lax", path: "/" };
    res.cookie("accessToken",  newAccessToken,  { ...cookieBase, maxAge: 15 * 60 * 1000 });
    res.cookie("refreshToken", newRefreshToken, { ...cookieBase, maxAge: 7 * 24 * 60 * 60 * 1000 });

    return res.json({
      success: true,
      accessToken:  newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    console.error("refreshAccessToken error:", error);
    return res.status(500).json({ success: false, message: "Server error during token refresh" });
  }
};