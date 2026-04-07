import jwt from "jsonwebtoken";
import User from "../models/userModel.js";
import Session from "../models/sessionModel.js";

export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Access token required" });
    }

    // Use ACCESS_SECRET (or JWT_SECRET as fallback)
    const secret = process.env.ACCESS_SECRET || process.env.JWT_SECRET;
    const decoded = jwt.verify(token, secret);

    // Support both 'userId' and 'id' fields
    const userId = decoded.userId || decoded.id;
    if (!userId) {
      return res.status(401).json({ error: "Invalid token payload" });
    }

    if (!decoded.sessionId) {
      return res
        .status(401)
        .json({ error: "Session is required. Please login again." });
    }

    const activeSession = await Session.findOne({
      _id: decoded.sessionId,
      userId,
      isActive: true,
    });

    if (!activeSession) {
      return res
        .status(401)
        .json({ error: "Session expired or logged out from another device" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    if (!user.isActive) {
      return res.status(401).json({ error: "Account is deactivated" });
    }

    req.user = user;
    req.userId = user._id;
    req.userType = user.role;
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token" });
    }
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired" });
    }
    console.error("Auth error:", error);
    return res.status(500).json({ error: "Authentication error" });
  }
};

export const authenticateSocket = (socket, next) => {
  try {
    const token = socket.handshake.auth.token;

    if (!token) {
      return next(new Error("Authentication required"));
    }

    const secret = process.env.ACCESS_SECRET || process.env.JWT_SECRET;
    const decoded = jwt.verify(token, secret);
    const userId = decoded.userId || decoded.id;

    if (!userId) {
      return next(new Error("Invalid token payload"));
    }

    User.findById(userId)
      .then((user) => {
        if (!user || !user.isActive) {
          return next(new Error("User not found or inactive"));
        }

        socket.userId = user._id.toString();
        socket.userRole = user.role;
        return next();
      })
      .catch((error) => {
        console.error("Socket auth user lookup error:", error);
        return next(new Error("Authentication failed"));
      });
  } catch (error) {
    console.error("Socket auth error:", error);
    next(new Error("Authentication failed"));
  }
};
