// services/tokenService.js
import jwt from "jsonwebtoken";
import crypto from "crypto";
import RefreshToken from "../models/refreshTokenModel.js";
import User from "../models/userModel.js";

class TokenService {
  constructor() {
    this.accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
    this.refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
    this.accessTokenExpiry = "15d"; // Access token expires in 15 days
  }

  // Generate access token
  generateAccessToken(userId, email, role) {
    return jwt.sign(
      {
        userId,
        email,
        role,
      },
      this.accessTokenSecret,
      { expiresIn: this.accessTokenExpiry },
    );
  }

  // Generate unique refresh token
  generateRefreshToken() {
    return crypto.randomBytes(40).toString("hex");
  }

  // Create refresh token in database (NO EXPIRY)
  async createRefreshToken(userId, userAgent = null, ipAddress = null) {
    const refreshToken = this.generateRefreshToken();

    const savedToken = await RefreshToken.create({
      token: refreshToken,
      userId,
      userAgent,
      ipAddress,
      isActive: true,
      // NO expiresAt - token lives forever
    });

    return savedToken.token;
  }

  // Verify and get user from refresh token
  async verifyRefreshToken(token) {
    try {
      const refreshToken = await RefreshToken.findOne({
        token,
        isActive: true,
      }).populate("userId");

      if (!refreshToken) {
        throw new Error("Invalid refresh token");
      }

      // Check if user exists and is active
      if (!refreshToken.userId || !refreshToken.userId.isActive) {
        throw new Error("User not found or inactive");
      }

      return refreshToken.userId;
    } catch (error) {
      throw new Error("Token verification failed: " + error.message);
    }
  }

  // Delete refresh token (logout from this device)
  async revokeRefreshToken(token) {
    await RefreshToken.findOneAndUpdate(
      { token, isActive: true },
      { isActive: false, logoutAt: new Date() },
    );
  }

  // Delete all user refresh tokens (logout from all devices)
  async revokeAllUserTokens(userId) {
    await RefreshToken.updateMany(
      { userId, isActive: true },
      { isActive: false, logoutAt: new Date() },
    );
  }

  // Get all active sessions for a user
  async getUserSessions(userId) {
    return await RefreshToken.find({ userId, isActive: true })
      .select("-token") // Don't send the actual token
      .sort({ createdAt: -1 });
  }

  // Refresh access token using refresh token
  async refreshAccessToken(refreshToken) {
    const user = await this.verifyRefreshToken(refreshToken);

    if (!user) {
      throw new Error("Invalid refresh token");
    }

    // Generate new access token
    const newAccessToken = this.generateAccessToken(
      user._id,
      user.email,
      user.role,
    );

    return {
      accessToken: newAccessToken,
      user: {
        id: user._id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
      },
    };
  }
}

export default new TokenService();
