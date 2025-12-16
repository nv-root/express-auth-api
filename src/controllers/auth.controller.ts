import type { CookieOptions, Request, Response } from "express";
import z from "zod";
import User from "../models/user.model.ts";
import {
  AppError,
  NotFoundError,
  UnauthorizedError,
} from "../utils/appError.ts";
import bcrypt from "bcryptjs";
import { genAT, genRT, verifyRT, type Payload } from "../utils/jwtUtils.ts";
import { NODE_ENV } from "../utils/env.ts";
import RefreshToken from "../models/refreshToken.model.ts";
import { ObjectId } from "mongodb";
import crypto from "crypto";
import VerificationToken from "../models/verificationToken.model.ts";
import { sendVerificationEmail } from "../utils/email.ts";

const registerSchema = z
  .object({
    name: z.string().min(2).max(255),
    email: z.email(),
    password: z.string().min(8).max(255),
    confirmPassword: z.string().min(2),
  })
  .refine((data) => data.password === data.confirmPassword, {
    error: "Passwords do not match",
    path: ["confirmPassword"],
  });

const loginSchema = z.object({
  email: z.email(),
  password: z.string().min(2),
});

const cookieDefaults: CookieOptions = {
  sameSite: "strict",
  httpOnly: true,
  secure: NODE_ENV !== "development",
};

const getDeviceInfo = (req: Request) => ({
  userAgent: req.headers["user-agent"] || "Unknown",
  ipAddress: req.ip || req.socket.remoteAddress || "Unknown",
});

const genVerificationTokens = () => {
  const token = crypto.randomBytes(32).toString("hex");
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  return { token, hashedToken };
};

// controllers
export const register = async (req: Request, res: Response) => {
  const { name, email, password } = registerSchema.parse({
    ...req.body,
    userAgent: req.headers["user-agent"],
  });

  const existingUser = await User().findOne({ email });
  if (existingUser) {
    throw new AppError(400, "User already exists");
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const newUser = await User().insertOne({
    name,
    email,
    password: hashedPassword,
    verified: false,
    createdAt: new Date(),
  });

  if (!newUser) {
    throw new AppError(500, "Internal Server error");
  }

  //--------- verification -----------
  const { token: verificationToken, hashedToken } = genVerificationTokens();
  await VerificationToken().insertOne({
    userId: newUser.insertedId,
    token: hashedToken,
    type: "email_verification",
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    createdAt: new Date(),
  });

  try {
    await sendVerificationEmail(email, name, verificationToken);
  } catch (error) {
    console.error("Failed to send verification email:", error);
  }

  res.status(201).json({
    success: true,
    message:
      "Registration successful. Please check your email to verify your account.",
    user: {
      _id: newUser.insertedId,
      name,
      email,
    },
  });
};

export const verifyEmail = async (req: Request, res: Response) => {
  const { token } = req.query;
  if (!token || typeof token !== "string") {
    throw new AppError(400, "Invalid verification token");
  }
  // comparing hash
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  const verificationToken = await VerificationToken().findOne({
    token: hashedToken,
    type: "email_verification",
    expiresAt: { $gt: new Date() },
  });

  if (!verificationToken) {
    throw new AppError(400, "Invalid or expired verification token");
  }
  // updating user
  const verifiedUser = await User().updateOne(
    { _id: verificationToken.userId },
    { $set: { verified: true } }
  );

  if (verifiedUser.modifiedCount === 0) {
    throw new NotFoundError("User not found");
  }

  await VerificationToken().deleteOne({ _id: verificationToken._id });
  res.status(200).json({
    success: true,
    message: "Email verified successfully. You can now login.",
  });
};

export const resendVerificationEmail = async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) {
    throw new AppError(400, "Email is required");
  }
  const user = await User().findOne({ email });
  if (!user) {
    throw new NotFoundError("User not found");
  }
  if (user.verified) {
    return res.json({ message: "Email is already verified" });
  }
  //delete old ones
  await VerificationToken().deleteMany({
    userId: user._id,
    type: "email_verification",
  });

  const { token: verificationToken, hashedToken } = genVerificationTokens();
  await VerificationToken().insertOne({
    userId: user._id,
    token: hashedToken,
    type: "email_verification",
    expiresAt: new Date(Date.now() + 24 + 60 * 60 * 1000),
    createdAt: new Date(),
  });

  await sendVerificationEmail(email, user.name, verificationToken);
  res.status(200).json({
    success: true,
    message: "Verification email sent.",
  });
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = loginSchema.parse({ ...req.body });
  const user = await User().findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    throw new UnauthorizedError("Invalid credentials");
  }

  if (!user.verified) {
    throw new UnauthorizedError("Please verify your email.");
  }

  const { userAgent, ipAddress } = getDeviceInfo(req);
  const MAX_SESSIONS = 5;

  const sessionCount = await RefreshToken().countDocuments({
    userId: user._id,
  });
  if (sessionCount >= MAX_SESSIONS) {
    const oldestSession = await RefreshToken()
      .find({ userId: user._id })
      .sort({ createdAt: 1 })
      .limit(1)
      .toArray();

    if (oldestSession[0]) {
      await RefreshToken().deleteOne({ _id: oldestSession[0]._id });
    }
  }

  const accessToken = genAT(user._id, email);
  const refreshToken = genRT(user._id, email);
  const tokenFamily = crypto.randomUUID();

  await RefreshToken().insertOne({
    userId: user._id,
    token: refreshToken,
    family: tokenFamily,
    userAgent,
    ipAddress,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    lastUsedAt: new Date(),
  });

  res
    .cookie("accessToken", accessToken, {
      ...cookieDefaults,
      maxAge: 15 * 60 * 1000,
    })
    .cookie("refreshToken", refreshToken, {
      ...cookieDefaults,
      maxAge: 30 * 24 * 60 * 60 * 1000,
    })
    .status(200)
    .json({
      success: true,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
      },
    });
};

export const logout = async (req: Request, res: Response) => {
  const refreshToken = req.cookies["refreshToken"];
  if (refreshToken) {
    await RefreshToken().deleteOne({
      token: refreshToken,
      userId: req.user!._id,
    });
  }

  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");

  res.status(200).json({
    success: true,
    message: "Logged out",
  });
};

export const logoutAll = async (req: Request, res: Response) => {
  const userId = req.user!._id;
  await RefreshToken().deleteMany({ userId });
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");

  res.status(200).json({
    success: true,
    message: "Logged out from all devices",
  });
};

export const refresh = async (req: Request, res: Response) => {
  const oldRefreshToken = req.cookies["refreshToken"];
  if (!oldRefreshToken) {
    throw new UnauthorizedError("No token provided");
  }
  let payload: Payload;
  try {
    payload = verifyRT(oldRefreshToken);
  } catch (error) {
    throw new UnauthorizedError("Invalid token provided");
  }

  const user = await User().findOne({ _id: new ObjectId(payload._id) });
  if (!user) {
    await RefreshToken().deleteMany({ userId: new ObjectId(payload._id) });
    throw new NotFoundError("User not found");
  }

  const storedToken = await RefreshToken().findOne({ token: oldRefreshToken });

  if (!storedToken) {
    await RefreshToken().deleteMany({ userId: new ObjectId(payload._id) });
    throw new UnauthorizedError("Please login again.");
  }

  const { userAgent, ipAddress } = getDeviceInfo(req);
  const tokenFamily = storedToken.family;

  await RefreshToken().deleteOne({ token: oldRefreshToken });

  const newAccessToken = genAT(user._id, user.email);
  const newRefreshToken = genRT(user._id, user.email);

  await RefreshToken().insertOne({
    userId: user._id,
    token: newRefreshToken,
    family: tokenFamily,
    userAgent,
    ipAddress,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    lastUsedAt: new Date(),
  });

  res
    .cookie("accessToken", newAccessToken, {
      ...cookieDefaults,
      maxAge: 15 * 60 * 1000,
    })
    .cookie("refreshToken", newRefreshToken, {
      ...cookieDefaults,
      maxAge: 30 * 24 * 60 * 60 * 1000,
    })
    .status(200)
    .json({
      success: true,
      message: "Tokens refreshed.",
    });
};

export const getSessions = async (req: Request, res: Response) => {
  const { _id } = req.user!;
  const currentToken = req.cookies["refreshToken"];

  const sessions = await RefreshToken()
    .find({ userId: _id })
    .sort({ lastUsedAt: -1 })
    .toArray();

  const formattedSessions = sessions.map((session) => ({
    _id: session._id,
    userAgent: session.userAgent,
    ipAddress: session.ipAddress,
    createdAt: session.createdAt,
    lastUsedAt: session.lastUsedAt,
    isCurrent: session.token === currentToken,
  }));

  res.status(200).json({
    success: true,
    sessions: formattedSessions,
  });
};

export const revokeSession = async (req: Request, res: Response) => {
  const { _id } = req.user!;
  const { sessionId } = req.params;
  const session = await RefreshToken().findOne({
    _id: new ObjectId(sessionId),
    userId: _id,
  });

  if (!session) {
    throw new NotFoundError("Session not found");
  }
  await RefreshToken().deleteOne({ _id: session._id });

  res.status(200).json({
    success: true,
    message: "Session revoked",
  });
};
