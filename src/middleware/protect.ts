import type { NextFunction, Request, Response } from "express";
import { NotFoundError, UnauthorizedError } from "../utils/appError.ts";
import { verifyAT, type Payload } from "../utils/jwtUtils.ts";
import { ObjectId } from "mongodb";
import User from "../models/user.model.ts";
import jwt from "jsonwebtoken";

const { TokenExpiredError, JsonWebTokenError } = jwt;

export const protect = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const token =
    req.cookies["accessToken"] || req.headers.authorization?.split(" ")[1];
  if (!token) {
    throw new UnauthorizedError("Unauthorized. No token provided");
  }
  try {
    const payload: Payload = verifyAT(token);
    const user = await User().findOne({ _id: new ObjectId(payload._id) });

    if (!user) {
      throw new NotFoundError("User not found");
    }

    req.user = { _id: user._id, email: user.email };
    next();
  } catch (error) {
    if (error instanceof TokenExpiredError) {
      return res.status(401).json({
        success: false,
        message: "Access token expired",
        code: "TOKEN_EXPIRED",
      });
    }
    if (error instanceof JsonWebTokenError) {
      throw new UnauthorizedError("Invalid token");
    }
    throw error;
  }
};
