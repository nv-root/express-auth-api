import jwt from "jsonwebtoken";
import {
  JWT_ACCESS_EXPIRY,
  JWT_ACCESS_SECRET,
  JWT_REFRESH_EXPIRY,
  JWT_REFRESH_SECRET,
} from "./env.ts";
import type { ObjectId } from "mongodb";

export interface Payload {
  _id: ObjectId;
  email: string;
}

export const genAT = (_id: ObjectId, email: string): string => {
  return jwt.sign({ _id, email }, JWT_ACCESS_SECRET, {
    expiresIn: JWT_ACCESS_EXPIRY,
  } as jwt.SignOptions);
};

export const genRT = (_id: ObjectId, email: string): string => {
  return jwt.sign({ _id, email }, JWT_REFRESH_SECRET, {
    expiresIn: JWT_REFRESH_EXPIRY,
  } as jwt.SignOptions);
};

export const verifyAT = (token: string): Payload => {
  return jwt.verify(token, JWT_ACCESS_SECRET) as Payload;
};

export const verifyRT = (token: string): Payload => {
  return jwt.verify(token, JWT_REFRESH_SECRET) as Payload;
};
