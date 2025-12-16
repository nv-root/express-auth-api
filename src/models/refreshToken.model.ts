import type { Collection, ObjectId, Document } from "mongodb";
import { getDB } from "../config/db.ts";

export interface IRefreshToken extends Document {
  _id?: ObjectId;
  userId: ObjectId;
  token: string;
  userAgent?: string;
  ipAddress?: string;
  family: string;
  createdAt: Date;
  expiresAt: Date;
  lastUsedAt: Date;
}

const RefreshToken = (): Collection<IRefreshToken> => {
  return getDB().collection<IRefreshToken>("refresh_tokens");
};
export default RefreshToken;
