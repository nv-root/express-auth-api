import type { Collection, Document, ObjectId } from "mongodb";
import { getDB } from "../config/db.ts";

export interface IVerificationToken extends Document {
  _id?: ObjectId;
  userId: ObjectId;
  token: string;
  type: "email_verification" | "password_reset";
  expiresAt: Date;
  createdAt: Date;
}

const VerificationToken = (): Collection<IVerificationToken> => {
  return getDB().collection<IVerificationToken>("verification_tokens");
};

export default VerificationToken;
