import { ObjectId } from "mongodb";
import type { Collection, Document } from "mongodb";
import { getDB } from "../config/db.ts";

export interface IUser extends Document {
  _id?: ObjectId;
  name: string;
  email: string;
  password: string;
  verified: boolean;
  createdAt: Date;
}

const User = (): Collection<IUser> => {
  return getDB().collection<IUser>("users");
};
export default User;
