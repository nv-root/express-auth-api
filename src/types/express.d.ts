import type { ObjectId } from "mongodb";

declare global {
  namespace Express {
    interface Request {
      user?: {
        _id: ObjectId;
        email: string;
      };
    }
  }
}

export {};
