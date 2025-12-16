import { MongoClient, Db } from "mongodb";
import { DB_NAME, MONGO_URI } from "../utils/env.ts";

const uri = MONGO_URI;
const dbName = DB_NAME;

let client: MongoClient;
let db: Db;

export const connectDB = async (): Promise<Db> => {
  try {
    if (db) {
      return db;
    }

    client = new MongoClient(uri);
    await client.connect();
    db = client.db(dbName);

    await createIndexes();

    console.log("Connected to MongoDB");
    return db;
  } catch (error) {
    console.error("MongoDB connection error:", error);
    process.exit(1);
  }
};

export const createIndexes = async function (): Promise<void> {
  await Promise.all([
    db
      .collection("users")
      .createIndexes([
        { key: { email: 1 }, unique: true },
        { key: { createdAt: -1 } },
      ]),

    db
      .collection("refresh_tokens")
      .createIndexes([
        { key: { token: 1 }, unique: true },
        { key: { userId: 1 } },
        { key: { family: 1 } },
        { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
        { key: { lastUsedAt: -1 } },
      ]),

    db
      .collection("verification_tokens")
      .createIndexes([
        { key: { token: 1 }, unique: true },
        { key: { userId: 1 } },
        { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
      ]),
  ]);
};

export const getDB = (): Db => {
  if (!db) {
    throw new Error("Database not initialized. Call connectDB");
  }
  return db;
};
export const closeDB = async (): Promise<void> => {
  if (client) {
    await client.close();
  }
};
