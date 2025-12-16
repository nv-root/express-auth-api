import "dotenv/config";
import cors from "cors";
import express from "express";
import cookieParser from "cookie-parser";
import type { Express, Request, Response } from "express";
import { closeDB, connectDB } from "./config/db.ts";
import { errorHandler } from "./middleware/errorHandler.ts";
import { CLIENT_ORIGIN, PORT } from "./utils/env.ts";

import authRoutes from "./routes/auth.routes.ts";
import userRoutes from "./routes/user.routes.ts";

const app: Express = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(cookieParser());

app.get("/", (_req: Request, res: Response) => {
  res.status(200).json({
    status: "OK",
  });
});

app.use("/api/auth", authRoutes);
app.use("/api/user", userRoutes);

app.use(errorHandler);

(async () => {
  try {
    await connectDB();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
    process.on("SIGINT", async () => {
      await closeDB();
      process.exit(0);
    });
  } catch (error) {
    console.error("Error starting server:", error);
    process.exit(1);
  }
})();
