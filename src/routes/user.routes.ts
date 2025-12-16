import { Router } from "express";
import { protect } from "../middleware/protect.ts";
import { asyncHandler } from "../middleware/asyncHandler.ts";
import { profile } from "../controllers/user.controller.ts";

const userRoutes: Router = Router();

userRoutes.get("/profile", protect, asyncHandler(profile));

export default userRoutes;
