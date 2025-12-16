import { Router } from "express";
import { asyncHandler } from "../middleware/asyncHandler.ts";
import {
  getSessions,
  login,
  logout,
  logoutAll,
  refresh,
  register,
  resendVerificationEmail,
  revokeSession,
  verifyEmail,
} from "../controllers/auth.controller.ts";
import { protect } from "../middleware/protect.ts";

const authRoutes: Router = Router();

authRoutes.post("/register", asyncHandler(register));
authRoutes.get("/verify-email", asyncHandler(verifyEmail));
authRoutes.post("/resend-verification", asyncHandler(resendVerificationEmail));
authRoutes.post("/login", asyncHandler(login));
authRoutes.post("/refresh", asyncHandler(refresh));
authRoutes.post("/logout", protect, asyncHandler(logout));
authRoutes.post("/logout-all", protect, asyncHandler(logoutAll));
authRoutes.get("/sessions", protect, asyncHandler(getSessions));
authRoutes.delete("/sessions/:sessionId", protect, asyncHandler(revokeSession));

export default authRoutes;
