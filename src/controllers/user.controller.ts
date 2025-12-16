import type { Request, Response } from "express";
import User from "../models/user.model.ts";
import { NotFoundError } from "../utils/appError.ts";

export const profile = async (req: Request, res: Response) => {
  const { _id } = req.user!;
  const user = await User().findOne({ _id });
  if (!user) {
    throw new NotFoundError("User not found");
  }
  res.status(200).json({
    success: true,
    user: {
      _id: user._id,
      name: user.name,
      email: user.email,
    },
  });
};
