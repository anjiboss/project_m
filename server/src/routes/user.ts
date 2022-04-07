require("dotenv").config();
import express from "express";
import { getRepository } from "typeorm";
import { tokenVerify } from "../middlewares/token";
import { Profile } from "../entity/Profile";

const router = express.Router();

// ANCHOR get all user request
router.get("/userinfo", tokenVerify, async (req, res) => {
  console.log({ user: req.profile });
  const profileRepo = getRepository(Profile);
  const profile = await profileRepo.findOne({
    where: {
      id: req.profile.id,
    },
  });
  if (!profile) {
    return res.json({
      success: false,
      error: {
        message: "User Not found",
      },
    });
  }

  return res.status(200).json({
    userInfo: profile,
  });
});

export { router as userRouter };
