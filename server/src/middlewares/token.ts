require("dotenv").config();
import { Request, Response, NextFunction } from "express";
import { jwtVerify } from "../utils/jwtController";

export const tokenVerify = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  //check if the req.headers["authorization"] exist
  if (!req.headers["authorization"]) {
    return res.status(400).json({
      success: false,
      message: "Error : Missing Authorization Header provided!",
    });
  }

  const authHeader: string = req.headers.authorization;
  //getting authMethod and accessToken from the authHeader
  const authMethod: string = authHeader.split(" ")[0]; //authMethod == Bearer
  const accessToken: string = authHeader.split(" ")[1];

  //check is the authMethod & accessToken exist and the is method correct
  if (!authMethod || !accessToken) {
    return res.status(400).json({
      success: false,
      message: "Error : Invalid auth header!",
    });
  } else if (authMethod !== "Bearer") {
    return res.status(400).json({
      success: false,
      message: "Error : Invalid auth method!",
    });
  }

  const claims = jwtVerify<AccessToken>(
    accessToken,
    process.env.ACCESS_TOKEN_SECRET!
  );
  if (!claims) {
    return res.status(400).json({ message: "Error : Invalid token!" });
  }
  req.profile = claims;
  return next();
};
