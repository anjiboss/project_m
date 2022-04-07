require("dotenv").config();
import express from "express";
import { getRepository } from "typeorm";
import User from "../entity/User";
import bcrypt from "bcrypt";
import Jwt from "jsonwebtoken";
import {
  accessToken_Exp,
  refreshToken_Exp,
  accessTokenSecret,
  refreshTokenSecret,
} from "../constants/tokenConstant";
import { Profile } from "../entity/Profile";
import { jwtDecode, jwtVerify } from "../utils/jwtController";

const router = express.Router();

// SECTION Register Route
router.post("/register", async (req, res) => {
  const { email, username, password, firstname, lastname } = req.body;

  //ANCHOR Find is the email existed
  const userRepo = getRepository(User);
  const profileRepo = getRepository(Profile);
  const checkEmail = await userRepo.findOne({
    where: {
      email: email,
    },
  });
  //ANCHOR 1 Filter: check email
  if (checkEmail) {
    return res.status(400).json({
      success: false,
      message: "Email already existed!",
    });
  } else {
    //ANCHOR 2 Filter: check username
    const checkUsername = await profileRepo.findOne({
      where: {
        username: username,
      },
    });
    if (checkUsername) {
      return res.status(400).json({
        success: false,
        message: "Username already existed!",
      });
    } else {
      //ANCHOR Success data insert
      // bcrypt the password
      const hashedPassword = await bcrypt.hash(password, 10);
      // insert user into database
      const newUser = new User();
      newUser.email = email;
      newUser.password = hashedPassword;

      const newProfile = new Profile();
      newProfile.firstname = firstname;
      newProfile.lastname = lastname;
      newProfile.username = username;
      await profileRepo.save(newProfile);

      newUser.profile = newProfile;
      userRepo.save(newUser);

      return res.status(200).json({
        success: true,
        message: "Register success!",
      });
    }
  }
});
// !SECTION

// SECTION Login Route
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    //ANCHOR Check If Email Existed
    const userRepo = getRepository(User);
    const userCheck = await userRepo.findOne({
      select: ["id", "password", "refreshToken"],
      where: {
        email: email,
      },
      relations: ["profile"],
    });
    // ANCHOR 1 filter: Email validation
    if (!userCheck) {
      return res
        .status(400)
        .json({ success: false, message: "User not found!" });
    }
    // ANCHOR 2 filter : Password validation
    const validPassword = await bcrypt.compare(password, userCheck.password);
    if (!validPassword) {
      return res
        .status(400)
        .json({ success: false, message: "Wrong password!" });
    }
    //ANCHOR Success sending JWT
    // Create a plaintext payload for the JWT
    const userInform = { id: userCheck.profile.id };
    const accessToken = Jwt.sign(userInform, accessTokenSecret!, {
      expiresIn: accessToken_Exp,
    });
    const refreshToken = Jwt.sign(userInform, refreshTokenSecret!, {
      expiresIn: refreshToken_Exp,
    });
    let newRefreshToken: string[];
    //process refreshToken saving
    if (!userCheck.refreshToken) {
      newRefreshToken = [refreshToken];
    } else {
      newRefreshToken = userCheck.refreshToken;
      newRefreshToken.push(refreshToken);
    }
    userCheck.refreshToken = newRefreshToken;
    userRepo.save(userCheck);
    return res.status(200).json({
      success: true,
      message: "Valid email & password.",
      accessToken: accessToken,
      refreshToken: refreshToken,
      userCheck,
    });
  } catch (e) {
    console.log(e);
    return res.status(500).send("Login: Something is broken!");
  }
});
// !SECTION

// ANCHOR Access token validation
router.post("/token/access", async (req, res) => {
  //check if the req.headers["authorization"] exist
  if (!req.headers["authorization"]) {
    return res.status(400).json({
      success: false,
      message: "Error : Missing Authorization Header provided!",
    });
  }

  const authHeader: string = req.headers["authorization"];
  // //getting authMethod and accessToken from the authHeader
  const authMethod: string = authHeader.split(" ")[0]; //authMethod == Bearer
  const accessToken: string = authHeader.split(" ")[1];

  //check is the authMethod & accessToken exist and the is method correct
  //check is the authMethod & accessToken exist and the is method correct
  if (!authMethod || !accessToken) {
    return res
      .status(400)
      .json({ success: false, message: "Error : Invalid auth header!" });
  } else if (authMethod !== "Bearer") {
    return res
      .status(400)
      .json({ success: false, message: "Error : Invalid auth method!" });
  }
  const token = jwtVerify<AccessToken>(accessToken, accessTokenSecret);
  if (!token) {
    return res.json({
      success: false,
      error: {
        message: "Token is invalid",
      },
    });
  } else {
    return res.json({
      success: true,
      message: "Token is valid",
      token,
    });
  }
});

// ANCHOR Refresh token validation
router.post("/token/refresh", async (req, res) => {
  //check if the req.headers["authorization"] exist
  if (!req.headers["authorization"]) {
    return res.status(400).json({
      success: false,
      message: "Error : Missing Authorization Header provided!",
    });
  }

  const authHeader: string = req.headers["authorization"];
  //getting authMethod and accessToken from the authHeader
  const authMethod: string = authHeader.split(" ")[0]; //authMethod == Bearer
  const refreshToken: string = authHeader.split(" ")[1];

  //check is the authMethod & accessToken exist and the is method correct
  if (!authMethod || !refreshToken) {
    return res
      .status(400)
      .json({ success: false, message: "Error : Invalid auth header!" });
  } else if (authMethod !== "Bearer") {
    return res
      .status(400)
      .json({ success: false, message: "Error : Invalid auth method!" });
  }

  //verify refreshToken
  const refreshTokenPayloads = jwtVerify<RefreshToken>(
    refreshToken,
    refreshTokenSecret
  );
  const userRepo = getRepository(User);
  if (!refreshTokenPayloads) {
    return res.json({
      success: false,
      error: {
        message: "Refresh token invalid",
      },
    });
  }
  const refreshTokenCheck = await userRepo.findOne({
    select: ["refreshToken"],
    where: { profile: { id: refreshTokenPayloads.id } },
  });
  //check if user exist
  if (!refreshTokenCheck) {
    return res
      .status(401)
      .json({ success: false, message: "Error : User not exist!" });
  }
  //check if the refresh token is in the database refresh token string array
  const refreshTokenList = refreshTokenCheck.refreshToken as string[];
  if (!refreshTokenList.includes(refreshToken)) {
    return res.status(401).json({
      success: false.valueOf,
      message: "Error : Token is not in the list!",
    });
  }
  //the refresh token is valid so create and return a new access token
  const userInfo = { id: refreshTokenPayloads.id };
  const newAccessToken = Jwt.sign(userInfo, accessTokenSecret!, {
    expiresIn: accessToken_Exp,
  });
  return res.status(200).json({
    success: true,
    message: "Valid refresh token.",
    newAccessToken: newAccessToken,
  });
});

// ANCHOR Revoke refresh token after loagout
router.post("/token/logout", async (req, res) => {
  //check if the req.headers["authorization"] exist
  if (!req.headers["authorization"]) {
    return res.status(400).json({
      success: false,
      message: "Error : Missing Authorization Header provided!",
    });
  }

  const authHeader: string = req.headers["authorization"];
  // //getting authMethod and accessToken from the authHeader
  const authMethod: string = authHeader.split(" ")[0]; //authMethod == Bearer
  const refreshToken: string = authHeader.split(" ")[1];

  //check is the authMethod & accessToken exist and the is method correct
  if (!authMethod || !refreshToken) {
    return res
      .status(400)
      .json({ success: false, message: "Error : Invalid auth header!" });
  } else if (authMethod !== "Bearer") {
    return res
      .status(400)
      .json({ success: false, message: "Error : Invalid auth method!" });
  }
  //get the refreshToken list from database by tokenPoayloads id
  const profileRepo = getRepository(Profile);
  const refreshTokenPayloads = jwtDecode<RefreshToken>(refreshToken);
  if (!refreshTokenPayloads) {
    return res.json({
      success: false,
      error: {
        message: "Refresh Token not valid",
      },
    });
  }
  const userProfile = await profileRepo.findOne({
    where: { id: refreshTokenPayloads.id },
    relations: ["user"],
  });
  //if no user
  if (!userProfile) {
    return res
      .status(400)
      .json({ success: false, message: "Error : User not exist!" });
  }
  //check is the token in the list or not
  let refreshTokenList = userProfile.user.refreshToken as string[];
  //not in the list
  if (!refreshTokenList.includes(refreshToken)) {
    return res
      .status(400)
      .json({ success: false, message: "Error : Token is not in the list!" });
  }
  //in the list
  refreshTokenList = refreshTokenList.filter((token) => token != refreshToken);
  //create a update user form
  userProfile.user.refreshToken = refreshTokenList;
  await getRepository(User).save(userProfile.user);
  return res
    .status(200)
    .json({ success: true, message: "Refresh token removed." });
});

export { router as authRouter };
