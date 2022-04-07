
import express from "express";
import axios from "axios";
const router = express.Router();

let token = "";

router.post("/save-token", (req, res) => {
  token = req.body.token;
  res.json({
    save: true,
  });
});

router.get("/push", async (_, res) => {
  console.log(token);
  if (token !== "") {
    const message = {
      to: token,
      sound: "default",
      title: "Some Title",
      body: "sent from server",
      data: { someData: "goes here" },
    };
    await axios({
      url: "https://exp.host/--/api/v2/push/send",
      method: "post",
      headers: {
        Accept: "application/json",
        "Accept-encoding": "gzip, deflate",
        "Content-Type": "application/json",
      },
      data: message,
    });
    res.json({
      sent: true,
    });
  } else {
    res.json({
      error: {
        message: "upload token first",
      },
    });
  }
});

export { router as testRouter };
