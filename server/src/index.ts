import "reflect-metadata";
import express from "express";
import cors from "cors";
import { createConnection } from "typeorm";
import { userRouter } from "./routes/user";
import { authRouter } from "./routes/auth";
// SOCKET
import { createServer } from "http";
import { Server } from "socket.io";
import { socketController } from "./socket/socketController";
import { testRouter } from "./routes/test";

const PORT = process.env.PORT || 5000;
const app = express();

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: ["http://localhost:3000", "https://hoppscotch.io/realtime"],
  },
});

app.use(cors());
app.use(express.json());

const main = async () => {
  await createConnection();
  app.use("/api/v1/user", userRouter);
  app.use("/api/v1/auth", authRouter);
  app.use("/test", testRouter);
  io.on("connection", (socket) => {
    console.log("socket connected");
    socketController(io, socket);
  });

  httpServer.listen(PORT, () =>
    console.log(`Server is listening 🚀 on Port: ${PORT}`)
  );
};

main();
