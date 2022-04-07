import { Server, Socket } from "socket.io";

export const socketController = (_: Server, socket: Socket) => {
  socket.on("some-event", (params) => {
    console.log("listened from some-event", {
      params,
    });
  });
};
