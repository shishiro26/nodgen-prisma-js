import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import http from "http";
dotenv.config();
import cookieParser from "cookie-parser";
import { logger } from "./middleware/logger.js";
import { errorHandler } from "./middleware/errorHandler.js";
import userRoutes from "./routes/User.routes.js";
import otpRoutes from "./routes/OTP.routes.js";

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(express.urlencoded({ extended: true }));

app.use(logger);
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));
app.use(morgan("dev"));

app.use("/api/v1/auth", userRoutes);
app.use("/api/v1/auth/otp", otpRoutes);
app.use(errorHandler);

const server = http.createServer(app);

const port = process.env.PORT || 5000;

server.listen(port, () =>
  console.log(`🚀 server at http://localhost:${port}.`)
);
