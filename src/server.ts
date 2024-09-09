import express from "express";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/authRoutes";
import "dotenv/config";

const PORT = process.env.PORT || 3000;
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use("/auth", authRoutes);

app.listen(PORT, () => console.log("Server running on port " + PORT));
