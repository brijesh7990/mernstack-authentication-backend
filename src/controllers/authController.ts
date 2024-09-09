import { Request, Response } from "express";
import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import {
  userForgotPasswordSchema,
  userLoginSchema,
  userResetPasswordSchema,
  userSchema,
} from "../schemas/userSchema";
import {
  createUser,
  findUserByEmail,
  updateUserVerificationStatus,
  updateUserPassword,
} from "../models/userModel";
import { sendVerificationEmail, sendPasswordResetEmail } from "../utils/email";

export const register = async (req: Request, res: Response) => {
  try {
    const { email, username, password } = userSchema.parse(req.body);

    const existingUser = await findUserByEmail(email);
    if (existingUser)
      return res.status(400).json({ error: "Email already in use" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await createUser(email, username, hashedPassword);

    sendVerificationEmail(user.email);
    return res.status(201).json({
      message: "User registered successfully. Please verify your email.",
    });
  } catch (error) {
    return res.status(400).json({ error: error });
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  const token = req.query.token as string;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as {
      email: string;
    };
    await updateUserVerificationStatus(decoded.email);
    return res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const validatedata = userLoginSchema.parse(req.body);
    const user = await findUserByEmail(validatedata.email);

    if (!user) return res.status(400).json({ error: "Invalid credentials" });
    if (!user.verified)
      return res.status(400).json({ error: "Please verify your email" });

    const isPasswordValid = await bcrypt.compare(
      validatedata.password,
      user.password
    );
    if (!isPasswordValid)
      return res.status(400).json({ error: "Invalid credentials" });

    const accessToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET as string,
      { expiresIn: "5m" }
    );
    const refreshToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_REFRESH_SECRET as string,
      { expiresIn: "30d" }
    );

    res.cookie("refreshToken", refreshToken, { httpOnly: true });
    return res.status(200).json({ accessToken });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error });
    }
    return res.status(500).json({ error: error });
  }
};

export const refreshToken = (req: Request, res: Response) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken)
    return res.status(401).json({ error: "No refresh token provided" });

  try {
    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET as string
    ) as { userId: number };
    const newAccessToken = jwt.sign(
      { userId: decoded.userId },
      process.env.JWT_SECRET as string,
      { expiresIn: "5m" }
    );
    return res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    return res.status(401).json({ error: "Invalid refresh token" });
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const validatedata = userForgotPasswordSchema.parse(req.body);
    const user = await findUserByEmail(validatedata.email);
    if (!user) return res.status(400).json({ error: "Email not found" });

    sendPasswordResetEmail(validatedata.email);
    return res
      .status(200)
      .json({ message: "Password reset link sent to your email" });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error });
    }
    return res.status(400).json({ error: error });
  }
};

export const resetPassword = async (
  req: Request,
  res: Response
): Promise<Response> => {
  try {
    const { token } = req.query;

    // Type guard for `token` to ensure it exists and is a string
    if (typeof token !== "string") {
      return res
        .status(400)
        .json({ error: "Token is required and must be a string" });
    }

    // Validate the request body using the schema
    const validatedData = userResetPasswordSchema.parse(req.body);

    // Decode the JWT token
    const decoded = jwt.verify(
      token,
      process.env.JWT_RESET_SECRET as string
    ) as { email: string };

    // Hash the new password
    const hashedPassword = await bcrypt.hash(validatedData.confirmPassword, 10);

    // Update the user's password in the database
    await updateUserPassword(decoded.email, hashedPassword);

    // Return a success response
    return res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error });
    }
    return res.status(500).json({ error: "Invalid or expired token" });
  }
};
