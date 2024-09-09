import { z } from "zod";

export const userSchema = z.object({
  email: z
    .string()
    .email()
    .regex(/@gmail\.com$|@yahoo\.com$|@outlook\.com$|\.ac\.in$/),
  username: z.string().min(6).max(30),
  password: z.string().min(6).max(50),
});

export const userLoginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

export const userForgotPasswordSchema = z.object({
  email: z.string().email(),
});

export const userResetPasswordSchema = z.object({
  password: z.string().min(6).max(50),
  confirmPassword: z.string().min(6).max(50),
});
