import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import type SMTPTransport from "nodemailer/lib/smtp-transport"; // Import the SMTPTransport type

export const sendVerificationEmail = (email: string) => {
  const token = jwt.sign({ email }, process.env.JWT_SECRET as string, {
    expiresIn: "1h",
  });
  const url = `${process.env.CLIENT_URL}/verify-email?token=${token}`;

  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: Number(process.env.SMTP_PORT), // Ensure the port is a number
    secure: false, // Use TLS for port 587
    auth: {
      user: process.env.SMTP_USER as string,
      pass: process.env.SMTP_PASS as string,
    },
  } as SMTPTransport.Options); // Cast the options object to the correct type
  transporter.sendMail({
    to: email,
    subject: "Verify your email",
    html: `Click <a href="${url}">here</a> to verify your email.`,
  });
};

export const sendPasswordResetEmail = (email: string) => {
  const token = jwt.sign({ email }, process.env.JWT_RESET_SECRET as string, {
    expiresIn: "1h",
  });
  const url = `${process.env.CLIENT_URL}/reset-password?token=${token}`;

  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: Number(process.env.SMTP_PORT), // Ensure the port is a number
    secure: false, // Use TLS for port 587
    auth: {
      user: process.env.SMTP_USER as string,
      pass: process.env.SMTP_PASS as string,
    },
  } as SMTPTransport.Options);
  transporter.sendMail({
    to: email,
    subject: "Reset your password",
    html: `Click <a href="${url}">here</a> to reset your password.`,
  });
};
