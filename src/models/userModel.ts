import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export const createUser = async (
  email: string,
  username: string,
  password: string
) => {
  return await prisma.user.create({
    data: { email, username, password },
  });
};

export const findUserByEmail = async (email: string) => {
  return await prisma.user.findUnique({ where: { email } });
};

export const updateUserVerificationStatus = async (email: string) => {
  return await prisma.user.update({
    where: { email },
    data: { verified: true },
  });
};

export const updateUserPassword = async (
  email: string,
  newPassword: string
) => {
  return await prisma.user.update({
    where: { email },
    data: { password: newPassword },
  });
};
