import { Router } from "express";
import bcrypt from "bcrypt";
import { z } from "zod";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { prisma } from "../prismaClient.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../lib/jwt.js";

export const authRouter = Router();

function devDetails(err: unknown): { details?: string } {
  if (process.env.NODE_ENV !== "development") return {};
  const msg = err instanceof Error ? err.message : String(err);
  return msg ? { details: msg } : {};
}

const registerBodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(100)
});

const loginBodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(100)
});

const refreshBodySchema = z.object({
  refreshToken: z.string().min(1)
});

authRouter.post("/register", async (req, res) => {
  try {
    const body = registerBodySchema.parse(req.body);

    const existing = await prisma.user.findUnique({ where: { email: body.email }, select: { id: true } });
    if (existing) {
      res.status(409).json({ success: false, error: "Email already registered" });
      return;
    }

    const passwordHash = await bcrypt.hash(body.password, 12);

    const user = await prisma.user.create({
      data: {
        email: body.email,
        passwordHash,
        role: "ANALYST"
      },
      select: { id: true, email: true, role: true }
    });

    const accessToken = signAccessToken({ userId: user.id, email: user.email, role: user.role });
    const refreshToken = signRefreshToken({ userId: user.id });

    res.status(201).json({
      success: true,
      data: {
        user,
        accessToken,
        refreshToken
      }
    });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ success: false, error: "Invalid request body" });
      return;
    }

    if (err instanceof PrismaClientKnownRequestError && err.code === "P2002") {
      res.status(409).json({ success: false, error: "Email already registered" });
      return;
    }

    // eslint-disable-next-line no-console
    console.error("[auth] register failed:", err);
    res.status(500).json({ success: false, error: "Registration failed", ...devDetails(err) });
  }
});

authRouter.post("/login", async (req, res) => {
  try {
    const body = loginBodySchema.parse(req.body);

    const user = await prisma.user.findUnique({
      where: { email: body.email },
      select: { id: true, email: true, role: true, passwordHash: true }
    });

    if (!user) {
      res.status(401).json({ success: false, error: "Invalid credentials" });
      return;
    }

    const ok = await bcrypt.compare(body.password, user.passwordHash);
    if (!ok) {
      res.status(401).json({ success: false, error: "Invalid credentials" });
      return;
    }

    const accessToken = signAccessToken({ userId: user.id, email: user.email, role: user.role });
    const refreshToken = signRefreshToken({ userId: user.id });

    res.status(200).json({
      success: true,
      data: {
        user: { id: user.id, email: user.email, role: user.role },
        accessToken,
        refreshToken
      }
    });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ success: false, error: "Invalid request body" });
      return;
    }

    // eslint-disable-next-line no-console
    console.error("[auth] login failed:", err);
    res.status(500).json({ success: false, error: "Login failed", ...devDetails(err) });
  }
});

authRouter.post("/refresh", async (req, res) => {
  try {
    const body = refreshBodySchema.parse(req.body);
    const refreshPayload = verifyRefreshToken(body.refreshToken);

    const user = await prisma.user.findUnique({
      where: { id: refreshPayload.userId },
      select: { id: true, email: true, role: true }
    });

    if (!user) {
      res.status(401).json({ success: false, error: "Unauthorized" });
      return;
    }

    const accessToken = signAccessToken({ userId: user.id, email: user.email, role: user.role });
    const refreshToken = signRefreshToken({ userId: user.id });

    res.status(200).json({
      success: true,
      data: {
        user,
        accessToken,
        refreshToken
      }
    });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ success: false, error: "Invalid request body" });
      return;
    }

    res.status(401).json({ success: false, error: "Unauthorized" });
  }
});

