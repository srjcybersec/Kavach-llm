import type { NextFunction, Request, Response } from "express";
import { JwtError, verifyAccessToken } from "../lib/jwt.js";

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (typeof authHeader !== "string" || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ success: false, error: "Unauthorized" });
    return;
  }

  const token = authHeader.slice("Bearer ".length).trim();
  if (!token) {
    res.status(401).json({ success: false, error: "Unauthorized" });
    return;
  }

  try {
    const payload = verifyAccessToken(token);
    req.user = { userId: payload.userId, email: payload.email, role: payload.role };
    next();
  } catch (err: unknown) {
    if (err instanceof JwtError) {
      res.status(401).json({ success: false, error: "Unauthorized" });
      return;
    }

    res.status(401).json({ success: false, error: "Unauthorized" });
  }
}

