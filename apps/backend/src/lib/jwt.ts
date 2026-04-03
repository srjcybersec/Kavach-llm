import jwt from "jsonwebtoken";
import { env } from "../config.js";

type Role = "ADMIN" | "ANALYST" | "VIEWER";

type AccessTokenPayload = {
  sub: string;
  email: string;
  role: Role;
  type: "access";
};

type RefreshTokenPayload = {
  sub: string;
  type: "refresh";
};

const roleValues: ReadonlySet<Role> = new Set<Role>(["ADMIN", "ANALYST", "VIEWER"]);

export class JwtError extends Error {
  public readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export function signAccessToken(input: { userId: string; email: string; role: Role }): string {
  const payload: AccessTokenPayload = {
    sub: input.userId,
    email: input.email,
    role: input.role,
    type: "access"
  };

  return jwt.sign(payload, env.JWT_ACCESS_SECRET, { expiresIn: env.JWT_ACCESS_TTL_SECONDS });
}

export function signRefreshToken(input: { userId: string }): string {
  const payload: RefreshTokenPayload = {
    sub: input.userId,
    type: "refresh"
  };

  return jwt.sign(payload, env.JWT_REFRESH_SECRET, { expiresIn: env.JWT_REFRESH_TTL_SECONDS });
}

function isRole(value: unknown): value is Role {
  return typeof value === "string" && roleValues.has(value as Role);
}

export function verifyAccessToken(token: string): { userId: string; email: string; role: Role } {
  try {
    const decoded = jwt.verify(token, env.JWT_ACCESS_SECRET) as unknown;

    if (
      typeof decoded !== "object" ||
      decoded === null ||
      !("sub" in decoded) ||
      !("email" in decoded) ||
      !("role" in decoded) ||
      !("type" in decoded)
    ) {
      throw new JwtError("INVALID_PAYLOAD", "Invalid access token payload");
    }

    const payload = decoded as Record<string, unknown>;
    const type = payload.type;

    if (type !== "access") {
      throw new JwtError("INVALID_TYPE", "Invalid token type");
    }

    const sub = payload.sub;
    const email = payload.email;
    const role = payload.role;

    if (typeof sub !== "string" || typeof email !== "string" || !isRole(role)) {
      throw new JwtError("INVALID_CLAIMS", "Invalid access token claims");
    }

    return { userId: sub, email, role };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to verify access token";
    if (err instanceof JwtError) throw err;
    throw new JwtError("JWT_VERIFY_FAILED", message);
  }
}

export function verifyRefreshToken(token: string): { userId: string } {
  try {
    const decoded = jwt.verify(token, env.JWT_REFRESH_SECRET) as unknown;

    if (typeof decoded !== "object" || decoded === null || !("sub" in decoded) || !("type" in decoded)) {
      throw new JwtError("INVALID_PAYLOAD", "Invalid refresh token payload");
    }

    const payload = decoded as Record<string, unknown>;

    if (payload.type !== "refresh") {
      throw new JwtError("INVALID_TYPE", "Invalid token type");
    }

    const sub = payload.sub;
    if (typeof sub !== "string") {
      throw new JwtError("INVALID_CLAIMS", "Invalid refresh token claims");
    }

    return { userId: sub };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to verify refresh token";
    if (err instanceof JwtError) throw err;
    throw new JwtError("JWT_VERIFY_FAILED", message);
  }
}

