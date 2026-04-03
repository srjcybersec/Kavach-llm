import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import type { Express } from "express";
import { env } from "../config.js";
import { getRedisClient } from "../services/redisService.js";

function parseAllowedOrigins(): string[] {
  return env.CORS_ALLOWED_ORIGINS.split(",")
    .map((x) => x.trim())
    .filter((x) => x.length > 0);
}

export async function applySecurityMiddleware(app: Express): Promise<void> {
  app.set("trust proxy", env.TRUST_PROXY ? 1 : 0);

  app.use(
    helmet({
      contentSecurityPolicy: false // backend API responses only
    })
  );

  const allowedOrigins = parseAllowedOrigins();
  app.use(
    cors({
      origin(origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error("Origin not allowed by CORS"));
      },
      credentials: true
    })
  );

  let limiter = rateLimit({
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    max: env.RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false
  });

  try {
    const redis = await getRedisClient();
    limiter = rateLimit({
      windowMs: env.RATE_LIMIT_WINDOW_MS,
      max: env.RATE_LIMIT_MAX,
      standardHeaders: true,
      legacyHeaders: false,
      store: new RedisStore({
        sendCommand: (...args: string[]) => redis.sendCommand(args)
      })
    });
  } catch {
    // Fall back to memory store if Redis is unavailable at startup.
  }

  app.use(limiter);
}

