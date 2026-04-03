import { createClient, type RedisClientType } from "redis";
import { env } from "../config.js";

let redis: RedisClientType | null = null;
let connecting: Promise<void> | null = null;

/** Fail fast when Redis is down so the API can start (in-memory rate limit fallback). */
const redisSocketOptions = {
  connectTimeout: 3000,
  reconnectStrategy: false as const
};

export async function getRedisClient(): Promise<RedisClientType> {
  if (redis?.isOpen) return redis;
  if (connecting) {
    await connecting;
    if (redis?.isOpen) return redis;
    throw new Error("Redis client failed to initialize");
  }

  connecting = (async () => {
    const client = createClient({
      url: env.REDIS_URL,
      socket: redisSocketOptions
    });

    client.on("error", (err) => {
      // eslint-disable-next-line no-console
      console.error("Redis error:", err);
    });

    await client.connect();
    redis = client as RedisClientType;
  })();

  try {
    await connecting;
  } finally {
    connecting = null;
  }

  if (!redis?.isOpen) throw new Error("Redis client failed to initialize");
  return redis;
}

