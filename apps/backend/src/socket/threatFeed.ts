import { createClient } from "redis";
import { env } from "../config.js";
import type { Namespace } from "socket.io";

export const THREAT_FEED_EVENT = "threat_event";

export type ThreatFeedEventPayload = {
  time: string;
  category: string;
  riskScore: number; // 0..100
  actionTaken: string;
  redactedInputSnippet: string;
};

type RedisClient = ReturnType<typeof createClient>;

type PublisherState = {
  publisher: RedisClient;
  subscriber: RedisClient;
  connected: boolean;
};

let publisherState: PublisherState | null = null;

/** When Redis is down, events are emitted on this namespace directly (single-node dev). */
let localThreatNamespace: Namespace | null = null;

async function ensurePubSub(): Promise<PublisherState> {
  if (publisherState?.connected) return publisherState;

  const socketOpts = { connectTimeout: 3000, reconnectStrategy: false as const };
  const publisher = createClient({ url: env.REDIS_URL, socket: socketOpts });
  const subscriber = createClient({ url: env.REDIS_URL, socket: socketOpts });

  try {
    await Promise.all([publisher.connect(), subscriber.connect()]);
  } catch (err) {
    try {
      await publisher.disconnect();
    } catch {
      /* ignore */
    }
    try {
      await subscriber.disconnect();
    } catch {
      /* ignore */
    }
    throw err;
  }

  const state: PublisherState = { publisher, subscriber, connected: true };
  publisherState = state;
  return state;
}

export async function publishThreatEvent(payload: ThreatFeedEventPayload): Promise<void> {
  try {
    const { publisher } = await ensurePubSub();
    await publisher.publish(env.THREAT_FEED_CHANNEL, JSON.stringify(payload));
    return;
  } catch {
    // Redis unavailable — still try in-process emit so the Playground feed works locally.
  }
  localThreatNamespace?.emit(THREAT_FEED_EVENT, payload);
}

export async function bridgeThreatFeed(namespace: Namespace): Promise<void> {
  // Set synchronously so publishThreatEvent can emit before subscribe finishes connecting.
  localThreatNamespace = namespace;

  try {
    const { subscriber } = await ensurePubSub();

    await subscriber.subscribe(env.THREAT_FEED_CHANNEL, (message) => {
      if (!message) return;
      try {
        const parsed = JSON.parse(message) as unknown;
        if (
          typeof parsed === "object" &&
          parsed !== null &&
          "time" in parsed &&
          "category" in parsed &&
          "riskScore" in parsed &&
          "actionTaken" in parsed &&
          "redactedInputSnippet" in parsed
        ) {
          const p = parsed as ThreatFeedEventPayload;
          namespace.emit(THREAT_FEED_EVENT, p);
        }
      } catch {
        // ignore bad messages
      }
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // eslint-disable-next-line no-console
    console.warn(
      "[threat-feed] Redis pub/sub unavailable — using in-process Socket.IO emit only (start Redis for multi-instance fan-out).",
      msg
    );
  }
}

