import express from "express";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import { healthRouter } from "./routes/health.js";
import { authRouter } from "./routes/auth.js";
import { policiesRouter } from "./routes/policies.js";
import { auditRouter } from "./routes/audit.js";
import { proxyRouter } from "./routes/proxy.js";
import { keysRouter } from "./routes/keys.js";
import { feedbackRouter } from "./routes/feedback.js";
import { analyticsRouter } from "./routes/analytics.js";
import { env } from "./config.js";
import { bridgeThreatFeed } from "./socket/threatFeed.js";
import { applySecurityMiddleware } from "./middleware/security.js";

export async function startServer(opts: { port: number }): Promise<void> {
  const app = express();
  await applySecurityMiddleware(app);
  app.use(express.json({ limit: "1mb" }));

  app.get("/", (_req, res) => {
    res.json({ success: true, data: { service: "Kavach.LLM", status: "ok" } });
  });

  app.use("/api/v1", healthRouter);
  app.use("/api/v1/auth", authRouter);
  app.use("/api/v1/policies", policiesRouter);
  app.use("/api/v1/audit", auditRouter);
  app.use("/api/v1/keys", keysRouter);
  app.use("/api/v1/feedback", feedbackRouter);
  app.use("/api/v1/analytics", analyticsRouter);
  app.use("/api/v1/proxy", proxyRouter);

  const httpServer = http.createServer(app);
  const io = new SocketIOServer(httpServer, {
    cors: { origin: "*" }
  });

  const namespace = io.of(env.SOCKET_NAMESPACE);
  namespace.on("connection", () => {
    // Connections are bridged from Redis pub/sub into this namespace.
  });
  void bridgeThreatFeed(namespace);

  return new Promise((resolve, reject) => {
    httpServer.once("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        // eslint-disable-next-line no-console
        console.error(
          `Port ${opts.port} is already in use. Stop the other process (e.g. another terminal running the backend) or set PORT in .env to a free port.`
        );
      }
      reject(err);
    });
    httpServer.listen(opts.port, () => {
      // eslint-disable-next-line no-console
      console.info(`Kavach backend listening on http://localhost:${opts.port}`);
      resolve();
    });
  });
}

