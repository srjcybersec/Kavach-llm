import "./envLoader.js";
import { env } from "./config.js";
import { startServer } from "./server.js";

startServer({ port: env.PORT }).catch((err: unknown) => {
  const message = err instanceof Error ? err.message : "Unknown error";
  // eslint-disable-next-line no-console
  console.error(message);
  process.exit(1);
});

