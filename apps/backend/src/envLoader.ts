import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Monorepo root (kavach-llm/.env), then apps/backend/.env overrides.
dotenv.config({ path: path.resolve(__dirname, "../../..", ".env") });
dotenv.config({ path: path.resolve(__dirname, "..", ".env") });
