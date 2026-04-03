import crypto from "crypto";
import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../middleware/auth.js";
import { prisma } from "../prismaClient.js";

export const keysRouter = Router();

const createKeySchema = z.object({
  label: z.string().min(1).max(80)
});

function sha256(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

keysRouter.get("/", requireAuth, async (req, res) => {
  try {
    const keys = await prisma.apiKey.findMany({
      where: { userId: req.user!.userId },
      orderBy: { createdAt: "desc" }
    });

    const shaped = keys.map((k: (typeof keys)[number]) => ({
      id: k.id,
      label: k.label,
      reputationScore: k.reputationScore,
      status: k.status,
      createdAt: k.createdAt,
      lastUsed: k.lastUsed
    }));

    res.status(200).json({ success: true, data: shaped });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to fetch API keys" });
  }
});

keysRouter.post("/", requireAuth, async (req, res) => {
  try {
    const body = createKeySchema.parse(req.body);

    const plainKey = `kvc_${crypto.randomBytes(24).toString("hex")}`;
    const keyHash = sha256(plainKey);

    const created = await prisma.apiKey.create({
      data: {
        userId: req.user!.userId,
        keyHash,
        label: body.label,
        reputationScore: 0,
        status: "ACTIVE",
        lastUsed: null
      }
    });

    res.status(201).json({
      success: true,
      data: {
        id: created.id,
        label: created.label,
        reputationScore: created.reputationScore,
        status: created.status,
        createdAt: created.createdAt,
        lastUsed: created.lastUsed,
        plainKey
      }
    });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ success: false, error: "Invalid API key payload" });
      return;
    }
    res.status(500).json({ success: false, error: "Failed to create API key" });
  }
});

keysRouter.delete("/:id", requireAuth, async (req, res) => {
  try {
    const idRaw = req.params.id;
    const id = Array.isArray(idRaw) ? idRaw[0] : idRaw;
    if (!id || typeof id !== "string") {
      res.status(400).json({ success: false, error: "Invalid API key id" });
      return;
    }

    const result = await prisma.apiKey.updateMany({
      where: { id, userId: req.user!.userId, status: "ACTIVE" },
      data: { status: "REVOKED" }
    });

    if (result.count === 0) {
      res.status(404).json({ success: false, error: "API key not found or already revoked" });
      return;
    }

    res.status(200).json({ success: true, data: { revoked: true } });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to revoke API key" });
  }
});

