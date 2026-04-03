import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../middleware/auth.js";
import { prisma } from "../prismaClient.js";
import type { ThreatCategory } from "../lib/scorer.js";
import { applyFeedbackToCategoryWeight, currentAdaptiveWeightState } from "../lib/adaptiveWeights.js";

export const feedbackRouter = Router();

const categorySchema = z.union([
  z.literal("SAFE"),
  z.literal("SUSPICIOUS"),
  z.literal("PROMPT_INJECTION"),
  z.literal("JAILBREAK"),
  z.literal("PHISHING"),
  z.literal("SOCIAL_ENGINEERING"),
  z.literal("DATA_EXFILTRATION"),
  z.literal("NSFW"),
  z.literal("HATE_SPEECH"),
  z.literal("MALWARE_REQUEST")
]);

const createFeedbackSchema = z.object({
  auditLogId: z.string().min(1),
  correctedCategory: categorySchema,
  kind: z.union([z.literal("false_positive"), z.literal("false_negative")])
});

feedbackRouter.post("/", requireAuth, async (req, res) => {
  try {
    const body = createFeedbackSchema.parse(req.body);
    const audit = await prisma.auditLog.findFirst({
      where: { id: body.auditLogId, userId: req.user!.userId }
    });
    if (!audit) {
      res.status(404).json({ success: false, error: "Audit entry not found" });
      return;
    }

    const originalCategory = audit.threatCategory as ThreatCategory;
    const correctedCategory = body.correctedCategory as ThreatCategory;

    const created = await prisma.feedbackEntry.create({
      data: {
        auditLogId: audit.id,
        originalCategory,
        correctedCategory,
        adminId: req.user!.userId
      }
    });

    applyFeedbackToCategoryWeight({
      originalCategory,
      correctedCategory,
      kind: body.kind
    });

    res.status(201).json({
      success: true,
      data: {
        feedback: created,
        adaptiveWeights: currentAdaptiveWeightState()
      }
    });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ success: false, error: "Invalid feedback payload" });
      return;
    }
    res.status(500).json({ success: false, error: "Failed to save feedback" });
  }
});

feedbackRouter.get("/export", requireAuth, async (req, res) => {
  try {
    const format = String(req.query.format ?? "json").toLowerCase();
    const items = await prisma.feedbackEntry.findMany({
      where: { adminId: req.user!.userId },
      orderBy: { createdAt: "desc" }
    });

    if (format === "csv") {
      const header = "id,auditLogId,originalCategory,correctedCategory,adminId,createdAt";
      const rows = items.map((f: (typeof items)[number]) =>
        [f.id, f.auditLogId, f.originalCategory, f.correctedCategory, f.adminId, f.createdAt.toISOString()]
          .map((v) => `"${String(v).replaceAll("\"", "\"\"")}"`)
          .join(",")
      );
      res.setHeader("content-type", "text/csv");
      res.status(200).send([header, ...rows].join("\n"));
      return;
    }

    res.status(200).json({
      success: true,
      data: {
        exportedAt: new Date().toISOString(),
        feedback: items,
        adaptiveWeights: currentAdaptiveWeightState()
      }
    });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to export feedback" });
  }
});

