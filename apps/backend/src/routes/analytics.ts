import { Router } from "express";
import PDFDocument from "pdfkit";
import { z } from "zod";
import { requireAuth } from "../middleware/auth.js";
import { prisma } from "../prismaClient.js";

export const analyticsRouter = Router();

const rangeQuerySchema = z.object({
  range: z.union([z.literal("1h"), z.literal("24h"), z.literal("7d"), z.literal("30d")]).optional().default("24h")
});

const BLOCKED_ACTIONS: Array<"BLOCK" | "QUARANTINE" | "RATE_LIMIT"> = ["BLOCK", "QUARANTINE", "RATE_LIMIT"];

function isThreatBlockedAction(action: string): boolean {
  return (BLOCKED_ACTIONS as readonly string[]).includes(action);
}

function rangeWindowMs(range: "1h" | "24h" | "7d" | "30d"): number {
  switch (range) {
    case "1h":
      return 60 * 60 * 1000;
    case "24h":
      return 24 * 60 * 60 * 1000;
    case "7d":
      return 7 * 24 * 60 * 60 * 1000;
    case "30d":
      return 30 * 24 * 60 * 60 * 1000;
    default:
      return 24 * 60 * 60 * 1000;
  }
}

function bucketCountForRange(range: "1h" | "24h" | "7d" | "30d"): number {
  switch (range) {
    case "1h":
      return 12;
    case "24h":
      return 24;
    case "7d":
      return 14;
    case "30d":
      return 30;
    default:
      return 24;
  }
}

const reportQuerySchema = z.object({
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  mode: z.union([z.literal("GDPR"), z.literal("HIPAA"), z.literal("PCI-DSS"), z.literal("GENERAL")]).optional().default("GENERAL")
});

analyticsRouter.get("/summary", requireAuth, async (req, res) => {
  try {
    const [auditCount, blockedCount, avgLatencyResult] = await prisma.$transaction([
      prisma.auditLog.count({ where: { userId: req.user!.userId } }),
      prisma.auditLog.count({ where: { userId: req.user!.userId, action: { in: ["BLOCK", "QUARANTINE", "RATE_LIMIT"] } } }),
      prisma.auditLog.aggregate({ where: { userId: req.user!.userId }, _avg: { latencyMs: true } })
    ]);

    const complianceScore = Math.max(0, 100 - Math.round((blockedCount / Math.max(1, auditCount)) * 100));
    res.status(200).json({
      success: true,
      data: {
        requestsToday: auditCount,
        threatsBlocked: blockedCount,
        avgLatency: Math.round(avgLatencyResult._avg.latencyMs ?? 0),
        complianceScore
      }
    });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to fetch analytics summary" });
  }
});

/**
 * Dashboard analytics for a selected time range.
 * Uses persisted AuditLog rows so refresh/restart still shows the same stats.
 */
analyticsRouter.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const q = rangeQuerySchema.parse(req.query);
    const range = q.range;
    const now = new Date();
    const start = new Date(now.getTime() - rangeWindowMs(range));
    const end = now;

    const bucketCount = bucketCountForRange(range);
    const windowMs = end.getTime() - start.getTime();
    const bucketMs = windowMs <= 0 ? 1 : windowMs / bucketCount;

    const bucketLabels: string[] = Array.from({ length: bucketCount }, (_v, i) => {
      if (range === "1h") return String(i + 1);
      if (range === "24h") return String(i);
      return `D${i + 1}`;
    });

    const logs = await prisma.auditLog.findMany({
      where: {
        userId: req.user!.userId,
        createdAt: {
          gte: start,
          lte: end
        }
      },
      select: {
        createdAt: true,
        threatCategory: true,
        action: true,
        latencyMs: true
      }
    });

    const totalRequests = logs.length;
    const threatsBlocked = logs.filter((l) => isThreatBlockedAction(l.action)).length;
    const avgLatency = totalRequests > 0 ? Math.round(logs.reduce((acc, l) => acc + l.latencyMs, 0) / totalRequests) : 0;
    const complianceScore = Math.max(0, 100 - Math.round((threatsBlocked / Math.max(1, totalRequests)) * 100));

    // "Threats over time" = blocked incidents per bucket.
    const bucketRequests = Array.from({ length: bucketCount }, () => 0);
    const bucketBlocked = Array.from({ length: bucketCount }, () => 0);
    const bucketLatencySum = Array.from({ length: bucketCount }, () => 0);

    for (const l of logs) {
      const idx = bucketMs <= 0 ? 0 : Math.floor((l.createdAt.getTime() - start.getTime()) / bucketMs);
      const safeIdx = Math.max(0, Math.min(bucketCount - 1, idx));
      bucketRequests[safeIdx] = (bucketRequests[safeIdx] ?? 0) + 1;
      bucketLatencySum[safeIdx] = (bucketLatencySum[safeIdx] ?? 0) + l.latencyMs;
      if (isThreatBlockedAction(l.action)) bucketBlocked[safeIdx] = (bucketBlocked[safeIdx] ?? 0) + 1;
    }

    const points = Array.from({ length: bucketCount }, (_v, i) => ({
      t: bucketLabels[i] ?? `b${i}`,
      v: bucketBlocked[i] ?? 0
    }));
    const seriesRequests = bucketRequests;
    const seriesBlocked = bucketBlocked;
    const seriesAvgLatency = bucketRequests.map((r, i) => {
      const sum = bucketLatencySum[i] ?? 0;
      return r > 0 ? Math.round(sum / r) : 0;
    });
    const seriesComplianceScore = bucketRequests.map((r, i) => {
      const blocked = bucketBlocked[i] ?? 0;
      return r > 0 ? Math.max(0, 100 - Math.round((blocked / r) * 100)) : 100;
    });

    const byThreatCategory = new Map<string, number>();
    for (const l of logs) byThreatCategory.set(l.threatCategory, (byThreatCategory.get(l.threatCategory) ?? 0) + 1);

    res.status(200).json({
      success: true,
      data: {
        stats: {
          requestsToday: totalRequests,
          threatsBlocked,
          avgLatency,
          complianceScore
        },
        points,
        series: {
          requests: seriesRequests,
          blocked: seriesBlocked,
          avgLatency: seriesAvgLatency,
          complianceScore: seriesComplianceScore
        },
        donut: Array.from(byThreatCategory.entries()).map(([category, count]) => ({ category, count }))
      }
    });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to fetch dashboard analytics" });
  }
});

analyticsRouter.get("/threats", requireAuth, async (req, res) => {
  try {
    const last = await prisma.auditLog.findMany({
      where: { userId: req.user!.userId },
      orderBy: { createdAt: "desc" },
      take: 100
    });
    const grouped = new Map<string, number>();
    for (const e of last) grouped.set(e.threatCategory, (grouped.get(e.threatCategory) ?? 0) + 1);
    res.status(200).json({
      success: true,
      data: Array.from(grouped.entries()).map(([category, count]) => ({ category, count }))
    });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to fetch threat analytics" });
  }
});

analyticsRouter.get("/report/compliance", requireAuth, async (req, res) => {
  try {
    const q = reportQuerySchema.parse(req.query);

    const where: {
      userId: string;
      createdAt?: { gte?: Date; lte?: Date };
    } = { userId: req.user!.userId };
    if (q.startDate || q.endDate) {
      where.createdAt = {};
      if (q.startDate) where.createdAt.gte = new Date(q.startDate);
      if (q.endDate) where.createdAt.lte = new Date(q.endDate);
    }

    const [logs, feedback] = await prisma.$transaction([
      prisma.auditLog.findMany({ where, orderBy: { createdAt: "desc" }, take: 500 }),
      prisma.feedbackEntry.findMany({ where: { adminId: req.user!.userId }, orderBy: { createdAt: "desc" }, take: 500 })
    ]);

    const total = logs.length;
    const blocked = logs.filter((l: (typeof logs)[number]) => l.action === "BLOCK" || l.action === "QUARANTINE" || l.action === "RATE_LIMIT").length;
    const piiIncidents = logs.filter((l: (typeof logs)[number]) => {
      const v = l.piiFields as unknown;
      if (!v || typeof v !== "object") return false;
      const types = (v as { types?: unknown }).types;
      return Array.isArray(types) && types.length > 0;
    }).length;
    const avgLatency = total > 0 ? Math.round(logs.reduce((acc: number, l: (typeof logs)[number]) => acc + l.latencyMs, 0) / total) : 0;
    const complianceScore = Math.max(0, 100 - Math.round((blocked / Math.max(1, total)) * 100));

    const byCategory = new Map<string, number>();
    for (const l of logs) byCategory.set(l.threatCategory, (byCategory.get(l.threatCategory) ?? 0) + 1);

    const doc = new PDFDocument({ size: "A4", margin: 48 });
    const chunks: Buffer[] = [];
    doc.on("data", (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });

    await new Promise<void>((resolve) => {
      doc.on("end", () => resolve());

      doc.fontSize(22).text("Kavach.LLM Compliance Report");
      doc.moveDown(0.3);
      doc.fontSize(11).fillColor("#666").text(`Generated: ${new Date().toISOString()}`);
      doc.text(`Mode: ${q.mode}`);
      doc.text(`Period: ${q.startDate ?? "N/A"} - ${q.endDate ?? "N/A"}`);

      doc.moveDown();
      doc.fillColor("#000").fontSize(14).text("Executive Summary");
      doc.moveDown(0.4);
      doc.fontSize(11);
      doc.text(`Total Requests: ${total}`);
      doc.text(`Threats Blocked: ${blocked}`);
      doc.text(`PII Incidents: ${piiIncidents}`);
      doc.text(`Average Latency: ${avgLatency} ms`);
      doc.text(`Compliance Score: ${complianceScore}/100`);
      doc.text(`Feedback Entries: ${feedback.length}`);

      doc.moveDown();
      doc.fontSize(14).text("Threat Category Breakdown");
      doc.moveDown(0.4);
      doc.fontSize(11);
      for (const [category, count] of Array.from(byCategory.entries()).sort((a, b) => b[1] - a[1])) {
        doc.text(`- ${category}: ${count}`);
      }

      doc.moveDown();
      doc.fontSize(14).text("Retention & Controls");
      doc.moveDown(0.4);
      doc.fontSize(11);
      doc.text("- PII is hashed (SHA-256) in audit logs.");
      doc.text("- Policy controls include BLOCK/REDACT/WARN/RATE_LIMIT/QUARANTINE.");
      doc.text("- Feedback loop enabled for adaptive threat-weight calibration.");

      doc.end();
    });

    const pdfBuffer = Buffer.concat(chunks);
    const modeLabel = q.mode.toLowerCase().replace(/[^a-z0-9]+/g, "-");
    res.setHeader("content-type", "application/pdf");
    res.setHeader("content-disposition", `attachment; filename=\"kavach-compliance-report-${modeLabel}.pdf\"`);
    res.status(200).send(pdfBuffer);
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ success: false, error: "Invalid report query params" });
      return;
    }
    res.status(500).json({ success: false, error: "Failed to generate compliance report" });
  }
});

