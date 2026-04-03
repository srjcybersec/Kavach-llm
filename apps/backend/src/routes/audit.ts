import { Router } from "express";
import { z } from "zod";
import { PolicyAction, Prisma } from "@prisma/client";
import { prisma } from "../prismaClient.js";
import { requireAuth } from "../middleware/auth.js";

export const auditRouter = Router();

/** Express may surface repeated keys as `string[]`; coerce to a single string. */
function firstQueryString(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined;
  if (Array.isArray(v)) {
    const h = v[0];
    return typeof h === "string" ? h : undefined;
  }
  return typeof v === "string" ? v : undefined;
}

const sortByValues = ["createdAt", "threatCategory", "confidence", "action", "latencyMs"] as const;

const listQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  category: z.string().optional(),
  action: z.string().optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  sortBy: z.enum(sortByValues).default("createdAt"),
  sortDir: z.enum(["asc", "desc"]).default("desc"),
  q: z.string().max(256).optional()
});

const policyActionSet = new Set<string>(Object.values(PolicyAction));

auditRouter.get("/", requireAuth, async (req, res) => {
  try {
    const raw = req.query as Record<string, unknown>;
    const q = listQuerySchema.parse({
      ...raw,
      category: firstQueryString(raw.category),
      action: firstQueryString(raw.action),
      startDate: firstQueryString(raw.startDate),
      endDate: firstQueryString(raw.endDate),
      sortBy: firstQueryString(raw.sortBy),
      sortDir: firstQueryString(raw.sortDir),
      q: firstQueryString(raw.q)
    });

    const where: Prisma.AuditLogWhereInput = { userId: req.user!.userId };
    if (q.category?.trim()) where.threatCategory = q.category.trim();
    const actionTrim = q.action?.trim();
    if (actionTrim && policyActionSet.has(actionTrim)) where.action = actionTrim as PolicyAction;

    if (q.startDate || q.endDate) {
      where.createdAt = {};
      if (q.startDate) where.createdAt.gte = new Date(q.startDate);
      if (q.endDate) where.createdAt.lte = new Date(q.endDate);
    }

    const term = q.q?.trim();
    if (term) {
      where.OR = [
        { id: { contains: term, mode: "insensitive" } },
        { sessionId: { contains: term, mode: "insensitive" } },
        { threatCategory: { contains: term, mode: "insensitive" } },
        { inputHash: { contains: term, mode: "insensitive" } },
        { responseHash: { contains: term, mode: "insensitive" } }
      ];
    }

    const orderBy: Prisma.AuditLogOrderByWithRelationInput = {
      [q.sortBy]: q.sortDir
    };

    const [items, total] = await prisma.$transaction([
      prisma.auditLog.findMany({
        where,
        orderBy,
        skip: (q.page - 1) * q.pageSize,
        take: q.pageSize
      }),
      prisma.auditLog.count({ where })
    ]);

    res.status(200).json({ success: true, data: { items, total, page: q.page, pageSize: q.pageSize } });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ success: false, error: "Invalid query params" });
      return;
    }
    res.status(500).json({ success: false, error: "Failed to fetch audit logs" });
  }
});

auditRouter.get("/:id", requireAuth, async (req, res) => {
  try {
    const idRaw = req.params.id;
    const id = Array.isArray(idRaw) ? idRaw[0] : idRaw;
    if (!id || typeof id !== "string") {
      res.status(400).json({ success: false, error: "Invalid audit id" });
      return;
    }

    const entry = await prisma.auditLog.findFirst({
      where: { id, userId: req.user!.userId }
    });

    if (!entry) {
      res.status(404).json({ success: false, error: "Audit entry not found" });
      return;
    }

    res.status(200).json({ success: true, data: entry });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to fetch audit entry" });
  }
});

