import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Badge } from "../components/ui/badge";
import { ensureDemoAuth } from "../services/authApi";
import {
  fetchAuditListChunk,
  useAuditDetailQuery,
  useAuditListQuery,
  type AuditEntry,
  type AuditSortKey
} from "../services/auditApi";

type SortKey = AuditSortKey;
type SortDirection = "asc" | "desc";

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString();
}

function jsonForExport(entries: AuditEntry[]): string {
  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      count: entries.length,
      items: entries
    },
    null,
    2
  );
}

function csvForExport(entries: AuditEntry[]): string {
  const headers = ["Timestamp", "Session", "Category", "Score", "Action", "LatencyMs", "AuditId"];
  const lines = entries.map((e) =>
    [
      e.createdAt,
      e.sessionId,
      e.threatCategory,
      String(e.confidence),
      e.action,
      String(e.latencyMs),
      e.id
    ]
      .map((s) => `"${String(s).replaceAll("\"", "\"\"")}"`)
      .join(",")
  );
  return [headers.join(","), ...lines].join("\n");
}

function downloadText(filename: string, text: string, mime: string): void {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Audit(): React.ReactElement {
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [category, setCategory] = useState("");
  const [action, setAction] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("createdAt");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportBusy, setExportBusy] = useState(false);

  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedSearch(search.trim()), 300);
    return () => window.clearTimeout(t);
  }, [search]);

  const listParams = useMemo(
    () => ({
      page,
      pageSize,
      category: category || undefined,
      action: action || undefined,
      startDate: startDate ? new Date(startDate).toISOString() : undefined,
      endDate: endDate ? new Date(`${endDate}T23:59:59`).toISOString() : undefined,
      sortBy: sortKey,
      sortDir: sortDirection,
      q: debouncedSearch || undefined
    }),
    [page, pageSize, category, action, startDate, endDate, sortKey, sortDirection, debouncedSearch]
  );

  const listQuery = useAuditListQuery(listParams);

  useEffect(() => {
    setPage(1);
  }, [category, action, startDate, endDate, debouncedSearch, sortKey, sortDirection]);

  const detailQuery = useAuditDetailQuery(selectedId);

  useEffect(() => {
    void ensureDemoAuth();
  }, []);

  const items = listQuery.data?.items ?? [];
  const total = listQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const exportFilterParams = useMemo(
    () => ({
      category: category || undefined,
      action: action || undefined,
      startDate: startDate ? new Date(startDate).toISOString() : undefined,
      endDate: endDate ? new Date(`${endDate}T23:59:59`).toISOString() : undefined,
      sortBy: sortKey,
      sortDir: sortDirection,
      q: debouncedSearch || undefined
    }),
    [category, action, startDate, endDate, sortKey, sortDirection, debouncedSearch]
  );

  const onSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDirection("desc");
    }
  };

  const runExport = async (kind: "csv" | "json") => {
    setExportError(null);
    setExportBusy(true);
    try {
      const rows = await fetchAuditListChunk({ ...exportFilterParams, page: 1, pageSize: 500 });
      if (kind === "csv") {
        downloadText("kavach-audit-export.csv", csvForExport(rows), "text/csv");
      } else {
        downloadText("kavach-audit-export.json", jsonForExport(rows), "application/json");
      }
    } catch (e) {
      setExportError(e instanceof Error ? e.message : String(e));
    } finally {
      setExportBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">Audit Logs</h2>
        <div className="flex flex-col items-end gap-1">
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="secondary"
              disabled={exportBusy}
              onClick={() => void runExport("csv")}
            >
              Export CSV
            </Button>
            <Button
              type="button"
              variant="secondary"
              disabled={exportBusy}
              onClick={() => void runExport("json")}
            >
              Export JSON
            </Button>
          </div>
          <p className="max-w-xs text-right text-xs text-text-secondary">
            Export uses current filters and sort, up to 500 rows.
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Threats & Actions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {listQuery.isError ? (
            <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
              {listQuery.error.message}
            </div>
          ) : null}
          {exportError ? (
            <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-100">
              {exportError}
            </div>
          ) : null}
          <div className="grid gap-2 md:grid-cols-6">
            <Input
              placeholder="Search id, session, category, hashes…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="md:col-span-2"
            />
            <Input placeholder="Category filter" value={category} onChange={(e) => setCategory(e.target.value)} />
            <Input placeholder="Action filter" value={action} onChange={(e) => setAction(e.target.value)} />
            <Input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} />
            <Input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} />
          </div>

          <div className="overflow-x-auto rounded-md border border-border">
            <table className="min-w-full text-sm">
              <thead className="bg-bg-surface/50 text-text-secondary">
                <tr>
                  <th className="px-3 py-2 text-left">
                    <button type="button" onClick={() => onSort("createdAt")}>
                      Timestamp
                    </button>
                  </th>
                  <th className="px-3 py-2 text-left">Session</th>
                  <th className="px-3 py-2 text-left">
                    <button type="button" onClick={() => onSort("threatCategory")}>
                      Category
                    </button>
                  </th>
                  <th className="px-3 py-2 text-left">
                    <button type="button" onClick={() => onSort("confidence")}>
                      Score
                    </button>
                  </th>
                  <th className="px-3 py-2 text-left">
                    <button type="button" onClick={() => onSort("action")}>
                      Action
                    </button>
                  </th>
                  <th className="px-3 py-2 text-left">
                    <button type="button" onClick={() => onSort("latencyMs")}>
                      Latency
                    </button>
                  </th>
                  <th className="px-3 py-2 text-left">Details</th>
                </tr>
              </thead>
              <tbody>
                {listQuery.isLoading ? (
                  <tr>
                    <td colSpan={7} className="px-3 py-6 text-center text-text-secondary">
                      Loading...
                    </td>
                  </tr>
                ) : items.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-3 py-6 text-center text-text-secondary">
                      No audit entries found.
                    </td>
                  </tr>
                ) : (
                  items.map((row) => (
                    <tr key={row.id} className="border-t border-border/60">
                      <td className="px-3 py-2">{formatDate(row.createdAt)}</td>
                      <td className="px-3 py-2">
                        {row.sessionId.length > 16 ? `${row.sessionId.slice(0, 16)}…` : row.sessionId}
                      </td>
                      <td className="px-3 py-2">
                        <Badge variant="violet">{row.threatCategory}</Badge>
                      </td>
                      <td className="px-3 py-2">{row.confidence.toFixed(2)}</td>
                      <td className="px-3 py-2">{row.action}</td>
                      <td className="px-3 py-2">{row.latencyMs}ms</td>
                      <td className="px-3 py-2">
                        <Button type="button" size="sm" variant="outline" onClick={() => setSelectedId(row.id)}>
                          View
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between text-sm text-text-secondary">
            <div>
              Page {page} / {totalPages} • {total} total
            </div>
            <div className="flex items-center gap-2">
              <Button type="button" size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                Prev
              </Button>
              <Button type="button" size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                Next
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <AnimatePresence>
        {selectedId ? (
          <motion.div
            className="fixed inset-0 z-40 bg-black/60"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setSelectedId(null)}
          >
            <motion.div
              className="absolute right-0 top-0 h-full w-full max-w-xl border-l border-border bg-bg-surface p-4"
              initial={{ x: 480 }}
              animate={{ x: 0 }}
              exit={{ x: 480 }}
              transition={{ duration: 0.2 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="mb-3 flex items-center justify-between">
                <h3 className="text-base font-semibold">Audit Details</h3>
                <Button type="button" size="sm" variant="ghost" onClick={() => setSelectedId(null)}>
                  Close
                </Button>
              </div>

              {detailQuery.isError ? (
                <div className="rounded-md border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-200">
                  {detailQuery.error.message}
                </div>
              ) : detailQuery.isLoading ? (
                <div className="rounded-md border border-border bg-bg-surface/30 p-4 text-sm text-text-secondary">
                  Loading details...
                </div>
              ) : detailQuery.data ? (
                <div className="space-y-3 text-sm">
                  <div className="rounded-md border border-border bg-bg-card p-3">
                    <div className="text-xs text-text-secondary">Audit ID</div>
                    <div className="font-mono">{detailQuery.data.id}</div>
                  </div>
                  <div className="rounded-md border border-border bg-bg-card p-3">
                    <div className="text-xs text-text-secondary">Category / Action</div>
                    <div className="mt-1">
                      {detailQuery.data.threatCategory} / {detailQuery.data.action}
                    </div>
                  </div>
                  <div className="rounded-md border border-border bg-bg-card p-3">
                    <div className="text-xs text-text-secondary">Scan Breakdown</div>
                    <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap text-xs text-text-secondary">
                      {JSON.stringify(detailQuery.data.scanBreakdown, null, 2)}
                    </pre>
                  </div>
                  <div className="rounded-md border border-border bg-bg-card p-3">
                    <div className="text-xs text-text-secondary">PII Fields (hashed)</div>
                    <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap text-xs text-text-secondary">
                      {JSON.stringify(detailQuery.data.piiFields, null, 2)}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="rounded-md border border-border bg-bg-surface/30 p-4 text-sm text-text-secondary">
                  No details loaded.
                </div>
              )}
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}

