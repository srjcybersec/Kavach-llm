import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { motion, useReducedMotion } from "framer-motion";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { LiveThreatFeedPanel } from "../components/dashboard/LiveThreatFeedPanel";
import { useDownloadComplianceReportMutation } from "../services/reportApi";
import { ensureDemoAuth } from "../services/authApi";
import { useAnalyticsDashboardQuery, type RangeKey } from "../services/analyticsApi";
import { cn } from "../lib/utils";

function CountUp({ value, durationMs = 900 }: { value: number; durationMs?: number }): React.ReactElement {
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    let raf = 0;
    const start = performance.now();
    const from = display;
    const to = value;

    const tick = (t: number) => {
      const elapsed = t - start;
      const p = Math.min(1, elapsed / durationMs);
      const next = from + (to - from) * p;
      setDisplay(next);
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, durationMs]);

  return <>{Math.round(display)}</>;
}

const lineAnim = { duration: 0.45, ease: [0.22, 1, 0.36, 1] as const };

function Sparkline({
  data,
  animationDelay = 0,
  reduceMotion
}: {
  data: number[];
  animationDelay?: number;
  reduceMotion: boolean;
}): React.ReactElement {
  const chartData = useMemo(() => [...data].map((v, i) => ({ i, v })), [data]);
  return (
    <motion.div
      className="h-12 w-full min-h-12 min-w-0 shrink-0"
      initial={reduceMotion ? false : { opacity: 0, y: 6 }}
      animate={reduceMotion ? false : { opacity: 1, y: 0 }}
      transition={{ ...lineAnim, delay: animationDelay / 1000 }}
    >
      <div className={cn("h-full w-full", !reduceMotion && "chart-breathe")}>
        <ResponsiveContainer width="100%" height={48} minWidth={0}>
          <LineChart data={chartData} margin={{ top: 2, right: 2, left: 2, bottom: 2 }}>
            <Line
              type="monotone"
              dataKey="v"
              stroke="var(--accent-teal)"
              strokeWidth={2}
              dot={false}
              isAnimationActive={!reduceMotion}
              animationDuration={1100}
              animationEasing="ease-out"
              animationBegin={reduceMotion ? 0 : animationDelay}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}

const rangeOptions: Array<{ key: RangeKey; label: string }> = [
  { key: "1h", label: "1h" },
  { key: "24h", label: "24h" },
  { key: "7d", label: "7d" },
  { key: "30d", label: "30d" }
];

const colors = {
  violet: "var(--accent-violet)",
  teal: "var(--accent-teal)",
  red: "var(--accent-red)",
  amber: "var(--accent-amber)"
} as const;

export default function Dashboard(): React.ReactElement {
  const reduceMotion = useReducedMotion();
  const [range, setRange] = useState<RangeKey>("24h");
  const [reportMode, setReportMode] = useState<"GDPR" | "HIPAA" | "PCI-DSS" | "GENERAL">("GENERAL");
  const downloadReport = useDownloadComplianceReportMutation();

  useEffect(() => {
    void ensureDemoAuth();
  }, []);

  const dashboardQuery = useAnalyticsDashboardQuery(range);
  const analytics = dashboardQuery.data ?? {
    stats: {
      requestsToday: 0,
      threatsBlocked: 0,
      avgLatency: 0,
      complianceScore: 0
    },
    points: [] as Array<{ t: string; v: number }>,
    series: {
      requests: [0],
      blocked: [0],
      avgLatency: [0],
      complianceScore: [0]
    },
    donut: [] as Array<{ category: string; count: number }>
  };

  const statCards = useMemo(() => {
    const { stats } = analytics;
    const requestsSpark = analytics.series.requests.length ? analytics.series.requests.slice(-10) : [0];
    const blockedSpark = analytics.series.blocked.length ? analytics.series.blocked.slice(-10) : [0];
    const avgLatencySpark = analytics.series.avgLatency.length ? analytics.series.avgLatency.slice(-10) : [0];
    const complianceSpark = analytics.series.complianceScore.length ? analytics.series.complianceScore.slice(-10) : [0];
    return [
      { title: "Requests", value: stats.requestsToday, suffix: "", spark: requestsSpark },
      { title: "Threats Blocked", value: stats.threatsBlocked, suffix: "", spark: blockedSpark },
      { title: "Avg Latency", value: stats.avgLatency, suffix: "ms", spark: avgLatencySpark },
      { title: "Compliance Score", value: stats.complianceScore, suffix: "", spark: complianceSpark }
    ];
  }, [analytics]);

  const donut = useMemo(() => {
    const counts = new Map(analytics.donut.map((d) => [d.category, d.count]));
    return [
      { key: "PROMPT_INJECTION", label: "Prompt Injection", value: counts.get("PROMPT_INJECTION") ?? 0, color: colors.violet },
      { key: "JAILBREAK", label: "Jailbreak", value: counts.get("JAILBREAK") ?? 0, color: colors.red },
      { key: "DATA_EXFILTRATION", label: "Data Exfiltration", value: counts.get("DATA_EXFILTRATION") ?? 0, color: colors.teal },
      { key: "PHISHING", label: "Phishing", value: counts.get("PHISHING") ?? 0, color: colors.amber },
      { key: "SOCIAL_ENGINEERING", label: "Social Eng.", value: counts.get("SOCIAL_ENGINEERING") ?? 0, color: "rgba(0, 194, 168, 0.7)" },
      { key: "MALWARE_REQUEST", label: "Malware", value: counts.get("MALWARE_REQUEST") ?? 0, color: "rgba(108, 71, 255, 0.65)" }
    ];
  }, [analytics.donut]);

  const donutTotal = donut.reduce((acc, d) => acc + d.value, 0);

  return (
    <div className="space-y-4">
      <Card className="border-accent-teal/25 bg-gradient-to-br from-bg-card to-bg-surface/80">
        <CardHeader>
          <CardTitle className="text-base sm:text-lg">Getting started</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-text-secondary">
          <p className="text-text-primary">
            Charts are live dashboard metrics computed from your saved Playground runs (`AuditLog` in the backend).
            Use the <strong>Playground</strong> to generate new events; the dashboard updates automatically.
          </p>
          <Link
            to="/playground"
            className="inline-flex items-center rounded-md bg-accent-violet px-4 py-2 text-sm font-medium text-white hover:opacity-90"
          >
            Open Playground — try your own input
          </Link>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {statCards.map((card, idx) => (
          <motion.div
            key={card.title}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.06 }}
          >
            <Card className="h-full min-w-0">
              <CardHeader className="flex flex-row items-start justify-between gap-3">
                <CardTitle>{card.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-semibold">
                  <CountUp value={card.value} /> {card.suffix}
                </div>
                <div className="mt-3">
                  <Sparkline data={card.spark} animationDelay={idx * 100} reduceMotion={Boolean(reduceMotion)} />
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-3">
          <CardTitle>Compliance Report</CardTitle>
          <div className="flex items-center gap-2">
            <select
              className="h-9 rounded-md border border-border bg-bg-card px-3 text-sm"
              value={reportMode}
              onChange={(e) => setReportMode(e.target.value as "GDPR" | "HIPAA" | "PCI-DSS" | "GENERAL")}
            >
              <option value="GENERAL">GENERAL</option>
              <option value="GDPR">GDPR</option>
              <option value="HIPAA">HIPAA</option>
              <option value="PCI-DSS">PCI-DSS</option>
            </select>
            <Button
              type="button"
              onClick={() => {
                void downloadReport.mutateAsync({
                  mode: reportMode
                });
              }}
              disabled={downloadReport.isPending}
            >
              {downloadReport.isPending ? "Generating..." : "Download Compliance Report PDF"}
            </Button>
          </div>
        </CardHeader>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <motion.div
          initial={reduceMotion ? false : { opacity: 0, y: 14 }}
          animate={reduceMotion ? false : { opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        >
          <Card className="h-full">
            <CardHeader className="flex flex-row items-center justify-between gap-3">
              <CardTitle>Threats Over Time</CardTitle>
              <div className="flex gap-2">
                {rangeOptions.map((o) => (
                  <Button
                    key={o.key}
                    type="button"
                    variant={range === o.key ? "secondary" : "outline"}
                    size="sm"
                    onClick={() => setRange(o.key)}
                  >
                    {o.label}
                  </Button>
                ))}
              </div>
            </CardHeader>
            <CardContent>
              <motion.div
                key={range}
                className="h-64 w-full min-h-64 min-w-0"
                initial={reduceMotion ? false : { opacity: 0.4 }}
                animate={reduceMotion ? false : { opacity: 1 }}
                transition={{ duration: 0.4 }}
              >
                <div
                  className={cn("h-full w-full", !reduceMotion && "chart-breathe")}
                >
                  <ResponsiveContainer width="100%" height={256} minWidth={0} debounce={50}>
                    <AreaChart data={analytics.points}>
                      <defs>
                        <linearGradient id="threatAreaFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--accent-teal)" stopOpacity={0.35} />
                          <stop offset="100%" stopColor="var(--accent-teal)" stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke="rgba(42,40,64,0.7)" strokeDasharray="4 4" />
                      <XAxis dataKey="t" tick={{ fill: "#8884A0", fontSize: 11 }} />
                      <YAxis tick={{ fill: "#8884A0" }} />
                      <Tooltip
                        contentStyle={{ background: "#16161f", border: "1px solid #2a2840" }}
                        labelStyle={{ color: "#F0EFF8" }}
                        formatter={(v: unknown) => [`${v}`, "count"]}
                      />
                      <Area
                        type="monotone"
                        dataKey="v"
                        stroke={colors.teal}
                        fill="url(#threatAreaFill)"
                        strokeWidth={2}
                        isAnimationActive={!reduceMotion}
                        animationDuration={1650}
                        animationEasing="ease-out"
                        animationBegin={reduceMotion ? 0 : 80}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </motion.div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={reduceMotion ? false : { opacity: 0, y: 14 }}
          animate={reduceMotion ? false : { opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.06, ease: [0.22, 1, 0.36, 1] }}
        >
          <Card className="h-full">
            <CardHeader className="flex flex-row items-center justify-between gap-3">
              <CardTitle>Threat Breakdown</CardTitle>
              <Badge variant="violet">{donutTotal} total</Badge>
            </CardHeader>
            <CardContent>
              <motion.div
                key={range}
                className="h-64 w-full min-h-64 min-w-0"
                initial={reduceMotion ? false : { opacity: 0, scale: 0.92 }}
                animate={reduceMotion ? false : { opacity: 1, scale: 1 }}
                transition={
                  reduceMotion
                    ? { duration: 0 }
                    : { type: "spring", stiffness: 260, damping: 22 }
                }
              >
                <div className={cn("h-full w-full", !reduceMotion && "chart-breathe")}>
                  <ResponsiveContainer width="100%" height={256} minWidth={0} debounce={50}>
                    <PieChart>
                      <Tooltip
                        contentStyle={{ background: "#111118", border: "1px solid #252336" }}
                        labelStyle={{ color: "#f4f3f9" }}
                      />
                      <Pie
                        data={donut}
                        dataKey="value"
                        nameKey="label"
                        innerRadius={52}
                        outerRadius={88}
                        paddingAngle={2}
                        stroke="rgba(6,6,10,0.4)"
                        strokeWidth={1}
                        isAnimationActive={!reduceMotion}
                        animationDuration={1300}
                        animationEasing="ease-out"
                        animationBegin={reduceMotion ? 0 : 120}
                      >
                        {donut.map((d) => (
                          <Cell key={d.key} fill={d.color} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </motion.div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Live Threat Feed</CardTitle>
        </CardHeader>
        <CardContent>
          <LiveThreatFeedPanel />
        </CardContent>
      </Card>
    </div>
  );
}

