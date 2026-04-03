import { useEffect, useMemo, useState, type DragEvent } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { ensureDemoAuth } from "../services/authApi";
import {
  useApplyComplianceModeMutation,
  useApplyPresetMutation,
  useRemovePresetMutation,
  useCreatePolicyRuleMutation,
  useDeletePolicyRuleMutation,
  usePoliciesQuery,
  useUpdatePolicyRuleMutation,
  type PolicyAction,
  type PolicyRule,
  type ProductPresetName,
  type ThreatCategory
} from "../services/policiesApi";

type ComplianceMode = "GDPR" | "HIPAA" | "PCI-DSS" | "GENERAL";

const COMPLIANCE_MODE_STORAGE_KEY = "kavach-policies-compliance-mode";
const CATEGORY_ANY = "__ANY__";

const actionOptions: PolicyAction[] = ["ALLOW", "BLOCK", "REDACT_PII", "WARN_USER", "RATE_LIMIT", "QUARANTINE"];
const categoryOptions: Array<{ value: ThreatCategory | typeof CATEGORY_ANY; label: string }> = [
  { value: CATEGORY_ANY, label: "Any category" },
  { value: "SAFE", label: "SAFE" },
  { value: "SUSPICIOUS", label: "SUSPICIOUS" },
  { value: "PROMPT_INJECTION", label: "PROMPT_INJECTION" },
  { value: "JAILBREAK", label: "JAILBREAK" },
  { value: "PHISHING", label: "PHISHING" },
  { value: "SOCIAL_ENGINEERING", label: "SOCIAL_ENGINEERING" },
  { value: "DATA_EXFILTRATION", label: "DATA_EXFILTRATION" },
  { value: "NSFW", label: "NSFW" },
  { value: "HATE_SPEECH", label: "HATE_SPEECH" },
  { value: "MALWARE_REQUEST", label: "MALWARE_REQUEST" }
];

export default function Policies(): React.ReactElement {
  const [mode, setMode] = useState<ComplianceMode>("GENERAL");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [dragId, setDragId] = useState<string | null>(null);
  const [bannerError, setBannerError] = useState<string | null>(null);

  const [formCategory, setFormCategory] = useState<ThreatCategory | typeof CATEGORY_ANY>("PROMPT_INJECTION");
  const [formRequireConfidence, setFormRequireConfidence] = useState(true);
  const [formOperator, setFormOperator] = useState<">" | ">=" | "<" | "<=">(">");
  const [formThreshold, setFormThreshold] = useState("0.7");
  const [formAction, setFormAction] = useState<PolicyAction>("BLOCK");
  const [formAllowPhrases, setFormAllowPhrases] = useState("");
  const [formDenyPhrases, setFormDenyPhrases] = useState("");
  const [formPriority, setFormPriority] = useState("");

  const policiesQuery = usePoliciesQuery();
  const createRule = useCreatePolicyRuleMutation();
  const updateRule = useUpdatePolicyRuleMutation();
  const deleteRule = useDeletePolicyRuleMutation();
  const applyPreset = useApplyPresetMutation();
  const removePreset = useRemovePresetMutation();
  const applyCompliance = useApplyComplianceModeMutation();

  useEffect(() => {
    void ensureDemoAuth();
  }, []);

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(COMPLIANCE_MODE_STORAGE_KEY);
      if (raw === "GDPR" || raw === "HIPAA" || raw === "PCI-DSS" || raw === "GENERAL") setMode(raw);
    } catch {
      /* ignore */
    }
  }, []);

  const rules = useMemo(() => policiesQuery.data ?? [], [policiesQuery.data]);

  const productPresetRows = useMemo(
    () => ({
      DefaultSafePolicy: rules.some((r) => r.preset === "DefaultSafePolicy"),
      StrictEnterprisePolicy: rules.some((r) => r.preset === "StrictEnterprisePolicy"),
      DeveloperPolicy: rules.some((r) => r.preset === "DeveloperPolicy")
    }),
    [rules]
  );

  const presetCardsPending = applyPreset.isPending || removePreset.isPending;

  const openNewDrawer = () => {
    setEditingId(null);
    setFormCategory("PROMPT_INJECTION");
    setFormRequireConfidence(true);
    setFormOperator(">");
    setFormThreshold("0.7");
    setFormAction("BLOCK");
    setFormAllowPhrases("");
    setFormDenyPhrases("");
    setFormPriority("");
    setBannerError(null);
    setDrawerOpen(true);
  };

  const openEditDrawer = (rule: PolicyRule) => {
    setEditingId(rule.id);
    setFormCategory(rule.condition.category ?? CATEGORY_ANY);
    setFormRequireConfidence(Boolean(rule.condition.confidence));
    setFormOperator(rule.condition.confidence?.op ?? ">");
    setFormThreshold(String(rule.condition.confidence?.value ?? 0.7));
    setFormAction(rule.action);
    setFormAllowPhrases((rule.condition.allowPhrases ?? []).join(", "));
    setFormDenyPhrases((rule.condition.denyPhrases ?? []).join(", "));
    setFormPriority(String(rule.priority));
    setBannerError(null);
    setDrawerOpen(true);
  };

  const saveRule = async () => {
    setBannerError(null);
    const allowPhrases = formAllowPhrases
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const denyPhrases = formDenyPhrases
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    const hasCategory = formCategory !== CATEGORY_ANY;
    const hasConfidence =
      formRequireConfidence && formThreshold.trim().length > 0 && !Number.isNaN(Number(formThreshold.trim()));
    if (!hasCategory && !hasConfidence && allowPhrases.length === 0 && denyPhrases.length === 0) {
      setBannerError("Add a category, a confidence threshold, or allow/deny phrases so the rule is not unconditional.");
      return;
    }

    const ifClause: {
      category?: ThreatCategory;
      confidence?: string;
      allowPhrases: string[];
      denyPhrases: string[];
    } = { allowPhrases, denyPhrases };
    if (hasCategory) ifClause.category = formCategory as ThreatCategory;
    if (hasConfidence) ifClause.confidence = `${formOperator}${formThreshold.trim()}`;

    const payload: {
      if: typeof ifClause;
      then: PolicyAction;
      enabled: true;
      priority?: number;
    } = {
      if: ifClause,
      then: formAction,
      enabled: true
    };

    const p = formPriority.trim();
    if (p.length > 0) {
      const n = Number(p);
      if (!Number.isFinite(n) || !Number.isInteger(n)) {
        setBannerError("Priority must be an integer.");
        return;
      }
      payload.priority = n;
    }

    try {
      if (editingId) {
        await updateRule.mutateAsync({ id: editingId, patch: payload });
      } else {
        await createRule.mutateAsync(payload);
      }
      setDrawerOpen(false);
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : String(e));
    }
  };

  const toggleEnabled = async (rule: PolicyRule) => {
    setBannerError(null);
    try {
      await updateRule.mutateAsync({
        id: rule.id,
        patch: { enabled: !rule.enabled }
      });
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : String(e));
    }
  };

  /** Keep priorities in a high band so reordered rules stay above merged baseline (~≤9.2k preset / ≤200 built-in). */
  const PRIORITY_STACK_TOP = 100_000;

  const onDropReorder = async (targetId: string) => {
    if (!dragId || dragId === targetId) return;
    const ordered = [...rules];
    const from = ordered.findIndex((r) => r.id === dragId);
    const to = ordered.findIndex((r) => r.id === targetId);
    if (from < 0 || to < 0) return;

    const [moved] = ordered.splice(from, 1);
    if (!moved) return;
    ordered.splice(to, 0, moved);

    setBannerError(null);
    try {
      await Promise.all(
        ordered.map((r, i) =>
          updateRule.mutateAsync({
            id: r.id,
            patch: { priority: PRIORITY_STACK_TOP - i }
          })
        )
      );
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : String(e));
    }
    setDragId(null);
  };

  const applyComplianceMode = async (next: ComplianceMode) => {
    setBannerError(null);
    setMode(next);
    try {
      sessionStorage.setItem(COMPLIANCE_MODE_STORAGE_KEY, next);
      await applyCompliance.mutateAsync(next);
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : String(e));
    }
  };

  const applyPresetNamed = async (name: ProductPresetName) => {
    setBannerError(null);
    try {
      await applyPreset.mutateAsync(name);
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : String(e));
    }
  };

  const removePresetNamed = async (name: ProductPresetName) => {
    setBannerError(null);
    try {
      await removePreset.mutateAsync(name);
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : String(e));
    }
  };

  const deleteRuleById = async (id: string) => {
    setBannerError(null);
    try {
      await deleteRule.mutateAsync(id);
    } catch (e) {
      setBannerError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">Policies</h2>
        <div className="flex flex-wrap items-center gap-2">
          {(["GDPR", "HIPAA", "PCI-DSS", "GENERAL"] as ComplianceMode[]).map((m) => (
            <Button
              key={m}
              type="button"
              size="sm"
              variant={mode === m ? "secondary" : "outline"}
              disabled={applyCompliance.isPending}
              onClick={() => {
                void applyComplianceMode(m);
              }}
            >
              {m}
            </Button>
          ))}
        </div>
      </div>

      {bannerError ? (
        <div className="rounded-md border border-accent-red/40 bg-accent-red/10 px-3 py-2 text-sm text-text-primary">
          {bannerError}
        </div>
      ) : null}

      {policiesQuery.isError ? (
        <div className="rounded-md border border-accent-amber/40 bg-accent-amber/10 px-3 py-2 text-sm text-text-primary">
          {policiesQuery.error instanceof Error ? policiesQuery.error.message : "Failed to load policies"}
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>How enforcement works</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-text-secondary">
          <p>
            On each Playground request the backend evaluates rules in <strong>priority order</strong> (highest first) and
            applies the <strong>first match</strong>. New rules and presets use high priorities so they override the server
            baseline bundle from <code className="text-xs text-text-primary">POLICY_BASELINE_PRESET</code> in{" "}
            <code className="text-xs text-text-primary">.env</code>.
          </p>
          <p className="text-xs">
            Drag rules to reorder (top = evaluated first). Use compliance chips to replace preset-backed rules; custom
            rules without a preset tag are kept until you delete them.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Compliance chips (distinct rule packs)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-text-secondary">
          <p className="text-xs text-text-primary/90">
            These are <strong>LLM-gateway policy interpretations</strong> for demos—not a substitute for legal/compliance
            programs. Each chip loads a different rule set (count, thresholds, and actions differ).
          </p>
          <ul className="list-inside list-disc space-y-1.5 text-xs">
            <li>
              <strong className="text-text-primary">GENERAL</strong> — balanced defaults: block injection/jailbreak, redact
              on data-exfiltration risk, warn on phishing/social engineering.
            </li>
            <li>
              <strong className="text-text-primary">GDPR</strong> — emphasize personal-data abuse: quarantine exfiltration
              sooner, block phishing/social engineering (credential / data-harvest angles), tighter injection/jailbreak
              thresholds, rate-limit suspicious traffic.
            </li>
            <li>
              <strong className="text-text-primary">HIPAA</strong> — stricter PHI-style handling: very low bar for
              exfiltration/quarantine, block phishing, quarantine social engineering (pretexting), block NSFW at lower
              confidence, tighter suspicious rate limits.
            </li>
            <li>
              <strong className="text-text-primary">PCI-DSS</strong> — malware-first, then exfiltration/quarantine,
              aggressive phishing blocks, injection/jailbreak blocks, social engineering as warn (investigation), rate-limit
              suspicious patterns.
            </li>
          </ul>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex items-center justify-between gap-3">
          <CardTitle>Active Rules</CardTitle>
          <Button type="button" onClick={openNewDrawer}>
            New Rule
          </Button>
        </CardHeader>
        <CardContent className="space-y-2">
          {policiesQuery.isLoading ? (
            <div className="rounded-md border border-border bg-bg-surface/30 p-4 text-sm text-text-secondary">
              Loading rules...
            </div>
          ) : rules.length === 0 ? (
            <div className="rounded-md border border-border bg-bg-surface/30 p-4 text-sm text-text-secondary">
              No rules yet. Apply a preset or create one.
            </div>
          ) : (
            rules.map((rule) => (
              <div
                key={rule.id}
                draggable
                onDragStart={(e: DragEvent<HTMLDivElement>) => {
                  e.dataTransfer.effectAllowed = "move";
                  e.dataTransfer.setData("text/plain", rule.id);
                  setDragId(rule.id);
                }}
                onDragOver={(e) => e.preventDefault()}
                onDrop={() => {
                  void onDropReorder(rule.id);
                }}
                className="flex items-center justify-between gap-3 rounded-md border border-border bg-bg-surface/20 p-3"
              >
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-2">
                    <Badge variant={rule.enabled ? "teal" : "default"}>{rule.enabled ? "Enabled" : "Disabled"}</Badge>
                    <Badge variant="violet">{rule.action}</Badge>
                    <Badge variant="amber">Priority {rule.priority}</Badge>
                    {rule.preset ? <Badge>{rule.preset}</Badge> : null}
                  </div>
                  <div className="truncate text-sm text-text-secondary">
                    IF {rule.condition.category ?? "any category"}{" "}
                    {rule.condition.confidence
                      ? `confidence ${rule.condition.confidence.op} ${rule.condition.confidence.value}`
                      : ""}
                    {(rule.condition.allowPhrases?.length ?? 0) > 0
                      ? ` • allow: ${(rule.condition.allowPhrases ?? []).join(", ")}`
                      : ""}
                    {(rule.condition.denyPhrases?.length ?? 0) > 0
                      ? ` • deny: ${(rule.condition.denyPhrases ?? []).join(", ")}`
                      : ""}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <label className="text-xs text-text-secondary">
                    <input type="checkbox" checked={rule.enabled} onChange={() => void toggleEnabled(rule)} /> enable
                  </label>
                  <Button type="button" size="sm" variant="outline" onClick={() => openEditDrawer(rule)}>
                    Edit
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="destructive"
                    onClick={() => {
                      void deleteRuleById(rule.id);
                    }}
                  >
                    Delete
                  </Button>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>DefaultSafePolicy</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="text-sm text-text-secondary">Balanced protection for typical usage.</div>
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                disabled={presetCardsPending}
                onClick={() => void applyPresetNamed("DefaultSafePolicy")}
              >
                Apply
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={presetCardsPending || !productPresetRows.DefaultSafePolicy}
                onClick={() => void removePresetNamed("DefaultSafePolicy")}
              >
                Remove
              </Button>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>StrictEnterprisePolicy</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="text-sm text-text-secondary">Hardened controls for regulated teams.</div>
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                disabled={presetCardsPending}
                onClick={() => void applyPresetNamed("StrictEnterprisePolicy")}
              >
                Apply
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={presetCardsPending || !productPresetRows.StrictEnterprisePolicy}
                onClick={() => void removePresetNamed("StrictEnterprisePolicy")}
              >
                Remove
              </Button>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>DeveloperPolicy</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="text-sm text-text-secondary">Developer-friendly warnings and redaction.</div>
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                disabled={presetCardsPending}
                onClick={() => void applyPresetNamed("DeveloperPolicy")}
              >
                Apply
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={presetCardsPending || !productPresetRows.DeveloperPolicy}
                onClick={() => void removePresetNamed("DeveloperPolicy")}
              >
                Remove
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      <AnimatePresence>
        {drawerOpen ? (
          <motion.div
            className="fixed inset-0 z-40 bg-black/60"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setDrawerOpen(false)}
          >
            <motion.div
              className="absolute right-0 top-0 h-full w-full max-w-md border-l border-border bg-bg-surface p-4"
              initial={{ x: 420 }}
              animate={{ x: 0 }}
              exit={{ x: 420 }}
              transition={{ duration: 0.2 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="mb-3 flex items-center justify-between">
                <h3 className="text-base font-semibold">{editingId ? "Edit Rule" : "New Rule"}</h3>
                <Button size="sm" variant="ghost" onClick={() => setDrawerOpen(false)}>
                  Close
                </Button>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="mb-1 block text-xs text-text-secondary">Category</label>
                  <select
                    className="h-10 w-full rounded-md border border-border bg-bg-card px-3 text-sm"
                    value={formCategory}
                    onChange={(e) => setFormCategory(e.target.value as ThreatCategory | typeof CATEGORY_ANY)}
                  >
                    {categoryOptions.map((c) => (
                      <option key={c.value} value={c.value}>
                        {c.label}
                      </option>
                    ))}
                  </select>
                </div>

                <label className="flex cursor-pointer items-center gap-2 text-sm text-text-secondary">
                  <input
                    type="checkbox"
                    checked={formRequireConfidence}
                    onChange={(e) => setFormRequireConfidence(e.target.checked)}
                  />
                  Require confidence threshold
                </label>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="mb-1 block text-xs text-text-secondary">Operator</label>
                    <select
                      className="h-10 w-full rounded-md border border-border bg-bg-card px-3 text-sm disabled:opacity-50"
                      disabled={!formRequireConfidence}
                      value={formOperator}
                      onChange={(e) => setFormOperator(e.target.value as ">" | ">=" | "<" | "<=")}
                    >
                      <option value=">">{">"}</option>
                      <option value=">=">{">="}</option>
                      <option value="<">{"<"}</option>
                      <option value="<=">{"<="}</option>
                    </select>
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-text-secondary">Threshold</label>
                    <Input
                      disabled={!formRequireConfidence}
                      value={formThreshold}
                      onChange={(e) => setFormThreshold(e.target.value)}
                    />
                  </div>
                </div>

                <div>
                  <label className="mb-1 block text-xs text-text-secondary">Action</label>
                  <select
                    className="h-10 w-full rounded-md border border-border bg-bg-card px-3 text-sm"
                    value={formAction}
                    onChange={(e) => setFormAction(e.target.value as PolicyAction)}
                  >
                    {actionOptions.map((a) => (
                      <option key={a} value={a}>
                        {a}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="mb-1 block text-xs text-text-secondary">
                    Priority (optional, higher runs first; leave blank for server default on create)
                  </label>
                  <Input value={formPriority} onChange={(e) => setFormPriority(e.target.value)} placeholder="e.g. 10000" />
                </div>

                <div>
                  <label className="mb-1 block text-xs text-text-secondary">Allow Phrases (comma-separated)</label>
                  <Input value={formAllowPhrases} onChange={(e) => setFormAllowPhrases(e.target.value)} />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-text-secondary">Deny Phrases (comma-separated)</label>
                  <Input value={formDenyPhrases} onChange={(e) => setFormDenyPhrases(e.target.value)} />
                </div>

                <Button
                  className="w-full"
                  disabled={createRule.isPending || updateRule.isPending}
                  onClick={() => void saveRule()}
                >
                  {editingId ? "Update Rule" : "Create Rule"}
                </Button>
              </div>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}

