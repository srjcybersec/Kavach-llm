import { useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Badge } from "../components/ui/badge";
import { ensureDemoAuth } from "../services/authApi";
import { useApiKeysQuery, useCreateApiKeyMutation, useRevokeApiKeyMutation, type ApiKeyRow } from "../services/keysApi";

type TeamRole = "Admin" | "Analyst" | "Viewer";

function reputationBadge(score: number): { label: string; variant: "teal" | "default" | "amber" | "red" } {
  if (score <= 15) return { label: "TRUSTED", variant: "teal" };
  if (score <= 35) return { label: "NEUTRAL", variant: "default" };
  if (score <= 70) return { label: "WATCHLISTED", variant: "amber" };
  return { label: "SUSPENDED", variant: "red" };
}

export default function Settings(): React.ReactElement {
  const [newKeyLabel, setNewKeyLabel] = useState("Primary key");
  const [lastPlainKey, setLastPlainKey] = useState<string | null>(null);
  const [keysError, setKeysError] = useState<string | null>(null);
  const [localSaveHint, setLocalSaveHint] = useState<string | null>(null);

  const [provider, setProvider] = useState("gemini");
  const [model, setModel] = useState("gemini-2.0-flash");
  const [secondaryModel, setSecondaryModel] = useState("none");

  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookThreshold, setWebhookThreshold] = useState("80");

  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<TeamRole>("Viewer");
  const [team, setTeam] = useState<Array<{ email: string; role: TeamRole }>>([]);

  const keysQuery = useApiKeysQuery();
  const createKey = useCreateApiKeyMutation();
  const revokeKey = useRevokeApiKeyMutation();

  useEffect(() => {
    void ensureDemoAuth();

    const storedProvider = localStorage.getItem("kavach_model_provider");
    const storedModel = localStorage.getItem("kavach_model_name");
    const storedSecondary = localStorage.getItem("kavach_secondary_model");
    const storedWebhook = localStorage.getItem("kavach_webhook_url");
    const storedThreshold = localStorage.getItem("kavach_webhook_threshold");
    const storedTeam = localStorage.getItem("kavach_team");

    if (storedProvider) setProvider(storedProvider);
    if (storedModel) setModel(storedModel);
    if (storedSecondary) setSecondaryModel(storedSecondary);
    if (storedWebhook) setWebhookUrl(storedWebhook);
    if (storedThreshold) setWebhookThreshold(storedThreshold);
    if (storedTeam) {
      try {
        const parsed = JSON.parse(storedTeam) as Array<{ email: string; role: TeamRole }>;
        if (Array.isArray(parsed)) setTeam(parsed);
      } catch {
        // ignore malformed local storage
      }
    }
  }, []);

  const keys = useMemo(() => keysQuery.data ?? [], [keysQuery.data]);

  const flashLocalSave = (message: string) => {
    setLocalSaveHint(message);
    window.setTimeout(() => setLocalSaveHint(null), 2500);
  };

  const createApiKey = async () => {
    if (!newKeyLabel.trim()) return;
    setKeysError(null);
    try {
      const created = await createKey.mutateAsync(newKeyLabel.trim());
      setLastPlainKey(created.plainKey);
      setNewKeyLabel("");
    } catch (e) {
      setKeysError(e instanceof Error ? e.message : String(e));
    }
  };

  const revokeApiKey = async (id: string) => {
    setKeysError(null);
    try {
      await revokeKey.mutateAsync(id);
    } catch (e) {
      setKeysError(e instanceof Error ? e.message : String(e));
    }
  };

  const saveModelConfig = () => {
    localStorage.setItem("kavach_model_provider", provider);
    localStorage.setItem("kavach_model_name", model);
    localStorage.setItem("kavach_secondary_model", secondaryModel);
    flashLocalSave("Model preferences saved in this browser only.");
  };

  const saveWebhookConfig = () => {
    localStorage.setItem("kavach_webhook_url", webhookUrl);
    localStorage.setItem("kavach_webhook_threshold", webhookThreshold);
    flashLocalSave("Webhook preferences saved in this browser only (backend does not call this URL yet).");
  };

  const inviteMember = () => {
    if (!inviteEmail.trim()) return;
    const next = [...team, { email: inviteEmail.trim(), role: inviteRole }];
    setTeam(next);
    localStorage.setItem("kavach_team", JSON.stringify(next));
    setInviteEmail("");
    flashLocalSave("Team list saved in this browser only (no invite email is sent).");
  };

  const removeMember = (email: string) => {
    const next = team.filter((m) => m.email !== email);
    setTeam(next);
    localStorage.setItem("kavach_team", JSON.stringify(next));
    flashLocalSave("Team list updated locally.");
  };

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Settings</h2>

      {keysQuery.isError ? (
        <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
          {keysQuery.error.message}
        </div>
      ) : null}
      {keysError ? (
        <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{keysError}</div>
      ) : null}
      {localSaveHint ? (
        <div className="rounded-md border border-teal-500/30 bg-teal-500/10 px-3 py-2 text-sm text-teal-100">{localSaveHint}</div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>API Key Management</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-text-secondary">
              Keys are stored on the server (hashed). The Playground authenticates with your session token; the proxy still
              associates requests with your latest ACTIVE key (or an
              auto-created default) for audit logs and reputation scoring.
            </p>
            <div className="flex items-center gap-2">
              <Input
                value={newKeyLabel}
                onChange={(e) => setNewKeyLabel(e.target.value)}
                placeholder="Key label"
              />
              <Button onClick={() => void createApiKey()} disabled={createKey.isPending}>
                Create
              </Button>
            </div>

            {lastPlainKey ? (
              <div className="rounded-md border border-border bg-bg-surface p-3 text-xs">
                <div className="text-text-secondary">Copy this key now (shown once):</div>
                <div className="mt-1 font-mono">{lastPlainKey}</div>
              </div>
            ) : null}

            <div className="space-y-2">
              {keysQuery.isLoading ? (
                <div className="text-sm text-text-secondary">Loading keys...</div>
              ) : keys.length === 0 ? (
                <div className="text-sm text-text-secondary">No keys yet.</div>
              ) : (
                keys.map((k: ApiKeyRow) => {
                  const rep = reputationBadge(k.reputationScore);
                  return (
                    <div key={k.id} className="flex items-center justify-between rounded-md border border-border bg-bg-surface/30 p-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">{k.label}</span>
                          <Badge variant={rep.variant}>{rep.label}</Badge>
                          <Badge variant={k.status === "ACTIVE" ? "teal" : "red"}>{k.status}</Badge>
                        </div>
                        <div className="text-xs text-text-secondary">
                          Score {k.reputationScore} • Created {new Date(k.createdAt).toLocaleDateString()}
                        </div>
                      </div>
                      {k.status === "ACTIVE" ? (
                        <Button
                          variant="destructive"
                          size="sm"
                          disabled={revokeKey.isPending}
                          onClick={() => void revokeApiKey(k.id)}
                        >
                          Revoke
                        </Button>
                      ) : (
                        <span className="text-xs text-text-secondary">{k.status === "REVOKED" ? "Revoked" : "Suspended"}</span>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Model Config</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p className="text-xs text-text-secondary">
              The running backend uses <code className="text-text-primary">GEMINI_API_KEY</code> and{" "}
              <code className="text-text-primary">GEMINI_MODEL</code> from <code className="text-text-primary">.env</code>.
              Values here are for your notes / future wiring only.
            </p>
            <div>
              <label className="mb-1 block text-xs text-text-secondary">Provider</label>
              <select className="h-10 w-full rounded-md border border-border bg-bg-surface px-3" value={provider} onChange={(e) => setProvider(e.target.value)}>
                <option value="gemini">Google Gemini</option>
                <option value="openai">OpenAI</option>
                <option value="ollama">Ollama</option>
                <option value="azure-openai">Azure OpenAI</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs text-text-secondary">Primary model</label>
              <Input value={model} onChange={(e) => setModel(e.target.value)} />
            </div>
            <div>
              <label className="mb-1 block text-xs text-text-secondary">Secondary safety model</label>
              <Input
                value={secondaryModel}
                onChange={(e) => setSecondaryModel(e.target.value)}
                placeholder="none or model id"
              />
            </div>
            <Button onClick={saveModelConfig}>Save Model Config</Button>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Webhook Config</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p className="text-xs text-text-secondary">
              Stored in your browser only. The API does not post to this URL yet—useful for planned alerting or external
              integrations.
            </p>
            <div>
              <label className="mb-1 block text-xs text-text-secondary">Threat alert webhook URL</label>
              <Input value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} placeholder="https://example.com/webhook" />
            </div>
            <div>
              <label className="mb-1 block text-xs text-text-secondary">Alert threshold (risk score)</label>
              <Input value={webhookThreshold} onChange={(e) => setWebhookThreshold(e.target.value)} />
            </div>
            <Button onClick={saveWebhookConfig}>Save Webhook</Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Team Members</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p className="text-xs text-text-secondary">
              Demo-only: invitations are not sent and users are not created—entries are saved in local storage for UI
              mockups.
            </p>
            <div className="flex items-center gap-2">
              <Input placeholder="Invite by email" value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} />
              <select className="h-10 rounded-md border border-border bg-bg-surface px-3" value={inviteRole} onChange={(e) => setInviteRole(e.target.value as TeamRole)}>
                <option value="Admin">Admin</option>
                <option value="Analyst">Analyst</option>
                <option value="Viewer">Viewer</option>
              </select>
              <Button onClick={inviteMember}>Invite</Button>
            </div>

            <div className="space-y-2">
              {team.length === 0 ? (
                <div className="text-text-secondary">No invited members yet.</div>
              ) : (
                team.map((m) => (
                  <div key={`${m.email}-${m.role}`} className="flex items-center justify-between rounded-md border border-border bg-bg-surface/30 p-2">
                    <div>
                      <div>{m.email}</div>
                      <div className="text-xs text-text-secondary">{m.role}</div>
                    </div>
                    <Button size="sm" variant="destructive" onClick={() => removeMember(m.email)}>
                      Remove
                    </Button>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

