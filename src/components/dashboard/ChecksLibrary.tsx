import { useEffect, useMemo, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { LoaderCircle, Plus, Search, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { ConfidenceHint } from "@/components/dashboard/ConfidenceHint";
import {
  LAYERS,
  LAYER_LABEL,
  RULES,
  SEVERITY_ORDER,
  confidenceLabel,
  ruleConfidence,
  type Layer,
  type Severity,
} from "@/lib/scanner/rules";
import {
  createCustomCheck,
  deleteCustomCheck,
  listCustomChecks,
  setCustomCheckEnabled,
} from "@/lib/workspace.functions";

export type CustomCheck = Awaited<ReturnType<typeof listCustomChecks>>[number];

const severityClass: Record<Severity, string> = {
  critical: "text-critical",
  high: "text-critical",
  medium: "text-medium",
  low: "text-muted-foreground",
};

interface Props {
  organizationId: string;
  canEdit: boolean;
  checks: CustomCheck[];
  onChanged: () => Promise<void> | void;
}

export function ChecksLibrary({ organizationId, canEdit, checks, onChanged }: Props) {
  const create = useServerFn(createCustomCheck);
  const toggle = useServerFn(setCustomCheckEnabled);
  const remove = useServerFn(deleteCustomCheck);

  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState({
    code: "",
    title: "",
    severity: "high" as Severity,
    layer: "prompt" as Layer,
    pattern: "",
    rationale: "",
    remediation: "",
    confidence: 60,
  });

  const [patternError, setPatternError] = useState<string | null>(null);
  useEffect(() => {
    if (!draft.pattern) return setPatternError(null);
    try { new RegExp(draft.pattern, "i"); setPatternError(null); }
    catch { setPatternError("This pattern is not valid."); }
  }, [draft.pattern]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return RULES;
    return RULES.filter((rule) =>
      [rule.id, rule.title, rule.rationale, LAYER_LABEL[rule.layer]].join(" ").toLowerCase().includes(needle),
    );
  }, [query]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await create({ data: { organizationId, ...draft } });
      setDraft({ code: "", title: "", severity: "high", layer: "prompt", pattern: "", rationale: "", remediation: "", confidence: 60 });
      setOpen(false);
      await onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not save this check.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-8">
      <section className="rounded-xl border border-border bg-card">
        <div className="flex flex-col gap-4 border-b border-border px-6 py-5 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="label-mono">Your checks</p>
            <h2 className="mt-2 font-display text-xl font-medium">{checks.length} custom {checks.length === 1 ? "check" : "checks"}</h2>
            <p className="mt-1 text-sm text-muted-foreground">Written by your team, run alongside the built-in checks on every scan.</p>
          </div>
          {canEdit && (
            <Button className="rounded-full" onClick={() => setOpen((value) => !value)}>
              <Plus /> New check
            </Button>
          )}
        </div>

        {open && canEdit && (
          <div className="grid gap-4 border-b border-border px-6 py-6 sm:grid-cols-2">
            <label className="text-sm">
              <span className="mb-2 block text-muted-foreground">Code</span>
              <Input className="h-10 bg-background" placeholder="OPS-001" value={draft.code} onChange={(event) => setDraft({ ...draft, code: event.target.value })} />
            </label>
            <label className="text-sm">
              <span className="mb-2 block text-muted-foreground">Title</span>
              <Input className="h-10 bg-background" placeholder="Internal hostname referenced" value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} />
            </label>
            <label className="text-sm">
              <span className="mb-2 block text-muted-foreground">Severity</span>
              <select className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={draft.severity} onChange={(event) => setDraft({ ...draft, severity: event.target.value as Severity })}>
                {SEVERITY_ORDER.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
              </select>
            </label>
            <label className="text-sm">
              <span className="mb-2 block text-muted-foreground">Category</span>
              <select className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={draft.layer} onChange={(event) => setDraft({ ...draft, layer: event.target.value as Layer })}>
                {LAYERS.map((layer) => <option key={layer} value={layer}>{LAYER_LABEL[layer]}</option>)}
              </select>
            </label>
            <label className="text-sm sm:col-span-2">
              <span className="mb-2 block text-muted-foreground">Pattern to match (case-insensitive)</span>
              <Input className="h-10 bg-background font-mono text-xs" placeholder="internal\\.corp\\.example\\.com" value={draft.pattern} onChange={(event) => setDraft({ ...draft, pattern: event.target.value })} />
              {patternError && <span className="mt-2 block text-xs text-critical">{patternError}</span>}
            </label>
            <label className="text-sm">
              <span className="mb-2 block text-muted-foreground">Why it matters</span>
              <Textarea className="min-h-20 bg-background" value={draft.rationale} onChange={(event) => setDraft({ ...draft, rationale: event.target.value })} />
            </label>
            <label className="text-sm">
              <span className="mb-2 block text-muted-foreground">How to fix it</span>
              <Textarea className="min-h-20 bg-background" value={draft.remediation} onChange={(event) => setDraft({ ...draft, remediation: event.target.value })} />
            </label>
            <div className="sm:col-span-2 flex flex-wrap items-center gap-4">
              <Button className="rounded-full" disabled={busy || !!patternError || draft.pattern.length < 2 || draft.title.length < 3} onClick={() => void submit()}>
                {busy && <LoaderCircle className="animate-spin" />} Save check
              </Button>
              {error && <span className="text-sm text-critical">{error}</span>}
            </div>
          </div>
        )}

        {checks.length === 0 ? (
          <p className="px-6 py-8 text-sm text-muted-foreground">No custom checks yet.</p>
        ) : (
          <div className="divide-y divide-border">
            {checks.map((check) => (
              <div key={check.id} className="flex items-start justify-between gap-4 px-6 py-4">
                <div className="min-w-0">
                  <p className="font-medium">
                    <span className="font-mono text-xs text-muted-foreground">{check.code}</span> · {check.title}
                  </p>
                  <p className="mt-1 truncate font-mono text-xs text-muted-foreground">/{check.pattern}/i</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    <span className={severityClass[check.severity as Severity]}>{check.severity}</span> · {LAYER_LABEL[check.layer as Layer] ?? check.layer} · confidence {check.confidence}%
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-3">
                  <Switch checked={check.enabled} disabled={!canEdit} onCheckedChange={async (value) => { await toggle({ data: { id: check.id, enabled: value } }); await onChanged(); }} />
                  {canEdit && (
                    <Button variant="ghost" size="icon" title="Delete check" onClick={async () => { await remove({ data: { id: check.id } }); await onChanged(); }}>
                      <Trash2 className="text-muted-foreground" />
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="rounded-xl border border-border bg-card">
        <div className="flex flex-col gap-4 border-b border-border px-6 py-5 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="label-mono">Built-in checks</p>
            <h2 className="mt-2 font-display text-xl font-medium">{RULES.length} deterministic checks</h2>
            <p className="mt-1 text-sm text-muted-foreground">Every check, what it looks for, and how precise it is.</p>
          </div>
          <div className="relative w-full sm:w-64">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input className="h-10 bg-background pl-9" placeholder="Search checks" value={query} onChange={(event) => setQuery(event.target.value)} />
          </div>
        </div>
        <div className="divide-y divide-border">
          {filtered.map((rule) => {
            const confidence = ruleConfidence(rule.id, rule.severity);
            return (
              <details key={rule.id} className="group px-6 py-4">
                <summary className="flex cursor-pointer items-center justify-between gap-4 list-none">
                  <span className="min-w-0">
                    <span className="font-mono text-xs text-muted-foreground">{rule.id}</span>
                    <span className="ml-2 font-medium">{rule.title}</span>
                  </span>
                  <span className={`shrink-0 text-xs font-medium ${severityClass[rule.severity]}`}>{rule.severity}</span>
                </summary>
                <div className="mt-3 space-y-2 text-sm text-muted-foreground">
                  <p><span className="text-foreground">Category:</span> {LAYER_LABEL[rule.layer]}</p>
                  <p><span className="text-foreground">Confidence:</span> {confidence}% — {confidenceLabel(confidence)} <ConfidenceHint /></p>
                  <p><span className="text-foreground">Why it matters:</span> {rule.rationale}</p>
                  <p><span className="text-foreground">How to fix it:</span> {rule.remediation}</p>
                  <p className="break-all font-mono text-xs">{rule.pattern.source.length > 400 ? "structural check — evaluated on file metadata" : `/${rule.pattern.source}/i`}</p>
                </div>
              </details>
            );
          })}
        </div>
      </section>
    </div>
  );
}
