import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { ArrowUpRight, FileScan, LayoutGrid, LoaderCircle, LogOut, ShieldAlert, Upload } from "lucide-react";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { supabase } from "@/integrations/supabase/client";
import {
  DEFAULT_RISK_CONFIG,
  mergeAiFindings,
  scanArtifact,
  type CompiledCustomRule,
  type RiskConfig,
  type ScanResult,
} from "@/lib/scanner/engine";
import { ArtifactError, readArtifact } from "@/lib/scanner/load";
import { LAYER_LABEL, RULES, compileCustomCheck, type Layer, type Severity } from "@/lib/scanner/rules";
import { createWorkspace, getWorkspace, listCustomChecks, saveScan, updateRiskSettings } from "@/lib/workspace.functions";
import { streamAiScan } from "@/lib/ai-scan-stream";
import { ApprovalQueue } from "./ApprovalQueue";
import { PolicyBoard, type PolicyScan } from "./PolicyBoard";
import { ChecksLibrary, type CustomCheck } from "./ChecksLibrary";
import { ScanDetail, type ScanRecommendation } from "./ScanDetail";
import { ScanHistory, type HistoryRow } from "./ScanHistory";
import { ThinkingLog, type ThinkingStep } from "./ThinkingLog";

interface ThinkingState { artifact: string; steps: ThinkingStep[]; reasoning: string }

type Workspace = Awaited<ReturnType<typeof getWorkspace>>;
type HistoryScan = Workspace["scans"][number];

const verdictClass = { clean: "text-safe", suspicious: "text-medium", malicious: "text-critical" } as const;

function toSelection(scan: { id: string; artifact_name: string; declared_name: string | null; containment: string; ai_recommendation?: string; ai_recommendation_reason?: string; ai_recommendation_confidence?: number; recommendation_status?: string }) {
  return {
    id: scan.id,
    name: scan.declared_name ?? scan.artifact_name,
    containment: scan.containment,
    recommendation: {
      action: scan.ai_recommendation ?? "none",
      reason: scan.ai_recommendation_reason ?? "",
      confidence: scan.ai_recommendation_confidence ?? 0,
      status: scan.recommendation_status ?? "none",
    } satisfies ScanRecommendation,
  };
}

const VERDICT_COLORS: Record<string, string> = { clean: "#22c55e", suspicious: "#f59e0b", malicious: "#ef4444" };

function Trend({ scans }: { scans: HistoryScan[] }) {
  const recent = [...scans].slice(0, 20).reverse();
  const [hovered, setHovered] = useState<number | null>(null);
  if (recent.length < 2) return <div className="flex h-44 items-center justify-center text-sm text-muted-foreground">Scan two or more skills to see risk over time.</div>;
  const coords = recent.map((scan, index) => ({ x: (index / (recent.length - 1)) * 100, y: 100 - scan.score }));
  const points = coords.map((c) => `${c.x},${c.y}`).join(" ");
  const active = hovered !== null ? (recent[hovered] ?? null) : null;
  const activeCoords = hovered !== null ? (coords[hovered] ?? null) : null;
  const first = recent[0]!;
  const last = recent[recent.length - 1]!;
  return (
    <div aria-label="Risk score trend">
      <div className="relative h-52" onMouseLeave={() => setHovered(null)}>
        <div className="pointer-events-none absolute inset-y-0 left-0 flex w-10 flex-col justify-between py-1 text-[10px] tabular-nums text-muted-foreground">
          {[100, 75, 50, 25, 0].map((n) => <span key={n}>{n}</span>)}
        </div>
        <div className="absolute inset-y-0 left-12 right-0">
          <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-full w-full">
            {[0, 25, 50, 75, 100].map((n) => (
              <line key={n} x1="0" y1={100 - n} x2="100" y2={100 - n} className="stroke-border" vectorEffect="non-scaling-stroke" strokeDasharray={n === 0 || n === 100 ? "0" : "1.5 1.5"} />
            ))}
            <polyline points={points} fill="none" className="stroke-primary" strokeWidth="2" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          {coords.map((c, index) => {
            const scan = recent[index]!;
            return (
            <button
              key={scan.id}
              type="button"
              aria-label={`${scan.artifact_name}: score ${scan.score}, ${scan.verdict}`}
              className="absolute h-4 w-4 -translate-x-1/2 -translate-y-1/2 cursor-pointer rounded-full"
              style={{ left: `${c.x}%`, top: `${c.y}%` }}
              onMouseEnter={() => setHovered(index)}
              onFocus={() => setHovered(index)}
              onBlur={() => setHovered(null)}
            >
              <span
                className="absolute left-1/2 top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-background transition-transform"
                style={{ backgroundColor: VERDICT_COLORS[scan.verdict] ?? "#6366f1", transform: `translate(-50%,-50%) scale(${hovered === index ? 1.6 : 1})` }}
              />
            </button>
            );
          })}
          {active && activeCoords && (
            <div
              className="pointer-events-none absolute z-10 w-44 -translate-x-1/2 rounded-lg border border-border bg-popover p-3 text-xs shadow-lg"
              style={{ left: `${Math.min(Math.max(activeCoords.x, 12), 88)}%`, top: `${activeCoords.y}%`, transform: `translate(-50%, ${activeCoords.y < 30 ? "12px" : "calc(-100% - 12px)"})` }}
            >
              <p className="truncate font-medium">{active.artifact_name}</p>
              <p className="mt-1 text-muted-foreground">{new Date(active.scanned_at).toLocaleDateString()}</p>
              <div className="mt-2 flex items-center justify-between">
                <span className="font-display text-base font-semibold tabular-nums">{active.score}</span>
                <span className="rounded-full px-2 py-0.5 capitalize text-[10px] font-medium" style={{ backgroundColor: `${VERDICT_COLORS[active.verdict] ?? "#6366f1"}20`, color: VERDICT_COLORS[active.verdict] ?? "#6366f1" }}>{active.verdict}</span>
              </div>
            </div>
          )}
        </div>
      </div>
      <div className="mt-2 flex items-center justify-between pl-12 text-[10px] text-muted-foreground">
        <span>{new Date(first.scanned_at).toLocaleDateString()}</span>
        <div className="flex items-center gap-3">
          {(["clean", "suspicious", "malicious"] as const).map((v) => (
            <span key={v} className="flex items-center gap-1 capitalize"><span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: VERDICT_COLORS[v] }} />{v}</span>
          ))}
        </div>
        <span>{new Date(last.scanned_at).toLocaleDateString()}</span>
      </div>
    </div>
  );
}

export function WorkspaceDashboard() {
  const navigate = useNavigate();
  const loadWorkspace = useServerFn(getWorkspace);
  const createWorkspaceFn = useServerFn(createWorkspace);
  const updateSettingsFn = useServerFn(updateRiskSettings);
  const saveScanFn = useServerFn(saveScan);
  const listChecksFn = useServerFn(listCustomChecks);
  
  const inputRef = useRef<HTMLInputElement>(null);
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [checks, setChecks] = useState<CustomCheck[]>([]);
  const [loading, setLoading] = useState(true);
  const [workspaceName, setWorkspaceName] = useState("");
  const [policy, setPolicy] = useState<RiskConfig>(DEFAULT_RISK_CONFIG);
  const [queue, setQueue] = useState<ScanResult[]>([]);
  const [scanning, setScanning] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [tab, setTab] = useState<"overview" | "approvals" | "policy" | "history" | "checks">("overview");
  const [selected, setSelected] = useState<{ id: string; name: string; containment: string; recommendation: ScanRecommendation } | null>(null);
  const [thinking, setThinking] = useState<ThinkingState | null>(null);

  const refresh = async () => {
    const data = await loadWorkspace();
    setWorkspace(data);
    if (data.settings) setPolicy({ acceptableScore: data.settings.acceptable_score, maliciousScore: data.settings.malicious_score, blockOnCritical: data.settings.block_on_critical });
    if (data.organization) setChecks(await listChecksFn({ data: { organizationId: data.organization.id } }));
  };

  const refreshChecks = async () => {
    if (!workspace?.organization) return;
    setChecks(await listChecksFn({ data: { organizationId: workspace.organization.id } }));
  };

  useEffect(() => {
    void supabase.auth.getSession().then(async ({ data }) => {
      if (!data.session) {
        await navigate({ to: "/login", replace: true });
        return;
      }
      try { await refresh(); } finally { setLoading(false); }
    });
  }, []);

  const summary = useMemo(() => {
    const scans = workspace?.scans ?? [];
    return {
      total: scans.length,
      average: scans.length ? Math.round(scans.reduce((sum, scan) => sum + scan.score, 0) / scans.length) : 0,
      blocked: scans.filter((scan) => scan.verdict === "malicious").length,
    };
  }, [workspace]);

  const compiledChecks = useMemo<CompiledCustomRule[]>(
    () =>
      checks
        .filter((check) => check.enabled)
        .flatMap((check) => {
          const compiled = compileCustomCheck({
            code: check.code,
            title: check.title,
            severity: check.severity as Severity,
            layer: check.layer as Layer,
            pattern: check.pattern,
            rationale: check.rationale,
            remediation: check.remediation,
            confidence: check.confidence,
          });
          return compiled ? [{ ...compiled, confidence: check.confidence }] : [];
        }),
    [checks],
  );

  const establishWorkspace = async () => {
    if (workspaceName.trim().length < 2) return;
    setLoading(true);
    setMessage(null);
    try { await createWorkspaceFn({ data: { name: workspaceName } }); await refresh(); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Could not create the workspace."); }
    finally { setLoading(false); }
  };

  const savePolicy = async () => {
    if (!workspace?.organization) return;
    setSavingPolicy(true);
    setMessage(null);
    try {
      await updateSettingsFn({ data: { organizationId: workspace.organization.id, ...policy } });
      setMessage("Risk policy saved. New scans will use these thresholds.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not save the policy."); }
    finally { setSavingPolicy(false); }
  };

  const scanFiles = async (files: FileList | null) => {
    if (!files?.length || !workspace?.organization) return;
    setScanning(true);
    setMessage(null);
    setSelected(null);
    const completed: ScanResult[] = [];
    try {
      for (const file of Array.from(files)) {
        setThinking({ artifact: file.name, reasoning: "", steps: [{ label: "Reading the skill files", done: false }] });
        const artifact = await readArtifact([file]);
        const fileList = artifact.files.map((item) => item.path).join(", ");
        setThinking((current) => current && ({
          ...current,
          artifact: artifact.name,
          steps: [
            { label: `Read ${artifact.files.length} file${artifact.files.length === 1 ? "" : "s"}: ${fileList}`, done: true },
            { label: `Running ${RULES.length + compiledChecks.length} deterministic checks`, done: false },
          ],
        }));
        const deterministic = await scanArtifact(artifact.name, artifact.files, policy, compiledChecks);
        setThinking((current) => current && ({
          ...current,
          steps: [
            { ...(current.steps[0] as ThinkingStep) },
            { label: `Deterministic checks complete · ${deterministic.findings.length} finding${deterministic.findings.length === 1 ? "" : "s"}`, done: true },
            { label: "GPT reviewing intent, combinations and evasion", done: false },
          ],
        }));
        const content = artifact.files.filter((item) => item.text !== null).map((item) => `--- FILE: ${item.path} ---\n${item.text}`).join("\n\n").slice(0, 500_000);
        const ai = await streamAiScan(
          {
            artifactName: artifact.name,
            content,
            deterministicFindings: deterministic.findings.map(({ ruleId, title, severity, file: findingFile, line, evidence }) => ({ ruleId, title, severity, file: findingFile, line, evidence })),
          },
          (text) => setThinking((current) => current && { ...current, reasoning: current.reasoning + text }),
        );
        setThinking((current) => current && ({
          ...current,
          steps: current.steps.map((step, index) => (index === current.steps.length - 1 ? { label: `GPT review complete · ${ai.findings.length} additional finding${ai.findings.length === 1 ? "" : "s"}`, done: true } : step)),
        }));
        const result = mergeAiFindings(deterministic, ai.findings, ai.model);
        completed.push(result);
        await saveScanFn({ data: {
          organizationId: workspace.organization.id,
          artifactName: result.artifactName,
          ...(result.metadata.name ? { declaredName: result.metadata.name } : {}),
          sha256: result.sha256,
          score: result.score,
          verdict: result.verdict,
          filesCount: result.files.length,
          rulesEvaluated: result.rulesEvaluated,
          counts: result.counts,
          scannedAt: result.scannedAt,
          recommendation: ai.recommendation,
          findings: result.findings.map((finding) => ({ ...finding, category: LAYER_LABEL[finding.layer] })),
        } });
      }
      setQueue(completed);
      await refresh();
      setMessage(`${completed.length} skill${completed.length === 1 ? "" : "s"} analyzed and saved.`);
    } catch (error) {
      setMessage(error instanceof ArtifactError || error instanceof Error ? error.message : "Could not analyze this batch.");
    } finally {
      setScanning(false);
      if (inputRef.current) inputRef.current.value = "";
    }
  };

  const signOut = async () => { await supabase.auth.signOut(); await navigate({ to: "/", replace: true }); };

  if (loading) return <main className="flex min-h-screen items-center justify-center bg-background"><LoaderCircle className="size-5 animate-spin text-primary" /></main>;

  if (!workspace?.organization) return (
    <main className="min-h-screen bg-background px-6">
      <header className="mx-auto flex h-16 max-w-6xl items-center justify-between"><Logo /><Button variant="ghost" size="sm" onClick={() => void signOut()}><LogOut /> Sign out</Button></header>
      <section className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-md flex-col justify-center pb-24">
        <span className="flex size-12 items-center justify-center rounded-xl bg-secondary text-primary"><LayoutGrid /></span>
        <h1 className="mt-6 font-display text-4xl font-semibold">Name your workspace.</h1>
        <p className="mt-3 text-muted-foreground">This keeps your policy, checks, and scan history together.</p>
        <Input className="mt-8 h-11 bg-card" placeholder="Workspace name" value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} onKeyDown={(event) => event.key === "Enter" && void establishWorkspace()} />
        {message && <p className="mt-3 text-sm text-critical">{message}</p>}
        <Button className="mt-4 h-11 rounded-full" onClick={() => void establishWorkspace()}>Create workspace <ArrowUpRight /></Button>
      </section>
    </main>
  );

  const canEdit = workspace.role === "admin" || workspace.role === "analyst";

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur-xl">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-5"><Logo /><div className="flex items-center gap-3"><span className="hidden text-sm text-muted-foreground sm:inline">{workspace.organization.name}</span><Button variant="ghost" size="icon" title="Sign out" onClick={() => void signOut()}><LogOut /></Button></div></div>
      </header>
      <main className="mx-auto max-w-7xl px-5 py-10 sm:py-14">
        <div className="flex flex-col justify-between gap-6 sm:flex-row sm:items-end">
          <div>
            <p className="text-sm font-medium text-primary">Security workspace</p>
            <h1 className="mt-2 font-display text-4xl font-semibold sm:text-5xl">Risk, without the noise.</h1>
            <p className="mt-3 text-muted-foreground">{RULES.length} built-in checks, {checks.filter((check) => check.enabled).length} of your own, plus GPT intent review.</p>
          </div>
          <input ref={inputRef} type="file" multiple accept=".md,.txt,.json,.yaml,.yml,.zip,.py,.js,.ts,.sh" className="hidden" onChange={(event) => void scanFiles(event.target.files)} />
          <Button className="h-11 rounded-full px-6" disabled={scanning} onClick={() => inputRef.current?.click()}>{scanning ? <LoaderCircle className="animate-spin" /> : <Upload />} {scanning ? "Analyzing…" : "Scan multiple skills"}</Button>
        </div>
        {message && <div className="mt-6 rounded-lg border border-border bg-card px-4 py-3 text-sm text-muted-foreground">{message}</div>}

        <div className="mt-8 inline-flex rounded-full border border-border bg-card p-1 text-sm">
          {([["overview", "Scan"], ["history", "History"], ["approvals", "Review queue"], ["checks", "Checks"], ["policy", "Policy"]] as const).map(([value, label]) => (
            <button key={value} type="button" onClick={() => setTab(value)} className={`rounded-full px-4 py-1.5 transition-colors ${tab === value ? "bg-primary text-primary-foreground" : "text-muted-foreground"}`}>
              {label}
            </button>
          ))}
        </div>

        {tab === "approvals" ? (
          <div className="mt-8">
            <ApprovalQueue organizationId={workspace.organization.id} canReview={canEdit} onChanged={refresh} />
          </div>
        ) : tab === "policy" ? (
          <div className="mt-8">
            <PolicyBoard
              policy={policy}
              onChange={setPolicy}
              scans={workspace.scans as unknown as PolicyScan[]}
              canSave={workspace.role === "admin"}
              saving={savingPolicy}
              onSave={() => void savePolicy()}
            />
          </div>
        ) : tab === "history" ? (
          <div className="mt-8 space-y-8">
            <ScanHistory
              scans={workspace.scans as unknown as HistoryRow[]}
              canEdit={canEdit}
              blockOnCritical={policy.blockOnCritical}
              selectedId={selected?.id}
              onOpen={(scan) => setSelected(toSelection(scan))}
              onChanged={async () => { setSelected(null); await refresh(); }}
            />
            {selected && (
              <ScanDetail
                scanId={selected.id}
                name={selected.name}
                policy={policy}
                canReview={canEdit}
                containment={selected.containment}
                recommendation={selected.recommendation}
                onClose={() => setSelected(null)}
                onReviewed={refresh}
              />
            )}
          </div>
        ) : tab === "checks" ? (
          <div className="mt-8">
            <ChecksLibrary organizationId={workspace.organization.id} canEdit={canEdit} checks={checks} onChanged={refreshChecks} />
          </div>
        ) : (
          <div className="mx-auto mt-8 max-w-3xl space-y-8">
            <section className="grid gap-px overflow-hidden rounded-xl border border-border bg-border sm:grid-cols-3">
              {[{ label: "Scans", value: summary.total }, { label: "Average risk", value: `${summary.average}/100` }, { label: "Blocked", value: summary.blocked }].map((metric) => <div key={metric.label} className="bg-card p-6"><p className="label-mono">{metric.label}</p><p className="mt-3 font-display text-4xl font-medium">{metric.value}</p></div>)}
            </section>

            {thinking && (
              <ThinkingLog artifact={thinking.artifact} steps={thinking.steps} reasoning={thinking.reasoning} active={scanning} />
            )}

            {queue.length > 0 && (
              <section>
                <p className="label-mono mb-3">Latest batch</p>
                <div className="grid gap-3 sm:grid-cols-2">
                  {queue.map((scan) => (
                    <div key={scan.sha256} className="rounded-lg border border-border bg-card p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="truncate font-medium">{scan.metadata.name ?? scan.artifactName}</p>
                          <p className="mt-1 text-xs text-muted-foreground">{scan.findings.length} findings · {scan.durationMs} ms{scan.ai ? ` · ${scan.ai.findings} from AI` : ""}</p>
                        </div>
                        <span className={`font-mono text-lg ${verdictClass[scan.verdict]}`}>{scan.score}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            )}

            <section className="rounded-xl border border-border bg-card p-6">
              <div className="flex items-center justify-between"><div><p className="label-mono">Risk trend</p><h2 className="mt-2 font-display text-xl font-medium">Scores over time</h2></div><FileScan className="text-muted-foreground" /></div>
              <div className="mt-8"><Trend scans={workspace.scans} /></div>
            </section>

            <section className="overflow-hidden rounded-xl border border-border bg-card">
              <div className="flex items-center justify-between border-b border-border px-6 py-5">
                <div><p className="label-mono">Recent scans</p><h2 className="mt-2 font-display text-xl font-medium">Latest analyzed skills</h2></div>
                {workspace.scans.length > 0 && <Button variant="ghost" size="sm" onClick={() => setTab("history")}>View all <ArrowUpRight /></Button>}
              </div>
              {workspace.scans.length === 0 ? (
                <div className="flex min-h-52 flex-col items-center justify-center px-6 text-center">
                  <ShieldAlert className="text-muted-foreground" />
                  <p className="mt-3 text-sm text-muted-foreground">No scans yet. Upload skills with the button above to begin.</p>
                </div>
              ) : (
                <div className="divide-y divide-border">
                  {workspace.scans.slice(0, 5).map((scan) => (
                    <button
                      type="button"
                      key={scan.id}
                      onClick={() => { setSelected(toSelection(scan)); setTab("history"); }}
                      className="grid w-full grid-cols-[1fr_auto] gap-4 px-6 py-4 text-left transition-colors hover:bg-secondary sm:grid-cols-[1fr_120px_120px]"
                    >
                      <span className="min-w-0">
                        <span className="block truncate font-medium">{scan.declared_name ?? scan.artifact_name}</span>
                        <span className="mt-1 block text-xs text-muted-foreground">
                          {new Date(scan.scanned_at).toLocaleString()} · {scan.findings_count} findings
                          {policy.blockOnCritical && ((scan.severity_counts as Record<string, number> | null)?.["critical"] ?? 0) > 0 ? (
                            <span className="ml-2 rounded-full bg-critical/10 px-2 py-0.5 font-medium text-critical">Auto-blocked · critical</span>
                          ) : scan.containment === "quarantined" ? (
                            <span className="ml-2 rounded-full bg-critical/10 px-2 py-0.5 font-medium text-critical">Quarantined</span>
                          ) : null}
                          {scan.containment === "cleared" && <span className="ml-2 rounded-full bg-safe/10 px-2 py-0.5 font-medium text-safe">Cleared</span>}
                        </span>
                      </span>
                      <span className={`self-center text-right text-sm font-medium capitalize ${verdictClass[scan.verdict as keyof typeof verdictClass] ?? "text-foreground"}`}>{scan.verdict}</span>
                      <span className="hidden self-center text-right font-mono text-lg sm:block">{scan.score}</span>
                    </button>
                  ))}
                </div>
              )}
            </section>
          </div>
        )}
      </main>
    </div>
  );
}
