import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { ArrowUpRight, FileScan, LayoutGrid, LoaderCircle, LogOut, Settings2, ShieldAlert, Sparkles, Upload } from "lucide-react";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
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
import { ChecksLibrary, type CustomCheck } from "./ChecksLibrary";
import { ScanDetail, type ScanRecommendation } from "./ScanDetail";
import { ScanHistory, type HistoryRow } from "./ScanHistory";
import { ScoreExplainer } from "./ScoreExplainer";
import { ThinkingLog, type ThinkingStep } from "./ThinkingLog";

interface ThinkingState { artifact: string; steps: ThinkingStep[]; reasoning: string }

type Workspace = Awaited<ReturnType<typeof getWorkspace>>;
type HistoryScan = Workspace["scans"][number];

const verdictClass = { clean: "text-safe", suspicious: "text-medium", malicious: "text-critical" } as const;

function Trend({ scans }: { scans: HistoryScan[] }) {
  const recent = [...scans].slice(0, 20).reverse();
  if (recent.length < 2) return <div className="flex h-44 items-center justify-center text-sm text-muted-foreground">Scan two or more skills to see risk over time.</div>;
  const points = recent.map((scan, index) => `${(index / (recent.length - 1)) * 100},${100 - scan.score}`).join(" ");
  return (
    <div className="h-44 w-full" aria-label="Risk score trend">
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-full w-full overflow-visible">
        <line x1="0" y1="20" x2="100" y2="20" className="stroke-border" vectorEffect="non-scaling-stroke" />
        <line x1="0" y1="50" x2="100" y2="50" className="stroke-border" vectorEffect="non-scaling-stroke" />
        <line x1="0" y1="80" x2="100" y2="80" className="stroke-border" vectorEffect="non-scaling-stroke" />
        <polyline points={points} fill="none" className="stroke-primary" strokeWidth="2" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
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
  const [tab, setTab] = useState<"overview" | "history" | "checks">("overview");
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
  const latest = queue[0];

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
          {(["overview", "checks"] as const).map((value) => (
            <button key={value} type="button" onClick={() => setTab(value)} className={`rounded-full px-4 py-1.5 capitalize transition-colors ${tab === value ? "bg-primary text-primary-foreground" : "text-muted-foreground"}`}>
              {value}
            </button>
          ))}
        </div>

        {tab === "checks" ? (
          <div className="mt-8">
            <ChecksLibrary organizationId={workspace.organization.id} canEdit={canEdit} checks={checks} onChanged={refreshChecks} />
          </div>
        ) : (
          <>
            <section className="mt-8 grid gap-px overflow-hidden rounded-xl border border-border bg-border sm:grid-cols-3">
              {[{ label: "Scans", value: summary.total }, { label: "Average risk", value: `${summary.average}/100` }, { label: "Blocked", value: summary.blocked }].map((metric) => <div key={metric.label} className="bg-card p-6"><p className="label-mono">{metric.label}</p><p className="mt-3 font-display text-4xl font-medium">{metric.value}</p></div>)}
            </section>

            <div className="mt-8 grid gap-8 lg:grid-cols-[1fr_360px]">
              <div className="space-y-8">
                <section className="rounded-xl border border-border bg-card p-6"><div className="flex items-center justify-between"><div><p className="label-mono">Risk trend</p><h2 className="mt-2 font-display text-xl font-medium">Policy-adjusted score</h2></div><FileScan className="text-muted-foreground" /></div><div className="mt-8"><Trend scans={workspace.scans} /></div></section>

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

                {selected && (
                  <ScanDetail
                    scanId={selected.id}
                    name={selected.name}
                    policy={policy}
                    canReview={canEdit}
                    containment={selected.containment}
                    onClose={() => setSelected(null)}
                    onReviewed={refresh}
                  />
                )}

                <section className="overflow-hidden rounded-xl border border-border bg-card">
                  <div className="border-b border-border px-6 py-5"><p className="label-mono">Scan history</p><h2 className="mt-2 font-display text-xl font-medium">All analyzed skills</h2><p className="mt-1 text-sm text-muted-foreground">Select a scan to review its findings and flag false positives.</p></div>
                  {workspace.scans.length === 0 ? (
                    <div className="flex min-h-52 flex-col items-center justify-center px-6 text-center"><ShieldAlert className="text-muted-foreground" /><p className="mt-3 text-sm text-muted-foreground">No scans yet. Upload real skills to begin.</p></div>
                  ) : (
                    <div className="divide-y divide-border">
                      {workspace.scans.map((scan) => (
                        <button
                          type="button"
                          key={scan.id}
                          onClick={() => setSelected({ id: scan.id, name: scan.declared_name ?? scan.artifact_name, containment: scan.containment })}
                          className={`grid w-full grid-cols-[1fr_auto] gap-4 px-6 py-4 text-left transition-colors hover:bg-secondary sm:grid-cols-[1fr_120px_120px] ${selected?.id === scan.id ? "bg-secondary" : ""}`}
                        >
                          <span className="min-w-0">
                            <span className="block truncate font-medium">{scan.declared_name ?? scan.artifact_name}</span>
                            <span className="mt-1 block text-xs text-muted-foreground">
                              {new Date(scan.scanned_at).toLocaleString()} · {scan.findings_count} findings
                              {scan.containment === "quarantined" && <span className="ml-2 rounded-full bg-critical/10 px-2 py-0.5 font-medium text-critical">Quarantined</span>}
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

              <div className="space-y-8">
                <aside className="h-fit rounded-xl border border-border bg-card p-6">
                  <div className="flex items-center gap-3"><Settings2 className="text-primary" /><div><p className="font-medium">Risk policy</p><p className="text-xs text-muted-foreground">Changes the score and verdict.</p></div></div>
                  <div className="mt-8"><div className="flex justify-between text-sm"><span>Review threshold</span><span className="font-mono text-medium">{policy.acceptableScore}</span></div><Slider className="mt-4" min={0} max={98} step={1} value={[policy.acceptableScore]} onValueChange={([value]) => setPolicy((current) => ({ ...current, acceptableScore: Math.min(value ?? current.acceptableScore, current.maliciousScore - 1) }))} /></div>
                  <div className="mt-8"><div className="flex justify-between text-sm"><span>Block threshold</span><span className="font-mono text-critical">{policy.maliciousScore}</span></div><Slider className="mt-4" min={1} max={100} step={1} value={[policy.maliciousScore]} onValueChange={([value]) => setPolicy((current) => ({ ...current, maliciousScore: Math.max(value ?? current.maliciousScore, current.acceptableScore + 1) }))} /></div>
                  <div className="mt-8 flex items-center justify-between gap-4"><div><p className="text-sm">Block critical findings</p><p className="mt-1 text-xs leading-relaxed text-muted-foreground">A critical match is malicious regardless of score.</p></div><Switch checked={policy.blockOnCritical} onCheckedChange={(checked) => setPolicy((current) => ({ ...current, blockOnCritical: checked }))} /></div>
                  <Button className="mt-8 w-full rounded-full" disabled={savingPolicy || workspace.role !== "admin"} onClick={() => void savePolicy()}>{savingPolicy && <LoaderCircle className="animate-spin" />}Save policy</Button>
                  {workspace.role !== "admin" && <p className="mt-3 text-center text-xs text-muted-foreground">Only workspace administrators can change policy.</p>}
                </aside>

                <ScoreExplainer
                  policy={policy}
                  {...(latest ? { breakdown: latest.breakdown, rawScore: latest.rawScore, score: latest.score, label: latest.metadata.name ?? latest.artifactName } : {})}
                />

                <section className="rounded-xl border border-border bg-card p-6">
                  <div className="flex items-center gap-3"><Sparkles className="text-primary" /><p className="font-medium">What this can and cannot do</p></div>
                  <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
                    Built-in checks are pattern-based, so they are repeatable and always quote the exact line they matched — but they can miss novel or obfuscated behaviour and can flag legitimate content. Each finding shows a confidence estimate, and reviewers can mark false positives so the record reflects a human decision.
                  </p>
                </section>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
