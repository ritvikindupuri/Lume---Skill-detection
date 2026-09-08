import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { ArrowUpRight, Building2, FileScan, LoaderCircle, LogOut, Settings2, ShieldAlert, Upload } from "lucide-react";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { supabase } from "@/integrations/supabase/client";
import { DEFAULT_RISK_CONFIG, scanArtifact, type RiskConfig, type ScanResult } from "@/lib/scanner/engine";
import { ArtifactError, readArtifact } from "@/lib/scanner/load";
import { LAYER_LABEL, RULES } from "@/lib/scanner/rules";
import { createWorkspace, getWorkspace, saveScan, updateRiskSettings } from "@/lib/workspace.functions";
import { analyzeSkillWithAi } from "@/lib/ai-scan.functions";
import { mergeAiFindings } from "@/lib/scanner/engine";

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

export function CompanyDashboard() {
  const navigate = useNavigate();
  const loadWorkspace = useServerFn(getWorkspace);
  const createWorkspaceFn = useServerFn(createWorkspace);
  const updateSettingsFn = useServerFn(updateRiskSettings);
  const saveScanFn = useServerFn(saveScan);
  const analyzeWithAi = useServerFn(analyzeSkillWithAi);
  const inputRef = useRef<HTMLInputElement>(null);
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [loading, setLoading] = useState(true);
  const [companyName, setCompanyName] = useState("");
  const [policy, setPolicy] = useState<RiskConfig>(DEFAULT_RISK_CONFIG);
  const [queue, setQueue] = useState<ScanResult[]>([]);
  const [scanning, setScanning] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const refresh = async () => {
    const data = await loadWorkspace();
    setWorkspace(data);
    if (data.settings) setPolicy({ acceptableScore: data.settings.acceptable_score, maliciousScore: data.settings.malicious_score, blockOnCritical: data.settings.block_on_critical });
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

  const establishWorkspace = async () => {
    if (companyName.trim().length < 2) return;
    setLoading(true);
    setMessage(null);
    try { await createWorkspaceFn({ data: { name: companyName } }); await refresh(); }
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
    const completed: ScanResult[] = [];
    try {
      for (const file of Array.from(files)) {
        const artifact = await readArtifact([file]);
        const deterministic = await scanArtifact(artifact.name, artifact.files, policy);
        const content = artifact.files.filter((item) => item.text !== null).map((item) => `--- FILE: ${item.path} ---\n${item.text}`).join("\n\n").slice(0, 500_000);
        const ai = await analyzeWithAi({ data: {
          artifactName: artifact.name,
          content,
          deterministicFindings: deterministic.findings.map(({ ruleId, title, severity, file: findingFile, line, evidence }) => ({ ruleId, title, severity, file: findingFile, line, evidence })),
        } });
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
        <span className="flex size-12 items-center justify-center rounded-xl bg-secondary text-primary"><Building2 /></span>
        <h1 className="mt-6 font-display text-4xl font-semibold">Name your workspace.</h1>
        <p className="mt-3 text-muted-foreground">This keeps your company’s policies and scan history together.</p>
        <Input className="mt-8 h-11 bg-card" placeholder="Company name" value={companyName} onChange={(event) => setCompanyName(event.target.value)} onKeyDown={(event) => event.key === "Enter" && void establishWorkspace()} />
        {message && <p className="mt-3 text-sm text-critical">{message}</p>}
        <Button className="mt-4 h-11 rounded-full" onClick={() => void establishWorkspace()}>Create workspace <ArrowUpRight /></Button>
      </section>
    </main>
  );

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur-xl">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-5"><Logo /><div className="flex items-center gap-3"><span className="hidden text-sm text-muted-foreground sm:inline">{workspace.organization.name}</span><Button variant="ghost" size="icon" title="Sign out" onClick={() => void signOut()}><LogOut /></Button></div></div>
      </header>
      <main className="mx-auto max-w-7xl px-5 py-10 sm:py-14">
        <div className="flex flex-col justify-between gap-6 sm:flex-row sm:items-end">
          <div><p className="text-sm font-medium text-primary">Security workspace</p><h1 className="mt-2 font-display text-4xl font-semibold sm:text-5xl">Risk, without the noise.</h1><p className="mt-3 text-muted-foreground">{RULES.length} deterministic checks plus the strongest GPT intent review. No sample findings.</p></div>
          <input ref={inputRef} type="file" multiple accept=".md,.txt,.json,.yaml,.yml,.zip,.py,.js,.ts,.sh" className="hidden" onChange={(event) => void scanFiles(event.target.files)} />
          <Button className="h-11 rounded-full px-6" disabled={scanning} onClick={() => inputRef.current?.click()}>{scanning ? <LoaderCircle className="animate-spin" /> : <Upload />} {scanning ? "Analyzing…" : "Scan multiple skills"}</Button>
        </div>
        {message && <div className="mt-6 rounded-lg border border-border bg-card px-4 py-3 text-sm text-muted-foreground">{message}</div>}

        <section className="mt-10 grid gap-px overflow-hidden rounded-xl border border-border bg-border sm:grid-cols-3">
          {[{ label: "Scans", value: summary.total }, { label: "Average risk", value: `${summary.average}/100` }, { label: "Blocked", value: summary.blocked }].map((metric) => <div key={metric.label} className="bg-card p-6"><p className="label-mono">{metric.label}</p><p className="mt-3 font-display text-4xl font-medium">{metric.value}</p></div>)}
        </section>

        <div className="mt-8 grid gap-8 lg:grid-cols-[1fr_360px]">
          <div className="space-y-8">
            <section className="rounded-xl border border-border bg-card p-6"><div className="flex items-center justify-between"><div><p className="label-mono">Risk trend</p><h2 className="mt-2 font-display text-xl font-medium">Policy-adjusted score</h2></div><FileScan className="text-muted-foreground" /></div><div className="mt-8"><Trend scans={workspace.scans} /></div></section>
            {queue.length > 0 && <section><p className="label-mono mb-3">Latest batch</p><div className="grid gap-3 sm:grid-cols-2">{queue.map((scan) => <div key={scan.sha256} className="rounded-lg border border-border bg-card p-4"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="truncate font-medium">{scan.metadata.name ?? scan.artifactName}</p><p className="mt-1 text-xs text-muted-foreground">{scan.findings.length} findings · {scan.durationMs} ms</p></div><span className={`font-mono text-lg ${verdictClass[scan.verdict]}`}>{scan.score}</span></div></div>)}</div></section>}
            <section className="overflow-hidden rounded-xl border border-border bg-card"><div className="border-b border-border px-6 py-5"><p className="label-mono">Scan history</p><h2 className="mt-2 font-display text-xl font-medium">All analyzed skills</h2></div>{workspace.scans.length === 0 ? <div className="flex min-h-52 flex-col items-center justify-center px-6 text-center"><ShieldAlert className="text-muted-foreground" /><p className="mt-3 text-sm text-muted-foreground">No scans yet. Upload real skills to begin.</p></div> : <div className="divide-y divide-border">{workspace.scans.map((scan) => <div key={scan.id} className="grid grid-cols-[1fr_auto] gap-4 px-6 py-4 sm:grid-cols-[1fr_120px_120px]"><div className="min-w-0"><p className="truncate font-medium">{scan.declared_name ?? scan.artifact_name}</p><p className="mt-1 text-xs text-muted-foreground">{new Date(scan.scanned_at).toLocaleString()} · {scan.findings_count} findings</p></div><span className={`self-center text-right text-sm font-medium capitalize ${verdictClass[scan.verdict as keyof typeof verdictClass] ?? "text-foreground"}`}>{scan.verdict}</span><span className="hidden self-center text-right font-mono text-lg sm:block">{scan.score}</span></div>)}</div>}</section>
          </div>

          <aside className="h-fit rounded-xl border border-border bg-card p-6 lg:sticky lg:top-24">
            <div className="flex items-center gap-3"><Settings2 className="text-primary" /><div><p className="font-medium">Risk policy</p><p className="text-xs text-muted-foreground">Changes the score and verdict.</p></div></div>
            <div className="mt-8"><div className="flex justify-between text-sm"><span>Review threshold</span><span className="font-mono text-medium">{policy.acceptableScore}</span></div><Slider className="mt-4" min={0} max={98} step={1} value={[policy.acceptableScore]} onValueChange={([value]) => setPolicy((current) => ({ ...current, acceptableScore: Math.min(value ?? current.acceptableScore, current.maliciousScore - 1) }))} /></div>
            <div className="mt-8"><div className="flex justify-between text-sm"><span>Block threshold</span><span className="font-mono text-critical">{policy.maliciousScore}</span></div><Slider className="mt-4" min={1} max={100} step={1} value={[policy.maliciousScore]} onValueChange={([value]) => setPolicy((current) => ({ ...current, maliciousScore: Math.max(value ?? current.maliciousScore, current.acceptableScore + 1) }))} /></div>
            <div className="mt-8 flex items-center justify-between gap-4"><div><p className="text-sm">Block critical findings</p><p className="mt-1 text-xs leading-relaxed text-muted-foreground">A critical match is malicious regardless of score.</p></div><Switch checked={policy.blockOnCritical} onCheckedChange={(checked) => setPolicy((current) => ({ ...current, blockOnCritical: checked }))} /></div>
            <Button className="mt-8 w-full rounded-full" disabled={savingPolicy || workspace.role !== "admin"} onClick={() => void savePolicy()}>{savingPolicy && <LoaderCircle className="animate-spin" />}Save policy</Button>
            {workspace.role !== "admin" && <p className="mt-3 text-center text-xs text-muted-foreground">Only company administrators can change policy.</p>}
          </aside>
        </div>
      </main>
    </div>
  );
}