import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import { ArrowLeftRight, Bot, LoaderCircle, ShieldAlert, ShieldBan, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { deleteScan } from "@/lib/workspace.functions";

export interface HistoryRow {
  id: string;
  artifact_name: string;
  declared_name: string | null;
  sha256: string;
  score: number;
  verdict: string;
  findings_count: number;
  files_count: number;
  severity_counts: unknown;
  scanned_at: string;
  containment: string;
  ai_recommendation: string;
  recommendation_status: string;
}

const verdictClass: Record<string, string> = { clean: "text-safe", suspicious: "text-medium", malicious: "text-critical" };

function counts(value: unknown) {
  const record = (value && typeof value === "object" ? value : {}) as Record<string, unknown>;
  const read = (key: string) => (typeof record[key] === "number" ? (record[key] as number) : 0);
  return { critical: read("critical"), high: read("high"), medium: read("medium"), low: read("low") };
}

function label(scan: HistoryRow) {
  return scan.declared_name ?? scan.artifact_name;
}

function Delta({ a, b, invert = true }: { a: number; b: number; invert?: boolean }) {
  const diff = b - a;
  if (diff === 0) return <span className="text-xs text-muted-foreground">no change</span>;
  const worse = invert ? diff > 0 : diff < 0;
  return <span className={`text-xs font-medium ${worse ? "text-critical" : "text-safe"}`}>{diff > 0 ? "+" : ""}{diff}</span>;
}

interface Props {
  scans: HistoryRow[];
  canEdit: boolean;
  blockOnCritical: boolean;
  selectedId?: string | undefined;
  onOpen: (scan: HistoryRow) => void;
  onChanged: () => void | Promise<void>;
}

export function ScanHistory({ scans, canEdit, blockOnCritical, selectedId, onOpen, onChanged }: Props) {
  const remove = useServerFn(deleteScan);
  const [selected, setSelected] = useState<string[]>([]);
  const [comparing, setComparing] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [deletingAll, setDeletingAll] = useState(false);

  const toggleSelect = (id: string) => {
    setComparing(false);
    setSelected((current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]));
  };

  const pair =
    comparing && selected.length === 2
      ? selected.map((id) => scans.find((scan) => scan.id === id)).filter((scan): scan is HistoryRow => Boolean(scan))
      : [];

  const confirmDelete = async (scan: HistoryRow) => {
    if (!window.confirm(`Delete the scan of "${label(scan)}"? Its findings are removed too.`)) return;
    setDeleting(scan.id);
    const toastId = toast.loading("Deleting this scan…");
    try {
      await remove({ data: { scanId: scan.id } });
      setSelected((current) => current.filter((id) => id !== scan.id));
      await onChanged();
      toast.success("Scan deleted", { id: toastId, description: `${label(scan)} is no longer in your history.` });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not delete this scan.", { id: toastId });
    } finally {
      setDeleting(null);
    }
  };

  const confirmDeleteAll = async () => {
    const targets = scans.filter((scan) => selected.includes(scan.id));
    if (targets.length === 0) return;
    if (!window.confirm(`Delete ${targets.length} selected scan${targets.length === 1 ? "" : "s"}? Their findings are removed too.`)) return;
    setDeletingAll(true);
    const toastId = toast.loading(`Deleting ${targets.length} scan${targets.length === 1 ? "" : "s"}…`);
    let deleted = 0;
    try {
      for (const scan of targets) {
        await remove({ data: { scanId: scan.id } });
        deleted += 1;
      }
      setSelected([]);
      setComparing(false);
      await onChanged();
      toast.success("Scans deleted", { id: toastId, description: `${deleted} scan${deleted === 1 ? "" : "s"} removed from your history.` });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not delete every selected scan.", { id: toastId });
      setSelected((current) => current.filter((id) => !targets.slice(0, deleted).some((scan) => scan.id === id)));
      await onChanged();
    } finally {
      setDeletingAll(false);
    }
  };

  return (
    <div className="space-y-8">
      {pair.length === 2 && (
        <section className="overflow-hidden rounded-xl border border-border bg-card">
          <div className="flex items-center gap-3 border-b border-border px-6 py-5">
            <ArrowLeftRight className="text-primary" />
            <div>
              <p className="label-mono">Comparison</p>
              <h2 className="mt-1 font-display text-xl font-medium">Two analyzed skills, side by side</h2>
            </div>
          </div>
          <div className="grid gap-px bg-border sm:grid-cols-[200px_1fr_1fr]">
            {[
              { row: "Skill", left: label(pair[0]!), right: label(pair[1]!) },
              { row: "Scanned", left: new Date(pair[0]!.scanned_at).toLocaleString(), right: new Date(pair[1]!.scanned_at).toLocaleString() },
              { row: "Verdict", left: pair[0]!.verdict, right: pair[1]!.verdict },
              { row: "Findings", left: String(pair[0]!.findings_count), right: String(pair[1]!.findings_count), delta: [pair[0]!.findings_count, pair[1]!.findings_count] as const },
              { row: "Critical", left: String(counts(pair[0]!.severity_counts).critical), right: String(counts(pair[1]!.severity_counts).critical), delta: [counts(pair[0]!.severity_counts).critical, counts(pair[1]!.severity_counts).critical] as const },
              { row: "High", left: String(counts(pair[0]!.severity_counts).high), right: String(counts(pair[1]!.severity_counts).high), delta: [counts(pair[0]!.severity_counts).high, counts(pair[1]!.severity_counts).high] as const },
              { row: "Medium", left: String(counts(pair[0]!.severity_counts).medium), right: String(counts(pair[1]!.severity_counts).medium), delta: [counts(pair[0]!.severity_counts).medium, counts(pair[1]!.severity_counts).medium] as const },
              { row: "Files", left: String(pair[0]!.files_count), right: String(pair[1]!.files_count) },
              { row: "Containment", left: pair[0]!.containment, right: pair[1]!.containment },
              { row: "AI call", left: pair[0]!.ai_recommendation, right: pair[1]!.ai_recommendation },
            ].map((line) => (
              <div key={line.row} className="contents">
                <div className="bg-card px-6 py-3 text-sm text-muted-foreground">{line.row}</div>
                <div className="bg-card px-6 py-3 text-sm capitalize">{line.left}</div>
                <div className="flex items-center gap-2 bg-card px-6 py-3 text-sm capitalize">
                  {line.right}
                  {line.delta && <Delta a={line.delta[0]} b={line.delta[1]} />}
                </div>
              </div>
            ))}
            <div className="bg-card px-6 py-4 text-sm text-muted-foreground">Score</div>
            <div className={`bg-card px-6 py-4 font-mono text-2xl ${verdictClass[pair[0]!.verdict] ?? ""}`}>{pair[0]!.score}</div>
            <div className={`flex items-center gap-3 bg-card px-6 py-4 font-mono text-2xl ${verdictClass[pair[1]!.verdict] ?? ""}`}>
              {pair[1]!.score}
              <Delta a={pair[0]!.score} b={pair[1]!.score} />
            </div>
          </div>
          <div className="border-t border-border px-6 py-4">
            <Button variant="outline" size="sm" className="rounded-full" onClick={() => setComparing(false)}>Clear comparison</Button>
          </div>
        </section>
      )}

      <section className="overflow-hidden rounded-xl border border-border bg-card">
        <div className="border-b border-border px-6 py-5">
          <p className="label-mono">History</p>
          <h2 className="mt-2 font-display text-xl font-medium">Every analyzed skill</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Tick scans to select them — pick two and hit Compare, or select several and delete them all at once.
          </p>
        </div>
        {scans.length === 0 ? (
          <div className="flex min-h-52 flex-col items-center justify-center px-6 text-center">
            <ShieldAlert className="text-muted-foreground" />
            <p className="mt-3 text-sm text-muted-foreground">No scans yet. Analyze a skill to start the history.</p>
          </div>
        ) : (
          <>
            {selected.length > 0 && (
              <div className="flex flex-wrap items-center gap-3 border-b border-border bg-secondary/40 px-6 py-3">
                <span className="text-sm text-muted-foreground">{selected.length} selected</span>
                <div className="ml-auto flex items-center gap-2">
                  <Button size="sm" className="rounded-full" disabled={selected.length !== 2 || deletingAll} onClick={() => setComparing(true)}>
                    <ArrowLeftRight className="size-4" /> Compare
                  </Button>
                  {canEdit && (
                    <Button variant="destructive" size="sm" className="rounded-full" disabled={deletingAll} onClick={() => void confirmDeleteAll()}>
                      {deletingAll ? <LoaderCircle className="size-4 animate-spin" /> : <Trash2 className="size-4" />} Delete all
                    </Button>
                  )}
                  <Button variant="ghost" size="sm" className="rounded-full" onClick={() => { setSelected([]); setComparing(false); }}>
                    Clear
                  </Button>
                </div>
              </div>
            )}
            <div className="divide-y divide-border">
              {scans.map((scan) => (
                <div key={scan.id} className={`flex items-center gap-4 px-6 py-4 ${selectedId === scan.id ? "bg-secondary" : ""}`}>
                  <input
                    type="checkbox"
                    aria-label={`Select ${label(scan)}`}
                    checked={selected.includes(scan.id)}
                    onChange={() => toggleSelect(scan.id)}
                    className="size-4 shrink-0 accent-[hsl(var(--primary))]"
                  />
                  <button type="button" onClick={() => onOpen(scan)} className="min-w-0 flex-1 text-left">
                    <span className="block truncate font-medium">{label(scan)}</span>
                    <span className="mt-1 block text-xs text-muted-foreground">
                      {new Date(scan.scanned_at).toLocaleString()} · {scan.findings_count} findings · {scan.files_count} files
                      {scan.ai_recommendation === "quarantine" && scan.recommendation_status === "pending" && (
                        <span className="ml-2 inline-flex items-center gap-1 rounded-full bg-medium/10 px-2 py-0.5 font-medium text-medium"><Bot className="size-3" /> Awaiting your approval</span>
                      )}
                      {blockOnCritical && counts(scan.severity_counts).critical > 0 ? (
                        <span className="ml-2 inline-flex items-center gap-1 rounded-full bg-critical/10 px-2 py-0.5 font-medium text-critical"><ShieldBan className="size-3" /> Auto-blocked · critical</span>
                      ) : scan.containment === "quarantined" ? (
                        <span className="ml-2 rounded-full bg-critical/10 px-2 py-0.5 font-medium text-critical">Quarantined</span>
                      ) : null}
                      {scan.containment === "cleared" && <span className="ml-2 rounded-full bg-safe/10 px-2 py-0.5 font-medium text-safe">Cleared</span>}
                    </span>
                  </button>
                  <span className={`hidden w-24 text-right text-sm font-medium capitalize sm:block ${verdictClass[scan.verdict] ?? ""}`}>{scan.verdict}</span>
                  <span className="w-10 text-right font-mono text-lg">{scan.score}</span>
                  {canEdit && (
                    <Button variant="ghost" size="icon" title="Delete scan" disabled={deleting === scan.id || deletingAll} onClick={() => void confirmDelete(scan)}>
                      {deleting === scan.id ? <LoaderCircle className="animate-spin" /> : <Trash2 className="text-muted-foreground" />}
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </>
        )}
      </section>
    </div>
  );
}
