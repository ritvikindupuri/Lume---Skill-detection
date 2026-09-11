import { useEffect, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import { Bot, CheckCircle2, Hourglass, LoaderCircle, ShieldBan, ShieldCheck, Undo2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ConfidenceHint } from "@/components/dashboard/ConfidenceHint";
import { confidenceLabel, type Severity } from "@/lib/scanner/rules";
import { decideRecommendation, listPendingApprovals, reviewFinding } from "@/lib/workspace.functions";

type Queue = Awaited<ReturnType<typeof listPendingApprovals>>;

const severityClass: Record<Severity, string> = {
  critical: "text-critical",
  high: "text-critical",
  medium: "text-medium",
  low: "text-muted-foreground",
};

interface Props {
  organizationId: string;
  canReview: boolean;
  onChanged?: () => void | Promise<void>;
}

export function ApprovalQueue({ organizationId, canReview, onChanged }: Props) {
  const loadQueue = useServerFn(listPendingApprovals);
  const review = useServerFn(reviewFinding);
  const decide = useServerFn(decideRecommendation);
  const [queue, setQueue] = useState<Queue | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const refresh = async () => {
    try { setQueue(await loadQueue({ data: { organizationId } })); }
    catch { setQueue({ findings: [], containment: [] }); }
  };

  useEffect(() => { void refresh(); }, [organizationId]);

  const resolveFinding = async (findingId: string, scanId: string, decision: "approve" | "revert") => {
    setBusy(findingId);
    const toastId = toast.loading(decision === "approve" ? "Approving this finding…" : "Reverting to unreviewed…");
    try {
      const result = await review({ data: { findingId, scanId, status: decision === "approve" ? "confirmed" : "open" } });
      await refresh();
      await onChanged?.();
      if (decision === "approve") {
        toast.error(`Finding approved · score ${result.score}, verdict ${result.verdict}`, {
          id: toastId,
          description: result.containment === "quarantined" ? "The skill is now quarantined." : "The scan was re-scored with this risk counted.",
        });
      } else {
        toast.success("Sent back for review", { id: toastId, description: "The finding is unreviewed again." });
      }
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Could not record this decision.", { id: toastId });
    } finally {
      setBusy(null);
    }
  };

  const resolveContainment = async (scanId: string, decision: "approve" | "reject") => {
    setBusy(scanId);
    const toastId = toast.loading(decision === "approve" ? "Quarantining this skill…" : "Rejecting the recommendation…");
    try {
      await decide({ data: { scanId, decision } });
      await refresh();
      await onChanged?.();
      if (decision === "approve") toast.error("Skill quarantined", { id: toastId, description: "You approved the AI containment call." });
      else toast.success("Recommendation rejected", { id: toastId, description: "The skill stays available and the decision is on record." });
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Could not record this decision.", { id: toastId });
    } finally {
      setBusy(null);
    }
  };

  if (!queue) return <div className="flex min-h-40 items-center justify-center rounded-xl border border-border bg-card"><LoaderCircle className="size-4 animate-spin text-primary" /></div>;

  const empty = queue.findings.length === 0 && queue.containment.length === 0;

  return (
    <div className="space-y-8">
      <section className="rounded-xl border border-border bg-card p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="label-mono">Analyst approvals</p>
            <h2 className="mt-2 font-display text-xl font-medium">Nothing changes until a human signs off</h2>
            <p className="mt-1 text-sm text-muted-foreground">Findings marked as a real risk and AI containment calls wait here. Approving re-scores the scan; reverting puts it back to unreviewed.</p>
          </div>
          <Button variant="outline" size="sm" className="rounded-full" onClick={() => void refresh()}>Refresh</Button>
        </div>
      </section>

      {empty && (
        <div className="flex min-h-52 flex-col items-center justify-center rounded-xl border border-border bg-card px-6 text-center">
          <CheckCircle2 className="text-safe" />
          <p className="mt-3 text-sm text-muted-foreground">The approval queue is clear.</p>
        </div>
      )}

      {queue.containment.length > 0 && (
        <section className="space-y-3">
          <p className="label-mono">AI containment recommendations · {queue.containment.length}</p>
          {queue.containment.map((scan) => (
            <div key={scan.id} className="rounded-xl border border-border bg-card p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate font-medium">{scan.declared_name ?? scan.artifact_name}</p>
                  <p className="mt-1 text-xs text-muted-foreground">Score {scan.score} · {scan.verdict} · {new Date(scan.scanned_at).toLocaleString()}</p>
                </div>
                <span className="flex items-center gap-1.5 rounded-full bg-medium/10 px-3 py-1 text-xs font-medium text-medium"><Hourglass className="size-3" /> Awaiting approval</span>
              </div>
              <div className="mt-4 rounded-lg border border-border bg-secondary/60 p-4">
                <p className="flex items-center gap-2 text-xs font-medium"><Bot className="size-3.5 text-primary" /> Analysis log · {scan.ai_recommendation_confidence}% confidence</p>
                <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-muted-foreground">{scan.ai_recommendation_reason || "The reviewer recommended containment without a written rationale."}</p>
              </div>
              {canReview && (
                <div className="mt-4 flex flex-wrap gap-2">
                  <Button size="sm" variant="destructive" className="rounded-full" disabled={busy === scan.id} onClick={() => void resolveContainment(scan.id, "approve")}>
                    {busy === scan.id ? <LoaderCircle className="animate-spin" /> : <ShieldBan />} Approve quarantine
                  </Button>
                  <Button size="sm" variant="outline" className="rounded-full" disabled={busy === scan.id} onClick={() => void resolveContainment(scan.id, "reject")}>
                    <ShieldCheck /> Reject
                  </Button>
                </div>
              )}
            </div>
          ))}
        </section>
      )}

      {queue.findings.length > 0 && (
        <section className="space-y-3">
          <p className="label-mono">Pending findings · {queue.findings.length}</p>
          {queue.findings.map((finding) => (
            <div key={finding.id} className="rounded-xl border border-border bg-card p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="font-mono text-xs text-muted-foreground">{finding.rule_id} · {finding.category}</p>
                  <p className="mt-1 font-medium">{finding.title}</p>
                  <p className="mt-1 text-xs text-muted-foreground">{finding.scanName} · {finding.file_path}:{finding.line_number}</p>
                </div>
                <div className="text-right">
                  <p className={`text-sm font-medium capitalize ${severityClass[finding.severity as Severity] ?? ""}`}>{finding.severity}</p>
                  <p className="mt-1 flex items-center justify-end gap-1 text-xs text-muted-foreground">{finding.confidence}% {confidenceLabel(finding.confidence)} <ConfidenceHint /></p>
                </div>
              </div>
              <div className="mt-4 space-y-3 rounded-lg border border-border bg-secondary/60 p-4">
                <div>
                  <p className="text-xs font-medium">Found in the skill — not advice</p>
                  <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs text-muted-foreground">{finding.evidence}</pre>
                </div>
                <div>
                  <p className="text-xs font-medium">What to do</p>
                  <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{finding.remediation}</p>
                </div>
                {finding.aiReason && (
                  <div>
                    <p className="flex items-center gap-2 text-xs font-medium"><Bot className="size-3.5 text-primary" /> AI reading of this skill</p>
                    <p className="mt-1 whitespace-pre-wrap text-sm leading-relaxed text-muted-foreground">{finding.aiReason}</p>
                  </div>
                )}
              </div>
              {canReview && (
                <div className="mt-4 flex flex-wrap gap-2">
                  <Button size="sm" className="rounded-full" disabled={busy === finding.id} onClick={() => void resolveFinding(finding.id, finding.scan_id, "approve")}>
                    {busy === finding.id ? <LoaderCircle className="animate-spin" /> : <CheckCircle2 />} Approve
                  </Button>
                  <Button size="sm" variant="outline" className="rounded-full" disabled={busy === finding.id} onClick={() => void resolveFinding(finding.id, finding.scan_id, "revert")}>
                    <Undo2 /> Revert
                  </Button>
                </div>
              )}
            </div>
          ))}
        </section>
      )}

      {!canReview && !empty && <p className="text-xs text-muted-foreground">Viewers can see the queue but cannot approve or revert.</p>}
    </div>
  );
}
