import { useEffect, useRef, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import { Bot, CheckCircle2, LoaderCircle, ShieldBan, ShieldCheck, X, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ConfidenceHint } from "@/components/dashboard/ConfidenceHint";
import { computeScore, type RiskConfig } from "@/lib/scanner/engine";
import { confidenceLabel, type Severity } from "@/lib/scanner/rules";
import { decideRecommendation, getScanFindings, reviewFinding } from "@/lib/workspace.functions";

type StoredFinding = Awaited<ReturnType<typeof getScanFindings>>[number];

const severityClass: Record<Severity, string> = {
  critical: "text-critical",
  high: "text-critical",
  medium: "text-medium",
  low: "text-muted-foreground",
};

export interface ScanRecommendation {
  action: string;
  reason: string;
  confidence: number;
  status: string;
}

interface Props {
  scanId: string;
  name: string;
  policy: RiskConfig;
  canReview: boolean;
  containment?: string;
  recommendation?: ScanRecommendation;
  onClose: () => void;
  onReviewed?: () => void | Promise<void>;
}

type Outcome = { score: number; verdict: string; containment: string };

export function ScanDetail({ scanId, name, policy, canReview, containment, recommendation, onClose, onReviewed }: Props) {
  const load = useServerFn(getScanFindings);
  const review = useServerFn(reviewFinding);
  const decideContainment = useServerFn(decideRecommendation);
  const [findings, setFindings] = useState<StoredFinding[] | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decisionStatus, setDecisionStatus] = useState<string | null>(null);
  const [deciding, setDeciding] = useState(false);
  const bannerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setFindings(null);
    setOutcome(null);
    setError(null);
    setDecisionStatus(null);
    void load({ data: { scanId } }).then(setFindings).catch(() => setFindings([]));
  }, [scanId]);

  const state = outcome?.containment ?? containment ?? "none";
  const recommendationStatus = decisionStatus ?? recommendation?.status ?? "none";

  const resolveRecommendation = async (decision: "approve" | "reject") => {
    setDeciding(true);
    const toastId = toast.loading(decision === "approve" ? "Quarantining this skill…" : "Rejecting the AI recommendation…");
    try {
      const result = await decideContainment({ data: { scanId, decision } });
      setDecisionStatus(result.status);
      setOutcome((current) => (current ? { ...current, containment: result.containment } : { score: adjusted.score, verdict: adjusted.verdict, containment: result.containment }));
      await onReviewed?.();
      if (decision === "approve") toast.error("Skill quarantined — not safe to deploy", { id: toastId, description: "You approved the AI's containment call." });
      else toast.success("Recommendation rejected", { id: toastId, description: "The skill stays available and the decision is on record." });
      bannerRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Could not record this decision.";
      setError(message);
      toast.error(message, { id: toastId });
    } finally {
      setDeciding(false);
    }
  };


  const decide = async (finding: StoredFinding, status: "confirmed" | "false_positive" | "open") => {
    setPending(finding.id);
    setError(null);
    const toastId = toast.loading(
      status === "confirmed" ? "Recording a real risk…" : status === "false_positive" ? "Dismissing as a false positive…" : "Reopening this finding…",
    );
    try {
      const result = await review({ data: { findingId: finding.id, scanId, status } });
      setFindings((current) => (current ?? []).map((item) => (item.id === finding.id ? { ...item, status } : item)));
      setOutcome(result);
      await onReviewed?.();
      const detail = `New score ${result.score}/100 · ${result.verdict}`;
      if (result.containment === "quarantined") {
        toast.error("Skill quarantined — not safe to deploy", { id: toastId, description: detail });
      } else if (result.containment === "cleared") {
        toast.success("Skill cleared for deployment", { id: toastId, description: detail });
      } else {
        toast.success("Decision saved and the skill re-scored", { id: toastId, description: detail });
      }
      bannerRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Could not save this decision.";
      setError(message);
      toast.error(message, { id: toastId });
    } finally {
      setPending(null);
    }
  };

  const active = (findings ?? []).filter((finding) => finding.status !== "false_positive");
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of active) counts[finding.severity as Severity] += 1;
  const adjusted = computeScore(counts, policy);
  const dismissed = (findings ?? []).length - active.length;

  return (
    <section className="rounded-xl border border-border bg-card">
      <div className="flex items-start justify-between gap-4 border-b border-border px-6 py-5">
        <div className="min-w-0">
          <p className="label-mono">Findings</p>
          <h2 className="mt-2 truncate font-display text-xl font-medium">{name}</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            {dismissed > 0
              ? `${dismissed} marked as a false positive · score excluding them: ${adjusted.score}/100 (${adjusted.verdict})`
              : "Mark anything your reviewers judge to be a false positive."}
          </p>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} title="Close"><X /></Button>
      </div>

      <div ref={bannerRef} />
      {recommendation && recommendation.action !== "none" && (
        <div className="border-b border-border bg-secondary/60 px-6 py-4">
          <div className="flex items-start gap-3">
            <Bot className="mt-0.5 size-5 shrink-0 text-primary" />
            <div className="min-w-0">
              <p className="font-medium">
                AI recommends {recommendation.action === "quarantine" ? "quarantine" : "no containment"}
                <span className="ml-2 text-xs font-normal text-muted-foreground">{recommendation.confidence}% confidence</span>
              </p>
              {recommendation.reason && <p className="mt-1 text-sm text-muted-foreground">{recommendation.reason}</p>}
              <p className="mt-1 text-xs text-muted-foreground">
                {recommendationStatus === "approved" ? "A reviewer approved this recommendation."
                  : recommendationStatus === "rejected" ? "A reviewer rejected this recommendation."
                  : recommendation.action === "quarantine" ? "Nothing is enforced until a person approves it."
                  : "No approval needed — the AI found no reason to contain this skill."}
              </p>
              {canReview && recommendation.action === "quarantine" && recommendationStatus === "pending" && (
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button size="sm" className="rounded-full" disabled={deciding} onClick={() => void resolveRecommendation("approve")}>
                    {deciding ? <LoaderCircle className="animate-spin" /> : <ShieldBan />} Approve quarantine
                  </Button>
                  <Button size="sm" variant="outline" className="rounded-full" disabled={deciding} onClick={() => void resolveRecommendation("reject")}>
                    {deciding ? <LoaderCircle className="animate-spin" /> : <XCircle />} Reject
                  </Button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
      {state === "quarantined" && (
        <div className="flex items-start gap-3 border-b border-border bg-critical/10 px-6 py-4">
          <ShieldBan className="mt-0.5 size-5 shrink-0 text-critical" />
          <div>
            <p className="font-medium text-critical">Skill quarantined</p>
            <p className="mt-1 text-sm text-muted-foreground">
              A reviewer confirmed a real serious risk, so this skill is marked as not safe to deploy
              {outcome ? ` · score ${outcome.score}/100 (${outcome.verdict})` : ""}.
            </p>
          </div>
        </div>
      )}
      {state === "cleared" && (
        <div className="flex items-start gap-3 border-b border-border bg-safe/10 px-6 py-4">
          <ShieldCheck className="mt-0.5 size-5 shrink-0 text-safe" />
          <div>
            <p className="font-medium text-safe">Skill cleared</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Reviewers dismissed the remaining flags, so this skill is recorded as safe to deploy
              {outcome ? ` · score ${outcome.score}/100` : ""}.
            </p>
          </div>
        </div>
      )}
      {error && <p className="border-b border-border px-6 py-3 text-sm text-critical">{error}</p>}


      {findings === null ? (
        <div className="flex min-h-40 items-center justify-center"><LoaderCircle className="size-5 animate-spin text-primary" /></div>
      ) : findings.length === 0 ? (
        <p className="px-6 py-8 text-sm text-muted-foreground">No findings were recorded for this scan.</p>
      ) : (
        <div>
          {groups.map((group) => (
            <section key={group.key}>
              <div className="flex items-center justify-between gap-3 border-b border-border bg-secondary/40 px-6 py-3">
                <p className="text-sm font-medium">{group.title}</p>
                <span className="rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground">{group.items.length}</span>
              </div>
              {group.items.length === 0 ? (
                <p className="border-b border-border px-6 py-4 text-sm text-muted-foreground">{group.empty}</p>
              ) : (
                <div className="divide-y divide-border border-b border-border">
                  {group.items.map((finding) => renderFinding(finding))}
                </div>
              )}
            </section>
          ))}
        </div>
      )}
    </section>
  );
}
