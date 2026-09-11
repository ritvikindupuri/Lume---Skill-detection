import { useEffect, useRef, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import { Bot, CheckCircle2, Hourglass, LoaderCircle, ShieldBan, ShieldCheck, Undo2, X, XCircle } from "lucide-react";
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
  const [noteFor, setNoteFor] = useState<string | null>(null);
  const [note, setNote] = useState("");
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


  const decide = async (finding: StoredFinding, status: "pending_confirm" | "confirmed" | "false_positive" | "open", note?: string) => {
    setPending(finding.id);
    setError(null);
    const toastId = toast.loading(
      status === "pending_confirm" ? "Sending for analyst approval…"
        : status === "confirmed" ? "Approving this real risk…"
        : status === "false_positive" ? "Dismissing as a false positive…"
        : "Reverting this finding…",
    );
    try {
      const result = await review({ data: { findingId: finding.id, scanId, status, note: note ?? "" } });
      setFindings((current) => (current ?? []).map((item) => (item.id === finding.id ? { ...item, status, review_note: note ?? "" } : item)));
      setOutcome(result);
      setNoteFor(null);
      setNote("");
      await onReviewed?.();
      const detail = `New score ${result.score}/100 · ${result.verdict}`;
      if (status === "pending_confirm") {
        toast.success("Sent for analyst approval", { id: toastId, description: "The score and containment stay unchanged until an analyst approves it." });
      } else if (result.containment === "quarantined") {
        toast.error("Skill blocked — not safe to deploy", { id: toastId, description: detail });
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
  const autoBlocked = policy.blockOnCritical && counts.critical > 0;

  const all = findings ?? [];
  const groups = [
    { key: "open", title: "Needs review", empty: "Everything here has been reviewed.", items: all.filter((f) => f.status === "open") },
    { key: "pending_confirm", title: "Pending analyst approval", empty: "Nothing is waiting for approval.", items: all.filter((f) => f.status === "pending_confirm") },
    { key: "confirmed", title: "Real risks", empty: "No findings confirmed as a real risk yet.", items: all.filter((f) => f.status === "confirmed") },
    { key: "false_positive", title: "False positives", empty: "Nothing dismissed as a false positive.", items: all.filter((f) => f.status === "false_positive") },
  ];

  const renderFinding = (finding: StoredFinding) => (
    <div key={finding.id} className={`px-6 py-5 ${finding.status === "false_positive" ? "opacity-55" : ""}`}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="font-mono text-xs text-muted-foreground">{finding.rule_id}</span>
        <span className="font-medium">{finding.title}</span>
        <span className={`text-xs font-medium ${severityClass[finding.severity as Severity]}`}>{finding.severity}</span>
        <span className="text-xs text-muted-foreground">{finding.confidence}% · {confidenceLabel(finding.confidence)} <ConfidenceHint /></span>
      </div>
      <p className="mt-2 font-mono text-xs text-muted-foreground">{finding.file_path}:{finding.line_number}</p>
      <div className="mt-2 rounded-md border border-border bg-background px-3 py-2">
        <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">Found in the skill — not advice</p>
        <p className="mt-1 break-all font-mono text-xs">{finding.evidence}</p>
      </div>
      <p className="mt-2 text-sm"><span className="mr-2 rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-widest text-primary">What to do</span><span className="text-muted-foreground">{finding.remediation}</span></p>
      {finding.status === "pending_confirm" && (
        <p className="mt-3 flex items-center gap-2 text-xs text-muted-foreground"><Hourglass className="size-3.5" /> Waiting for an analyst to approve this as a real risk. The score is unchanged until then.</p>
      )}
      {finding.status === "false_positive" && finding.review_note && (
        <p className="mt-3 rounded-md border border-border px-3 py-2 text-xs text-muted-foreground"><span className="font-medium">Why it was dismissed:</span> {finding.review_note}</p>
      )}
      {canReview && (
        <>
          <div className="mt-3 flex flex-wrap gap-2">
            {autoBlocked ? null : finding.status === "pending_confirm" ? (
              <>
                <Button size="sm" className="rounded-full" disabled={pending === finding.id} onClick={() => void decide(finding, "confirmed")}>
                  {pending === finding.id ? <LoaderCircle className="animate-spin" /> : <CheckCircle2 />} Approve
                </Button>
                <Button size="sm" variant="outline" className="rounded-full" disabled={pending === finding.id} onClick={() => void decide(finding, "open")}>
                  {pending === finding.id ? <LoaderCircle className="animate-spin" /> : <Undo2 />} Revert
                </Button>
              </>
            ) : (
              <Button size="sm" variant={finding.status === "confirmed" ? "default" : "outline"} className="rounded-full" disabled={pending === finding.id} onClick={() => void decide(finding, finding.status === "confirmed" ? "open" : "pending_confirm")}>
                {pending === finding.id ? <LoaderCircle className="animate-spin" /> : <CheckCircle2 />} Real risk
              </Button>
            )}
            <Button
              size="sm"
              variant={finding.status === "false_positive" ? "default" : "outline"}
              className="rounded-full"
              disabled={pending === finding.id}
              onClick={() => {
                if (finding.status === "false_positive") { void decide(finding, "open"); return; }
                setNote("");
                setNoteFor(noteFor === finding.id ? null : finding.id);
              }}
            >
              {pending === finding.id ? <LoaderCircle className="animate-spin" /> : <XCircle />} False positive
            </Button>
          </div>
          {noteFor === finding.id && finding.status !== "false_positive" && (
            <div className="mt-3 rounded-lg border border-border p-3">
              <label htmlFor={`note-${finding.id}`} className="text-xs font-medium">Why is this a false positive?</label>
              <textarea
                id={`note-${finding.id}`}
                value={note}
                onChange={(event) => setNote(event.target.value)}
                rows={3}
                placeholder="Explain what this pattern actually does and why it is safe in this skill."
                className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:border-primary"
              />
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Button size="sm" className="rounded-full" disabled={note.trim().length < 15 || pending === finding.id} onClick={() => void decide(finding, "false_positive", note.trim())}>
                  {pending === finding.id ? <LoaderCircle className="animate-spin" /> : <XCircle />} Dismiss with this reason
                </Button>
                <Button size="sm" variant="ghost" className="rounded-full" onClick={() => { setNoteFor(null); setNote(""); }}>Cancel</Button>
                <span className="text-xs text-muted-foreground">{note.trim().length < 15 ? "At least 15 characters — this is kept on record." : "Kept on record with your name."}</span>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );

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
      {autoBlocked && (
        <div className="flex items-start gap-3 border-b border-border bg-critical/10 px-6 py-4">
          <ShieldBan className="mt-0.5 size-5 shrink-0 text-critical" />
          <div>
            <p className="font-medium text-critical">Auto-blocked by policy</p>
            <p className="mt-1 text-sm text-muted-foreground">
              {counts.critical} critical {counts.critical === 1 ? "finding" : "findings"} matched, and your policy blocks any skill with a critical finding. This skill stays blocked — there is nothing to approve.
              {canReview ? " The only way to change it is to dismiss the critical findings as false positives with a written reason." : ""}
            </p>
          </div>
        </div>
      )}
      {recommendation && recommendation.action !== "none" && !autoBlocked && (
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
      {state === "quarantined" && !autoBlocked && (
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
